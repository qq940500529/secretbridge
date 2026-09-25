// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, Arc, AxumPath, ClientTerminalMessage, CreateTerminal, Duration, HeaderMap,
    IntoResponse, Json, MAX_WEBSOCKET_MESSAGE_BYTES, Message, Response, ServerTerminalMessage,
    State, StatusCode, TerminalCapabilities, TerminalConnection, TerminalError, TerminalEvent,
    TerminalListResponse, TerminalShell, TerminalStatus, TerminalSummary, Uuid,
    WEBSOCKET_AUTH_TIMEOUT, WEBSOCKET_SEND_TIMEOUT, WebSocket, WebSocketUpgrade, broadcast,
    constant_time_equal, map_terminal_error, require_session, task, timeout, token_digest,
    validate_origin,
};

pub(crate) async fn list_terminals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TerminalListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    Ok(Json(TerminalListResponse {
        terminals: state.terminals.list(),
    }))
}

pub(crate) async fn get_terminal_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TerminalCapabilities>, ApiError> {
    require_session(&state, &headers).await?;
    Ok(Json(state.terminals.capabilities()))
}

pub(crate) async fn create_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTerminal>,
) -> Result<(StatusCode, Json<TerminalSummary>), ApiError> {
    let _lifecycle = state.configuration_gate.read().await;
    if state
        .runtime_control
        .as_ref()
        .is_some_and(|control| control.stopping.is_cancelled())
    {
        return Err(ApiError::PolicyDenied);
    }
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let terminals = state.terminals.clone();
    let summary = task::spawn_blocking(move || terminals.create(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_terminal_error)?;
    Ok((StatusCode::CREATED, Json(summary)))
}

pub(crate) async fn delete_terminal(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let terminals = state.terminals.clone();
    task::spawn_blocking(move || terminals.remove(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_terminal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn attach_terminal(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    validate_origin(&headers, &state)?;
    Ok(upgrade
        .max_message_size(MAX_WEBSOCKET_MESSAGE_BYTES)
        .on_upgrade(move |socket| terminal_socket(socket, state, id))
        .into_response())
}

pub(crate) async fn terminal_socket(mut socket: WebSocket, state: AppState, terminal_id: Uuid) {
    let mut revocations = state.session_revocations.subscribe();
    let Some(prepared) = prepare_terminal_socket(&mut socket, &state, terminal_id).await else {
        return;
    };
    if !prepared.running {
        return;
    }
    let terminal = prepared.terminal;
    let mut events = prepared.events;
    let mut expected_cursor = prepared.expected_cursor;
    let authentication = prepared.authentication;
    let session_expiry = tokio::time::sleep(Duration::from_secs(authentication.expires_in_seconds));
    tokio::pin!(session_expiry);

    loop {
        tokio::select! {
            () = &mut session_expiry => {
                let _ = send_server_message(
                    &mut socket,
                    &ServerTerminalMessage::Error {
                        code: "session_expired",
                        message: "The browser session expired.",
                    },
                ).await;
                break;
            }
            revoked = revocations.recv() => {
                let is_revoked = match revoked {
                    Ok(revoked_digest) => {
                        constant_time_equal(&authentication.session_digest, &revoked_digest)
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state
                            .authenticate_digest(&authentication.session_digest)
                            .await
                            .is_none()
                    }
                    Err(broadcast::error::RecvError::Closed) => true,
                };
                if is_revoked {
                    let _ = send_server_message(
                        &mut socket,
                        &ServerTerminalMessage::Error {
                            code: "session_revoked",
                            message: "The browser session was revoked.",
                        },
                    ).await;
                    break;
                }
            }
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else { break };
                if !handle_client_message(&mut socket, &terminal, message).await {
                    break;
                }
            }
            event = events.recv() => {
                if !handle_terminal_event(
                    &mut socket,
                    &terminal,
                    &mut expected_cursor,
                    event,
                ).await {
                    break;
                }
            }
        }
    }
    // Flush a closing frame after lag, revocation or process exit rather than
    // dropping the upgraded socket with an unexpected protocol reset.
    let _ = send_socket_message(&mut socket, Message::Close(None)).await;
}

struct PreparedTerminal {
    terminal: Arc<TerminalConnection>,
    events: broadcast::Receiver<TerminalEvent>,
    expected_cursor: u64,
    authentication: SocketAuthentication,
    running: bool,
}

async fn prepare_terminal_socket(
    socket: &mut WebSocket,
    state: &AppState,
    terminal_id: Uuid,
) -> Option<PreparedTerminal> {
    let authentication = authenticate_terminal_socket(socket, state).await?;
    let terminal = state.terminals.attach(
        terminal_id,
        authentication.client_id,
        authentication.request_input,
        authentication.cursor,
    );
    let Ok((terminal, snapshot)) = terminal else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "terminal_not_found",
                message: "The terminal session does not exist.",
            },
        )
        .await;
        return None;
    };
    if send_server_message(
        socket,
        &ServerTerminalMessage::Ready {
            terminal_id: snapshot.summary.id,
            mode: if snapshot.summary.shell == TerminalShell::Synthetic {
                "synthetic_test"
            } else {
                "system_shell"
            },
            shell: snapshot.summary.shell,
            status: snapshot.summary.status,
            replay_from: snapshot.replay_from,
            next_cursor: snapshot.next_cursor,
            replay_truncated: snapshot.replay_truncated,
            retained_bytes: snapshot.retained_bytes,
            retention_capacity: snapshot.retention_capacity,
            input_granted: snapshot.input_granted,
        },
    )
    .await
    .is_err()
    {
        return None;
    }
    if !snapshot.output.is_empty()
        && send_socket_message(socket, Message::Binary(snapshot.output.into()))
            .await
            .is_err()
    {
        return None;
    }
    Some(PreparedTerminal {
        terminal: Arc::new(terminal),
        events: snapshot.events,
        expected_cursor: snapshot.next_cursor,
        authentication,
        running: snapshot.summary.status == TerminalStatus::Running,
    })
}

struct SocketAuthentication {
    session_digest: [u8; 32],
    expires_in_seconds: u64,
    client_id: Uuid,
    request_input: bool,
    cursor: Option<u64>,
}

async fn authenticate_terminal_socket(
    socket: &mut WebSocket,
    state: &AppState,
) -> Option<SocketAuthentication> {
    let authenticated = match timeout(WEBSOCKET_AUTH_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            serde_json::from_str::<ClientTerminalMessage>(&text).ok()
        }
        _ => None,
    };
    let Some(ClientTerminalMessage::Authenticate {
        token,
        client_id,
        request_input,
        cursor,
    }) = authenticated
    else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "authentication_required",
                message: "Authenticate in the first WebSocket message.",
            },
        )
        .await;
        let _ = send_socket_message(socket, Message::Close(None)).await;
        return None;
    };
    let digest = token_digest(&token);
    let Some(expires_in_seconds) = state.authenticate_digest(&digest).await else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "unauthorized",
                message: "The session token is invalid or expired.",
            },
        )
        .await;
        let _ = send_socket_message(socket, Message::Close(None)).await;
        return None;
    };
    Some(SocketAuthentication {
        session_digest: digest,
        expires_in_seconds,
        client_id,
        request_input,
        cursor,
    })
}

pub(crate) async fn handle_terminal_event(
    socket: &mut WebSocket,
    terminal: &TerminalConnection,
    expected_cursor: &mut u64,
    event: Result<TerminalEvent, broadcast::error::RecvError>,
) -> bool {
    match event {
        Ok(TerminalEvent::Output { cursor, data }) => {
            if cursor != *expected_cursor {
                return send_output_gap(socket, terminal).await;
            }
            let sent = send_socket_message(socket, Message::Binary(data.to_vec().into()))
                .await
                .is_ok();
            if sent {
                *expected_cursor = (*expected_cursor)
                    .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
            }
            sent
        }
        Ok(TerminalEvent::Exited(exit_code)) => {
            let _ = send_server_message(socket, &ServerTerminalMessage::Exited { exit_code }).await;
            false
        }
        Ok(TerminalEvent::Terminated) => {
            let _ = send_server_message(socket, &ServerTerminalMessage::Terminated).await;
            false
        }
        Ok(TerminalEvent::Failed) => {
            let _ = send_server_message(
                socket,
                &ServerTerminalMessage::Error {
                    code: "terminal_failed",
                    message: "The terminal process failed.",
                },
            )
            .await;
            false
        }
        Err(broadcast::error::RecvError::Lagged(_)) => send_output_gap(socket, terminal).await,
        Err(broadcast::error::RecvError::Closed) => false,
    }
}

pub(crate) async fn send_output_gap(socket: &mut WebSocket, terminal: &TerminalConnection) -> bool {
    let (oldest_cursor, next_cursor) = terminal.output_bounds();
    let _ = send_server_message(
        socket,
        &ServerTerminalMessage::OutputLagged {
            oldest_cursor,
            next_cursor,
        },
    )
    .await;
    false
}

pub(crate) async fn handle_client_message(
    socket: &mut WebSocket,
    terminal: &Arc<TerminalConnection>,
    message: Message,
) -> bool {
    let Message::Text(text) = message else {
        return !matches!(message, Message::Close(_));
    };
    let Ok(message) = serde_json::from_str::<ClientTerminalMessage>(&text) else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "invalid_message",
                message: "The WebSocket message is invalid.",
            },
        )
        .await;
        return true;
    };

    let terminal = Arc::clone(terminal);
    let result = match message {
        ClientTerminalMessage::Input { data } => {
            task::spawn_blocking(move || terminal.write(data.as_bytes())).await
        }
        ClientTerminalMessage::Resize { rows, cols } => {
            task::spawn_blocking(move || terminal.resize(rows, cols)).await
        }
        ClientTerminalMessage::Terminate => {
            task::spawn_blocking(move || terminal.terminate()).await
        }
        ClientTerminalMessage::Authenticate { .. } => {
            let _ = send_server_message(
                socket,
                &ServerTerminalMessage::Error {
                    code: "already_authenticated",
                    message: "The WebSocket is already authenticated.",
                },
            )
            .await;
            return true;
        }
    };

    let error = match result {
        Ok(Ok(())) => return true,
        Ok(Err(TerminalError::InputLeaseRequired)) => ServerTerminalMessage::Error {
            code: "input_lease_required",
            message: "This connection has read-only access.",
        },
        Ok(Err(TerminalError::InvalidInput)) => ServerTerminalMessage::Error {
            code: "input_too_large",
            message: "The terminal input is too large.",
        },
        Ok(Err(TerminalError::Busy)) => ServerTerminalMessage::Error {
            code: "approved_command_running",
            message: "An approved command currently owns terminal input.",
        },
        _ => ServerTerminalMessage::Error {
            code: "terminal_operation_failed",
            message: "The terminal operation failed.",
        },
    };
    let _ = send_server_message(socket, &error).await;
    true
}

pub(crate) async fn send_server_message(
    socket: &mut WebSocket,
    message: &ServerTerminalMessage,
) -> Result<(), ()> {
    let text = serde_json::to_string(message).expect("server terminal message is serializable");
    send_socket_message(socket, Message::Text(text.into())).await
}

pub(crate) async fn send_socket_message(
    socket: &mut WebSocket,
    message: Message,
) -> Result<(), ()> {
    match timeout(WEBSOCKET_SEND_TIMEOUT, socket.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}
