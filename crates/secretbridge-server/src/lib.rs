// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod terminal;

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{
        Path as AxumPath, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY},
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use secretbridge_core::StatusResponse;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{RwLock, broadcast},
    task,
    time::timeout,
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use uuid::Uuid;

use terminal::{
    TerminalError, TerminalEvent, TerminalHandle, TerminalManager, TerminalStatus, TerminalSummary,
};

const BEARER_PREFIX: &str = "Bearer ";
const SESSION_TTL: Duration = Duration::from_mins(30);
const WEBSOCKET_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AppState {
    bootstrap_token: Arc<RwLock<Option<[u8; 32]>>>,
    session_tokens: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    session_revocations: broadcast::Sender<[u8; 32]>,
    trusted_origins: Arc<HashSet<String>>,
    terminals: TerminalManager,
}

impl AppState {
    #[must_use]
    pub fn new(trusted_origins: impl IntoIterator<Item = String>) -> (Self, String) {
        let program =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("secretbridge-server"));
        Self::new_with_terminal_program(trusted_origins, program)
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_with_terminal_program(
        trusted_origins: impl IntoIterator<Item = String>,
        program: PathBuf,
    ) -> (Self, String) {
        let bootstrap_token = new_token();
        let (session_revocations, _) = broadcast::channel(64);
        let state = Self {
            bootstrap_token: Arc::new(RwLock::new(Some(token_digest(&bootstrap_token)))),
            session_tokens: Arc::new(RwLock::new(HashMap::new())),
            session_revocations,
            trusted_origins: Arc::new(trusted_origins.into_iter().collect()),
            terminals: TerminalManager::new(program),
        };
        (state, bootstrap_token)
    }

    async fn issue_session(&self) -> (String, u64) {
        let token = new_token();
        self.session_tokens
            .write()
            .await
            .insert(token_digest(&token), Instant::now() + SESSION_TTL);
        (token, SESSION_TTL.as_secs())
    }

    async fn authenticate(&self, token: &str) -> Option<u64> {
        self.authenticate_digest(&token_digest(token)).await
    }

    async fn authenticate_digest(&self, digest: &[u8; 32]) -> Option<u64> {
        let now = Instant::now();
        let mut sessions = self.session_tokens.write().await;
        sessions.retain(|_, expires_at| *expires_at > now);
        sessions
            .get(digest)
            .map(|expires_at| expires_at.saturating_duration_since(now).as_secs())
    }

    async fn revoke(&self, token: &str) -> bool {
        let digest = token_digest(token);
        let removed = self.session_tokens.write().await.remove(&digest).is_some();
        if removed {
            let _ = self.session_revocations.send(digest);
        }
        removed
    }

    async fn active_session_count(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.session_tokens.write().await;
        sessions.retain(|_, expires_at| *expires_at > now);
        sessions.len()
    }
}

#[derive(Serialize)]
struct PairResponse {
    session_token: String,
    token_type: &'static str,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    mode: &'static str,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTerminalRequest {
    rows: u16,
    cols: u16,
}

#[derive(Serialize)]
struct TerminalListResponse {
    terminals: Vec<TerminalSummary>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientTerminalMessage {
    Authenticate { token: String },
    Input { data: String },
    Resize { rows: u16, cols: u16 },
    Terminate,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerTerminalMessage {
    Ready {
        terminal_id: Uuid,
        mode: &'static str,
        status: TerminalStatus,
    },
    Exited {
        exit_code: u32,
    },
    Terminated,
    Error {
        code: &'static str,
        message: &'static str,
    },
    OutputLagged {
        dropped_messages: u64,
    },
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

enum ApiError {
    BadRequest,
    Conflict,
    Internal,
    InvalidOrigin,
    NotFound,
    Unauthorized,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                "The request is invalid.",
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "capacity_reached",
                "The synthetic terminal limit has been reached.",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "The local operation failed.",
            ),
            Self::InvalidOrigin => (
                StatusCode::FORBIDDEN,
                "invalid_origin",
                "The request origin is not trusted.",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "The requested resource was not found.",
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication failed.",
            ),
        };
        (status, Json(ErrorResponse { code, message })).into_response()
    }
}

pub fn router(state: AppState) -> Router {
    apply_security_headers(api_router(state))
}

pub fn router_with_web(state: AppState, web_root: impl AsRef<Path>) -> Router {
    apply_security_headers(
        api_router(state)
            .fallback_service(ServeDir::new(web_root).append_index_html_on_directories(true)),
    )
}

fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/session/pair", post(pair))
        .route("/api/v1/session", get(session).delete(revoke_session))
        .route(
            "/api/v1/terminals",
            get(list_terminals).post(create_terminal),
        )
        .route("/api/v1/terminals/{id}", delete(delete_terminal))
        .route("/api/v1/terminals/{id}/attach", get(attach_terminal))
        .with_state(state)
}

fn apply_security_headers(router: Router) -> Router {
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
                 script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                 form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let paired = state.active_session_count().await > 0;
    Json(StatusResponse::synthetic_only(paired))
}

async fn pair(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let mut bootstrap = state.bootstrap_token.write().await;
    let Some(expected) = bootstrap.as_ref() else {
        return Err(ApiError::Unauthorized);
    };
    if !constant_time_equal(&token_digest(presented), expected) {
        return Err(ApiError::Unauthorized);
    }
    bootstrap.take();
    drop(bootstrap);

    let (session_token, expires_in_seconds) = state.issue_session().await;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let expires_in_seconds = state
        .authenticate(presented)
        .await
        .ok_or(ApiError::Unauthorized)?;
    Ok(Json(SessionResponse {
        authenticated: true,
        mode: "synthetic_only",
        expires_in_seconds,
    }))
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    state
        .revoke(presented)
        .await
        .then_some(StatusCode::NO_CONTENT)
        .ok_or(ApiError::Unauthorized)
}

async fn list_terminals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TerminalListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    Ok(Json(TerminalListResponse {
        terminals: state.terminals.list(),
    }))
}

async fn create_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTerminalRequest>,
) -> Result<(StatusCode, Json<TerminalSummary>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let terminals = state.terminals.clone();
    let summary = task::spawn_blocking(move || terminals.create(request.rows, request.cols))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_terminal_error)?;
    Ok((StatusCode::CREATED, Json(summary)))
}

async fn delete_terminal(
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

async fn attach_terminal(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    validate_origin(&headers, &state)?;
    let terminal = state.terminals.get(id).map_err(map_terminal_error)?;
    Ok(upgrade
        .max_message_size(MAX_WEBSOCKET_MESSAGE_BYTES)
        .on_upgrade(move |socket| terminal_socket(socket, state, terminal))
        .into_response())
}

async fn terminal_socket(mut socket: WebSocket, state: AppState, terminal: TerminalHandle) {
    let mut revocations = state.session_revocations.subscribe();
    let Some((session_digest, expires_in_seconds)) =
        authenticate_terminal_socket(&mut socket, &state).await
    else {
        return;
    };

    let (summary, backlog, mut events) = terminal.snapshot_and_subscribe();
    if send_server_message(
        &mut socket,
        &ServerTerminalMessage::Ready {
            terminal_id: summary.id,
            mode: "synthetic_only",
            status: summary.status,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    if !backlog.is_empty() && socket.send(Message::Binary(backlog.into())).await.is_err() {
        return;
    }
    if summary.status != TerminalStatus::Running {
        return;
    }
    let session_expiry = tokio::time::sleep(Duration::from_secs(expires_in_seconds));
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
                    Ok(revoked_digest) => constant_time_equal(&session_digest, &revoked_digest),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state.authenticate_digest(&session_digest).await.is_none()
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
                if !handle_terminal_event(&mut socket, event).await {
                    break;
                }
            }
        }
    }
}

async fn authenticate_terminal_socket(
    socket: &mut WebSocket,
    state: &AppState,
) -> Option<([u8; 32], u64)> {
    let authenticated = match timeout(WEBSOCKET_AUTH_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            serde_json::from_str::<ClientTerminalMessage>(&text).ok()
        }
        _ => None,
    };
    let Some(ClientTerminalMessage::Authenticate { token }) = authenticated else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "authentication_required",
                message: "Authenticate in the first WebSocket message.",
            },
        )
        .await;
        let _ = socket.send(Message::Close(None)).await;
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
        let _ = socket.send(Message::Close(None)).await;
        return None;
    };
    Some((digest, expires_in_seconds))
}

async fn handle_terminal_event(
    socket: &mut WebSocket,
    event: Result<TerminalEvent, broadcast::error::RecvError>,
) -> bool {
    match event {
        Ok(TerminalEvent::Output(output)) => socket
            .send(Message::Binary(output.to_vec().into()))
            .await
            .is_ok(),
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
                    message: "The synthetic terminal process failed.",
                },
            )
            .await;
            false
        }
        Err(broadcast::error::RecvError::Lagged(dropped_messages)) => send_server_message(
            socket,
            &ServerTerminalMessage::OutputLagged { dropped_messages },
        )
        .await
        .is_ok(),
        Err(broadcast::error::RecvError::Closed) => false,
    }
}

async fn handle_client_message(
    socket: &mut WebSocket,
    terminal: &TerminalHandle,
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

    let terminal = terminal.clone();
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

    if let Ok(Ok(())) = result {
        true
    } else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "terminal_operation_failed",
                message: "The synthetic terminal operation failed.",
            },
        )
        .await;
        true
    }
}

async fn send_server_message(
    socket: &mut WebSocket,
    message: &ServerTerminalMessage,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(message).expect("server terminal message is serializable");
    socket.send(Message::Text(text.into())).await
}

async fn require_session(state: &AppState, headers: &HeaderMap) -> Result<u64, ApiError> {
    let token = bearer_token(headers).ok_or(ApiError::Unauthorized)?;
    state
        .authenticate(token)
        .await
        .ok_or(ApiError::Unauthorized)
}

fn map_terminal_error(error: TerminalError) -> ApiError {
    match error {
        TerminalError::Capacity => ApiError::Conflict,
        TerminalError::InvalidSize | TerminalError::Closed => ApiError::BadRequest,
        TerminalError::NotFound => ApiError::NotFound,
        TerminalError::SpawnFailed => ApiError::Internal,
    }
}

fn validate_origin(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidOrigin)?;
    state
        .trusted_origins
        .contains(origin)
        .then_some(())
        .ok_or(ApiError::InvalidOrigin)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix(BEARER_PREFIX)
        .filter(|token| !token.is_empty())
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_equal(presented: &[u8; 32], expected: &[u8; 32]) -> bool {
    bool::from(presented.ct_eq(expected))
}

fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header::AUTHORIZATION},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{AppState, SESSION_TTL, apply_security_headers, router};

    const ORIGIN: &str = "http://127.0.0.1:8787";

    fn test_app() -> (axum::Router, String) {
        let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
        (router(state), bootstrap)
    }

    #[tokio::test]
    async fn status_is_explicitly_synthetic_only() {
        let (app, _) = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let status: serde_json::Value = serde_json::from_slice(&bytes).expect("status JSON");
        assert_eq!(status["mode"], "synthetic_only");
        assert_eq!(status["real_credentials_enabled"], false);
    }

    #[tokio::test]
    async fn pairing_rejects_missing_origin() {
        let (app, bootstrap) = test_app();
        let response = app
            .oneshot(pair_request(&bootstrap, None))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pairing_rejects_wrong_token() {
        let (app, _) = test_app();
        let response = app
            .oneshot(pair_request("synthetic-wrong-token", Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_token_can_only_be_used_once() {
        let (app, bootstrap) = test_app();
        let first = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(first.status(), StatusCode::OK);
        let body = first
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        assert_eq!(pair["token_type"], "Bearer");
        assert_eq!(pair["expires_in_seconds"], SESSION_TTL.as_secs());
        assert!(
            pair["session_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );

        let replay = app
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_can_be_checked_and_revoked() {
        let (app, bootstrap) = test_app();
        let paired = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        let body = paired
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        let token = pair["session_token"]
            .as_str()
            .expect("session token")
            .to_owned();

        let session = app
            .clone()
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/session",
                &token,
                None,
            ))
            .await
            .expect("router response");
        assert_eq!(session.status(), StatusCode::OK);

        let revoked = app
            .clone()
            .oneshot(authenticated_request(
                "DELETE",
                "/api/v1/session",
                &token,
                Some(ORIGIN),
            ))
            .await
            .expect("router response");
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

        let rejected = app
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/session",
                &token,
                None,
            ))
            .await
            .expect("router response");
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn terminal_creation_requires_a_trusted_origin() {
        let (app, bootstrap) = test_app();
        let paired = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        let body = paired
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        let token = pair["session_token"].as_str().expect("session token");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/terminals")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":24,"cols":80}"#))
                    .expect("valid request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn security_headers_cover_web_fallbacks() {
        let app = apply_security_headers(axum::Router::new().fallback(|| async { "web" }));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(response.headers().contains_key("content-security-policy"));
    }

    fn pair_request(token: &str, origin: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/session/pair")
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(Body::empty()).expect("valid request")
    }

    fn authenticated_request(
        method: &str,
        uri: &str,
        token: &str,
        origin: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(Body::empty()).expect("valid request")
    }
}
