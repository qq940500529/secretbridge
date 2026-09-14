// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::{Duration, Instant};

use axum::{
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use secretbridge_server::{AppState, router};
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread")]
async fn platform_shell_preserves_state_across_browser_reconnection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("test listener address");
    let origin = format!("http://{address}");
    let (state, bootstrap) = AppState::new([origin.clone()]);
    let control = router(state.clone());
    let token = pair(control.clone(), &origin, &bootstrap).await;

    assert_terminal_capabilities(control.clone(), &token).await;
    assert_invalid_terminal_requests(control.clone(), &origin, &token).await;
    let terminal_id = create_real_terminal(control.clone(), &origin, &token).await;

    let server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .await
            .expect("test server");
    });
    let url = format!("ws://{address}/api/v1/terminals/{terminal_id}/attach");
    let client_id = uuid::Uuid::new_v4();
    let (mut first, ready) = connect(&url, &origin, &token, client_id, None).await;
    assert_eq!(ready["mode"], "system_shell");
    assert_eq!(ready["shell"], expected_shell());
    assert_eq!(ready["input_granted"], true);
    first
        .send(input_message(&first_command()))
        .await
        .expect("write real shell command");
    let first_output = read_until(&mut first, b"real-shell-marker").await;
    let first_cursor = ready["replay_from"].as_u64().expect("replay cursor")
        + u64::try_from(first_output.len()).expect("output length");
    first.close(None).await.expect("detach browser socket");

    let listed = control
        .clone()
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/terminals",
            &token,
            None,
            Body::empty(),
        ))
        .await
        .expect("terminal list response");
    assert_eq!(
        response_json(listed).await["terminals"][0]["status"],
        "running"
    );

    let (mut reattached, ready) =
        connect(&url, &origin, &token, client_id, Some(first_cursor)).await;
    assert_eq!(ready["replay_from"], first_cursor);
    reattached
        .send(input_message(&exit_command()))
        .await
        .expect("write reconnect command");
    let _ = read_until(&mut reattached, b"reconnected-shell").await;
    assert!(wait_for_message_type(&mut reattached, "exited").await);

    assert_real_terminal_force_termination(control.clone(), address, &origin, &token).await;
    #[cfg(windows)]
    assert_windows_cmd(control, address, &origin, &token).await;
    server.abort();
    let _ = server.await;
}

async fn assert_terminal_capabilities(control: axum::Router, token: &str) {
    let response = control
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/terminals/capabilities",
            token,
            None,
            Body::empty(),
        ))
        .await
        .expect("capability response");
    assert_eq!(response.status(), StatusCode::OK);
    let capabilities = response_json(response).await;
    assert_eq!(capabilities["platform"], expected_platform());
    assert_eq!(capabilities["default_shell"], expected_shell());
}

async fn create_real_terminal(control: axum::Router, origin: &str, token: &str) -> String {
    let working_directory = std::env::current_dir()
        .expect("current directory")
        .canonicalize()
        .expect("canonical current directory");
    let response = control
        .oneshot(authenticated_request(
            "POST",
            "/api/v1/terminals",
            token,
            Some(origin),
            Body::from(
                serde_json::json!({
                    "rows": 24,
                    "cols": 100,
                    "shell": expected_shell(),
                    "name": "Cross-platform acceptance",
                    "working_directory": working_directory,
                    "environment": {
                        "SECRETBRIDGE_INTEGRATION_MARKER": "real-shell-marker"
                    }
                })
                .to_string(),
            ),
        ))
        .await
        .expect("terminal response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    assert_eq!(created["name"], "Cross-platform acceptance");
    assert_eq!(created["shell"], expected_shell());
    assert_eq!(created["status"], "running");
    assert_eq!(created["environment_variable_count"], 1);
    assert!(created["process_id"].as_u64().is_some());
    created["id"].as_str().expect("terminal id").to_owned()
}

async fn assert_invalid_terminal_requests(control: axum::Router, origin: &str, token: &str) {
    for body in [
        serde_json::json!({
            "rows": 24,
            "cols": 80,
            "shell": "synthetic",
            "environment": {}
        }),
        serde_json::json!({
            "rows": 24,
            "cols": 80,
            "shell": expected_shell(),
            "working_directory": "relative/path",
            "environment": {}
        }),
        serde_json::json!({
            "rows": 24,
            "cols": 80,
            "shell": expected_shell(),
            "environment": { "INVALID-NAME": "value" }
        }),
    ] {
        let response = control
            .clone()
            .oneshot(authenticated_request(
                "POST",
                "/api/v1/terminals",
                token,
                Some(origin),
                Body::from(body.to_string()),
            ))
            .await
            .expect("invalid terminal response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(windows)]
async fn assert_windows_cmd(
    control: axum::Router,
    address: std::net::SocketAddr,
    origin: &str,
    token: &str,
) {
    let created = control
        .oneshot(authenticated_request(
            "POST",
            "/api/v1/terminals",
            token,
            Some(origin),
            Body::from(
                serde_json::json!({
                    "rows": 24,
                    "cols": 80,
                    "shell": "cmd",
                    "name": "CMD acceptance",
                    "environment": {}
                })
                .to_string(),
            ),
        ))
        .await
        .expect("create CMD terminal");
    assert_eq!(created.status(), StatusCode::CREATED);
    let terminal = response_json(created).await;
    assert_eq!(terminal["shell"], "cmd");
    let id = terminal["id"].as_str().expect("CMD terminal id");
    let url = format!("ws://{address}/api/v1/terminals/{id}/attach");
    let (mut socket, ready) = connect(&url, origin, token, uuid::Uuid::new_v4(), None).await;
    assert_eq!(ready["shell"], "cmd");
    socket
        .send(input_message("echo cmd-shell-marker\r\nexit 7\r\n"))
        .await
        .expect("write CMD command");
    let _ = read_until(&mut socket, b"cmd-shell-marker").await;
    assert!(wait_for_message_type(&mut socket, "exited").await);
}

async fn assert_real_terminal_force_termination(
    control: axum::Router,
    address: std::net::SocketAddr,
    origin: &str,
    token: &str,
) {
    let created = control
        .clone()
        .oneshot(authenticated_request(
            "POST",
            "/api/v1/terminals",
            token,
            Some(origin),
            Body::from(
                serde_json::json!({
                    "rows": 24,
                    "cols": 80,
                    "shell": expected_shell(),
                    "name": "Cancellation acceptance",
                    "environment": {}
                })
                .to_string(),
            ),
        ))
        .await
        .expect("create cancellable terminal");
    assert_eq!(created.status(), StatusCode::CREATED);
    let terminal = response_json(created).await;
    let id = terminal["id"].as_str().expect("terminal id");
    let url = format!("ws://{address}/api/v1/terminals/{id}/attach");
    let (mut socket, _) = connect(&url, origin, token, uuid::Uuid::new_v4(), None).await;
    socket
        .send(input_message(&wait_command()))
        .await
        .expect("start long command");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let started = Instant::now();
    let deleted = control
        .oneshot(authenticated_request(
            "DELETE",
            &format!("/api/v1/terminals/{id}"),
            token,
            Some(origin),
            Body::empty(),
        ))
        .await
        .expect("terminate response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(wait_for_message_type(&mut socket, "terminated").await);
    assert!(started.elapsed() < Duration::from_secs(5));
}

async fn pair(control: axum::Router, origin: &str, bootstrap: &str) -> String {
    let response = control
        .oneshot(authenticated_request(
            "POST",
            "/api/v1/session/pair",
            bootstrap,
            Some(origin),
            Body::empty(),
        ))
        .await
        .expect("pairing response");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await["session_token"]
        .as_str()
        .expect("session token")
        .to_owned()
}

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(
    url: &str,
    origin: &str,
    token: &str,
    client_id: uuid::Uuid,
    cursor: Option<u64>,
) -> (TestSocket, serde_json::Value) {
    let mut request = url.into_client_request().expect("websocket request");
    request
        .headers_mut()
        .insert("origin", origin.parse().expect("origin header"));
    let (mut socket, response) = connect_async(request).await.expect("websocket connection");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    socket
        .send(Message::Text(
            serde_json::json!({
                "type": "authenticate",
                "token": token,
                "client_id": client_id,
                "request_input": true,
                "cursor": cursor,
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("authenticate websocket");
    let ready = timeout(Duration::from_secs(10), socket.next())
        .await
        .expect("ready timeout")
        .expect("websocket open")
        .expect("ready message");
    let Message::Text(ready) = ready else {
        panic!("ready control message must precede terminal output");
    };
    (socket, serde_json::from_str(&ready).expect("ready JSON"))
}

async fn read_until(socket: &mut TestSocket, needle: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for _ in 0..1024 {
        let message = timeout(Duration::from_secs(15), socket.next())
            .await
            .expect("terminal output timeout")
            .expect("websocket remains open")
            .expect("valid websocket message");
        if let Message::Binary(bytes) = message {
            output.extend_from_slice(&bytes);
            if output.ends_with(b"\x1b[6n") {
                socket
                    .send(input_message("\u{1b}[1;1R"))
                    .await
                    .expect("answer terminal cursor query");
            }
            if contains(&output, needle) {
                return output;
            }
        }
    }
    panic!("real terminal output was not received");
}

async fn wait_for_message_type(socket: &mut TestSocket, message_type: &str) -> bool {
    for _ in 0..32 {
        let Some(Ok(message)) = timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("terminal status timeout")
        else {
            return false;
        };
        if let Message::Text(text) = message {
            let value: serde_json::Value = serde_json::from_str(&text).expect("control JSON");
            if value["type"] == message_type {
                return true;
            }
        }
    }
    false
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    serde_json::from_slice(&body).expect("response JSON")
}

fn authenticated_request(
    method: &str,
    uri: &str,
    token: &str,
    origin: Option<&str>,
    body: Body,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder.body(body).expect("valid request")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn input_message(data: &str) -> Message {
    Message::Text(
        serde_json::json!({ "type": "input", "data": data })
            .to_string()
            .into(),
    )
}

#[cfg(windows)]
const fn expected_platform() -> &'static str {
    "windows"
}

#[cfg(target_os = "macos")]
const fn expected_platform() -> &'static str {
    "macos"
}

#[cfg(all(unix, not(target_os = "macos")))]
const fn expected_platform() -> &'static str {
    "linux"
}

#[cfg(windows)]
const fn expected_shell() -> &'static str {
    "powershell"
}

#[cfg(target_os = "macos")]
const fn expected_shell() -> &'static str {
    "zsh"
}

#[cfg(all(unix, not(target_os = "macos")))]
const fn expected_shell() -> &'static str {
    "bash"
}

#[cfg(windows)]
fn first_command() -> String {
    "Write-Output $env:SECRETBRIDGE_INTEGRATION_MARKER; (Get-Location).Path\r\n".to_owned()
}

#[cfg(unix)]
fn first_command() -> String {
    "printf '%s\\n' \"$SECRETBRIDGE_INTEGRATION_MARKER\"; pwd\n".to_owned()
}

#[cfg(windows)]
fn exit_command() -> String {
    "Write-Output 'reconnected-shell'; exit 0\r\n".to_owned()
}

#[cfg(unix)]
fn exit_command() -> String {
    "printf '%s\\n' 'reconnected-shell'; exit 0\n".to_owned()
}

#[cfg(windows)]
fn wait_command() -> String {
    "Start-Sleep -Seconds 30\r\n".to_owned()
}

#[cfg(unix)]
fn wait_command() -> String {
    "sleep 30\n".to_owned()
}
