// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

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
async fn websocket_can_detach_reattach_and_observe_revocation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("test listener address");
    let origin = format!("http://{address}");
    let program = PathBuf::from(env!("CARGO_BIN_EXE_secretbridge-server"));
    let (state, bootstrap) = AppState::new_with_terminal_program([origin.clone()], program);
    let control = router(state.clone());

    let paired = control
        .clone()
        .oneshot(authenticated_request(
            "POST",
            "/api/v1/session/pair",
            &bootstrap,
            Some(&origin),
            Body::empty(),
        ))
        .await
        .expect("pairing response");
    assert_eq!(paired.status(), StatusCode::OK);
    let pair = response_json(paired).await;
    let token = pair["session_token"]
        .as_str()
        .expect("session token")
        .to_owned();

    let created = control
        .clone()
        .oneshot(authenticated_request(
            "POST",
            "/api/v1/terminals",
            &token,
            Some(&origin),
            Body::from(r#"{"rows":24,"cols":80}"#),
        ))
        .await
        .expect("terminal response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    let terminal_id = created["id"].as_str().expect("terminal id");

    let server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .await
            .expect("test server");
    });

    let url = format!("ws://{address}/api/v1/terminals/{terminal_id}/attach");
    let first_client = uuid::Uuid::new_v4();
    let second_client = uuid::Uuid::new_v4();
    let (mut first, ready) = connect(&url, &origin, &token, first_client, None).await;
    assert_eq!(ready["input_granted"], true);
    assert_eq!(ready["replay_from"], 0);
    let first_output = read_until(&mut first, b"SecretBridge synthetic terminal").await;
    assert!(contains(&first_output, b"SecretBridge synthetic terminal"));
    let first_cursor = ready["replay_from"].as_u64().expect("replay cursor")
        + u64::try_from(first_output.len()).expect("output length");
    first
        .send(Message::Text(
            serde_json::json!({"type": "input", "data": "status\r\n"})
                .to_string()
                .into(),
        ))
        .await
        .expect("write before disconnect");
    first.close(None).await.expect("detach first websocket");

    assert_terminal_running(control.clone(), &token).await;

    let (mut reattached, ready) =
        connect(&url, &origin, &token, first_client, Some(first_cursor)).await;
    assert_eq!(ready["input_granted"], true);
    assert_eq!(ready["replay_from"], first_cursor);
    let replay = read_until(&mut reattached, b"mode=synthetic_only").await;
    assert!(contains(&replay, b"mode=synthetic_only"));

    let (mut read_only, ready) = connect(&url, &origin, &token, second_client, None).await;
    assert_eq!(ready["input_granted"], false);
    read_only
        .send(Message::Text(
            serde_json::json!({"type": "input", "data": "status\r\n"})
                .to_string()
                .into(),
        ))
        .await
        .expect("send read-only input");
    assert!(wait_for_control_message(&mut read_only, "input_lease_required").await);
    read_only.close(None).await.expect("close read-only socket");
    reattached
        .close(None)
        .await
        .expect("release input lease connection");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (next_writer, ready) = connect(&url, &origin, &token, second_client, None).await;
    assert_eq!(ready["input_granted"], true);
    let mut next_writer =
        assert_output_flood_and_truncation(&url, &origin, &token, second_client, next_writer).await;

    assert_terminal_cancellation(control.clone(), address, &origin, &token).await;
    revoke_and_assert(control, &token, &origin, &mut next_writer).await;

    server.abort();
    let _ = server.await;
}

async fn assert_output_flood_and_truncation(
    url: &str,
    origin: &str,
    token: &str,
    client_id: uuid::Uuid,
    mut writer: TestSocket,
) -> TestSocket {
    writer
        .send(Message::Text(
            serde_json::json!({"type": "input", "data": "flood 2097152\r\n"})
                .to_string()
                .into(),
        ))
        .await
        .expect("request synthetic output flood");
    // Deliberately stop reading while the child emits more than the broadcast and
    // replay capacities. A new attachment must remain responsive and explicit.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let (mut recovered, ready) = connect(url, origin, token, client_id, Some(0)).await;
    drop(writer);
    assert_eq!(ready["input_granted"], true);
    assert_eq!(ready["replay_truncated"], true);
    assert_eq!(ready["retained_bytes"], 64 * 1024);
    assert_eq!(ready["retention_capacity"], 64 * 1024);
    let replay_from = ready["replay_from"].as_u64().expect("replay start");
    let next_cursor = ready["next_cursor"].as_u64().expect("next cursor");
    assert_eq!(next_cursor - replay_from, 64 * 1024);
    let _ = read_until(&mut recovered, b"flood complete bytes=2097152").await;
    recovered
}

async fn assert_terminal_cancellation(
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
            Body::from(r#"{"rows":24,"cols":80}"#),
        ))
        .await
        .expect("second terminal response");
    let terminal = response_json(created).await;
    let id = terminal["id"].as_str().expect("second terminal id");
    let url = format!("ws://{address}/api/v1/terminals/{id}/attach");
    let (mut socket, ready) = connect(&url, origin, token, uuid::Uuid::new_v4(), None).await;
    assert_eq!(ready["input_granted"], true);
    let _ = read_until(&mut socket, b"SecretBridge synthetic terminal").await;
    socket
        .send(Message::Text(
            serde_json::json!({"type": "input", "data": "wait 30000\r\n"})
                .to_string()
                .into(),
        ))
        .await
        .expect("start synthetic wait");
    let _ = read_until(&mut socket, b"wait begin milliseconds=30000").await;

    let cancellation_started = Instant::now();
    let deleted = control
        .oneshot(authenticated_request(
            "DELETE",
            &format!("/api/v1/terminals/{id}"),
            token,
            Some(origin),
            Body::empty(),
        ))
        .await
        .expect("terminal cancellation response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(wait_for_message_type(&mut socket, "terminated").await);
    assert!(cancellation_started.elapsed() < Duration::from_secs(5));
}

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn revoke_and_assert(
    control: axum::Router,
    token: &str,
    origin: &str,
    socket: &mut TestSocket,
) {
    let revoked = control
        .oneshot(authenticated_request(
            "DELETE",
            "/api/v1/session",
            token,
            Some(origin),
            Body::empty(),
        ))
        .await
        .expect("revocation response");
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    assert!(wait_for_control_message(socket, "session_revoked").await);
}

async fn assert_terminal_running(control: axum::Router, token: &str) {
    let listed = control
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/terminals",
            token,
            None,
            Body::empty(),
        ))
        .await
        .expect("terminal list response");
    let listed = response_json(listed).await;
    assert_eq!(listed["terminals"][0]["status"], "running");
}

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
    let ready = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("ready timeout")
        .expect("websocket open")
        .expect("ready message");
    let Message::Text(ready) = ready else {
        panic!("ready control message must precede terminal output");
    };
    let ready = serde_json::from_str(&ready).expect("ready JSON");
    (socket, ready)
}

async fn read_until<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>, needle: &[u8]) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut output = Vec::new();
    for _ in 0..1024 {
        let message = timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("websocket output timeout")
            .expect("websocket remains open")
            .expect("valid websocket message");
        if let Message::Binary(bytes) = message {
            output.extend_from_slice(&bytes);
            if output.ends_with(b"\x1b[6n") {
                socket
                    .send(Message::Text(
                        serde_json::json!({"type": "input", "data": "\u{1b}[1;1R"})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .expect("answer cursor query");
            }
            if contains(&output, needle) {
                return output;
            }
        }
    }
    panic!("terminal output was not received");
}

async fn wait_for_control_message<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    code: &str,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    for _ in 0..10 {
        let Some(Ok(message)) = timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("revocation notification timeout")
        else {
            return false;
        };
        if let Message::Text(text) = message {
            let value: serde_json::Value = serde_json::from_str(&text).expect("control JSON");
            if value["code"] == code {
                return true;
            }
        }
    }
    false
}

async fn wait_for_message_type<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    message_type: &str,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    for _ in 0..10 {
        let Some(Ok(message)) = timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("control notification timeout")
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
