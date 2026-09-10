// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{path::PathBuf, time::Duration};

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
    let mut first = connect(&url, &origin, &token).await;
    let first_output = read_until(&mut first, b"SecretBridge synthetic terminal").await;
    assert!(contains(&first_output, b"SecretBridge synthetic terminal"));
    first.close(None).await.expect("detach first websocket");

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
    let listed = response_json(listed).await;
    assert_eq!(listed["terminals"][0]["status"], "running");

    let mut reattached = connect(&url, &origin, &token).await;
    let replay = read_until(&mut reattached, b"SecretBridge synthetic terminal").await;
    assert!(contains(&replay, b"SecretBridge synthetic terminal"));

    let revoked = control
        .oneshot(authenticated_request(
            "DELETE",
            "/api/v1/session",
            &token,
            Some(&origin),
            Body::empty(),
        ))
        .await
        .expect("revocation response");
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    assert!(wait_for_control_message(&mut reattached, "session_revoked").await);

    server.abort();
    let _ = server.await;
}

async fn connect(
    url: &str,
    origin: &str,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut request = url.into_client_request().expect("websocket request");
    request
        .headers_mut()
        .insert("origin", origin.parse().expect("origin header"));
    let (mut socket, response) = connect_async(request).await.expect("websocket connection");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    socket
        .send(Message::Text(
            serde_json::json!({"type": "authenticate", "token": token})
                .to_string()
                .into(),
        ))
        .await
        .expect("authenticate websocket");
    socket
}

async fn read_until<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>, needle: &[u8]) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut output = Vec::new();
    for _ in 0..100 {
        let message = timeout(Duration::from_millis(250), socket.next())
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
        let Some(Ok(message)) = timeout(Duration::from_secs(1), socket.next())
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
