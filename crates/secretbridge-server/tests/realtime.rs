// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use secretbridge_server::{AppState, router};
use serde_json::{Value, json};
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use tower::ServiceExt;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one contiguous stream authentication, invalidation and revocation acceptance scenario"
)]
async fn status_stream_requires_origin_and_first_frame_auth_and_closes_on_revocation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let origin = format!("http://{address}");
    let (state, bootstrap) = AppState::new([origin.clone()]);
    let control = router(state.clone());
    let response = control
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/session/pair",
            &bootstrap,
            &origin,
            "",
        ))
        .await
        .expect("pair");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let pair: Value = serde_json::from_slice(&body).expect("pair JSON");
    let token = pair["session_token"].as_str().expect("token");
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.expect("serve");
    });
    let url = format!("ws://{address}/api/v1/events");

    let mut bad_origin = url.clone().into_client_request().expect("request");
    bad_origin.headers_mut().insert(
        "origin",
        "http://localhost.invalid".parse().expect("header"),
    );
    assert!(connect_async(bad_origin).await.is_err());

    let mut upgrade = url.into_client_request().expect("request");
    upgrade
        .headers_mut()
        .insert("origin", origin.parse().expect("header"));
    let (mut invalid, _) = connect_async(upgrade.clone()).await.expect("upgrade");
    invalid
        .send(Message::Text(
            json!({"type":"authenticate","token":"invalid"})
                .to_string()
                .into(),
        ))
        .await
        .expect("send");
    let rejected = timeout(Duration::from_secs(3), invalid.next())
        .await
        .expect("rejected promptly");
    assert!(matches!(rejected, Some(Ok(Message::Close(_))) | None));

    let (mut socket, _) = connect_async(upgrade).await.expect("upgrade");
    socket
        .send(Message::Text(
            json!({"type":"authenticate","token":token})
                .to_string()
                .into(),
        ))
        .await
        .expect("authenticate");
    assert_eq!(next_text(&mut socket).await, json!({"type":"ready"}));
    let response = control
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/credential-references",
            token,
            &origin,
            r#"{"name":"Live updates reference","kind":"password"}"#,
        ))
        .await
        .expect("create");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        next_text(&mut socket).await,
        json!({"type":"changed"}),
        "notifications contain no resource values"
    );
    let response = control
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/credential-references",
            token,
            &origin,
            r#"{"name":"","kind":"password"}"#,
        ))
        .await
        .expect("invalid mutation");
    assert!(!response.status().is_success());
    assert!(
        timeout(Duration::from_millis(100), socket.next())
            .await
            .is_err(),
        "failed writes do not claim a change"
    );
    let response = control
        .oneshot(request("DELETE", "/api/v1/session", token, &origin, ""))
        .await
        .expect("revoke");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    for _ in 0..4 {
        match timeout(Duration::from_secs(3), socket.next())
            .await
            .expect("revocation closes promptly")
        {
            Some(Ok(Message::Close(_))) | None => {
                server.abort();
                return;
            }
            Some(Ok(Message::Text(_))) => {}
            other => panic!("unexpected stream result: {other:?}"),
        }
    }
    panic!("revoked stream remained open");
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn next_text(socket: &mut Socket) -> Value {
    let frame = timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("frame timeout")
        .expect("open socket")
        .expect("frame");
    let Message::Text(text) = frame else {
        panic!("expected text frame");
    };
    serde_json::from_str(&text).expect("frame JSON")
}

fn request(method: &str, uri: &str, token: &str, origin: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("origin", origin)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request")
}
