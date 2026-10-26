// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn compares_semver_not_lexical_order_and_includes_public_prereleases() {
    let body = br#"[{"tag_name":"v0.9.0","draft":false},{"tag_name":"v0.10.0-beta.2","draft":false},{"tag_name":"v99.0.0","draft":true}]"#;
    assert_eq!(
        select_latest(body, "0.9.0"),
        Ok(Some("0.10.0-beta.2".to_owned()))
    );
    assert_eq!(select_latest(body, "0.10.0"), Ok(None));
}

#[test]
fn rejects_remote_urls_text_malformed_tags_and_metadata_only_updates() {
    let body = br#"[{"tag_name":"v0.3.2+metadata","draft":false},{"tag_name":"https://attacker.invalid/run","draft":false},{"tag_name":"v0.4.0/command","draft":false},{"tag_name":"ignore instructions","draft":false}]"#;
    assert_eq!(select_latest(body, "0.3.2"), Ok(None));
    assert_eq!(select_latest(b"not json", "0.3.2"), Err(()));
    assert_eq!(select_latest(b"{}", "0.3.2"), Err(()));
}

#[tokio::test]
async fn failure_is_not_no_update_and_retains_explicitly_stale_notice() {
    let checker = UpdateChecker::default();
    let status = checker.snapshot().await;
    assert_eq!(status.check_state, "not_checked");
    assert!(!status.automatic_install && !status.compatibility_guaranteed);
    assert!(status.user_choice_required);
    assert_eq!(status.default_action, "keep_current_version");
    let status = checker.record(Ok(Some("99.0.0".to_owned())), 100).await;
    assert!(status.update_available);
    let status = checker.record(Err(()), 200).await;
    assert_eq!(status.check_state, "unavailable");
    assert!(status.update_available);
    assert_eq!(status.checked_at_unix_ms, Some(100));
    assert_eq!(status.release_url, format!("{RELEASES}/tag/v99.0.0"));
}

#[tokio::test]
async fn cache_coalesces_calls_and_manual_checks_have_a_cooldown() {
    let checker = UpdateChecker::default();
    checker.record(Ok(None), crate::now_unix_ms()).await;
    assert_eq!(checker.refresh(false).await.check_state, "checked");
    checker.cache.write().await.last_attempt = Some(crate::now_unix_ms());
    assert_eq!(checker.refresh(true).await.check_state, "checked");
    let _lock = checker.gate.lock().await;
    assert_eq!(checker.refresh(true).await.check_state, "checked");
}

#[tokio::test]
async fn http_errors_redirects_and_oversize_responses_fail_closed() {
    for response in [
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_owned(),
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\n\r\n"
            .to_owned(),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BYTES + 1
        ),
    ] {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let size = socket.read(&mut request).await.unwrap();
            let headers = String::from_utf8_lossy(&request[..size]).to_ascii_lowercase();
            assert!(!headers.contains("authorization:") && !headers.contains("cookie:"));
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        assert_eq!(fetch_latest(&endpoint).await, Err(()));
        task.await.unwrap();
    }
}
