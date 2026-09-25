// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{fs, sync::Arc};

use crate::application::status::ConfigurationStorage;
use axum::{
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use http_body_util::BodyExt;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret};
use tower::ServiceExt;
use uuid::Uuid;

use super::{AppState, SESSION_TTL, apply_security_headers, router};

const ORIGIN: &str = "http://127.0.0.1:8787";

#[test]
fn bridge_startup_failure_records_fixed_summary_and_encrypted_event() {
    let (state, _) = AppState::new([ORIGIN.to_owned()]);
    let pin = "synthetic-bridge-startup-pin";
    state.catalog.initialize_diagnostic_vault(pin).unwrap();
    state.record_bridge_startup_failure();
    let failures = state.catalog.list_diagnostic_failures().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].code, "bridge_startup_failed");
    assert_eq!(failures[0].stage, "bridge_startup");
    assert_eq!(
        failures[0].recovery_actions,
        &["check_local_broker_health", "review_private_data_directory"]
    );
    let events = state
        .catalog
        .unlock_diagnostic_records(pin, false, true)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data["code"], "bridge_startup_failed");
}

fn test_app() -> (axum::Router, String) {
    let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    (router(state), bootstrap)
}

fn postgres_test_app() -> (axum::Router, String) {
    let (mut state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    state.postgres_executor = Arc::new(crate::postgres::TestPostgresExecutor::succeeding());
    (router(state), bootstrap)
}

fn delayed_postgres_test_app() -> (axum::Router, String) {
    let (mut state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    state.postgres_executor = Arc::new(crate::postgres::TestPostgresExecutor::delayed(
        std::time::Duration::from_secs(30),
    ));
    (router(state), bootstrap)
}

#[tokio::test]
async fn conversation_and_notification_settings_require_the_human_web_session() {
    let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    let conversation = state
        .catalog
        .create_ai_conversation("Synthetic chat")
        .unwrap();
    let app = router(state);
    let token = pair_test_session(&app, &bootstrap).await;
    let list = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/ai-conversations",
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(
        response_json(list).await["items"][0]["id"],
        conversation.id.to_string()
    );

    let path = format!("/api/v1/ai-conversations/{}/policy", conversation.id);
    let grant = serde_json::json!({
        "expected_version": conversation.version,
        "approval_policy": "conversation_once",
        "risk_acknowledgement": "allow_all_operations_in_this_ai_conversation",
    })
    .to_string();
    let no_origin = app
        .clone()
        .oneshot(authenticated_request_with_body(
            "PUT", &path, &token, None, &grant,
        ))
        .await
        .unwrap();
    assert_eq!(no_origin.status(), StatusCode::FORBIDDEN);
    let no_session = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&path)
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(grant.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
    let granted = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT", &path, &token, ORIGIN, &grant,
        ))
        .await
        .unwrap();
    assert_eq!(granted.status(), StatusCode::OK);
    assert_eq!(
        response_json(granted).await["approval_policy"],
        "conversation_once"
    );

    let settings = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/notification-settings",
            &token,
            ORIGIN,
            r#"{"channel":"system"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(settings.status(), StatusCode::OK);
    assert_eq!(response_json(settings).await["channel"], "system");
    let read = app
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/notification-settings",
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response_json(read).await["channel"], "system");
}

#[test]
fn persistent_state_reports_sqlite_storage() {
    let path = std::env::temp_dir().join(format!(
        "secretbridge-state-test-{}.sqlite3",
        Uuid::new_v4()
    ));
    let (state, _) =
        AppState::new_persistent([ORIGIN.to_owned()], &path).expect("persistent application state");

    assert_eq!(state.configuration_storage, ConfigurationStorage::Sqlite);
    drop(state);
    fs::remove_file(path).expect("remove temporary database");
}

#[tokio::test]
async fn browser_session_survives_reopen_until_explicitly_revoked() {
    let path = std::env::temp_dir().join(format!(
        "secretbridge-browser-session-test-{}.sqlite3",
        Uuid::new_v4()
    ));
    let (state, _) =
        AppState::new_persistent([ORIGIN.to_owned()], &path).expect("persistent state");
    let (token, _) = state.issue_session().await.expect("issue session");
    drop(state);

    let (reopened, _) =
        AppState::new_persistent([ORIGIN.to_owned()], &path).expect("reopen persistent state");
    assert!(reopened.authenticate(&token).await.is_some());
    assert!(reopened.revoke(&token).await);
    drop(reopened);

    let (revoked, _) =
        AppState::new_persistent([ORIGIN.to_owned()], &path).expect("reopen revoked state");
    assert!(revoked.authenticate(&token).await.is_none());
    drop(revoked);
    fs::remove_file(path).expect("remove temporary database");
}

#[tokio::test]
async fn status_exposes_current_runtime_capabilities() {
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
    assert_eq!(status["mode"], "controlled_operations");
    assert_eq!(status["configuration_storage"], "memory_only");
    assert_eq!(status["real_credentials_enabled"], true);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the browser PIN lifecycle is kept in one end-to-end security regression"
)]
async fn browser_pin_is_write_only_rate_bounded_and_can_issue_a_page_session() {
    let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    let app = router(state.clone());
    let token = pair_test_session(&app, &bootstrap).await;
    let configured = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &token,
            ORIGIN,
            r#"{"method":"pin","pin":"synthetic-local-pin"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(configured.status(), StatusCode::OK);
    let recovery_key = response_json(configured).await["recovery_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(recovery_key.len(), 64);
    assert!(state.catalog.diagnostic_vault_ready().unwrap());
    assert!(
        state
            .catalog
            .verify_diagnostic_pin("synthetic-local-pin")
            .unwrap()
    );

    let methods = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session/methods")
                .body(Body::empty())
                .expect("methods request"),
        )
        .await
        .expect("router response");
    let methods = response_json(methods).await;
    assert_eq!(methods["pin_enabled"], true);
    assert!(!methods.to_string().contains("synthetic-local-pin"));

    let missing_current_proof = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &token,
            ORIGIN,
            r#"{"method":"pairing_link"}"#,
        ))
        .await
        .expect("current PIN is required to disable it");
    assert_eq!(missing_current_proof.status(), StatusCode::BAD_REQUEST);

    let incorrect = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/pin")
                .header("Origin", ORIGIN)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"pin":"incorrect-pin"}"#))
                .expect("incorrect PIN request"),
        )
        .await
        .expect("router response");
    assert_eq!(incorrect.status(), StatusCode::UNAUTHORIZED);

    let paired = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/pin")
                .header("Origin", ORIGIN)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"pin":"synthetic-local-pin"}"#))
                .expect("PIN request"),
        )
        .await
        .expect("router response");
    assert_eq!(paired.status(), StatusCode::OK);
    let paired = response_json(paired).await;
    assert!(
        paired["session_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(!paired.to_string().contains("synthetic-local-pin"));

    for attempt in 0..5 {
        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/session/pin")
                    .header("Origin", ORIGIN)
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"pin":"incorrect-pin"}"#))
                    .expect("incorrect PIN request"),
            )
            .await
            .expect("router response");
        assert_eq!(
            rejected.status(),
            if attempt == 4 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
    }
    let blocked = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/pin")
                .header("Origin", ORIGIN)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"pin":"synthetic-local-pin"}"#))
                .expect("blocked PIN request"),
        )
        .await
        .expect("router response");
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().get("retry-after").is_some());

    state.catalog.reset_failed_pin_attempts().unwrap();
    let rejected_disable = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &token,
            ORIGIN,
            r#"{"method":"pairing_link","current_pin":"synthetic-local-pin"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(rejected_disable.status(), StatusCode::BAD_REQUEST);
    let rotated = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT", "/api/v1/session/method", &token, ORIGIN,
            r#"{"method":"pin","pin":"new-synthetic-local-pin","current_pin":"synthetic-local-pin"}"#,
        ))
        .await.unwrap();
    assert_eq!(rotated.status(), StatusCode::NO_CONTENT);
    assert!(
        !state
            .catalog
            .verify_diagnostic_pin("synthetic-local-pin")
            .unwrap()
    );
    assert!(
        state
            .catalog
            .verify_diagnostic_pin("new-synthetic-local-pin")
            .unwrap()
    );
    let audit = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/session/auth-events",
            &token,
            Some(ORIGIN),
        ))
        .await
        .expect("PIN disablement audit");
    assert_eq!(audit.status(), StatusCode::OK);
    let methods = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/session/methods")
                .body(Body::empty())
                .expect("methods request"),
        )
        .await
        .expect("router response");
    assert_eq!(response_json(methods).await["pin_enabled"], true);
}

#[tokio::test]
async fn recovery_key_resets_a_six_character_pin_and_rotates_itself() {
    let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    let app = router(state.clone());
    let old_session = pair_test_session(&app, &bootstrap).await;
    let initialized = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &old_session,
            ORIGIN,
            r#"{"method":"pin","pin":"123456"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let initial_key = response_json(initialized).await["recovery_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(state.catalog.verify_diagnostic_pin("123456").unwrap());

    let recover = |key: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/session/recover")
            .header("Origin", ORIGIN)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"recovery_key": key, "new_pin": "654321"}).to_string(),
            ))
            .unwrap()
    };
    let incorrect = app.clone().oneshot(recover(&"0".repeat(64))).await.unwrap();
    assert_eq!(incorrect.status(), StatusCode::UNAUTHORIZED);
    let recovered = app.clone().oneshot(recover(&initial_key)).await.unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered = response_json(recovered).await;
    let next_key = recovered["recovery_key"].as_str().unwrap();
    assert_ne!(next_key, initial_key);
    assert!(!state.catalog.verify_diagnostic_pin("123456").unwrap());
    assert!(state.catalog.verify_diagnostic_pin("654321").unwrap());
    assert_eq!(
        app.clone()
            .oneshot(recover(&initial_key))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/session",
                &old_session,
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let fresh_session = recovered["session_token"].as_str().unwrap();
    assert_eq!(
        app.oneshot(authenticated_request(
            "GET",
            "/api/v1/session",
            fresh_session,
            None
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn installed_broker_blocks_operations_until_pin_initialization() {
    let (mut state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    state.enable_runtime_control(
        ORIGIN.to_owned(),
        tokio_util::sync::CancellationToken::new(),
    );
    let app = router(state);
    let token = pair_test_session(&app, &bootstrap).await;
    let before = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/targets",
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(before.status(), StatusCode::CONFLICT);
    let initialized = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &token,
            ORIGIN,
            r#"{"method":"pin","pin":"synthetic-initial-pin"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let after = app
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/targets",
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::OK);
}

fn totp_code(secret: &str, step_offset: i64) -> String {
    let totp = TotpBuilder::new()
        .with_secret(TotpSecret::try_from_base32(secret).expect("base32 test secret"))
        .with_skew(0)
        .build()
        .expect("test TOTP");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("current time")
        .as_secs();
    totp.generate(
        now.saturating_add_signed(step_offset * crate::totp_auth::STEP_SECONDS.cast_signed()),
    )
    .to_string()
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "TOTP enrollment, replay, recovery, audit and disablement form one lifecycle"
)]
async fn totp_enrollment_is_write_only_and_codes_are_single_use() {
    let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
    let app = router(state.clone());
    let token = pair_test_session(&app, &bootstrap).await;
    let pin_setup = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &token,
            ORIGIN,
            r#"{"method":"pin","pin":"synthetic-local-pin"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(pin_setup.status(), StatusCode::OK);
    let setup = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/session/totp/setup",
            &token,
            ORIGIN,
            r#"{"current_pin":"synthetic-local-pin"}"#,
        ))
        .await
        .expect("start TOTP setup");
    assert_eq!(setup.status(), StatusCode::OK);
    let setup = response_json(setup).await;
    let manual_key = setup["manual_key"].as_str().expect("manual setup key");
    assert!(
        setup["qr_code_data_url"]
            .as_str()
            .is_some_and(|value| value.starts_with("data:image/png;base64,"))
    );
    let enrollment_code = totp_code(manual_key, 0);
    let confirmed = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/session/totp/confirm",
            &token,
            ORIGIN,
            &serde_json::json!({ "code": enrollment_code }).to_string(),
        ))
        .await
        .expect("confirm TOTP setup");
    assert_eq!(confirmed.status(), StatusCode::NO_CONTENT);

    let methods = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session/methods")
                .body(Body::empty())
                .expect("methods request"),
        )
        .await
        .expect("methods response");
    let methods = response_json(methods).await;
    assert_eq!(methods["totp_enabled"], true);
    assert_eq!(methods["pin_enabled"], true);
    assert!(!methods.to_string().contains(manual_key));

    let rebind_without_disable = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/session/totp/setup",
            &token,
            ORIGIN,
            r#"{"current_pin":"synthetic-local-pin"}"#,
        ))
        .await
        .expect("active TOTP rebind response");
    assert_eq!(rebind_without_disable.status(), StatusCode::BAD_REQUEST);

    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/totp")
                .header("Origin", ORIGIN)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "code": enrollment_code }).to_string(),
                ))
                .expect("replay request"),
        )
        .await
        .expect("replay response");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let next_code = totp_code(manual_key, 1);
    let paired = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/totp")
                .header("Origin", ORIGIN)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "code": next_code }).to_string(),
                ))
                .expect("TOTP pair request"),
        )
        .await
        .expect("TOTP pair response");
    assert_eq!(paired.status(), StatusCode::OK);
    assert!(!response_json(paired).await.to_string().contains(manual_key));

    let events = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/session/auth-events",
            &token,
            Some(ORIGIN),
        ))
        .await
        .expect("TOTP audit events");
    assert_eq!(events.status(), StatusCode::OK);
    let events = response_json(events).await.to_string();
    assert!(events.contains("\"retention_truncated\":false"));
    assert!(events.contains("enrollment_started"));
    assert!(events.contains("enrollment_succeeded"));
    assert!(events.contains("verification_failed"));
    assert!(events.contains("verification_succeeded"));
    assert!(!events.contains(manual_key));
    assert!(!events.contains(&enrollment_code));
    assert!(!events.contains(&next_code));

    // Advance the isolated fixture's replay state to model a later verification window.
    state.catalog.reset_totp_replay_guard().unwrap();

    let disabled = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            "/api/v1/session/method",
            &token,
            ORIGIN,
            &serde_json::json!({
                "method": "disable_totp",
                "current_pin": "synthetic-local-pin",
            })
            .to_string(),
        ))
        .await
        .expect("disable TOTP");
    assert_eq!(disabled.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .secret_store
            .get(super::BROWSER_TOTP_CREDENTIAL_ID)
            .is_err()
    );
    assert!(
        state
            .catalog
            .verify_diagnostic_pin("synthetic-local-pin")
            .unwrap()
    );
    let disabled_events = app
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/session/auth-events",
            &token,
            Some(ORIGIN),
        ))
        .await
        .expect("disablement audit events");
    let disabled_events = response_json(disabled_events).await.to_string();
    assert!(disabled_events.contains("disabled"));
    assert!(!disabled_events.contains(manual_key));
}

#[tokio::test]
async fn credential_secret_is_write_only_versioned_and_clearable() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/credential-references",
            &token,
            ORIGIN,
            r#"{"name":"Database reader","kind":"password"}"#,
        ))
        .await
        .expect("router response");
    let credential = response_json(created).await;
    let id = credential["id"].as_str().expect("credential id");

    let stored = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            &format!("/api/v1/credential-references/{id}/secret"),
            &token,
            ORIGIN,
            r#"{"secret":"test-only-password","expected_version":1}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(stored.status(), StatusCode::OK);
    let stored_body = response_json(stored).await;
    assert_eq!(stored_body["secret_state"], "available");
    assert_eq!(stored_body["version"], 2);
    assert!(!stored_body.to_string().contains("test-only-password"));

    let read_attempt = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/credential-references/{id}/secret"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    assert_eq!(read_attempt.status(), StatusCode::METHOD_NOT_ALLOWED);

    let cleared = app
        .clone()
        .oneshot(authenticated_json_request(
            "DELETE",
            &format!("/api/v1/credential-references/{id}/secret"),
            &token,
            ORIGIN,
            r#"{"expected_version":2}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(cleared.status(), StatusCode::OK);
    let cleared_body = response_json(cleared).await;
    assert_eq!(cleared_body["secret_state"], "not_configured");
    assert_eq!(cleared_body["version"], 3);

    let oversized_body = serde_json::json!({
        "secret": "x".repeat(17 * 1024),
        "expected_version": 3
    })
    .to_string();
    let oversized = app
        .oneshot(authenticated_json_request(
            "PUT",
            &format!("/api/v1/credential-references/{id}/secret"),
            &token,
            ORIGIN,
            &oversized_body,
        ))
        .await
        .expect("router response");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
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
async fn catalog_relationships_are_session_protected_and_deletable_in_order() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;

    let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/credential-references",
                &token,
                ORIGIN,
                r#"{"name":"Synthetic database operator","kind":"password","purpose":"Test-only metadata"}"#,
            ))
            .await
            .expect("router response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let credential = response_json(created).await;
    assert_eq!(credential["secret_state"], "not_configured");
    assert!(credential.get("secret").is_none());
    let credential_id = credential["id"].as_str().expect("credential id");

    let target_body = serde_json::json!({
        "name": "Synthetic reporting database",
        "kind": "database",
        "environment": "test",
        "description": "No network address is accepted in this alpha",
        "credential_reference_id": credential_id,
    })
    .to_string();
    let target = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/targets",
            &token,
            ORIGIN,
            &target_body,
        ))
        .await
        .expect("router response");
    assert_eq!(target.status(), StatusCode::CREATED);
    let target = response_json(target).await;
    let target_id = target["id"].as_str().expect("target id");

    let in_use = app
        .clone()
        .oneshot(authenticated_request(
            "DELETE",
            &format!("/api/v1/credential-references/{credential_id}"),
            &token,
            Some(ORIGIN),
        ))
        .await
        .expect("router response");
    assert_eq!(in_use.status(), StatusCode::CONFLICT);

    let targets = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/targets",
            &token,
            None,
        ))
        .await
        .expect("router response");
    assert_eq!(targets.status(), StatusCode::OK);
    let body = targets
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let targets: serde_json::Value = serde_json::from_slice(&body).expect("targets JSON");
    assert_eq!(targets["storage"], "memory_only");
    assert_eq!(targets["items"].as_array().map(Vec::len), Some(1));

    let deleted_target = app
        .clone()
        .oneshot(authenticated_request(
            "DELETE",
            &format!("/api/v1/targets/{target_id}"),
            &token,
            Some(ORIGIN),
        ))
        .await
        .expect("router response");
    assert_eq!(deleted_target.status(), StatusCode::NO_CONTENT);

    let deleted_credential = app
        .oneshot(authenticated_request(
            "DELETE",
            &format!("/api/v1/credential-references/{credential_id}"),
            &token,
            Some(ORIGIN),
        ))
        .await
        .expect("router response");
    assert_eq!(deleted_credential.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn credential_reference_api_rejects_secret_fields() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let response = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/credential-references",
            &token,
            ORIGIN,
            r#"{"name":"Rejected input","kind":"api_token","secret":"synthetic-placeholder"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let list = app
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/credential-references",
            &token,
            None,
        ))
        .await
        .expect("router response");
    let body = list
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let list: serde_json::Value = serde_json::from_slice(&body).expect("list JSON");
    assert_eq!(list["storage"], "memory_only");
    assert_eq!(list["items"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn catalog_update_requires_origin_and_increments_version() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/credential-references",
            &token,
            ORIGIN,
            r#"{"name":"Synthetic reference","kind":"password"}"#,
        ))
        .await
        .expect("router response");
    let item = response_json(created).await;
    let id = item["id"].as_str().expect("credential id");
    assert_eq!(item["version"], 1);

    let missing_origin = app
        .clone()
        .oneshot(authenticated_request_with_body(
            "PUT",
            &format!("/api/v1/credential-references/{id}"),
            &token,
            None,
            r#"{"name":"Blocked update","kind":"api_token","expected_version":1}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let updated = app
            .clone()
            .oneshot(authenticated_json_request(
                "PUT",
                &format!("/api/v1/credential-references/{id}"),
                &token,
                ORIGIN,
                r#"{"name":"Updated reference","kind":"api_token","purpose":"Synthetic metadata","expected_version":1}"#,
            ))
            .await
            .expect("router response");
    assert_eq!(updated.status(), StatusCode::OK);
    let item = response_json(updated).await;
    assert_eq!(item["name"], "Updated reference");
    assert_eq!(item["version"], 2);
    assert_eq!(item["secret_state"], "not_configured");

    let stale = app
        .oneshot(authenticated_json_request(
            "PUT",
            &format!("/api/v1/credential-references/{id}"),
            &token,
            ORIGIN,
            r#"{"name":"Stale update","kind":"password","expected_version":1}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let error = response_json(stale).await;
    assert_eq!(error["code"], "version_conflict");
}

#[tokio::test]
async fn policy_evaluation_api_is_explainable_and_session_protected() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let template_id = create_test_action_template(&app, &token).await;
    let path = format!("/api/v1/action-templates/{template_id}/policy-evaluation");

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let evaluation = app
        .oneshot(authenticated_request("GET", &path, &token, None))
        .await
        .expect("router response");
    assert_eq!(evaluation.status(), StatusCode::OK);
    let evaluation = response_json(evaluation).await;
    assert_eq!(evaluation["policy_version"], "synthetic-policy-v1");
    assert_eq!(evaluation["decision"], "eligible_for_approval");
    assert_eq!(evaluation["execution_mode"], "synthetic_simulation");
    assert_eq!(evaluation["action_template_version"], 1);
    assert_eq!(evaluation["target_version"], 1);
    assert_eq!(evaluation["requirements"].as_array().map(Vec::len), Some(5));
}

#[tokio::test]
async fn approval_api_is_scoped_versioned_and_never_executes() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let template_id = create_test_action_template(&app, &token).await;
    let create_body = serde_json::json!({
        "action_template_id": template_id,
        "reason": "Verify approval lifecycle without an operation",
        "expires_in_seconds": 300
    })
    .to_string();

    let missing_origin = app
        .clone()
        .oneshot(authenticated_request_with_body(
            "POST",
            "/api/v1/approvals",
            &token,
            None,
            &create_body,
        ))
        .await
        .expect("router response");
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/approvals",
            &token,
            ORIGIN,
            &create_body,
        ))
        .await
        .expect("router response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let approval = response_json(created).await;
    assert_eq!(approval["state"], "pending");
    assert_eq!(approval["version"], 1);
    assert_eq!(approval["action_template_id"], template_id);
    assert_eq!(approval["action_template_version"], 1);
    assert_eq!(approval["target_version"], 1);
    let approval_id = approval["id"].as_str().expect("approval id");

    let approved = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/approve"),
            &token,
            ORIGIN,
            r#"{"expected_version":1,"note":"Scope reviewed"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(approved.status(), StatusCode::OK);
    let approved = response_json(approved).await;
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["version"], 2);

    let invalid = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/deny"),
            &token,
            ORIGIN,
            r#"{"expected_version":2}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(invalid.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(invalid).await["code"],
        "invalid_approval_transition"
    );

    let revoked = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/revoke"),
            &token,
            ORIGIN,
            r#"{"expected_version":2,"note":"No longer needed"}"#,
        ))
        .await
        .expect("router response");
    let revoked = response_json(revoked).await;
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(revoked["version"], 3);

    let list = app
        .oneshot(authenticated_request(
            "GET",
            "/api/v1/approvals",
            &token,
            None,
        ))
        .await
        .expect("router response");
    let list = response_json(list).await;
    assert_eq!(list["execution_enabled"], true);
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn synthetic_run_api_is_idempotent_observable_and_origin_protected() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let approval_id = create_test_approved_approval(&app, &token).await;
    let body = serde_json::json!({
        "approval_id": approval_id,
        "idempotency_key": "integration-run-001"
    })
    .to_string();

    let rejected = app
        .clone()
        .oneshot(authenticated_request_with_body(
            "POST",
            "/api/v1/runs",
            &token,
            None,
            &body,
        ))
        .await
        .expect("router response");
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/runs",
            &token,
            ORIGIN,
            &body,
        ))
        .await
        .expect("router response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    assert_eq!(created["execution_mode"], "synthetic_simulation");
    assert_eq!(created["replayed"], false);
    let run_id = created["run"]["id"].as_str().expect("run id");

    let replayed = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/runs",
            &token,
            ORIGIN,
            &body,
        ))
        .await
        .expect("router response");
    assert_eq!(replayed.status(), StatusCode::OK);
    let replayed = response_json(replayed).await;
    assert_eq!(replayed["replayed"], true);
    assert_eq!(replayed["run"]["id"], run_id);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let completed = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let completed = response_json(completed).await;
    assert_eq!(completed["state"], "succeeded");
    assert_eq!(completed["result_status"], "synthetic_ok");

    let events = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let events = response_json(events).await;
    assert_eq!(events["payload_policy"], "fixed_safe_messages_only");
    assert_eq!(events["items"].as_array().map(Vec::len), Some(3));

    let consumed_body = serde_json::json!({
        "approval_id": approval_id,
        "idempotency_key": "integration-run-002"
    })
    .to_string();
    let consumed = app
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/runs",
            &token,
            ORIGIN,
            &consumed_body,
        ))
        .await
        .expect("router response");
    assert_eq!(consumed.status(), StatusCode::CONFLICT);
    assert_eq!(response_json(consumed).await["code"], "approval_consumed");
}

#[tokio::test]
async fn postgres_connection_check_uses_write_only_secret_and_safe_results() {
    let (app, bootstrap) = postgres_test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let (approval_id, secret) = create_test_approved_postgres_approval(&app, &token).await;

    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/runs",
            &token,
            ORIGIN,
            &serde_json::json!({
                "approval_id": approval_id,
                "idempotency_key": "postgres-integration-001"
            })
            .to_string(),
        ))
        .await
        .expect("router response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    assert_eq!(created["execution_mode"], "controlled_postgres");
    let run_id = created["run"]["id"].as_str().expect("run id");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let completed = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let completed = response_json(completed).await;
    assert_eq!(completed["state"], "succeeded");
    assert_eq!(completed["result_status"], "postgres_connection_ok");

    let events = app
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let events = response_json(events).await;
    assert_eq!(events["payload_policy"], "fixed_safe_messages_only");
    assert_eq!(events["items"].as_array().map(Vec::len), Some(3));
    assert!(!events.to_string().contains(secret));
}

#[tokio::test]
async fn postgres_connection_check_cancels_an_in_flight_executor() {
    let (app, bootstrap) = delayed_postgres_test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let (approval_id, _) = create_test_approved_postgres_approval(&app, &token).await;
    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/runs",
            &token,
            ORIGIN,
            &serde_json::json!({
                "approval_id": approval_id,
                "idempotency_key": "postgres-cancel-001"
            })
            .to_string(),
        ))
        .await
        .expect("router response");
    let created = response_json(created).await;
    let run_id = created["run"]["id"].as_str().expect("run id");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let running = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let running = response_json(running).await;
    assert_eq!(running["state"], "running");
    let cancelled = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/runs/{run_id}/cancel"),
            &token,
            ORIGIN,
            &serde_json::json!({"expected_version": running["version"]}).to_string(),
        ))
        .await
        .expect("router response");
    let cancelled = response_json(cancelled).await;
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["result_status"], "cancelled");
}

#[tokio::test]
async fn synthetic_run_driver_stops_after_approval_revocation() {
    let (app, bootstrap) = test_app();
    let token = pair_test_session(&app, &bootstrap).await;
    let approval_id = create_test_approved_approval(&app, &token).await;
    let body = serde_json::json!({
        "approval_id": approval_id,
        "idempotency_key": "integration-revocation-001"
    })
    .to_string();
    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/runs",
            &token,
            ORIGIN,
            &body,
        ))
        .await
        .expect("router response");
    let created = response_json(created).await;
    let run_id = created["run"]["id"].as_str().expect("run id");

    let revoked = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/revoke"),
            &token,
            ORIGIN,
            r#"{"expected_version":2,"note":"Authorization withdrawn during integration test"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(revoked.status(), StatusCode::OK);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let stopped = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let stopped = response_json(stopped).await;
    assert_eq!(stopped["state"], "cancelled");
    assert_eq!(stopped["result_status"], "authorization_revoked");

    let events = app
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            &token,
            None,
        ))
        .await
        .expect("router response");
    let events = response_json(events).await;
    let last_event = events["items"].as_array().and_then(|items| items.last());
    assert_eq!(
        last_event.and_then(|event| event["kind"].as_str()),
        Some("authorization_revoked")
    );
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

async fn pair_test_session(app: &axum::Router, bootstrap: &str) -> String {
    let paired = app
        .clone()
        .oneshot(pair_request(bootstrap, Some(ORIGIN)))
        .await
        .expect("router response");
    let body = paired
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
    pair["session_token"]
        .as_str()
        .expect("session token")
        .to_owned()
}

async fn create_test_action_template(app: &axum::Router, token: &str) -> String {
    let target = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/targets",
            token,
            ORIGIN,
            r#"{"name":"Synthetic health target","kind":"http_service","environment":"test"}"#,
        ))
        .await
        .expect("router response");
    let target = response_json(target).await;
    let body = serde_json::json!({
        "target_id": target["id"],
        "name": "Synthetic target health",
        "operation": "synthetic_health_check",
        "result_scope": "status_only",
        "description": "Fixed synthetic template",
        "timeout_seconds": 15
    })
    .to_string();
    let template = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/action-templates",
            token,
            ORIGIN,
            &body,
        ))
        .await
        .expect("router response");
    assert_eq!(template.status(), StatusCode::CREATED);
    response_json(template).await["id"]
        .as_str()
        .expect("template id")
        .to_owned()
}

async fn create_test_approved_approval(app: &axum::Router, token: &str) -> String {
    let template_id = create_test_action_template(app, token).await;
    let body = serde_json::json!({
        "action_template_id": template_id,
        "reason": "Synthetic integration run",
        "expires_in_seconds": 300
    })
    .to_string();
    let created = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/approvals",
            token,
            ORIGIN,
            &body,
        ))
        .await
        .expect("router response");
    let approval = response_json(created).await;
    let id = approval["id"].as_str().expect("approval id").to_owned();
    let approved = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/approvals/{id}/approve"),
            token,
            ORIGIN,
            r#"{"expected_version":1,"note":"Integration scope approved"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(approved.status(), StatusCode::OK);
    id
}

#[allow(
    clippy::too_many_lines,
    reason = "the helper provisions every boundary required by the integration tests"
)]
async fn create_test_approved_postgres_approval(
    app: &axum::Router,
    token: &str,
) -> (String, &'static str) {
    let credential = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/credential-references",
            token,
            ORIGIN,
            r#"{"name":"PostgreSQL reader","kind":"password","purpose":"Connection check"}"#,
        ))
        .await
        .expect("router response");
    let credential = response_json(credential).await;
    let credential_id = credential["id"].as_str().expect("credential id");
    let secret = "integration-only-postgres-password";
    let stored = app
        .clone()
        .oneshot(authenticated_json_request(
            "PUT",
            &format!("/api/v1/credential-references/{credential_id}/secret"),
            token,
            ORIGIN,
            &serde_json::json!({"secret": secret, "expected_version": 1}).to_string(),
        ))
        .await
        .expect("router response");
    assert_eq!(stored.status(), StatusCode::OK);

    let target = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/targets",
            token,
            ORIGIN,
            &serde_json::json!({
                "name": "PostgreSQL integration target",
                "kind": "database",
                "environment": "test",
                "credential_reference_id": credential_id,
                "postgres": {
                    "host": "db.example.invalid",
                    "port": 5432,
                    "database": "secretbridge_test",
                    "username": "secretbridge_reader",
                    "tls_mode": "verify_full"
                }
            })
            .to_string(),
        ))
        .await
        .expect("router response");
    let target = response_json(target).await;
    let template = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/action-templates",
            token,
            ORIGIN,
            &serde_json::json!({
                "target_id": target["id"],
                "name": "PostgreSQL fixed connection check",
                "operation": "postgres_connection_check",
                "result_scope": "status_only",
                "timeout_seconds": 5
            })
            .to_string(),
        ))
        .await
        .expect("router response");
    let template = response_json(template).await;
    let template_id = template["id"].as_str().expect("template id");
    let evaluation = app
        .clone()
        .oneshot(authenticated_request(
            "GET",
            &format!("/api/v1/action-templates/{template_id}/policy-evaluation"),
            token,
            None,
        ))
        .await
        .expect("router response");
    let evaluation = response_json(evaluation).await;
    assert_eq!(evaluation["decision"], "eligible_for_approval");
    assert_eq!(evaluation["policy_version"], "postgres-readonly-policy-v1");
    assert_eq!(evaluation["execution_mode"], "controlled_postgres");
    let approval = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            "/api/v1/approvals",
            token,
            ORIGIN,
            &serde_json::json!({
                "action_template_id": template_id,
                "reason": "Verify the fixed read-only adapter",
                "expires_in_seconds": 300
            })
            .to_string(),
        ))
        .await
        .expect("router response");
    let approval = response_json(approval).await;
    let approval_id = approval["id"].as_str().expect("approval id").to_owned();
    let approved = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/approve"),
            token,
            ORIGIN,
            r#"{"expected_version":1,"note":"Fixed scope reviewed"}"#,
        ))
        .await
        .expect("router response");
    assert_eq!(approved.status(), StatusCode::OK);
    (approval_id, secret)
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

fn authenticated_json_request(
    method: &str,
    uri: &str,
    token: &str,
    origin: &str,
    body: &str,
) -> Request<Body> {
    authenticated_request_with_body(method, uri, token, Some(origin), body)
}

fn authenticated_request_with_body(
    method: &str,
    uri: &str,
    token: &str,
    origin: Option<&str>,
    body: &str,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder
        .body(Body::from(body.to_owned()))
        .expect("valid request")
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
