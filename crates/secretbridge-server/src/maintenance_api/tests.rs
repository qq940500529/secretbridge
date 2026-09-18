// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    AppState,
    catalog::{Catalog, RunState},
    command::tests::configure,
    router,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
const ORIGIN: &str = "http://127.0.0.1:8787";
fn request(method: &str, path: &str, token: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .body(body.into())
        .unwrap()
}
async fn json_body(response: axum::response::Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end maintenance workflow keeps preview, confirmation and replay assertions together"
)]
async fn maintenance_requires_session_and_preflights_without_writing() {
    let (state, _) = AppState::new([ORIGIN.to_owned()]);
    configure(&state, "environment", 10);
    let app = router(state.clone());
    for path in ["configuration", "backup", "diagnostics"] {
        let response = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/api/v1/maintenance/{path}"),
                "invalid",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let (token, _) = state.issue_session().await;
    let bundle = json_body(
        app.clone()
            .oneshot(request(
                "GET",
                "/api/v1/maintenance/configuration",
                &token,
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let text = bundle.to_string();
    assert!(!text.contains("Synthetic-SB-command_A&z"));
    assert!(bundle.get("approvals").is_none());
    assert!(bundle["credentials"][0].get("secret_state").is_none());
    let preview = json_body(
        app.clone()
            .oneshot(request(
                "POST",
                "/api/v1/maintenance/configuration/preview",
                &token,
                text.clone(),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(state.catalog.list_credential_references().unwrap().len(), 1);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/maintenance/configuration/import",
            &token,
            json!({"bundle":bundle,"expected_digest":"wrong"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let input = json!({"bundle":bundle,"expected_digest":preview["digest"]}).to_string();
    let imported = json_body(
        app.clone()
            .oneshot(request(
                "POST",
                "/api/v1/maintenance/configuration/import",
                &token,
                input.clone(),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(imported["replayed"], false);
    let repeated = json_body(
        app.clone()
            .oneshot(request(
                "POST",
                "/api/v1/maintenance/configuration/import",
                &token,
                input,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(repeated["replayed"], true);
    let bad = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/maintenance/configuration/preview",
            &token,
            r#"{"format":"secret-never-echo"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert!(
        !String::from_utf8_lossy(&bad.into_body().collect().await.unwrap().to_bytes())
            .contains("secret-never-echo")
    );
    let diagnostic = json_body(
        app.clone()
            .oneshot(request(
                "GET",
                "/api/v1/maintenance/diagnostics",
                &token,
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(diagnostic["templates"], 2);
    assert!(!diagnostic.to_string().contains("Credential echo fixture"));
    let bytes = app
        .clone()
        .oneshot(request(
            "GET",
            "/api/v1/maintenance/backup",
            &token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(bytes.headers()["content-type"], "application/vnd.sqlite3");
    assert_eq!(bytes.headers()["cache-control"], "no-store");
    let bytes = bytes.into_body().collect().await.unwrap().to_bytes();
    let preview = json_body(
        app.oneshot(request(
            "POST",
            "/api/v1/maintenance/backup/preview",
            &token,
            bytes,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(preview["integrity_ok"], true);
    assert_eq!(preview["restores_authorizations"], false);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "a restored real command workflow verifies re-entry, fresh authorization, execution and filtered output together"
)]
async fn restored_directory_can_reenter_secret_authorize_and_execute_original_command() {
    let root = std::env::temp_dir().join(format!("secretbridge-restore-test-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let source_path = root.join("source.sqlite3");
    let (mut source, _) = AppState::new([ORIGIN.to_owned()]);
    source.catalog = Catalog::open(&source_path).unwrap();
    let (approval, credential) = configure(&source, "environment", 10);
    let pending_run = source
        .catalog
        .create_synthetic_run(
            &serde_json::from_value(
                json!({"approval_id":approval,"idempotency_key":"before-restore"}),
            )
            .unwrap(),
        )
        .unwrap()
        .run;
    let backup_path = root.join("backup.sqlite3");
    std::fs::write(&backup_path, source.catalog.backup_bytes().unwrap()).unwrap();
    assert!(
        crate::inspect_configuration_backup(&backup_path)
            .unwrap()
            .integrity_ok
    );
    let destination = root.join("restored");
    crate::restore_configuration_backup(&backup_path, &destination).unwrap();
    assert!(crate::restore_configuration_backup(&backup_path, &destination).is_err());
    let restored = Catalog::open(&destination.join("secretbridge.sqlite3")).unwrap();
    assert_eq!(
        restored.list_synthetic_runs().unwrap()[0].state,
        RunState::Failed
    );
    assert_eq!(
        restored.list_synthetic_runs().unwrap()[0].id,
        pending_run.id
    );
    assert_eq!(
        restored.list_approvals().unwrap()[0].state,
        crate::catalog::ApprovalState::Revoked
    );
    assert_eq!(
        restored.list_credential_references().unwrap()[0].secret_state,
        crate::catalog::SecretState::NotConfigured
    );
    assert_eq!(
        source.catalog.list_credential_references().unwrap()[0].secret_state,
        crate::catalog::SecretState::Available
    );
    let (mut state, _) = AppState::new([ORIGIN.to_owned()]);
    state.catalog = restored;
    let app = router(state.clone());
    let (token, _) = state.issue_session().await;
    let template_before = state.catalog.list_action_templates().unwrap().remove(0);
    assert!(matches!(
        state.catalog.create_approval(
            &serde_json::from_value(
                json!({"action_template_id":template_before.id,"expires_in_seconds":60})
            )
            .unwrap()
        ),
        Err(crate::catalog::CatalogError::PolicyDenied)
    ));
    let record = state
        .catalog
        .list_credential_references()
        .unwrap()
        .remove(0);
    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            &format!("/api/v1/credential-references/{credential}/secret"),
            &token,
            json!({"secret":"Synthetic-SB-restored_B&z","expected_version":record.version})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let template = state.catalog.list_action_templates().unwrap().remove(0);
    let granted = state
        .catalog
        .create_approval(
            &serde_json::from_value(
                json!({"action_template_id":template.id,"expires_in_seconds":60}),
            )
            .unwrap(),
        )
        .unwrap();
    state
        .catalog
        .approve_approval(
            granted.id,
            &serde_json::from_value(json!({"expected_version":granted.version})).unwrap(),
        )
        .unwrap();
    let response = app
        .oneshot(request(
            "POST",
            "/api/v1/runs",
            &token,
            json!({"approval_id":granted.id,"idempotency_key":"after-restore"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let run =
        serde_json::from_slice::<Value>(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let run_id = Uuid::parse_str(run["run"]["id"].as_str().unwrap()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let output = state.catalog.output(run_id, 0).unwrap();
            if !matches!(output.state, RunState::Queued | RunState::Running) {
                assert_eq!(output.state, RunState::Succeeded);
                let text = output
                    .items
                    .iter()
                    .map(|item| item.text.as_str())
                    .collect::<String>();
                assert!(text.contains("[REDACTED]"));
                assert!(!text.contains("Synthetic-SB-restored_B&z"));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    // Completion is committed before the asynchronous driver releases its state.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while state
            .run_cancellations
            .active
            .lock()
            .await
            .contains_key(&run_id)
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(state);
    drop(source);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match std::fs::remove_dir_all(&root) {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn maintenance_body_limits_and_origin_checks_apply_before_import() {
    let (state, _) = AppState::new([ORIGIN.to_owned()]);
    configure(&state, "environment", 10);
    let mut bundle = state.catalog.export_configuration().unwrap();
    bundle.templates[0]
        .command
        .as_mut()
        .unwrap()
        .arguments
        .extend(vec!["x".repeat(2048); 16]);
    let body = serde_json::to_string(&bundle).unwrap();
    assert!(body.len() > 16 * 1024);
    let (token, _) = state.issue_session().await;
    let app = router(state);
    let preview = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/maintenance/configuration/preview",
            &token,
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    let mut no_origin = request(
        "POST",
        "/api/v1/maintenance/configuration/preview",
        &token,
        body,
    );
    no_origin.headers_mut().remove("origin");
    let rejected = app.oneshot(no_origin).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
}
