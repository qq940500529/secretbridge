// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::catalog::{
    CreateActionTemplate, CreateApproval, CreateCredentialReference, CreateSyntheticRun,
    CreateTarget, DecideApproval,
};

pub(crate) fn fixture(mode: &str, id: Uuid) -> CommandConfig {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (program, mut arguments) = if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").expect("Windows root");
        (
            PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
            vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-File".into(),
                directory
                    .join("tests/fixtures/credential-command.ps1")
                    .to_string_lossy()
                    .into_owned(),
                mode.into(),
            ],
        )
    } else {
        (
            PathBuf::from("/bin/sh"),
            vec![
                directory
                    .join("tests/fixtures/credential-command.sh")
                    .to_string_lossy()
                    .into_owned(),
                mode.into(),
            ],
        )
    };
    if matches!(mode, "argument" | "file" | "file_sleep") {
        arguments.push("{{password}}".into());
    }
    CommandConfig {
        database: None,
        http: None,
        ssh: None,
        git: None,
        parameters: Vec::new(),
        program: program.to_string_lossy().into_owned(),
        working_directory: directory.to_string_lossy().into_owned(),
        arguments,
        slots: vec![CredentialSlot {
            name: "password".into(),
            credential_id: id,
            injection: match mode {
                "environment" => Injection::Environment,
                "argument" => Injection::Argument,
                "file" | "file_sleep" => Injection::File,
                _ => Injection::Stdin,
            },
            environment_variable: (mode == "environment").then(|| "SB_TEST_SECRET".into()),
        }],
    }
}

pub(crate) fn configure(state: &AppState, mode: &str, timeout: u64) -> (Uuid, Uuid) {
    let credential: CreateCredentialReference = serde_json::from_value(
        serde_json::json!({"name":"Synthetic command test","kind":"password"}),
    )
    .unwrap();
    let credential = state
        .catalog
        .create_credential_reference(&credential)
        .unwrap();
    state
        .secret_store
        .set(credential.id, "Synthetic-SB-command_A&z")
        .unwrap();
    state
        .catalog
        .set_credential_secret_state(credential.id, credential.version, true)
        .unwrap();
    let target: CreateTarget = serde_json::from_value(
        serde_json::json!({"name":"Local command","kind":"http_service","environment":"test"}),
    )
    .unwrap();
    let target = state.catalog.create_target(&target).unwrap();
    let template:CreateActionTemplate=serde_json::from_value(serde_json::json!({"name":"Credential echo fixture","target_id":target.id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"command":fixture(mode,credential.id)})).unwrap();
    let template = state.catalog.create_action_template(&template).unwrap();
    let request: CreateApproval = serde_json::from_value(
        serde_json::json!({"action_template_id":template.id,"expires_in_seconds":60}),
    )
    .unwrap();
    let approval = state.catalog.create_approval(&request).unwrap();
    let decision: DecideApproval =
        serde_json::from_value(serde_json::json!({"expected_version":approval.version})).unwrap();
    state
        .catalog
        .approve_approval(approval.id, &decision)
        .unwrap();
    (approval.id, credential.id)
}

async fn wait(state: &AppState, id: Uuid) -> OutputPage {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let page = state.catalog.output(id, 0).unwrap();
            if !matches!(page.state, RunState::Queued | RunState::Running) {
                return page;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("command reaches a terminal state")
}

#[tokio::test]
async fn real_program_uses_all_injections_without_persisting_plaintext() {
    for mode in ["stdin", "environment", "argument", "file"] {
        let (state, _) = AppState::new([]);
        let (approval, credential) = configure(&state, mode, 10);
        assert!(matches!(
            state.catalog.delete_credential_reference(credential),
            Err(CatalogError::ResourceInUse)
        ));
        let request = CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        };
        let result = crate::create_run_for_state(&state, request).await.unwrap();
        let page = wait(&state, result.run.id).await;
        assert_eq!(
            page.state,
            RunState::Succeeded,
            "{mode}: code={:?}, exit={:?}",
            state
                .catalog
                .get_synthetic_run(result.run.id)
                .unwrap()
                .result_status,
            page.exit_code
        );
        assert_eq!(page.exit_code, Some(0));
        let output = page
            .items
            .iter()
            .map(|c| c.text.as_str())
            .collect::<String>();
        assert!(output.contains("[REDACTED]"), "{mode}: {output}");
        assert!(output.contains("stdout-marker") && output.contains("stderr-marker"));
        assert!(!output.contains("Synthetic-SB-command_A&z"));
        let retained: Vec<String> = state
            .catalog
            .lock()
            .prepare("SELECT text FROM run_output")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            retained
                .iter()
                .all(|text| !text.contains("Synthetic-SB-command_A&z"))
        );
        assert!(
            state
                .catalog
                .output(result.run.id, page.next_cursor)
                .unwrap()
                .items
                .is_empty()
        );
        if mode == "file" {
            assert_eq!(
                std::fs::read_dir(&*state.command_directory)
                    .unwrap()
                    .count(),
                0
            );
            std::fs::remove_dir(&*state.command_directory).unwrap();
        }
    }
}

#[test]
fn process_completion_commits_exit_code_state_and_event_together() {
    let (state, _) = AppState::new([]);
    let (approval, _) = configure(&state, "argument", 10);
    let created = state
        .catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        })
        .unwrap();
    let id = created.run.id;
    state.catalog.start_run(id).unwrap();
    // A deterministic invariant: a successful process must become visible
    // with its exit code in the same SQL update, never a later statement.
    state.catalog.lock().execute_batch("CREATE TEMP TRIGGER process_completion_requires_exit BEFORE UPDATE ON synthetic_runs WHEN NEW.state='succeeded' AND NEW.result_status='command_ok' AND NEW.exit_code IS NULL BEGIN SELECT RAISE(ABORT,'exit code must be atomic'); END;").unwrap();
    assert!(
        state
            .catalog
            .complete_command_run(id, "command_ok", None)
            .is_err()
    );
    let page = state.catalog.output(id, 0).unwrap();
    assert_eq!(page.state, RunState::Running);
    assert_eq!(page.exit_code, None);
    let events = state.catalog.list_safe_events(Some(id)).unwrap();
    assert_eq!(events.len(), 2);
    state
        .catalog
        .complete_command_run(id, "command_ok", Some(0))
        .unwrap();
    let page = state.catalog.output(id, 0).unwrap();
    assert_eq!(page.state, RunState::Succeeded);
    assert_eq!(page.exit_code, Some(0));
    assert_eq!(state.catalog.list_safe_events(Some(id)).unwrap().len(), 3);
}

#[tokio::test]
async fn command_timeout_and_explicit_cancellation_stop_real_processes() {
    for cancel in [false, true] {
        let (state, _) = AppState::new([]);
        let (approval, _) = configure(&state, "sleep", if cancel { 10 } else { 1 });
        let outcome = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .unwrap();
        if cancel {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let run = state.catalog.get_synthetic_run(outcome.run.id).unwrap();
            crate::cancel_run_for_state(
                &state,
                outcome.run.id,
                crate::catalog::CancelSyntheticRun {
                    expected_version: run.version,
                },
            )
            .await
            .unwrap();
        }
        let page = wait(&state, outcome.run.id).await;
        assert_eq!(
            page.state,
            if cancel {
                RunState::Cancelled
            } else {
                RunState::Failed
            }
        );
        if !cancel {
            assert_eq!(
                state
                    .catalog
                    .get_synthetic_run(outcome.run.id)
                    .unwrap()
                    .result_status
                    .as_deref(),
                Some("timed_out")
            );
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if state.command_capacity.available_permits() == 4 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn credential_file_storage_failure_is_atomic_and_releases_capacity() {
    let blocker = std::env::temp_dir().join(format!(
        "secretbridge-command-storage-failure-{}",
        Uuid::new_v4()
    ));
    std::fs::write(&blocker, b"not a directory").unwrap();
    let (mut state, _) = AppState::new([]);
    state.command_directory = std::sync::Arc::new(blocker.clone());
    let (approval, _) = configure(&state, "file", 10);
    let result = crate::create_run_for_state(
        &state,
        CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        },
    )
    .await
    .unwrap();
    let page = wait(&state, result.run.id).await;
    assert_eq!(page.state, RunState::Failed);
    assert_eq!(page.exit_code, None);
    assert_eq!(
        state
            .catalog
            .get_synthetic_run(result.run.id)
            .unwrap()
            .result_status
            .as_deref(),
        Some("command_failed")
    );
    assert!(
        page.items
            .iter()
            .all(|item| !item.text.contains("Synthetic-SB-command_A&z"))
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.command_capacity.available_permits() != 4
            || !state.run_cancellations.active.lock().await.is_empty()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read(&blocker).unwrap(), b"not a directory");
    std::fs::remove_file(blocker).unwrap();
}

#[test]
fn template_storage_failure_rolls_back_definition_and_credential_links() {
    let (state, _) = AppState::new([]);
    configure(&state, "file", 10);
    let before = state.catalog.list_action_templates().unwrap().remove(0);
    state
        .catalog
        .lock()
        .execute_batch(
            "CREATE TEMP TRIGGER reject_command_slot_write
                 BEFORE INSERT ON command_slots
                 BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END;",
        )
        .unwrap();
    let command = before.command.clone().unwrap();
    let update = serde_json::from_value(serde_json::json!({
        "target_id": before.target_id,
        "name": "must roll back",
        "operation": "command_execution",
        "result_scope": "sanitized_output",
        "timeout_seconds": 20,
        "enabled": true,
        "expected_version": before.version,
        "command": command
    }))
    .unwrap();
    assert!(matches!(
        state.catalog.update_action_template(before.id, &update),
        Err(CatalogError::Storage)
    ));
    let after = state
        .catalog
        .list_action_templates()
        .unwrap()
        .into_iter()
        .find(|item| item.id == before.id)
        .unwrap();
    assert_eq!(after.name, before.name);
    assert_eq!(after.version, before.version);
    assert_eq!(after.timeout_seconds, before.timeout_seconds);
    assert_eq!(
        after.command.unwrap().working_directory,
        before.command.unwrap().working_directory
    );
    let linked: i64 = state
        .catalog
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM command_slots WHERE template_id=?1",
            [before.id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(linked, 1);
}

#[test]
fn invalid_placeholder_and_duplicate_stdin_are_rejected() {
    let mut config = fixture("argument", Uuid::new_v4());
    config.arguments.push("prefix{{password}}".into());
    assert!(config.validate().is_err());
    let mut config = fixture("stdin", Uuid::new_v4());
    let mut second = config.slots[0].clone();
    second.name = "second".into();
    config.slots.push(second);
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn parameterized_commands_freeze_values_and_do_not_expand_them_again() {
    let (state, _) = AppState::new([]);
    let (_, credential) = configure(&state, "argument", 10);
    let template = state.catalog.list_action_templates().unwrap().remove(0);
    let mut config = fixture("argument", credential);
    config.arguments.push("{{param:company}}".into());
    config.parameters = serde_json::from_value(serde_json::json!([{
        "name":"company","label":"公司","kind":"string","required":true,
        "default":"天津; {{password}} & 100","choices":[],"max_length":128
    }]))
    .unwrap();
    let update = serde_json::from_value(serde_json::json!({
        "target_id":template.target_id,"name":template.name,"operation":"command_execution",
        "result_scope":"sanitized_output","timeout_seconds":10,"enabled":true,
        "expected_version":template.version,"command":config
    }))
    .unwrap();
    let template = state
        .catalog
        .update_action_template(template.id, &update)
        .unwrap();
    let request = serde_json::from_value(serde_json::json!({
        "action_template_id":template.id,"expires_in_seconds":60,"authorization_mode":"time_window"
    }))
    .unwrap();
    let approval = state.catalog.create_approval(&request).unwrap();
    assert_eq!(approval.parameters["company"], "天津; {{password}} & 100");
    let decision =
        serde_json::from_value(serde_json::json!({"expected_version":approval.version})).unwrap();
    state
        .catalog
        .approve_approval(approval.id, &decision)
        .unwrap();
    for _ in 0..2 {
        let key = Uuid::new_v4().to_string();
        let request = CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: key.clone(),
        };
        let result = crate::create_run_for_state(&state, request).await.unwrap();
        let page = wait(&state, result.run.id).await;
        assert_eq!(
            page.state,
            RunState::Succeeded,
            "code={:?}, exit={:?}",
            state
                .catalog
                .get_synthetic_run(result.run.id)
                .unwrap()
                .result_status,
            page.exit_code
        );
        let output = page
            .items
            .iter()
            .map(|c| c.text.as_str())
            .collect::<String>();
        assert!(
            output.contains("|parameter:天津; {{password}} & 100|"),
            "{output}"
        );
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("Synthetic-SB-command_A&z"));
        let replay = state
            .catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: key,
            })
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.run.id, result.run.id);
    }
    let current = state.catalog.get_approval(approval.id).unwrap();
    state
        .catalog
        .revoke_approval(
            approval.id,
            &crate::catalog::DecideApproval {
                expected_version: current.version,
                note: None,
            },
        )
        .unwrap();
    assert!(
        state
            .catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: Uuid::new_v4().to_string()
            })
            .is_err()
    );
}

#[test]
fn retained_output_reports_gaps_and_rotation_invalidates_approval() {
    let (state, _) = AppState::new([]);
    let (approval, credential) = configure(&state, "stdin", 10);
    let outcome = state
        .catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        })
        .unwrap();
    for _ in 0..70 {
        state
            .catalog
            .append_output(outcome.run.id, "stdout", "中\n")
            .unwrap();
    }
    let page = state.catalog.output(outcome.run.id, 0).unwrap();
    assert!(page.truncated && page.has_more);
    assert_eq!(page.oldest_cursor, 7);
    assert_eq!(page.items.len(), 16);
    assert!(state.catalog.output(outcome.run.id, 71).is_err());
    assert!(
        !state
            .catalog
            .output(outcome.run.id, page.next_cursor)
            .unwrap()
            .truncated
    );
    let current = state.catalog.get_credential_reference(credential).unwrap();
    state
        .catalog
        .set_credential_secret_state(credential, current.version, true)
        .unwrap();
    assert!(matches!(
        state.catalog.start_run(outcome.run.id),
        Err(CatalogError::PolicyDenied)
    ));
}

pub(crate) async fn web_request(
    state: &AppState,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    web_request_method(state, token, "POST", path, body).await
}

pub(crate) async fn web_request_method(
    state: &AppState,
    token: &str,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let response = crate::router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("origin", "http://127.0.0.1:8787")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16_384).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn web_parameter_approval_and_time_window_use_the_real_executor() {
    use axum::http::StatusCode;
    use serde_json::json;
    let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
    let (_, credential) = configure(&state, "argument", 10);
    let template = state.catalog.list_action_templates().unwrap().remove(0);
    let mut config = fixture("argument", credential);
    config.arguments.push("{{param:company}}".into());
    config.parameters=serde_json::from_value(json!([{"name":"company","label":"公司","kind":"string","required":true,"default":"100","choices":["100","101"],"max_length":3}])).unwrap();
    let update=serde_json::from_value(json!({"target_id":template.target_id,"name":template.name,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":10,"enabled":true,"expected_version":template.version,"command":config})).unwrap();
    state
        .catalog
        .update_action_template(template.id, &update)
        .unwrap();
    let (token, _) = state.issue_session().await;
    for parameters in [
        json!({"company":100}),
        json!({"company":"102"}),
        json!({"unknown":"100"}),
    ] {
        let (status,_)=web_request(&state,&token,"/api/v1/approvals",json!({"action_template_id":template.id,"expires_in_seconds":60,"parameters":parameters})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status,approval)=web_request(&state,&token,"/api/v1/approvals",json!({"action_template_id":template.id,"expires_in_seconds":60,"authorization_mode":"time_window"})).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(approval["parameters"]["company"], "100");
    let id = approval["id"].as_str().unwrap();
    let (status, approved) = web_request(
        &state,
        &token,
        &format!("/api/v1/approvals/{id}/approve"),
        json!({"expected_version":approval["version"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..2 {
        let request = json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()});
        let (status, result) = web_request(&state, &token, "/api/v1/runs", request.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        let run = Uuid::parse_str(result["run"]["id"].as_str().unwrap()).unwrap();
        let page = wait(&state, run).await;
        assert_eq!(
            page.state,
            RunState::Succeeded,
            "code={:?}, exit={:?}",
            state.catalog.get_synthetic_run(run).unwrap().result_status,
            page.exit_code
        );
        let output = page
            .items
            .iter()
            .map(|c| c.text.as_str())
            .collect::<String>();
        assert!(output.contains("|parameter:100|"));
        assert!(!output.contains("Synthetic-SB-command_A&z"));
        let (_, replay) = web_request(&state, &token, "/api/v1/runs", request).await;
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["run"]["id"], result["run"]["id"]);
    }
    let (status, _) = web_request(
        &state,
        &token,
        &format!("/api/v1/approvals/{id}/revoke"),
        json!({"expected_version":approved["version"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = web_request(
        &state,
        &token,
        "/api/v1/runs",
        json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn output_api_is_authenticated_origin_checked_and_does_not_notify_on_read() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let origin = "http://127.0.0.1:8787";
    let (state, _) = AppState::new([origin.to_owned()]);
    let (approval, _) = configure(&state, "stdin", 10);
    let run = state
        .catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        })
        .unwrap()
        .run;
    state
        .catalog
        .append_output(run.id, "stdout", "[REDACTED]")
        .unwrap();
    let (token, _) = state.issue_session().await;
    let mut changes = state.changes.subscribe();
    for (provided_origin, provided_token, body, expected) in [
        (
            origin,
            "invalid",
            r#"{"cursor":0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "http://untrusted.invalid",
            token.as_str(),
            r#"{"cursor":0}"#,
            StatusCode::FORBIDDEN,
        ),
        (
            origin,
            token.as_str(),
            r#"{"cursor":0,"wait_ms":5001}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            origin,
            token.as_str(),
            r#"{"cursor":0,"secret":"not-accepted"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (origin, token.as_str(), r#"{"cursor":0}"#, StatusCode::OK),
    ] {
        let response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/runs/{}/output", run.id))
                    .header("origin", provided_origin)
                    .header("authorization", format!("Bearer {provided_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), changes.recv())
            .await
            .is_err()
    );
}

#[test]
fn recovery_cleanup_removes_only_owned_regular_secret_files() {
    let directory = std::env::temp_dir().join(format!("sb-clean-{}", Uuid::new_v4()));
    let mut files = TemporaryFiles { paths: Vec::new() };
    let path = secret_file(&directory, &mut files, "synthetic-cleanup").unwrap();
    let unrelated = directory.join("notes.secret");
    std::fs::write(&unrelated, b"not a managed file").unwrap();
    cleanup_files(&directory).unwrap();
    assert!(!path.exists());
    assert!(unrelated.exists());
    std::fs::remove_file(unrelated).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
