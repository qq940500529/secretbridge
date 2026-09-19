// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{fmt::Write as _, time::Duration};

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState,
    catalog::{CancelSyntheticRun, CreateSyntheticRun, RunState},
    command::{
        OutputPage,
        tests::{configure, web_request_method},
    },
};

const ORIGIN: &str = "http://127.0.0.1:8787";

fn encoded_forms(secret: &str) -> Vec<Vec<u8>> {
    let mut forms = vec![
        secret.as_bytes().to_vec(),
        secret.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        secret.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    ];
    let escaped = serde_json::to_string(secret).expect("serialize canary");
    forms.push(escaped.as_bytes().to_vec());
    forms.push(escaped.as_bytes()[1..escaped.len() - 1].to_vec());
    let mut upper = String::new();
    let mut lower = String::new();
    for byte in secret.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            upper.push(char::from(byte));
            lower.push(char::from(byte));
        } else {
            write!(upper, "%{byte:02X}").expect("encode canary");
            write!(lower, "%{byte:02x}").expect("encode canary");
        }
    }
    forms.push(upper.into_bytes());
    forms.push(lower.into_bytes());
    forms.sort();
    forms.dedup();
    forms
}

fn assert_canary_absent(surface: &str, contents: &[u8], secret: &str) {
    for encoded in encoded_forms(secret) {
        assert!(
            !contents
                .windows(encoded.len())
                .any(|window| window == encoded),
            "credential canary leaked through {surface}"
        );
    }
}

async fn wait_for_run(state: &AppState, id: Uuid) -> OutputPage {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let page = state.catalog.output(id, 0).expect("read output");
            if !matches!(page.state, RunState::Queued | RunState::Running) {
                return page;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("credential command reaches a terminal state")
}

async fn wait_for_driver_release(state: &AppState, id: Uuid) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !state
                .run_cancellations
                .active
                .lock()
                .await
                .contains_key(&id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("credential command driver releases the run");
}

async fn api_surfaces(state: &AppState, run_id: Uuid) -> Vec<(String, Vec<u8>)> {
    let (token, _) = state.issue_session().await;
    let mut surfaces = Vec::new();
    for path in [
        "/api/v1/credential-references",
        "/api/v1/targets",
        "/api/v1/action-templates",
        "/api/v1/approvals",
        "/api/v1/runs",
        "/api/v1/safe-events",
        "/api/v1/maintenance/configuration",
        "/api/v1/maintenance/diagnostics",
    ] {
        let (status, value) = web_request_method(state, &token, "GET", path, json!({})).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        surfaces.push((
            format!("API {path}"),
            serde_json::to_vec(&value).expect("serialize API response"),
        ));
    }
    let path = format!("/api/v1/runs/{run_id}/output");
    let (status, value) =
        web_request_method(state, &token, "POST", &path, json!({"cursor":0})).await;
    assert_eq!(status, StatusCode::OK, "POST {path}");
    surfaces.push((
        format!("API {path}"),
        serde_json::to_vec(&value).expect("serialize output response"),
    ));
    surfaces
}

async fn all_surfaces(state: &AppState, run_id: Uuid, page: &OutputPage) -> Vec<(String, Vec<u8>)> {
    let mut surfaces = api_surfaces(state, run_id).await;
    surfaces.push((
        "catalog configuration export".into(),
        serde_json::to_vec(
            &state
                .catalog
                .export_configuration()
                .expect("export configuration"),
        )
        .expect("serialize configuration"),
    ));
    surfaces.push((
        "SQLite backup".into(),
        state.catalog.backup_bytes().expect("create backup"),
    ));
    surfaces.push((
        "direct output page".into(),
        serde_json::to_vec(page).expect("serialize output page"),
    ));
    surfaces
}

#[tokio::test]
async fn credential_canary_is_absent_from_persistence_and_normal_apis() {
    for mode in ["stdin", "environment", "argument", "file"] {
        let (state, _) = AppState::new([ORIGIN.to_owned()]);
        let (approval, credential) = configure(&state, mode, 10);
        let secret = format!("SB-{mode}-{}-&\"Z", Uuid::new_v4().simple());
        state
            .secret_store
            .set(credential, &secret)
            .expect("replace synthetic secret");
        let parent_environment = std::env::var_os("SB_TEST_SECRET");
        let outcome = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .expect("start credential command");
        let page = wait_for_run(&state, outcome.run.id).await;
        wait_for_driver_release(&state, outcome.run.id).await;
        assert_eq!(page.state, RunState::Succeeded, "injection mode {mode}");
        let output = page
            .items
            .iter()
            .map(|item| item.text.as_str())
            .collect::<String>();
        assert!(
            output.contains(&format!("|length:{}|", secret.len())),
            "injection mode {mode} did not observe the complete canary"
        );
        assert!(
            output.contains("[REDACTED]"),
            "injection mode {mode} did not exercise output redaction"
        );
        assert_eq!(
            std::env::var_os("SB_TEST_SECRET"),
            parent_environment,
            "child environment injection changed the broker environment"
        );
        for (surface, contents) in all_surfaces(&state, outcome.run.id, &page).await {
            assert_canary_absent(&format!("{mode}: {surface}"), &contents, &secret);
        }
        if mode == "file" {
            assert_eq!(
                std::fs::read_dir(&*state.command_directory)
                    .expect("read command directory")
                    .count(),
                0,
                "successful file injection left temporary material"
            );
            std::fs::remove_dir(&*state.command_directory).expect("remove command directory");
        }
    }
}

#[tokio::test]
async fn cancellation_and_timeout_remove_temporary_credential_files() {
    for cancel in [false, true] {
        let (state, _) = AppState::new([ORIGIN.to_owned()]);
        let (approval, credential) = configure(&state, "file_sleep", if cancel { 10 } else { 1 });
        let secret = format!("SB-file-stop-{}-&\"Z", Uuid::new_v4().simple());
        state
            .secret_store
            .set(credential, &secret)
            .expect("replace synthetic secret");
        let outcome = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .expect("start delayed file command");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if std::fs::read_dir(&*state.command_directory)
                    .is_ok_and(|mut entries| entries.next().is_some())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("temporary credential file becomes observable");
        if cancel {
            let run = state
                .catalog
                .get_synthetic_run(outcome.run.id)
                .expect("get active run");
            crate::cancel_run_for_state(
                &state,
                outcome.run.id,
                CancelSyntheticRun {
                    expected_version: run.version,
                },
            )
            .await
            .expect("cancel delayed command");
        }
        let page = wait_for_run(&state, outcome.run.id).await;
        wait_for_driver_release(&state, outcome.run.id).await;
        assert_eq!(
            page.state,
            if cancel {
                RunState::Cancelled
            } else {
                RunState::Failed
            }
        );
        assert_eq!(
            std::fs::read_dir(&*state.command_directory)
                .expect("read command directory")
                .count(),
            0,
            "stopped file injection left temporary material"
        );
        for (_surface, contents) in all_surfaces(&state, outcome.run.id, &page).await {
            assert_canary_absent(
                if cancel {
                    "cancel surface"
                } else {
                    "timeout surface"
                },
                &contents,
                &secret,
            );
        }
        std::fs::remove_dir(&*state.command_directory).expect("remove command directory");
    }
}
