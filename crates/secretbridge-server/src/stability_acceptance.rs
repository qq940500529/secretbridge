// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    catalog::{
        CancelSyntheticRun, CatalogError, CreateApproval, CreateSyntheticRun, DecideApproval,
        RunState,
    },
};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

fn approve(state: &AppState, template: Uuid) -> Uuid {
    let request: CreateApproval = serde_json::from_value(json!({
        "action_template_id": template,
        "expires_in_seconds": 60,
        "authorization_mode": "time_window"
    }))
    .unwrap();
    let approval = state.catalog.create_approval(&request).unwrap();
    state
        .catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    approval.id
}

async fn start(state: &AppState, approval: Uuid) -> Uuid {
    crate::create_run_for_state(
        state,
        CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        },
    )
    .await
    .unwrap()
    .run
    .id
}

async fn wait_for_terminal_state(state: &AppState, id: Uuid) -> crate::command::OutputPage {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = state.catalog.output(id, 0).unwrap();
            if !matches!(page.state, RunState::Queued | RunState::Running)
                && !state
                    .run_cancellations
                    .active
                    .lock()
                    .await
                    .contains_key(&id)
            {
                return page;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("run reaches a terminal state")
}

async fn cancel_with_latest_version(state: &AppState, id: Uuid) {
    for _ in 0..10 {
        let current = state.catalog.get_synthetic_run(id).unwrap();
        match crate::cancel_run_for_state(
            state,
            id,
            CancelSyntheticRun {
                expected_version: current.version,
            },
        )
        .await
        {
            Ok(_) => return,
            Err(CatalogError::VersionConflict) => tokio::task::yield_now().await,
            Err(error) => panic!("cancelling an active run failed: {error:?}"),
        }
    }
    panic!("run version did not settle after bounded cancellation retries");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_cancellation_releases_capacity_and_follow_up_work_succeeds() {
    let fixture = crate::http_task::tests::server().await;
    let (state, _) = AppState::new([]);
    let template = crate::http_task::tests::configure(&state, &fixture.url, 30);
    let current = state
        .catalog
        .list_action_templates()
        .unwrap()
        .into_iter()
        .find(|item| item.id == template)
        .unwrap();
    let mut command = current.command.unwrap();
    let http = command.http.as_mut().unwrap();
    http.url = format!("{}/slow", fixture.url);
    http.method = "GET".into();
    http.headers.clear();
    http.query.clear();
    http.body.clear();
    http.response_fields.clear();
    command.slots.clear();
    command.parameters.clear();
    let updated = state
        .catalog
        .update_action_template(
            template,
            &serde_json::from_value(json!({
                "target_id": current.target_id,
                "name": current.name,
                "operation": "command_execution",
                "result_scope": "sanitized_output",
                "timeout_seconds": 30,
                "enabled": true,
                "expected_version": current.version,
                "command": command
            }))
            .unwrap(),
        )
        .unwrap();
    let approval = approve(&state, updated.id);
    let mut ids = Vec::new();
    for _ in 0..8 {
        ids.push(start(&state, approval).await);
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        while state.command_capacity.available_permits() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("four operations consume the personal-use concurrency budget");

    // Configuration reads and writes remain responsive while connector work is saturated.
    let target_count = state.catalog.list_targets().unwrap().len();
    let probe = state
        .catalog
        .create_target(
            &serde_json::from_value(json!({
                "name": "Concurrent responsiveness probe",
                "kind": "http_service",
                "environment": "test"
            }))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        state.catalog.list_targets().unwrap().len(),
        target_count + 1
    );
    state.catalog.delete_target(probe.id).unwrap();

    for id in &ids {
        cancel_with_latest_version(&state, *id).await;
    }
    for id in ids {
        let page = wait_for_terminal_state(&state, id).await;
        assert_eq!(page.state, RunState::Cancelled);
    }
    assert_eq!(state.command_capacity.available_permits(), 4);
    assert!(state.run_cancellations.active.lock().await.is_empty());

    let follow_up = crate::http_task::tests::configure(&state, &fixture.url, 5);
    let page =
        wait_for_terminal_state(&state, start(&state, approve(&state, follow_up)).await).await;
    assert_eq!(page.state, RunState::Succeeded);
    let text = page
        .items
        .iter()
        .map(|item| item.text.as_str())
        .collect::<String>();
    assert!(!text.contains(crate::http_task::tests::SECRET));
}
