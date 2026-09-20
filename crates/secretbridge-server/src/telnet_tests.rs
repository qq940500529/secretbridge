// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::catalog::{
    CancelSyntheticRun, CreateApproval, CreateSyntheticRun, DecideApproval, RunState,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

const SECRET: &str = "Synthetic_telnet_password_42";

#[derive(Clone, Copy)]
enum Mode {
    Success,
    RejectAuthentication,
    StallCommand,
    RejectInjectedPassword,
}

struct Fixture {
    port: u16,
    command_seen: Arc<Notify>,
    disconnected: Arc<AtomicBool>,
}

async fn read_line(stream: &mut TcpStream) -> Option<String> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await.ok()?;
        if byte == IAC {
            let _command = stream.read_u8().await.ok()?;
            let _option = stream.read_u8().await.ok()?;
            continue;
        }
        if byte == b'\n' {
            return String::from_utf8(line).ok();
        }
        if byte != b'\r' {
            line.push(byte);
        }
    }
}

async fn server(mode: Mode) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let command_seen = Arc::new(Notify::new());
    let disconnected = Arc::new(AtomicBool::new(false));
    let notify = command_seen.clone();
    let closed = disconnected.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(&[IAC, WILL, 1]).await.unwrap();
        stream.write_all(b"legacy login: ").await.unwrap();
        assert_eq!(read_line(&mut stream).await.as_deref(), Some("operator"));
        stream.write_all(b"Password: ").await.unwrap();
        let supplied = read_line(&mut stream).await;
        if matches!(mode, Mode::RejectInjectedPassword) {
            assert!(supplied.is_none());
            closed.store(true, Ordering::SeqCst);
            return;
        }
        let supplied = supplied.unwrap();
        if matches!(mode, Mode::RejectAuthentication) || supplied != SECRET {
            stream.write_all(b"Login incorrect\r\n").await.unwrap();
            return;
        }
        // Deliberately echo the secret across writes. The connector must redact
        // across protocol and UTF-8 chunk boundaries before storing output.
        stream.write_all(b"welcome ").await.unwrap();
        let split = SECRET.len() / 2;
        stream.write_all(&SECRET.as_bytes()[..split]).await.unwrap();
        stream.write_all(&SECRET.as_bytes()[split..]).await.unwrap();
        stream.write_all(b"\r\nlegacy> ").await.unwrap();
        assert_eq!(read_line(&mut stream).await.as_deref(), Some("show status"));
        notify.notify_one();
        if matches!(mode, Mode::StallCommand) {
            let mut byte = [0_u8; 1];
            while stream.read(&mut byte).await.unwrap_or(0) != 0 {}
            closed.store(true, Ordering::SeqCst);
            return;
        }
        stream
            .write_all(b"status: ready\r\nlegacy> ")
            .await
            .unwrap();
        assert_eq!(read_line(&mut stream).await.as_deref(), Some("exit"));
        closed.store(true, Ordering::SeqCst);
    });
    Fixture {
        port,
        command_seen,
        disconnected,
    }
}

fn configure(
    state: &AppState,
    fixture: &Fixture,
    allowed: bool,
    timeout: u64,
    secret: &str,
) -> Uuid {
    let credential = state
        .catalog
        .create_credential_reference(
            &serde_json::from_value(json!({"name":"Telnet password","kind":"password"})).unwrap(),
        )
        .unwrap();
    state.secret_store.set(credential.id, secret).unwrap();
    state
        .catalog
        .set_credential_secret_state(credential.id, credential.version, true)
        .unwrap();
    let target = state
        .catalog
        .create_target(
            &serde_json::from_value(json!({
                "name":"Legacy test device",
                "kind":"telnet_host",
                "environment":"test",
                "address":"127.0.0.1",
                "username":"operator",
                "allow_insecure_protocol":allowed,
                "credential_reference_id":credential.id
            }))
            .unwrap(),
        )
        .unwrap();
    state
        .catalog
        .create_action_template(
            &serde_json::from_value(json!({
                "name":"Legacy status",
                "target_id":target.id,
                "operation":"command_execution",
                "result_scope":"sanitized_output",
                "timeout_seconds":timeout,
                "command":{
                    "program":"",
                    "working_directory":"",
                    "arguments":[],
                    "slots":[{"name":"password","credential_id":credential.id,"injection":"protocol","environment_variable":null}],
                    "telnet":{
                        "host":"127.0.0.1",
                        "port":fixture.port,
                        "username":"operator",
                        "password_slot":"password",
                        "login_prompt":"login: ",
                        "password_prompt":"Password: ",
                        "command_prompt":"legacy> ",
                        "authentication_failure_prompt":"Login incorrect",
                        "commands":["show status"],
                        "logout_command":"exit",
                        "max_output_bytes":65536
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap()
        .id
}

fn approve(state: &AppState, template: Uuid) -> Uuid {
    let approval = state
        .catalog
        .create_approval(
            &serde_json::from_value(json!({
                "action_template_id":template,
                "expires_in_seconds":60,
                "authorization_mode":"once"
            }))
            .unwrap(),
        )
        .unwrap();
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

async fn run(state: &AppState, approval: Uuid) -> Uuid {
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

async fn wait(state: &AppState, id: Uuid) -> crate::command::OutputPage {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let page = state.catalog.output(id, 0).unwrap();
            if !matches!(page.state, RunState::Queued | RunState::Running) {
                return page;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

fn text(page: &crate::command::OutputPage) -> String {
    page.items.iter().map(|item| item.text.as_str()).collect()
}

#[tokio::test]
async fn real_telnet_negotiates_logs_in_runs_fixed_script_and_redacts_echo() {
    let fixture = server(Mode::Success).await;
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, true, 5, SECRET);
    let id = run(&state, approve(&state, template)).await;
    let page = wait(&state, id).await;
    assert_eq!(page.state, RunState::Succeeded);
    assert_eq!(page.exit_code, Some(0));
    let output = text(&page);
    assert!(output.contains("status: ready"));
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(SECRET));
    assert!(fixture.disconnected.load(Ordering::SeqCst));
}

#[tokio::test]
async fn telnet_requires_target_opt_in_and_reports_authentication_failure_safely() {
    let fixture = server(Mode::Success).await;
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, false, 5, SECRET);
    let request: CreateApproval = serde_json::from_value(json!({
        "action_template_id":template,
        "expires_in_seconds":60,
        "authorization_mode":"once"
    }))
    .unwrap();
    assert!(matches!(
        state.catalog.create_approval(&request),
        Err(CatalogError::PolicyDenied)
    ));

    let fixture = server(Mode::RejectAuthentication).await;
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, true, 5, SECRET);
    let id = run(&state, approve(&state, template)).await;
    let page = wait(&state, id).await;
    assert_eq!(page.state, RunState::Failed);
    let output = text(&page);
    assert!(output.contains("authentication_failed"));
    assert!(!output.contains(SECRET));
}

#[tokio::test]
async fn telnet_timeout_and_cancel_close_the_transport() {
    let fixture = server(Mode::StallCommand).await;
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, true, 1, SECRET);
    let id = run(&state, approve(&state, template)).await;
    let page = wait(&state, id).await;
    assert_eq!(page.state, RunState::Failed);
    assert!(text(&page).contains("timed_out"));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.disconnected.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let fixture = server(Mode::StallCommand).await;
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, true, 20, SECRET);
    let id = run(&state, approve(&state, template)).await;
    fixture.command_seen.notified().await;
    let current = state.catalog.get_synthetic_run(id).unwrap();
    crate::cancel_run_for_state(
        &state,
        id,
        CancelSyntheticRun {
            expected_version: current.version,
        },
    )
    .await
    .unwrap();
    let page = wait(&state, id).await;
    assert_eq!(page.state, RunState::Cancelled);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.disconnected.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn telnet_rejects_passwords_that_could_inject_protocol_lines() {
    let fixture = server(Mode::RejectInjectedPassword).await;
    let (state, _) = AppState::new([]);
    let injected = "password\r\nshow hidden";
    let template = configure(&state, &fixture, true, 5, injected);
    let id = run(&state, approve(&state, template)).await;
    let page = wait(&state, id).await;
    assert_eq!(page.state, RunState::Failed);
    let output = text(&page);
    assert!(output.contains("invalid_input"));
    assert!(!output.contains(injected));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.disconnected.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
