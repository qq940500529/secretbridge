// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, fs, time::Duration};
use tokio::time;

use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ErrorData},
};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret};
use uuid::Uuid;

use super::{
    BridgeClient, BridgeResponse, LocalMcpBridge, OwnedTerminalRequest, SecretBridgeMcp,
    TerminalRequest,
};
use crate::{
    AppState,
    catalog::{
        ApprovalOperation, ApprovalResultScope, CreateActionTemplate, CreateTarget, DecideApproval,
        TargetEnvironment, TargetKind,
    },
};

const SENSITIVE_MARKER: &str = "sensitive-marker-must-not-cross-mcp-boundary";

#[test]
fn bridge_argument_errors_preserve_field_bounds_without_echoing_values() {
    let response = BridgeResponse::from_error(ErrorData::invalid_params(
        "command_argument_too_large",
        Some(json!({
            "field": "arguments[0]",
            "actual_bytes": 9000,
            "limit_bytes": 8192,
            "untrusted_value": SENSITIVE_MARKER,
        })),
    ));
    assert_eq!(
        response.error.as_deref(),
        Some("command_argument_too_large")
    );
    assert_eq!(
        response.error_data.as_ref().unwrap()["field"],
        "arguments[0]"
    );
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains(SENSITIVE_MARKER)
    );
}

#[tokio::test]
async fn bridge_validation_failure_records_only_a_safe_diagnostic_code() {
    let (state, _) = AppState::new([]);
    let token = "synthetic-bridge-token";
    let encoded = serde_json::to_vec(&json!({
        "schema_version": super::BRIDGE_CONNECTION_SCHEMA,
        "token": token,
        "operation": "request_command",
        "payload": {"untrusted_value": SENSITIVE_MARKER}
    }))
    .unwrap();
    let response =
        super::process_bridge_request(&state, super::token_digest(token), true, &encoded).await;
    assert_eq!(response.error.as_deref(), Some("invalid_request"));
    let failures = state.catalog.list_diagnostic_failures().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].code, "invalid_request");
    assert!(
        !serde_json::to_string(&failures)
            .unwrap()
            .contains(SENSITIVE_MARKER)
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one MCP scenario keeps catalog discovery, command drafting, and terminal validation contiguous"
)]
async fn dynamic_command_uses_catalog_metadata_and_requires_a_running_secure_terminal() {
    let (state, _) = AppState::new([]);
    let credential = state
        .catalog
        .create_credential_reference(
            &serde_json::from_value(json!({
                "name": "Dynamic MCP credential",
                "kind": "password",
                "purpose": "Synthetic MCP test",
                "address": "service.example.test",
                "username": "synthetic-user"
            }))
            .expect("credential request"),
        )
        .expect("create credential metadata");
    state
        .secret_store
        .set(credential.id, "synthetic-dynamic-secret")
        .expect("store synthetic secret");
    state
        .catalog
        .set_credential_secret_state(credential.id, credential.version, true)
        .expect("mark synthetic secret available");
    let target = state
        .catalog
        .create_target(&CreateTarget {
            name: "Dynamic MCP connection".to_owned(),
            kind: TargetKind::HttpService,
            environment: TargetEnvironment::Test,
            description: None,
            address: Some("service.example.test:22".to_owned()),
            username: Some("synthetic-user".to_owned()),
            allow_insecure_protocol: false,
            credential_reference_id: Some(credential.id),
            postgres: None,
        })
        .expect("create connection metadata");
    let terminal = state
        .terminals
        .create(&crate::terminal::CreateTerminal {
            rows: 24,
            cols: 100,
            shell: None,
            name: Some("MCP secure terminal".to_owned()),
            working_directory: None,
            environment: BTreeMap::new(),
        })
        .expect("create secure terminal");
    let (client, server_handle) = connect(state.clone()).await;

    let catalog = client
        .call_tool(CallToolRequestParams::new("secretbridge_list_catalog"))
        .await
        .expect("list safe catalog");
    let catalog = catalog.structured_content.expect("catalog content");
    assert_eq!(catalog["credentials"][0]["address"], "service.example.test");
    assert_eq!(catalog["connections"][0]["username"], "synthetic-user");

    let executable = std::env::current_exe()
        .expect("test executable")
        .to_string_lossy()
        .into_owned();
    let directory = std::env::current_dir()
        .expect("current directory")
        .to_string_lossy()
        .into_owned();
    let requested = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_request_command").with_arguments(arguments(
                json!({
                    "name": "Dynamic approved command",
                    "connection_id": target.id,
                    "terminal_id": terminal.id,
                    "program": executable.clone(),
                    "working_directory": directory.clone(),
                    "arguments": ["{{password}}"],
                    "credential_slots": [{
                        "name": "password",
                        "credential_id": credential.id,
                        "injection": "argument"
                    }],
                    "authorization_mode": "once",
                    "expires_in_seconds": 300,
                    "timeout_seconds": 30
                }),
            )),
        )
        .await
        .expect("request command without a user-created template");
    let approval = requested.structured_content.expect("approval content");
    assert_eq!(approval["state"], "pending");

    let missing_terminal = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_request_command").with_arguments(arguments(
                json!({
                    "name": "Missing terminal",
                    "connection_id": target.id,
                    "terminal_id": Uuid::new_v4(),
                    "program": executable,
                    "working_directory": directory,
                    "arguments": [],
                    "credential_slots": [],
                    "authorization_mode": "once",
                    "expires_in_seconds": 300,
                    "timeout_seconds": 30
                }),
            )),
        )
        .await;
    assert!(missing_terminal.is_err());

    client.cancel().await.expect("stop MCP client");
    server_handle.await.expect("join MCP server");
    state
        .terminals
        .remove(terminal.id)
        .expect("remove secure terminal");
}

async fn connect(
    state: AppState,
) -> (
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
) {
    connect_server(SecretBridgeMcp::new_local(state)).await
}

async fn connect_server(
    server: SecretBridgeMcp,
) -> (
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
) {
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
    let server_handle = tokio::spawn(async move {
        let backend = server.backend.clone();
        let actor = server.actor;
        server
            .serve(server_transport)
            .await
            .expect("MCP server starts")
            .waiting()
            .await
            .expect("MCP server stops cleanly");
        backend
            .terminal_request(OwnedTerminalRequest {
                actor,
                request: TerminalRequest::Release,
            })
            .await
            .expect("release MCP attachments");
    });
    let client = ().serve(client_transport).await.expect("MCP client starts");
    (client, server_handle)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "test call sites construct short-lived JSON values"
)]
fn arguments(value: Value) -> Map<String, Value> {
    value.as_object().expect("object arguments").clone()
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete public tool and schema allowlist is reviewed in one test"
)]
async fn advertises_only_the_bounded_tool_surface() {
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let (client, server_handle) = connect(state).await;
    let tools = client.list_all_tools().await.expect("list MCP tools");
    let actual = tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            "secretbridge_cancel_run",
            "secretbridge_confirm_approval",
            "secretbridge_create_run",
            "secretbridge_evaluate_policy",
            "secretbridge_get_approval",
            "secretbridge_get_run",
            "secretbridge_list_action_templates",
            "secretbridge_list_catalog",
            "secretbridge_list_run_events",
            "secretbridge_read_run_output",
            "secretbridge_request_approval",
            "secretbridge_request_command",
            "secretbridge_request_ssh",
            "secretbridge_terminal_attach",
            "secretbridge_terminal_capabilities",
            "secretbridge_terminal_close",
            "secretbridge_terminal_create",
            "secretbridge_terminal_detach",
            "secretbridge_terminal_interrupt",
            "secretbridge_terminal_list",
            "secretbridge_terminal_read",
            "secretbridge_terminal_resize",
            "secretbridge_terminal_write",
        ]
    );

    let expected_properties = BTreeMap::from([
        ("secretbridge_list_action_templates", vec![]),
        ("secretbridge_list_catalog", vec![]),
        (
            "secretbridge_confirm_approval",
            vec!["approval_id", "expected_version", "verification_code"],
        ),
        ("secretbridge_evaluate_policy", vec!["id"]),
        (
            "secretbridge_request_approval",
            vec![
                "action_template_id",
                "authorization_mode",
                "expires_in_seconds",
                "language",
                "parameters",
                "reason",
            ],
        ),
        (
            "secretbridge_request_command",
            vec![
                "arguments",
                "authorization_mode",
                "connection_id",
                "credential_slots",
                "expires_in_seconds",
                "language",
                "name",
                "program",
                "reason",
                "terminal_id",
                "timeout_seconds",
                "working_directory",
            ],
        ),
        (
            "secretbridge_request_ssh",
            vec![
                "arguments",
                "connection_id",
                "expires_in_seconds",
                "host_key_sha256",
                "language",
                "name",
                "port",
                "reason",
                "remote_program",
                "timeout_seconds",
            ],
        ),
        ("secretbridge_get_approval", vec!["id"]),
        (
            "secretbridge_create_run",
            vec!["approval_id", "idempotency_key"],
        ),
        ("secretbridge_get_run", vec!["id"]),
        (
            "secretbridge_cancel_run",
            vec!["expected_version", "run_id"],
        ),
        ("secretbridge_list_run_events", vec!["id"]),
        (
            "secretbridge_read_run_output",
            vec!["cursor", "id", "wait_ms"],
        ),
        ("secretbridge_terminal_attach", vec!["id", "request_input"]),
        ("secretbridge_terminal_capabilities", vec![]),
        ("secretbridge_terminal_close", vec!["id"]),
        (
            "secretbridge_terminal_create",
            vec![
                "cols",
                "environment",
                "name",
                "rows",
                "shell",
                "working_directory",
            ],
        ),
        ("secretbridge_terminal_detach", vec!["id"]),
        ("secretbridge_terminal_interrupt", vec!["id"]),
        ("secretbridge_terminal_list", vec![]),
        (
            "secretbridge_terminal_read",
            vec!["cursor", "id", "max_bytes", "wait_ms"],
        ),
        ("secretbridge_terminal_resize", vec!["cols", "id", "rows"]),
        ("secretbridge_terminal_write", vec!["data", "id"]),
    ]);
    for tool in &tools {
        let mut properties = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .map_or_else(Vec::new, |properties| {
                properties.keys().map(String::as_str).collect::<Vec<_>>()
            });
        properties.sort_unstable();
        assert_eq!(
            properties,
            expected_properties[tool.name.as_ref()],
            "unexpected input surface for {}",
            tool.name
        );
    }

    client.cancel().await.expect("stop MCP client");
    server_handle.await.expect("join MCP server");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "MCP TOTP approval binding, replay rejection and audit form one lifecycle"
)]
async fn user_supplied_totp_confirms_only_one_pending_approval() {
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let secret = TotpSecret::from(b"12345678901234567890".as_slice());
    let encoded = secret.to_base32();
    state
        .secret_store
        .set(crate::BROWSER_TOTP_CREDENTIAL_ID, &encoded)
        .expect("store synthetic TOTP secret");
    state
        .catalog
        .set_browser_auth_mode(crate::catalog::BrowserAuthMode::Totp)
        .expect("enable TOTP");
    let target = state
        .catalog
        .create_target(&CreateTarget {
            name: "TOTP approval target".to_owned(),
            kind: TargetKind::HttpService,
            environment: TargetEnvironment::Test,
            description: None,
            address: Some("https://example.test".to_owned()),
            username: None,
            allow_insecure_protocol: false,
            credential_reference_id: None,
            postgres: None,
        })
        .expect("create target");
    let template = state
        .catalog
        .create_action_template(&CreateActionTemplate {
            command: None,
            target_id: target.id,
            name: "TOTP approval action".to_owned(),
            operation: ApprovalOperation::InspectMetadata,
            result_scope: ApprovalResultScope::MetadataSummary,
            description: None,
            timeout_seconds: 15,
        })
        .expect("create template");
    let (client, server_handle) = connect(state.clone()).await;
    let request = || {
        CallToolRequestParams::new("secretbridge_request_approval").with_arguments(arguments(
            json!({"action_template_id":template.id,"expires_in_seconds":300}),
        ))
    };
    let first = client
        .call_tool(request())
        .await
        .expect("request first approval");
    let first = first.structured_content.expect("first approval");
    let totp = TotpBuilder::new()
        .with_secret(secret)
        .with_skew(0)
        .build()
        .expect("test TOTP");
    let code = totp.generate_current().to_string();
    let confirmed = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_confirm_approval").with_arguments(arguments(
                json!({
                    "approval_id": first["id"],
                    "expected_version": first["version"],
                    "verification_code": code
                }),
            )),
        )
        .await
        .expect("confirm first approval");
    assert_eq!(
        confirmed
            .structured_content
            .as_ref()
            .expect("confirmed approval")["state"],
        "approved"
    );
    assert!(
        !serde_json::to_string(&confirmed)
            .expect("serialize confirmation")
            .contains(&code)
    );

    let second = client
        .call_tool(request())
        .await
        .expect("request second approval")
        .structured_content
        .expect("second approval");
    let replay = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_confirm_approval").with_arguments(arguments(
                json!({
                    "approval_id": second["id"],
                    "expected_version": second["version"],
                    "verification_code": code
                }),
            )),
        )
        .await;
    assert!(replay.is_err(), "one TOTP step cannot approve twice");
    let events = state
        .catalog
        .list_browser_auth_events()
        .expect("MCP verification events");
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].approval_id,
        Some(second["id"].as_str().unwrap().parse().unwrap())
    );
    assert_eq!(
        events[1].approval_id,
        Some(first["id"].as_str().unwrap().parse().unwrap())
    );

    client.cancel().await.expect("stop MCP client");
    server_handle.await.expect("join MCP server");
}

#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "native MCP parameter, approval and output acceptance is one lifecycle"
)]
async fn native_mcp_reads_redacted_command_output_and_idempotent_runs() {
    let directory = std::env::temp_dir().join(format!(
        "sb-c-{}",
        &Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&directory).expect("create test directory");
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let (state, _) = AppState::new([]);
    let (_, credential) = crate::command::tests::configure(&state, "argument", 10);
    let template = state.catalog.list_action_templates().unwrap().remove(0);
    let mut config = crate::command::tests::fixture("argument", credential);
    config.arguments.push("{{param:company}}".into());
    config.parameters = serde_json::from_value(json!([{"name":"company","label":"公司","kind":"string","required":true,"default":"100","choices":["100","101"],"max_length":3}])).unwrap();
    let update = serde_json::from_value(json!({"target_id":template.target_id,"name":template.name,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":10,"enabled":true,"expected_version":template.version,"command":config})).unwrap();
    state
        .catalog
        .update_action_template(template.id, &update)
        .unwrap();
    let bridge = LocalMcpBridge::bind(&directory, state.clone()).unwrap();
    let stop = CancellationToken::new();
    let broker_stop = stop.clone();
    let broker = tokio::spawn(async move {
        bridge.serve(broker_stop).await.unwrap();
    });
    let (client, server) = connect_server(SecretBridgeMcp::new_remote(BridgeClient::from_file(
        directory.join("mcp-bridge.json"),
    )))
    .await;
    let templates = terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
    assert_eq!(
        templates["items"][0]["credential_slots"][0]["name"],
        "password"
    );
    assert!(
        templates["items"][0]["credential_slots"][0]
            .get("credential_id")
            .is_none()
    );
    let key = Uuid::new_v4().to_string();
    assert_eq!(templates["items"][0]["parameters"][0]["default"], "100");
    let approval = terminal_tool(&client,"secretbridge_request_approval",json!({"action_template_id":template.id,"expires_in_seconds":60,"authorization_mode":"time_window","parameters":{"company":"101"}})).await;
    assert_eq!(approval["state"], "pending");
    assert_eq!(approval["parameters"]["company"], "101");
    let approval = Uuid::parse_str(approval["id"].as_str().unwrap()).unwrap();
    let current = state.catalog.get_approval(approval).unwrap();
    state
        .catalog
        .approve_approval(
            approval,
            &DecideApproval {
                expected_version: current.version,
                note: None,
            },
        )
        .unwrap();
    let request = json!({"approval_id":approval.to_string(),"idempotency_key":key});
    let run = terminal_tool(&client, "secretbridge_create_run", request.clone()).await;
    assert_eq!(run["execution_mode"], "credential_command");
    let replay = terminal_tool(&client, "secretbridge_create_run", request).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(run["run"]["id"], replay["run"]["id"]);
    let mut cursor = 0;
    let mut output = String::new();
    time::timeout(Duration::from_secs(20), async {
        loop {
            let page = terminal_tool(
                &client,
                "secretbridge_read_run_output",
                json!({"id":run["run"]["id"],"cursor":cursor,"wait_ms":1000}),
            )
            .await;
            cursor = page["next_cursor"].as_u64().unwrap();
            for chunk in page["items"].as_array().unwrap() {
                output.push_str(chunk["text"].as_str().unwrap());
            }
            if page["state"] == "succeeded" && !page["has_more"].as_bool().unwrap() {
                assert_eq!(page["exit_code"], 0);
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(output.contains("[REDACTED]"));
    assert!(output.contains("|parameter:101|"));
    assert!(!output.contains("Synthetic-SB-command_A&z"));
    assert!(
        client
            .call_tool(
                CallToolRequestParams::new("secretbridge_read_run_output").with_arguments(
                    arguments(json!({"id":run["run"]["id"],"cursor":cursor,"wait_ms":5001}))
                )
            )
            .await
            .is_err()
    );
    client.cancel().await.unwrap();
    server.await.unwrap();
    stop.cancel();
    broker.await.unwrap();
    fs::remove_dir(&directory).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn native_mcp_executes_http_without_exposing_authentication() {
    let fixture = crate::http_task::tests::server().await;
    let directory = std::env::temp_dir().join(format!(
        "sb-h-{}",
        &Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let (state, _) = AppState::new([]);
    let template = crate::http_task::tests::configure(&state, &fixture.url, 5);
    let bridge = LocalMcpBridge::bind(&directory, state.clone()).unwrap();
    let stop = CancellationToken::new();
    let broker_stop = stop.clone();
    let broker = tokio::spawn(async move {
        bridge.serve(broker_stop).await.unwrap();
    });
    let (client, server) = connect_server(SecretBridgeMcp::new_remote(BridgeClient::from_file(
        directory.join("mcp-bridge.json"),
    )))
    .await;
    let templates = terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
    assert_eq!(templates["items"][0]["execution_kind"], "http");
    assert!(
        !templates
            .to_string()
            .contains(crate::http_task::tests::SECRET)
    );
    let approval = terminal_tool(
        &client,
        "secretbridge_request_approval",
        json!({"action_template_id":template,"expires_in_seconds":60}),
    )
    .await;
    assert_eq!(approval["state"], "pending");
    let id = Uuid::parse_str(approval["id"].as_str().unwrap()).unwrap();
    let current = state.catalog.get_approval(id).unwrap();
    state
        .catalog
        .approve_approval(
            id,
            &DecideApproval {
                expected_version: current.version,
                note: None,
            },
        )
        .unwrap();
    let request = json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()});
    let run = terminal_tool(&client, "secretbridge_create_run", request.clone()).await;
    let replay = terminal_tool(&client, "secretbridge_create_run", request).await;
    assert_eq!(replay["replayed"], true);
    let mut cursor = 0;
    let mut output = String::new();
    time::timeout(Duration::from_secs(15), async {
        loop {
            let page = terminal_tool(
                &client,
                "secretbridge_read_run_output",
                json!({"id":run["run"]["id"],"cursor":cursor,"wait_ms":1000}),
            )
            .await;
            cursor = page["next_cursor"].as_u64().unwrap();
            for chunk in page["items"].as_array().unwrap() {
                output.push_str(chunk["text"].as_str().unwrap());
            }
            if page["state"] == "succeeded" && !page["has_more"].as_bool().unwrap() {
                assert!(page["exit_code"].is_null());
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(crate::http_task::tests::SECRET));
    assert_eq!(fixture.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    client.cancel().await.unwrap();
    server.await.unwrap();
    stop.cancel();
    broker.await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn native_mcp_executes_ssh_and_reads_filtered_remote_output() {
    let fixture = crate::ssh_task::tests::server().await;
    let directory = std::env::temp_dir().join(format!(
        "sb-s-{}",
        &Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let (state, _) = AppState::new([]);
    let template = crate::ssh_task::tests::configure(&state, &fixture, 10);
    let bridge = LocalMcpBridge::bind(&directory, state.clone()).unwrap();
    let stop = CancellationToken::new();
    let broker_stop = stop.clone();
    let broker = tokio::spawn(async move {
        bridge.serve(broker_stop).await.unwrap();
    });
    let (client, server) = connect_server(SecretBridgeMcp::new_remote(BridgeClient::from_file(
        directory.join("mcp-bridge.json"),
    )))
    .await;
    let templates = terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
    assert_eq!(templates["items"][0]["execution_kind"], "ssh");
    assert!(
        !templates
            .to_string()
            .contains(crate::ssh_task::tests::SECRET)
    );
    let approval = terminal_tool(&client, "secretbridge_request_approval", json!({"action_template_id":template,"expires_in_seconds":60,"parameters":{"message":"100"}})).await;
    let id = Uuid::parse_str(approval["id"].as_str().unwrap()).unwrap();
    let current = state.catalog.get_approval(id).unwrap();
    state
        .catalog
        .approve_approval(
            id,
            &DecideApproval {
                expected_version: current.version,
                note: None,
            },
        )
        .unwrap();
    let request = json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()});
    let run = terminal_tool(&client, "secretbridge_create_run", request.clone()).await;
    assert_eq!(
        terminal_tool(&client, "secretbridge_create_run", request).await["replayed"],
        true
    );
    let mut cursor = 0;
    let mut output = String::new();
    time::timeout(Duration::from_secs(20), async {
        loop {
            let page = terminal_tool(
                &client,
                "secretbridge_read_run_output",
                json!({"id":run["run"]["id"],"cursor":cursor,"wait_ms":1000}),
            )
            .await;
            cursor = page["next_cursor"].as_u64().unwrap();
            for chunk in page["items"].as_array().unwrap() {
                output.push_str(chunk["text"].as_str().unwrap());
            }
            if page["state"] == "succeeded" && !page["has_more"].as_bool().unwrap() {
                assert_eq!(page["exit_code"], 0);
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(crate::ssh_task::tests::SECRET));
    assert_eq!(
        fixture.auth_hits.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.commands.lock().unwrap()[0],
        "'/usr/bin/printf' '%s' '100'"
    );
    client.cancel().await.unwrap();
    server.await.unwrap();
    stop.cancel();
    broker.await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn native_mcp_executes_sftp_and_git_through_the_shared_broker() {
    use crate::{
        git_task::{Operation, integration_tests as git},
        sftp_task::{Direction, tests::LocalDirectory},
    };
    let ssh = crate::ssh_task::tests::server().await;
    let git = git::server().await;
    let files = LocalDirectory::new();
    let source = files.0.join("source.bin");
    fs::write(&source, b"MCP transfer contents").unwrap();
    for kind in ["sftp", "git"] {
        let directory = std::env::temp_dir().join(format!(
            "sb-c-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        ));
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let (state, _) = AppState::new([]);
        let template = if kind == "sftp" {
            crate::sftp_task::tests::configure(&state, &ssh, &source, Direction::Upload, false, 10)
        } else {
            git::configure(&state, &git, Operation::Inspect, &git.url, 10)
        };
        let bridge = LocalMcpBridge::bind(&directory, state.clone()).unwrap();
        let stop = CancellationToken::new();
        let broker_stop = stop.clone();
        let broker = tokio::spawn(async move {
            bridge.serve(broker_stop).await.unwrap();
        });
        let (client, server) = connect_server(SecretBridgeMcp::new_remote(
            BridgeClient::from_file(directory.join("mcp-bridge.json")),
        ))
        .await;
        let templates =
            terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
        assert_eq!(templates["items"][0]["execution_kind"], kind);
        let approval = terminal_tool(
            &client,
            "secretbridge_request_approval",
            json!({"action_template_id":template,"expires_in_seconds":60}),
        )
        .await;
        let id = Uuid::parse_str(approval["id"].as_str().unwrap()).unwrap();
        let current = state.catalog.get_approval(id).unwrap();
        state
            .catalog
            .approve_approval(
                id,
                &DecideApproval {
                    expected_version: current.version,
                    note: None,
                },
            )
            .unwrap();
        let request = json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()});
        let run = terminal_tool(&client, "secretbridge_create_run", request.clone()).await;
        assert_eq!(
            terminal_tool(&client, "secretbridge_create_run", request).await["replayed"],
            true
        );
        let id = Uuid::parse_str(run["run"]["id"].as_str().unwrap()).unwrap();
        assert_eq!(
            crate::ssh_task::tests::wait(&state, id).await.state,
            crate::catalog::RunState::Succeeded
        );
        let page = terminal_tool(
            &client,
            "secretbridge_read_run_output",
            json!({"id":id,"cursor":0,"wait_ms":0}),
        )
        .await;
        assert_eq!(page["state"], "succeeded");
        assert_eq!(page["exit_code"], 0);
        assert!(!page.to_string().contains(crate::ssh_task::tests::SECRET));
        assert!(!page.to_string().contains(git::TOKEN));
        if kind == "sftp" {
            assert_eq!(
                ssh.files.lock().unwrap()["/fixture.bin"],
                b"MCP transfer contents"
            );
        } else {
            assert_eq!(git.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
        client.cancel().await.unwrap();
        server.await.unwrap();
        stop.cancel();
        broker.await.unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires both explicitly provisioned local database fixtures"]
async fn native_mcp_executes_real_databases_without_exposing_authentication() {
    use crate::database_task::{DatabaseEngine, tests as db};
    for engine in [DatabaseEngine::Postgres, DatabaseEngine::Mysql] {
        let directory = std::env::temp_dir().join(format!(
            "sb-d-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        ));
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let (state, _) = AppState::new([]);
        let template = db::configured(
            &state,
            &mut db::config(engine, db::port(engine), Uuid::nil()),
            10,
        );
        let bridge = LocalMcpBridge::bind(&directory, state.clone()).unwrap();
        let stop = CancellationToken::new();
        let broker_stop = stop.clone();
        let broker = tokio::spawn(async move {
            bridge.serve(broker_stop).await.unwrap();
        });
        let (client, server) = connect_server(SecretBridgeMcp::new_remote(
            BridgeClient::from_file(directory.join("mcp-bridge.json")),
        ))
        .await;
        let templates =
            terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
        assert_eq!(templates["items"][0]["execution_kind"], "database");
        assert!(!templates.to_string().contains("127.0.0.1"));
        let approval = terminal_tool(&client, "secretbridge_request_approval", json!({"action_template_id":template,"expires_in_seconds":60,"parameters":{"company":db::PASSWORD}})).await;
        let id = Uuid::parse_str(approval["id"].as_str().unwrap()).unwrap();
        let current = state.catalog.get_approval(id).unwrap();
        state
            .catalog
            .approve_approval(
                id,
                &DecideApproval {
                    expected_version: current.version,
                    note: None,
                },
            )
            .unwrap();
        let request = json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()});
        let run = terminal_tool(&client, "secretbridge_create_run", request.clone()).await;
        assert_eq!(
            terminal_tool(&client, "secretbridge_create_run", request).await["replayed"],
            true
        );
        let id = Uuid::parse_str(run["run"]["id"].as_str().unwrap()).unwrap();
        assert_eq!(db::wait(&state, id).await["rows"][0][0], "[REDACTED]");
        let page = terminal_tool(
            &client,
            "secretbridge_read_run_output",
            json!({"id":id,"cursor":0,"wait_ms":0}),
        )
        .await;
        assert!(page.to_string().contains("[REDACTED]"));
        assert!(!page.to_string().contains(db::PASSWORD));
        assert!(page["exit_code"].is_null());
        client.cancel().await.unwrap();
        server.await.unwrap();
        stop.cancel();
        broker.await.unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}

async fn terminal_tool(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    params: Value,
) -> Value {
    let result = client
        .call_tool(CallToolRequestParams::new(name).with_arguments(arguments(params)))
        .await
        .expect("terminal tool succeeds");
    result
        .structured_content
        .expect("structured terminal result")
}

#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "end-to-end native IPC and MCP lifecycle acceptance"
)]
async fn native_mcp_controls_real_terminal_without_reexecuting_on_reconnect() {
    let identifier = Uuid::new_v4().simple().to_string();
    let directory = std::env::temp_dir().join(format!("sb-t-{}", &identifier[..8]));
    fs::create_dir(&directory).expect("create test directory");
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("private directory");
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let bridge = LocalMcpBridge::bind(&directory, state.clone()).expect("bind bridge");
    let cancellation = CancellationToken::new();
    let broker_stop = cancellation.clone();
    let broker = tokio::spawn(async move {
        bridge.serve(broker_stop).await.expect("serve bridge");
    });
    let bridge_client = BridgeClient::from_file(directory.join("mcp-bridge.json"));
    let (client, server) = connect_server(SecretBridgeMcp::new_remote(bridge_client.clone())).await;
    let (other, other_server) = connect_server(SecretBridgeMcp::new_remote(bridge_client)).await;
    let capabilities =
        terminal_tool(&client, "secretbridge_terminal_capabilities", json!({})).await;
    assert!(
        !capabilities["shells"]
            .as_array()
            .expect("shells")
            .is_empty()
    );
    let created = terminal_tool(
        &client,
        "secretbridge_terminal_create",
        json!({"rows":24,"cols":80,"name":"AI acceptance"}),
    )
    .await;
    let id = created["terminal"]["id"].as_str().expect("terminal id");
    let first = terminal_tool(
        &client,
        "secretbridge_terminal_attach",
        json!({"id":id,"request_input":true}),
    )
    .await;
    assert_eq!(first["input_granted"], true);
    let mut cursor = first["oldest_cursor"].as_u64().expect("cursor");
    assert!(
        other
            .call_tool(
                CallToolRequestParams::new("secretbridge_terminal_read")
                    .with_arguments(arguments(json!({"id":id,"cursor":0})))
            )
            .await
            .is_err()
    );
    let observer = terminal_tool(
        &other,
        "secretbridge_terminal_attach",
        json!({"id":id,"request_input":true}),
    )
    .await;
    assert_eq!(observer["input_granted"], false);
    assert!(
        other
            .call_tool(
                CallToolRequestParams::new("secretbridge_terminal_write")
                    .with_arguments(arguments(json!({"id":id,"data":"echo forbidden\r"})))
            )
            .await
            .is_err()
    );
    terminal_tool(
        &client,
        "secretbridge_terminal_resize",
        json!({"id":id,"rows":30,"cols":100}),
    )
    .await;
    let command = if cfg!(windows) {
        "$sbAcceptance = 'ai-' + 'terminal-ready'; Write-Output $sbAcceptance\r"
    } else {
        "sb_acceptance=ai-; sb_acceptance=${sb_acceptance}terminal-ready; printf '%s\\n' \"$sb_acceptance\"\n"
    };
    terminal_tool(
        &client,
        "secretbridge_terminal_write",
        json!({"id":id,"data":command}),
    )
    .await;
    let mut output = Vec::new();
    for _ in 0..40 {
        let read = terminal_tool(
            &client,
            "secretbridge_terminal_read",
            json!({"id":id,"cursor":cursor,"wait_ms":1000,"max_bytes":1024}),
        )
        .await;
        assert_eq!(read["cursor"], cursor);
        let bytes = read["bytes"]
            .as_array()
            .expect("output bytes")
            .iter()
            .map(|byte| u8::try_from(byte.as_u64().expect("byte")).expect("u8"))
            .collect::<Vec<_>>();
        cursor = read["next_cursor"].as_u64().expect("next cursor");
        output.extend(bytes);
        if output.ends_with(b"\x1b[6n") {
            terminal_tool(
                &client,
                "secretbridge_terminal_write",
                json!({"id":id,"data":"\u{1b}[1;1R"}),
            )
            .await;
        }
        if output
            .windows(b"ai-terminal-ready".len())
            .any(|bytes| bytes == b"ai-terminal-ready")
        {
            break;
        }
    }
    assert!(
        output
            .windows(b"ai-terminal-ready".len())
            .any(|bytes| bytes == b"ai-terminal-ready"),
        "command really executed"
    );
    client.cancel().await.expect("disconnect first MCP session");
    server.await.expect("release first input lease");
    let attached = terminal_tool(
        &other,
        "secretbridge_terminal_attach",
        json!({"id":id,"request_input":true}),
    )
    .await;
    assert_eq!(attached["input_granted"], true);
    let persisted = if cfg!(windows) {
        "Write-Output ($sbAcceptance + '-persisted')\r"
    } else {
        "printf '%s%s\\n' \"$sb_acceptance\" -persisted\n"
    };
    terminal_tool(
        &other,
        "secretbridge_terminal_write",
        json!({"id":id,"data":persisted}),
    )
    .await;
    let mut continued = String::new();
    for _ in 0..20 {
        let read = terminal_tool(
            &other,
            "secretbridge_terminal_read",
            json!({"id":id,"cursor":cursor,"wait_ms":1000}),
        )
        .await;
        assert_eq!(read["cursor"], cursor);
        cursor = read["next_cursor"].as_u64().expect("next cursor");
        continued.push_str(read["text"].as_str().expect("preview"));
        if continued.contains("ai-terminal-ready-persisted") {
            break;
        }
    }
    assert!(
        continued.contains("ai-terminal-ready-persisted"),
        "same shell state survived MCP disconnect"
    );
    assert!(
        other
            .call_tool(
                CallToolRequestParams::new("secretbridge_terminal_read")
                    .with_arguments(arguments(json!({"id":id,"cursor":cursor,"wait_ms":5001})))
            )
            .await
            .is_err()
    );
    assert!(
        other
            .call_tool(
                CallToolRequestParams::new("secretbridge_terminal_write")
                    .with_arguments(arguments(json!({"id":id,"data":"x".repeat(4097)})))
            )
            .await
            .is_err()
    );
    terminal_tool(&other, "secretbridge_terminal_interrupt", json!({"id":id})).await;
    terminal_tool(
        &other,
        "secretbridge_terminal_write",
        json!({"id":id,"data":if cfg!(windows) { "exit 7\r" } else { "exit 7\n" }}),
    )
    .await;
    let mut exited = false;
    for _ in 0..40 {
        let read = terminal_tool(
            &other,
            "secretbridge_terminal_read",
            json!({"id":id,"cursor":cursor,"wait_ms":500}),
        )
        .await;
        cursor = read["next_cursor"].as_u64().expect("cursor");
        if read["terminal"]["status"] == "exited" {
            assert_eq!(read["terminal"]["exit_code"], 7);
            exited = true;
            break;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
    assert!(exited, "natural shell exit recorded");
    terminal_tool(&other, "secretbridge_terminal_detach", json!({"id":id})).await;
    terminal_tool(
        &other,
        "secretbridge_terminal_attach",
        json!({"id":id,"request_input":true}),
    )
    .await;
    terminal_tool(&other, "secretbridge_terminal_close", json!({"id":id})).await;
    assert!(state.terminals.list().is_empty());
    other.cancel().await.expect("stop other client");
    other_server.await.expect("stop other server");
    cancellation.cancel();
    broker.await.expect("stop broker");
    fs::remove_dir(&directory).expect("remove empty test directory");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one native IPC lifecycle scenario keeps authentication, validation and restart behavior contiguous"
)]
async fn detached_stdio_bridge_authenticates_reloads_and_does_not_own_broker_lifecycle() {
    let identifier = Uuid::new_v4().simple().to_string();
    let directory = std::env::temp_dir().join(format!("sb-m-{}", &identifier[..8]));
    fs::create_dir(&directory).expect("create bridge test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("restrict bridge test directory");
    }
    let connection_file = directory.join("mcp-bridge.json");
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let bridge = LocalMcpBridge::bind(&directory, state).expect("bind native bridge");
    let (second_state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    assert!(
        LocalMcpBridge::bind(&directory, second_state).is_err(),
        "one data directory must not publish two active bridges"
    );
    let cancellation = CancellationToken::new();
    let broker_cancellation = cancellation.clone();
    let broker = tokio::spawn(async move {
        bridge
            .serve(broker_cancellation)
            .await
            .expect("native bridge serves");
    });

    let bridge_client = BridgeClient::from_file(connection_file.clone());
    bridge_client.health().await.expect("authenticated health");

    let original_document = fs::read(&connection_file).expect("read connection document");
    let mut invalid_document =
        serde_json::from_slice::<Value>(&original_document).expect("parse connection document");
    invalid_document["token"] = Value::String(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
    );
    fs::write(
        &connection_file,
        serde_json::to_vec(&invalid_document).expect("serialize invalid connection document"),
    )
    .expect("write invalid connection document");
    assert!(bridge_client.health().await.is_err());

    invalid_document =
        serde_json::from_slice::<Value>(&original_document).expect("parse connection document");
    invalid_document["schema_version"] = Value::from(1);
    fs::write(
        &connection_file,
        serde_json::to_vec(&invalid_document).expect("serialize old connection schema"),
    )
    .expect("write old connection schema");
    assert!(bridge_client.health().await.is_err());

    invalid_document =
        serde_json::from_slice::<Value>(&original_document).expect("parse connection document");
    invalid_document["unexpected"] = Value::Bool(true);
    fs::write(
        &connection_file,
        serde_json::to_vec(&invalid_document).expect("serialize document with unknown field"),
    )
    .expect("write document with unknown field");
    assert!(bridge_client.health().await.is_err());

    invalid_document =
        serde_json::from_slice::<Value>(&original_document).expect("parse connection document");
    #[cfg(windows)]
    {
        invalid_document["endpoint"]["name"] =
            Value::String(r"\\.\pipe\not-secretbridge".to_owned());
    }
    #[cfg(unix)]
    {
        invalid_document["endpoint"]["path"] =
            Value::String(directory.join("outside-pattern.sock").display().to_string());
    }
    fs::write(
        &connection_file,
        serde_json::to_vec(&invalid_document).expect("serialize invalid endpoint"),
    )
    .expect("write invalid endpoint");
    assert!(bridge_client.health().await.is_err());

    fs::write(&connection_file, &original_document).expect("restore connection document");
    bridge_client
        .health()
        .await
        .expect("restored token authenticates");

    let (mcp_client, mcp_server) =
        connect_server(SecretBridgeMcp::new_remote(bridge_client.clone())).await;
    let result = mcp_client
        .call_tool(CallToolRequestParams::new(
            "secretbridge_list_action_templates",
        ))
        .await
        .expect("remote MCP tool call");
    assert_eq!(
        result
            .structured_content
            .as_ref()
            .and_then(|value| value["items"].as_array())
            .map(Vec::len),
        Some(0)
    );
    mcp_client.cancel().await.expect("disconnect MCP client");
    mcp_server.await.expect("join detached MCP bridge");

    bridge_client
        .health()
        .await
        .expect("broker survives MCP disconnect");
    cancellation.cancel();
    broker.await.expect("join native bridge");
    assert!(!connection_file.exists());

    let (replacement_state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let replacement_bridge =
        LocalMcpBridge::bind(&directory, replacement_state).expect("bind replacement bridge");
    let replacement_cancellation = CancellationToken::new();
    let replacement_server_cancellation = replacement_cancellation.clone();
    let replacement_broker = tokio::spawn(async move {
        replacement_bridge
            .serve(replacement_server_cancellation)
            .await
            .expect("replacement bridge serves");
    });
    bridge_client
        .health()
        .await
        .expect("bridge reloads replacement broker connection");
    replacement_cancellation.cancel();
    replacement_broker.await.expect("join replacement bridge");
    fs::remove_dir(directory).expect("remove bridge test directory");
}

#[tokio::test]
async fn native_bridge_reclaims_a_well_formed_stale_connection_document() {
    let identifier = Uuid::new_v4().simple().to_string();
    let directory = std::env::temp_dir().join(format!("sb-s-{}", &identifier[..8]));
    fs::create_dir(&directory).expect("create stale bridge test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("restrict stale bridge test directory");
    }
    let connection_file = directory.join("mcp-bridge.json");
    #[cfg(windows)]
    let endpoint = json!({
        "kind": "windows_named_pipe",
        "name": r"\\.\pipe\secretbridge-00000000000000000000000000000000"
    });
    #[cfg(unix)]
    let endpoint = {
        let socket_path = directory.join("sb-0000000000000000");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind stale socket");
        drop(listener);
        json!({"kind": "unix_socket", "path": socket_path})
    };
    fs::write(
        &connection_file,
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "instance_id": Uuid::nil(),
            "endpoint": endpoint,
            "token": "0000000000000000000000000000000000000000000000000000000000000000"
        }))
        .expect("serialize stale connection document"),
    )
    .expect("write stale connection document");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&connection_file, fs::Permissions::from_mode(0o600))
            .expect("restrict stale connection document");
    }

    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let bridge = LocalMcpBridge::bind(&directory, state).expect("replace stale bridge");
    drop(bridge);
    assert!(!connection_file.exists());
    fs::remove_dir(directory).expect("remove stale bridge test directory");
}

#[cfg(unix)]
#[test]
fn native_bridge_rejects_broad_and_symlinked_data_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = std::env::temp_dir().join(format!(
        "secretbridge-bridge-directory-test-{}",
        Uuid::new_v4()
    ));
    let broad = root.join("broad");
    let private = root.join("private");
    let linked = root.join("linked");
    fs::create_dir_all(&broad).expect("create broad directory");
    fs::set_permissions(&broad, fs::Permissions::from_mode(0o755)).expect("set broad permissions");
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    assert!(LocalMcpBridge::bind(&broad, state).is_err());

    fs::create_dir(&private).expect("create private directory");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
        .expect("set private permissions");
    symlink(&private, &linked).expect("create directory symlink");
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    assert!(LocalMcpBridge::bind(&linked, state).is_err());

    fs::remove_file(linked).expect("remove directory symlink");
    fs::remove_dir(private).expect("remove private directory");
    fs::remove_dir(broad).expect("remove broad directory");
    fs::remove_dir(root).expect("remove test root");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one protocol-level scenario keeps the approval boundary and run lifecycle contiguous"
)]
async fn approval_and_run_flow_requires_web_decision_and_returns_only_safe_data() {
    let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
    let target = state
        .catalog
        .create_target(&CreateTarget {
            name: "MCP test target".to_owned(),
            kind: TargetKind::HttpService,
            environment: TargetEnvironment::Test,
            description: Some(SENSITIVE_MARKER.to_owned()),
            address: Some("https://example.test".to_owned()),
            username: Some("synthetic-user".to_owned()),
            allow_insecure_protocol: false,
            credential_reference_id: None,
            postgres: None,
        })
        .expect("create target");
    let template = state
        .catalog
        .create_action_template(&CreateActionTemplate {
            command: None,
            target_id: target.id,
            name: "Inspect bounded metadata".to_owned(),
            operation: ApprovalOperation::InspectMetadata,
            result_scope: ApprovalResultScope::MetadataSummary,
            description: Some(SENSITIVE_MARKER.to_owned()),
            timeout_seconds: 15,
        })
        .expect("create template");
    let (client, server_handle) = connect(state.clone()).await;

    let templates = client
        .call_tool(CallToolRequestParams::new(
            "secretbridge_list_action_templates",
        ))
        .await
        .expect("list templates");
    assert!(
        !serde_json::to_string(&templates)
            .expect("serialize result")
            .contains(SENSITIVE_MARKER)
    );

    let approval_result = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_request_approval").with_arguments(arguments(
                json!({
                    "action_template_id": template.id,
                    "expires_in_seconds": 300
                }),
            )),
        )
        .await
        .expect("request approval");
    let approval = approval_result
        .structured_content
        .as_ref()
        .expect("structured approval");
    assert_eq!(approval["state"], "pending");
    assert!(
        !serde_json::to_string(&approval_result)
            .expect("serialize result")
            .contains(SENSITIVE_MARKER)
    );
    let approval_id = approval["id"].as_str().expect("approval id");
    let pending_status = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_get_approval")
                .with_arguments(arguments(json!({ "id": approval_id }))),
        )
        .await
        .expect("get pending approval");
    assert_eq!(
        pending_status
            .structured_content
            .as_ref()
            .expect("structured approval status")["state"],
        "pending"
    );

    let pending_run = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_create_run").with_arguments(arguments(
                json!({
                    "approval_id": approval_id,
                    "idempotency_key": "mcp-pending-denied"
                }),
            )),
        )
        .await;
    assert!(
        pending_run.is_err(),
        "MCP cannot approve its own request without user verification"
    );

    let approval_uuid = uuid::Uuid::parse_str(approval_id).expect("approval UUID");
    let current = state
        .catalog
        .list_approvals()
        .expect("list approvals")
        .into_iter()
        .find(|item| item.id == approval_uuid)
        .expect("requested approval");
    state
        .catalog
        .approve_approval(
            approval_uuid,
            &DecideApproval {
                expected_version: current.version,
                note: Some("Approved in trusted Web UI simulation".to_owned()),
            },
        )
        .expect("trusted approval decision");
    let approved_status = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_get_approval")
                .with_arguments(arguments(json!({ "id": approval_id }))),
        )
        .await
        .expect("get approved approval");
    assert_eq!(
        approved_status
            .structured_content
            .as_ref()
            .expect("structured approval status")["state"],
        "approved"
    );

    let created = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_create_run").with_arguments(arguments(
                json!({
                    "approval_id": approval_id,
                    "idempotency_key": "mcp-approved-run"
                }),
            )),
        )
        .await
        .expect("create approved run");
    let created_json = created.structured_content.as_ref().expect("structured run");
    let run_id = created_json["run"]["id"].as_str().expect("run id");

    let mut run = Value::Null;
    for _ in 0..50 {
        let result = client
            .call_tool(
                CallToolRequestParams::new("secretbridge_get_run")
                    .with_arguments(arguments(json!({ "id": run_id }))),
            )
            .await
            .expect("get run");
        run = result.structured_content.expect("structured run status");
        if run["state"] == "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(run["state"], "running");
    let cancelled = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_cancel_run").with_arguments(arguments(
                json!({
                    "run_id": run_id,
                    "expected_version": run["version"]
                }),
            )),
        )
        .await
        .expect("cancel run");
    assert_eq!(
        cancelled
            .structured_content
            .as_ref()
            .expect("structured cancelled run")["state"],
        "cancelled"
    );

    let events = client
        .call_tool(
            CallToolRequestParams::new("secretbridge_list_run_events")
                .with_arguments(arguments(json!({ "id": run_id }))),
        )
        .await
        .expect("list safe events");
    let events_json = events
        .structured_content
        .as_ref()
        .expect("structured events");
    assert_eq!(events_json["payload_policy"], "fixed_safe_messages_only");
    assert_eq!(
        events_json["items"].as_array().expect("event list").len(),
        3
    );
    assert!(
        !serde_json::to_string(&events)
            .expect("serialize result")
            .contains(SENSITIVE_MARKER)
    );

    client.cancel().await.expect("stop MCP client");
    server_handle.await.expect("join MCP server");
}
