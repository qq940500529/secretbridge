// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    error::Error,
    fs,
    io::{self, Write as _},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rmcp::{
    ErrorData, Json as McpJson, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Semaphore,
    task, time,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

mod bridge_response;
mod conversation;
mod errors;
mod ready;
use bridge_response::safe_bridge_error_code;
use conversation::{BeginConversationParams, resolve_conversation_id};
use errors::{catalog_error, parse_uuid, remote_error};
use ready::ensure_bridge_ready;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::terminal::{CreateTerminal, TerminalRead, TerminalShellCapability, TerminalSummary};
use crate::terminal_control::{
    AttachParams, OwnedTerminalRequest, ReadParams, ResizeParams, TerminalIdParams,
    TerminalRequest, WriteParams,
};
use crate::{
    AppState, cancel_run_for_state,
    catalog::{
        ActionTemplate, AiConversation, Approval, ApprovalOperation, ApprovalResultScope,
        ApprovalState, BrowserAuthChannel, CancelSyntheticRun, CatalogError, CreateApproval,
        CreateSyntheticRun, DecideApproval, PolicyDecision, PolicyEvaluation, PolicyReasonCode,
        PolicyRequirement, RunState, SafeEvent, SafeEventKind, SyntheticRun,
    },
    constant_time_equal, create_run_for_state, run_execution_mode, token_digest,
};

const SERVER_INSTRUCTIONS: &str = r"SecretBridge controlled operations / SecretBridge 安全操作
Use only these MCP tools. The local Web console is for the human; never inspect or automate it. Start each AI chat with secretbridge_begin_conversation using a short non-secret summary, then pass its conversation_id to every request in that chat. Only the human can set conversation approval policy in Web. A prior policy may preapprove a request; disclose its scope and risk before creating a run.
Discover with secretbridge_terminal_capabilities and secretbridge_list_catalog. The catalog returns credentials and connections as non-secret metadata. Prefer a structured connection operation where supported, a one-time request for a changing command, and a saved template only when the user explicitly wants reuse. With no template, use secretbridge_request_command for a controlled local command or secretbridge_request_ssh for a structured SSH operation; do not create helper scripts to handle credentials. A command argument or file credential slot uses one whole argv item in the form {{secret:slot_name}}; other double-brace text is literal.
Response paths: terminal creation returns terminal.id (not a top-level id); approval requests return id, state, version, next_actions and possibly console_url; run creation returns run.id and run.state; read_run_output returns items and next_cursor. Check advertised output schemas. For a pending approval, show its exact ID, target, program/parameters, opaque credential references, expiry and risk. Invite the human to approve in the local Web console, or accept only a current six-digit TOTP code the human voluntarily provides for that exact ID and version. Never ask for a PIN, passphrase, setup key, QR code or credential; never retain, repeat, log or reuse a TOTP code. Use secretbridge_confirm_approval only for that pending request.
Create a run only after approval; read sanitized output with the returned cursor. Inspect next_actions and stable error codes for recovery. Terminal input and output remain broker-mediated. Replace a timed-out or context-unknown terminal; do not blindly retry writes or use a shell to bypass approval.
中文：每段 AI 对话先登记不含秘密的摘要，并把会话 ID 传入后续申请。会话审批策略只由人在本机网页设置；先前策略可能使申请直接获批，执行前应说明范围与风险。先发现终端能力和非秘密目录；有结构化连接器时优先使用，一次性变化命令使用动态申请，只有用户明确要求复用时才保存模板。命令参数或文件凭据槽位须以完整参数 {{secret:slot_name}} 引用，其他双花括号文本按字面量传递。创建终端的 ID 位于 terminal.id；审批的 id、state、version、next_actions 表明下一步；创建运行后读取 run.id，再用输出的 next_cursor 继续读取。待审批时请用户在本机网页处理，或仅转交用户主动提供给该审批的当前六位 TOTP；不得索要或保存 PIN、凭据或 TOTP 密钥，也不得自动化网页。";

#[derive(Clone)]
struct SecretBridgeMcp {
    backend: McpBackend,
    tool_router: ToolRouter<Self>,
    actor: Uuid,
}

// These shapes describe the JSON emitted by TerminalControl. Keep them explicit:
// generic serde_json::Value otherwise advertises an unhelpful unconstrained output.
#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalCapabilitiesOutput {
    platform: String,
    default_shell: Option<crate::terminal::TerminalShell>,
    shells: Vec<TerminalShellCapability>,
    max_sessions: usize,
    max_environment_variables: usize,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalListOutput {
    items: Vec<TerminalSummary>,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalCreateOutput {
    terminal: TerminalSummary,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalAttachOutput {
    terminal: TerminalSummary,
    input_granted: bool,
    oldest_cursor: u64,
    next_cursor: u64,
    idle_timeout_seconds: u64,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalWriteOutput {
    terminal: TerminalSummary,
    input_written: bool,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalResizeOutput {
    terminal: TerminalSummary,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalInterruptOutput {
    terminal: TerminalSummary,
    interrupt_sent: bool,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalDetachOutput {
    #[schemars(with = "String")]
    id: Uuid,
    detached: bool,
}

#[allow(dead_code, reason = "schema-only MCP terminal output contracts")]
#[derive(JsonSchema)]
struct TerminalCloseOutput {
    #[schemars(with = "String")]
    id: Uuid,
    closed: bool,
}

impl SecretBridgeMcp {
    #[cfg(test)]
    fn new_local(state: AppState) -> Self {
        Self {
            backend: McpBackend::Local(state),
            tool_router: Self::tool_router(),
            actor: Uuid::new_v4(),
        }
    }

    fn new_remote(client: BridgeClient) -> Self {
        Self {
            backend: McpBackend::Remote(client),
            tool_router: Self::tool_router(),
            actor: Uuid::new_v4(),
        }
    }

    async fn terminal(
        &self,
        request: TerminalRequest,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        Ok(McpJson(
            self.backend
                .terminal_request(OwnedTerminalRequest {
                    actor: self.actor,
                    request,
                })
                .await?,
        ))
    }
}

#[derive(Clone)]
enum McpBackend {
    Local(AppState),
    Remote(BridgeClient),
}

impl McpBackend {
    async fn begin_conversation(
        &self,
        params: BeginConversationParams,
    ) -> Result<AiConversation, ErrorData> {
        match self {
            Self::Local(state) => {
                let catalog = state.catalog.clone();
                catalog_task(move || catalog.create_ai_conversation(&params.summary)).await
            }
            Self::Remote(client) => client.call(OP_BEGIN_CONVERSATION, &params).await,
        }
    }

    async fn terminal_request(
        &self,
        request: OwnedTerminalRequest,
    ) -> Result<serde_json::Value, ErrorData> {
        match self {
            Self::Local(state) => {
                state
                    .terminal_controls
                    .execute(&state.terminals, request)
                    .await
            }
            Self::Remote(client) => client.call(OP_TERMINAL, &request).await,
        }
    }
    async fn list_action_templates(&self) -> Result<TemplateList, ErrorData> {
        match self {
            Self::Local(state) => {
                let catalog = state.catalog.clone();
                let items = catalog_task(move || catalog.list_action_templates()).await?;
                Ok(TemplateList {
                    items: items.into_iter().map(TemplateSummary::from).collect(),
                })
            }
            Self::Remote(client) => client.call(OP_LIST_TEMPLATES, &BridgeEmpty {}).await,
        }
    }

    async fn list_catalog(&self) -> Result<CatalogSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let catalog = state.catalog.clone();
                catalog_task(move || {
                    Ok(CatalogSummary {
                        credentials: catalog
                            .list_credential_references()?
                            .into_iter()
                            .map(CredentialSummary::from)
                            .collect(),
                        connections: catalog
                            .list_targets()?
                            .into_iter()
                            .map(ConnectionSummary::from)
                            .collect(),
                    })
                })
                .await
            }
            Self::Remote(client) => client.call(OP_LIST_CATALOG, &BridgeEmpty {}).await,
        }
    }

    async fn evaluate_policy(&self, params: IdentifierParams) -> Result<PolicySummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let id = parse_uuid(&params.id)?;
                let catalog = state.catalog.clone();
                let evaluation = catalog_task(move || catalog.evaluate_action_template(id)).await?;
                Ok(PolicySummary::from(evaluation))
            }
            Self::Remote(client) => client.call(OP_EVALUATE_POLICY, &params).await,
        }
    }

    async fn request_approval(
        &self,
        params: RequestApprovalParams,
    ) -> Result<ApprovalSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let catalog = state.catalog.clone();
                let conversation_id =
                    resolve_conversation_id(catalog.clone(), params.conversation_id.as_deref())
                        .await?;
                let request = CreateApproval {
                    parameters: params.parameters,
                    authorization_mode: params.authorization_mode,
                    action_template_id: parse_uuid(&params.action_template_id)?,
                    conversation_id: Some(conversation_id),
                    reason: Some(
                        params
                            .reason
                            .unwrap_or_else(|| params.language.default_reason("template")),
                    ),
                    expires_in_seconds: params.expires_in_seconds,
                };
                let approval = catalog_task(move || catalog.create_approval(&request)).await?;
                crate::approval_notifications::notify_pending_approval(state, &approval);
                let _ = state.changes.send(());
                if approval.state == ApprovalState::Pending {
                    open_console_for_human(state).await;
                }
                Ok(ApprovalSummary::from(approval).with_human_action(state))
            }
            Self::Remote(client) => client.call(OP_REQUEST_APPROVAL, &params).await,
        }
    }

    async fn confirm_approval(
        &self,
        params: ConfirmApprovalParams,
    ) -> Result<ApprovalSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let id = parse_uuid(&params.approval_id)?;
                let current = {
                    let catalog = state.catalog.clone();
                    catalog_task(move || catalog.get_approval(id)).await?
                };
                if current.state != ApprovalState::Pending
                    || current.version != params.expected_version
                {
                    return Err(ErrorData::invalid_params("approval_not_pending", None));
                }
                state
                    .verify_and_consume_totp(
                        params.verification_code,
                        BrowserAuthChannel::Mcp,
                        Some(id),
                    )
                    .await
                    .map_err(|error| match error {
                        crate::ApiError::Unauthorized => {
                            ErrorData::invalid_params("verification_failed", None)
                        }
                        crate::ApiError::SecretStoreLocked
                        | crate::ApiError::SecretStoreUnavailable
                        | crate::ApiError::SecretEntryNotFound => {
                            ErrorData::internal_error("verification_unavailable", None)
                        }
                        _ => ErrorData::internal_error("secretbridge_operation_failed", None),
                    })?;
                let catalog = state.catalog.clone();
                let approval = catalog_task(move || {
                    catalog.approve_approval(
                        id,
                        &DecideApproval {
                            expected_version: params.expected_version,
                            note: Some(
                                "Approved with a user-provided authenticator code".to_owned(),
                            ),
                        },
                    )
                })
                .await?;
                let _ = state.changes.send(());
                Ok(ApprovalSummary::from(approval))
            }
            Self::Remote(client) => client.call(OP_CONFIRM_APPROVAL, &params).await,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "dynamic draft creation and approval rollback share one guarded transaction flow"
    )]
    async fn request_command(
        &self,
        params: RequestCommandParams,
    ) -> Result<ApprovalSummary, ErrorData> {
        validate_dynamic_arguments(&params)?;
        match self {
            Self::Local(state) => {
                let target_id = parse_uuid(&params.connection_id)?;
                let terminal_id = parse_uuid(&params.terminal_id)?;
                let terminal = state
                    .terminals
                    .list()
                    .into_iter()
                    .find(|terminal| terminal.id == terminal_id);
                if !terminal.as_ref().is_some_and(|terminal| {
                    terminal.status == crate::terminal::TerminalStatus::Running
                }) {
                    return Err(ErrorData::invalid_params(
                        "secure_terminal_not_running",
                        None,
                    ));
                }
                if terminal.is_some_and(|terminal| terminal.interactive_unverified) {
                    return Err(ErrorData::invalid_params("terminal_context_unknown", None));
                }
                let catalog = state.catalog.clone();
                let target = catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.get_target(target_id)
                })
                .await?;
                if target.kind == crate::catalog::TargetKind::TelnetHost
                    && !target.allow_insecure_protocol
                {
                    return Err(ErrorData::invalid_params(
                        "telnet_not_explicitly_allowed",
                        None,
                    ));
                }
                let template = crate::catalog::CreateActionTemplate {
                    command: Some(crate::command::CommandConfig {
                        terminal_id: Some(terminal_id),
                        database: None,
                        http: None,
                        ssh: None,
                        telnet: None,
                        git: None,
                        parameters: Vec::new(),
                        program: params.program,
                        working_directory: params.working_directory,
                        arguments: params.arguments,
                        slots: params
                            .credential_slots
                            .into_iter()
                            .map(|slot| {
                                Ok(crate::command::CredentialSlot {
                                    name: slot.name,
                                    credential_id: parse_uuid(&slot.credential_id)?,
                                    injection: slot.injection.into(),
                                    environment_variable: slot.environment_variable,
                                })
                            })
                            .collect::<Result<Vec<_>, ErrorData>>()?,
                    }),
                    target_id,
                    name: params.name,
                    operation: ApprovalOperation::CommandExecution,
                    result_scope: ApprovalResultScope::SanitizedOutput,
                    description: Some("One-time command draft requested through MCP".to_owned()),
                    timeout_seconds: params.timeout_seconds,
                };
                let created = catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.create_one_time_draft(&template)
                })
                .await?;
                let request = CreateApproval {
                    parameters: std::collections::BTreeMap::default(),
                    authorization_mode: params.authorization_mode,
                    action_template_id: created.id,
                    conversation_id: Some(
                        resolve_conversation_id(catalog.clone(), params.conversation_id.as_deref())
                            .await?,
                    ),
                    reason: Some(
                        params
                            .reason
                            .unwrap_or_else(|| params.language.default_reason("command")),
                    ),
                    expires_in_seconds: params.expires_in_seconds,
                };
                let approval = match catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.create_approval(&request)
                })
                .await
                {
                    Ok(approval) => approval,
                    Err(error) => {
                        let _ =
                            catalog_task(move || catalog.delete_action_template(created.id)).await;
                        return Err(error);
                    }
                };
                crate::approval_notifications::notify_pending_approval(state, &approval);
                let _ = state.changes.send(());
                if approval.state == ApprovalState::Pending {
                    open_console_for_human(state).await;
                }
                Ok(ApprovalSummary::from(approval).with_human_action(state))
            }
            Self::Remote(client) => client.call(OP_REQUEST_COMMAND, &params).await,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one SSH draft request validates and freezes its full approval scope"
    )]
    async fn request_ssh(&self, params: RequestSshParams) -> Result<ApprovalSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let connection_id = parse_uuid(&params.connection_id)?;
                let catalog = state.catalog.clone();
                let target = catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.get_target(connection_id)
                })
                .await?;
                if target.kind != crate::catalog::TargetKind::SshHost {
                    return Err(ErrorData::invalid_params("ssh_connection_required", None));
                }
                let host = target.address.ok_or_else(|| {
                    ErrorData::invalid_params("ssh_connection_address_required", None)
                })?;
                let username = target.username.ok_or_else(|| {
                    ErrorData::invalid_params("ssh_connection_username_required", None)
                })?;
                let credential_id = target.credential_reference_id.ok_or_else(|| {
                    ErrorData::invalid_params("ssh_connection_credential_required", None)
                })?;
                let credential = catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.get_credential_reference(credential_id)
                })
                .await?;
                if credential.kind != crate::catalog::CredentialKind::Password {
                    return Err(ErrorData::invalid_params(
                        "ssh_password_credential_required",
                        None,
                    ));
                }
                if credential
                    .address
                    .as_deref()
                    .is_some_and(|value| value != host.as_str())
                    || credential
                        .username
                        .as_deref()
                        .is_some_and(|value| value != username.as_str())
                {
                    return Err(ErrorData::invalid_params(
                        "ssh_credential_target_mismatch",
                        None,
                    ));
                }
                let command = crate::command::CommandConfig {
                    terminal_id: None,
                    database: None,
                    http: None,
                    ssh: Some(crate::ssh_task::SshConfig {
                        host,
                        port: params.port,
                        username,
                        host_key_sha256: params.host_key_sha256,
                        authentication: crate::ssh_task::Authentication::Password {
                            slot: "login".to_owned(),
                        },
                        remote_program: params.remote_program,
                        arguments: params
                            .arguments
                            .into_iter()
                            .map(|value| crate::ssh_task::Argument::Literal { value })
                            .collect(),
                        transfer: None,
                    }),
                    telnet: None,
                    git: None,
                    parameters: Vec::new(),
                    program: String::new(),
                    working_directory: String::new(),
                    arguments: Vec::new(),
                    slots: vec![crate::command::CredentialSlot {
                        name: "login".to_owned(),
                        credential_id,
                        injection: crate::command::Injection::Protocol,
                        environment_variable: None,
                    }],
                };
                let template = crate::catalog::CreateActionTemplate {
                    command: Some(command),
                    target_id: connection_id,
                    name: params.name,
                    operation: ApprovalOperation::CommandExecution,
                    result_scope: ApprovalResultScope::SanitizedOutput,
                    description: Some("One-time structured SSH operation".to_owned()),
                    timeout_seconds: params.timeout_seconds,
                };
                let created = catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.create_one_time_draft(&template)
                })
                .await?;
                let request = CreateApproval {
                    parameters: std::collections::BTreeMap::default(),
                    authorization_mode: crate::parameters::AuthorizationMode::EveryRun,
                    action_template_id: created.id,
                    conversation_id: Some(
                        resolve_conversation_id(catalog.clone(), params.conversation_id.as_deref())
                            .await?,
                    ),
                    reason: Some(
                        params
                            .reason
                            .unwrap_or_else(|| params.language.default_reason("ssh")),
                    ),
                    expires_in_seconds: params.expires_in_seconds,
                };
                let approval = match catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.create_approval(&request)
                })
                .await
                {
                    Ok(approval) => approval,
                    Err(error) => {
                        let _ =
                            catalog_task(move || catalog.delete_action_template(created.id)).await;
                        return Err(error);
                    }
                };
                crate::approval_notifications::notify_pending_approval(state, &approval);
                let _ = state.changes.send(());
                if approval.state == ApprovalState::Pending {
                    open_console_for_human(state).await;
                }
                Ok(ApprovalSummary::from(approval).with_human_action(state))
            }
            Self::Remote(client) => client.call(OP_REQUEST_SSH, &params).await,
        }
    }

    async fn get_approval(&self, params: IdentifierParams) -> Result<ApprovalSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let id = parse_uuid(&params.id)?;
                let catalog = state.catalog.clone();
                let approval = catalog_task(move || catalog.get_approval(id)).await?;
                Ok(ApprovalSummary::from(approval).with_human_action(state))
            }
            Self::Remote(client) => client.call(OP_GET_APPROVAL, &params).await,
        }
    }

    async fn create_run(&self, params: CreateRunParams) -> Result<CreateRunSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let outcome = create_run_for_state(
                    state,
                    CreateSyntheticRun {
                        approval_id: parse_uuid(&params.approval_id)?,
                        idempotency_key: params.idempotency_key,
                    },
                )
                .await
                .map_err(catalog_error)?;
                let _ = state.changes.send(());
                Ok(CreateRunSummary {
                    execution_mode: run_execution_mode(outcome.run.operation).to_owned(),
                    replayed: outcome.replayed,
                    run: RunSummary::from(outcome.run),
                })
            }
            Self::Remote(client) => client.call(OP_CREATE_RUN, &params).await,
        }
    }

    async fn get_run(&self, params: IdentifierParams) -> Result<RunSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let id = parse_uuid(&params.id)?;
                let catalog = state.catalog.clone();
                let run = catalog_task(move || catalog.get_synthetic_run(id)).await?;
                Ok(RunSummary::from(run))
            }
            Self::Remote(client) => client.call(OP_GET_RUN, &params).await,
        }
    }

    async fn read_output(
        &self,
        params: crate::command::OutputRequest,
    ) -> Result<crate::command::OutputPage, ErrorData> {
        match self {
            Self::Local(state) => crate::command::read_output(state, params)
                .await
                .map_err(catalog_error),
            Self::Remote(client) => client.call(OP_READ_OUTPUT, &params).await,
        }
    }

    async fn cancel_run(&self, params: CancelRunParams) -> Result<RunSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let run = cancel_run_for_state(
                    state,
                    parse_uuid(&params.run_id)?,
                    CancelSyntheticRun {
                        expected_version: params.expected_version,
                    },
                )
                .await
                .map_err(catalog_error)?;
                let _ = state.changes.send(());
                Ok(RunSummary::from(run))
            }
            Self::Remote(client) => client.call(OP_CANCEL_RUN, &params).await,
        }
    }

    async fn list_run_events(&self, params: IdentifierParams) -> Result<EventList, ErrorData> {
        match self {
            Self::Local(state) => {
                let id = parse_uuid(&params.id)?;
                let catalog = state.catalog.clone();
                let items = catalog_task(move || catalog.list_safe_events(Some(id))).await?;
                Ok(EventList {
                    payload_policy: "fixed_safe_messages_only".to_owned(),
                    items: items.into_iter().map(EventSummary::from).collect(),
                })
            }
            Self::Remote(client) => client.call(OP_LIST_RUN_EVENTS, &params).await,
        }
    }
}

fn validate_dynamic_arguments(params: &RequestCommandParams) -> Result<(), ErrorData> {
    let total = params.arguments.iter().map(String::len).sum::<usize>();
    if total > crate::command::MAX_ARGUMENTS_BYTES {
        return Err(ErrorData::invalid_params(
            "command_arguments_too_large",
            Some(serde_json::json!({
                "field": "arguments",
                "actual_bytes": total,
                "limit_bytes": crate::command::MAX_ARGUMENTS_BYTES,
                "next_actions": ["split_the_operation", "use_a_structured_connector"]
            })),
        ));
    }
    for (index, argument) in params.arguments.iter().enumerate() {
        errors::reject_legacy_placeholder(argument, index, &params.credential_slots)?;
        if argument.len() > crate::command::MAX_ARGUMENT_BYTES {
            return Err(ErrorData::invalid_params(
                "command_argument_too_large",
                Some(serde_json::json!({
                    "field": format!("arguments[{index}]"),
                    "actual_bytes": argument.len(),
                    "limit_bytes": crate::command::MAX_ARGUMENT_BYTES,
                    "next_actions": ["split_the_operation", "use_a_structured_connector"]
                })),
            ));
        }
        if argument.contains("{{secret:")
            && !params
                .credential_slots
                .iter()
                .any(|slot| argument == &format!("{{{{secret:{}}}}}", slot.name))
        {
            return Err(ErrorData::invalid_params(
                "unknown_credential_placeholder",
                Some(serde_json::json!({
                    "field": format!("arguments[{index}]"),
                    "next_actions": ["declare_matching_credential_slot", "use_literal_double_braces_without_secret_prefix"]
                })),
            ));
        }
    }
    Ok(())
}

async fn open_console_for_human(state: &AppState) {
    if state.runtime_control.is_some() {
        let _ = crate::runtime::handle(state, crate::runtime::RuntimeRequest::Open).await;
    }
}

#[tool_router]
impl SecretBridgeMcp {
    #[tool(
        name = "secretbridge_read_run_output",
        description = "Read retained, bounded, sanitized output for an approved run, including controlled commands sent to a secure terminal. cursor is the last chunk sequence; continue with next_cursor. Use secretbridge_terminal_read for live terminal interaction. Never re-execute a command to recover output.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<crate::command::OutputPage>()
    )]
    async fn read_run_output(
        &self,
        Parameters(params): Parameters<crate::command::OutputRequest>,
    ) -> Result<McpJson<crate::command::OutputPage>, ErrorData> {
        Ok(McpJson(self.backend.read_output(params).await?))
    }
    #[tool(
        name = "secretbridge_terminal_capabilities",
        description = "Discover supported secure continuous shells and terminal limits. Credential values are injected only by an approved SecretBridge command request, never by terminal creation.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalCapabilitiesOutput>()
    )]
    async fn terminal_capabilities(&self) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Capabilities).await
    }

    #[tool(
        name = "secretbridge_terminal_list",
        description = "List broker-owned terminal sessions, lifecycle status, process IDs and shell exit codes.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalListOutput>()
    )]
    async fn terminal_list(&self) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::List).await
    }

    #[tool(
        name = "secretbridge_terminal_create",
        description = "Create one broker-owned secure continuous terminal for ordinary commands and later human-approved credential commands. The returned ID is terminal.id. Environment and paths must contain no secrets. Creation does not grant input; attach next.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalCreateOutput>()
    )]
    async fn terminal_create(
        &self,
        Parameters(request): Parameters<CreateTerminal>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Create { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_attach",
        description = "Attach this MCP session to a terminal. Request input explicitly; input_granted=false means another client owns it. Idle attachments expire after 60 seconds; detach before yielding to the user.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalAttachOutput>()
    )]
    async fn terminal_attach(
        &self,
        Parameters(request): Parameters<AttachParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Attach { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_read",
        description = "Read broker-redacted terminal output after a byte cursor; this is the only AI-readable terminal result path. max_bytes=1..16384; wait_ms=0..5000. Continue with next_cursor; truncated reports a retention gap; bytes provide lossless decoding and text is a UTF-8 preview. Never re-execute a command to recover output.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalRead>()
    )]
    async fn terminal_read(
        &self,
        Parameters(request): Parameters<ReadParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Read { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_write",
        description = "Write at most 4096 bytes of non-secret input using this MCP session's input lease. Include the shell newline to execute. Failure may mean delivery is uncertain: do not blindly retry.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalWriteOutput>()
    )]
    async fn terminal_write(
        &self,
        Parameters(request): Parameters<WriteParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Write { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_resize",
        description = "Resize a terminal using its input lease. Does not restart or re-execute work.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalResizeOutput>()
    )]
    async fn terminal_resize(
        &self,
        Parameters(request): Parameters<ResizeParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Resize { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_interrupt",
        description = "Send Ctrl+C using the input lease. This is a best-effort foreground interruption, not guaranteed termination. Read subsequent output to confirm; close if forced termination is required.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalInterruptOutput>()
    )]
    async fn terminal_interrupt(
        &self,
        Parameters(request): Parameters<TerminalIdParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Interrupt { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_detach",
        description = "Release this MCP session's terminal attachment and input lease without stopping the shell. Safe to repeat.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalDetachOutput>()
    )]
    async fn terminal_detach(
        &self,
        Parameters(request): Parameters<TerminalIdParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Detach { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_close",
        description = "Terminate and remove the terminal using this MCP session's input lease. This stops running work; use detach to preserve it.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalCloseOutput>()
    )]
    async fn terminal_close(
        &self,
        Parameters(request): Parameters<TerminalIdParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Close { request }).await
    }
    #[tool(
        name = "secretbridge_list_action_templates",
        description = "List configured controlled-action templates without exposing target addresses, descriptions, credential references, or secrets.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TemplateList>()
    )]
    async fn list_action_templates(&self) -> Result<McpJson<TemplateList>, ErrorData> {
        Ok(McpJson(self.backend.list_action_templates().await?))
    }

    #[tool(
        name = "secretbridge_list_catalog",
        description = "List non-secret credential and connection metadata for planning commands: opaque IDs, types, addresses, accounts, environments and availability only. Secret values are never returned.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<CatalogSummary>()
    )]
    async fn list_catalog(&self) -> Result<McpJson<CatalogSummary>, ErrorData> {
        Ok(McpJson(self.backend.list_catalog().await?))
    }

    #[tool(
        name = "secretbridge_evaluate_policy",
        description = "Evaluate the current server policy for one action template before requesting approval. Returns fixed reason codes and requirements only.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<PolicySummary>()
    )]
    async fn evaluate_policy(
        &self,
        Parameters(IdentifierParams { id }): Parameters<IdentifierParams>,
    ) -> Result<McpJson<PolicySummary>, ErrorData> {
        Ok(McpJson(
            self.backend
                .evaluate_policy(IdentifierParams { id })
                .await?,
        ))
    }

    #[tool(
        name = "secretbridge_begin_conversation",
        description = "Create a local AI-conversation ID and short non-secret summary. Call once per AI chat and pass the returned ID to every request tool. This cannot change approval policy; the human controls that in the Web console.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<AiConversation>()
    )]
    async fn begin_conversation(
        &self,
        Parameters(params): Parameters<BeginConversationParams>,
    ) -> Result<McpJson<AiConversation>, ErrorData> {
        Ok(McpJson(self.backend.begin_conversation(params).await?))
    }

    #[tool(
        name = "secretbridge_request_approval",
        description = "Request approval for one enabled action template. The request may already be approved when the human previously enabled a matching conversation policy in the trusted Web console. This tool cannot change that policy or approve its own request.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApprovalSummary>()
    )]
    async fn request_approval(
        &self,
        Parameters(params): Parameters<RequestApprovalParams>,
    ) -> Result<McpJson<ApprovalSummary>, ErrorData> {
        Ok(McpJson(self.backend.request_approval(params).await?))
    }

    #[tool(
        name = "secretbridge_confirm_approval",
        description = "Confirm exactly one pending approval with a current six-digit TOTP code that the user voluntarily supplied after reviewing that request. Never ask for or accept a setup key, QR code, PIN, passphrase, or credential; never retain, echo, or reuse the code. Codes have a bounded delay allowance and are rejected after one use.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApprovalSummary>()
    )]
    async fn confirm_approval(
        &self,
        Parameters(params): Parameters<ConfirmApprovalParams>,
    ) -> Result<McpJson<ApprovalSummary>, ErrorData> {
        Ok(McpJson(self.backend.confirm_approval(params).await?))
    }

    #[tool(
        name = "secretbridge_request_command",
        description = "Submit an exact non-shell command and opaque credential placeholders for an existing secure terminal. A user-created template is not required. The request may be approved by a prior human-controlled conversation policy; this tool cannot set that policy, accept secret values, or execute the draft. Read eventual terminal output with secretbridge_terminal_read.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApprovalSummary>()
    )]
    async fn request_command(
        &self,
        Parameters(params): Parameters<RequestCommandParams>,
    ) -> Result<McpJson<ApprovalSummary>, ErrorData> {
        Ok(McpJson(self.backend.request_command(params).await?))
    }

    #[tool(
        name = "secretbridge_request_ssh",
        description = "Request a one-time structured SSH command using a saved SSH connection and its opaque password reference. The supplied SHA-256 host fingerprint must be confirmed by the local human through a trusted channel; no TOFU or host-key bypass. A prior human-controlled conversation policy may approve the request; this tool never executes immediately or saves a reusable template. Show target, command, fingerprint, expiry and risk before any new human decision.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApprovalSummary>()
    )]
    async fn request_ssh(
        &self,
        Parameters(params): Parameters<RequestSshParams>,
    ) -> Result<McpJson<ApprovalSummary>, ErrorData> {
        Ok(McpJson(self.backend.request_ssh(params).await?))
    }

    #[tool(
        name = "secretbridge_get_approval",
        description = "Read one approval lifecycle summary by its returned identifier. Reasons, decision notes, target details, credentials, and secrets are omitted.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApprovalSummary>()
    )]
    async fn get_approval(
        &self,
        Parameters(IdentifierParams { id }): Parameters<IdentifierParams>,
    ) -> Result<McpJson<ApprovalSummary>, ErrorData> {
        Ok(McpJson(
            self.backend.get_approval(IdentifierParams { id }).await?,
        ))
    }

    #[tool(
        name = "secretbridge_create_run",
        description = "Create a run from an approved, unexpired authorization. Single-use approvals allow one run; time_window approvals allow repeats of the same frozen parameters. No commands, SQL, addresses or secrets are accepted.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<CreateRunSummary>()
    )]
    async fn create_run(
        &self,
        Parameters(params): Parameters<CreateRunParams>,
    ) -> Result<McpJson<CreateRunSummary>, ErrorData> {
        Ok(McpJson(self.backend.create_run(params).await?))
    }

    #[tool(
        name = "secretbridge_get_run",
        description = "Read one controlled run's bounded lifecycle status. No raw adapter output, database errors, business rows, or credentials are returned.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<RunSummary>()
    )]
    async fn get_run(
        &self,
        Parameters(IdentifierParams { id }): Parameters<IdentifierParams>,
    ) -> Result<McpJson<RunSummary>, ErrorData> {
        Ok(McpJson(
            self.backend.get_run(IdentifierParams { id }).await?,
        ))
    }

    #[tool(
        name = "secretbridge_cancel_run",
        description = "Cancel one queued or running controlled run using its current optimistic version.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<RunSummary>()
    )]
    async fn cancel_run(
        &self,
        Parameters(params): Parameters<CancelRunParams>,
    ) -> Result<McpJson<RunSummary>, ErrorData> {
        Ok(McpJson(self.backend.cancel_run(params).await?))
    }

    #[tool(
        name = "secretbridge_list_run_events",
        description = "List the fixed safe-event stream for one run. Event messages come from a database-enforced allowlist and contain no adapter output or credentials.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<EventList>()
    )]
    async fn list_run_events(
        &self,
        Parameters(IdentifierParams { id }): Parameters<IdentifierParams>,
    ) -> Result<McpJson<EventList>, ErrorData> {
        Ok(McpJson(
            self.backend
                .list_run_events(IdentifierParams { id })
                .await?,
        ))
    }
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "the MCP SDK generates the asynchronous handler implementation"
)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for SecretBridgeMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("secretbridge", env!("CARGO_PKG_VERSION"))
                    .with_title("SecretBridge")
                    .with_description("Controlled local operations without secret disclosure"),
            )
            .with_instructions(SERVER_INSTRUCTIONS)
    }
}

pub async fn serve_stdio_bridge(
    connection_file: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = BridgeClient::from_file(connection_file);
    client.health().await.map_err(Box::new)?;
    let server = SecretBridgeMcp::new_remote(client);
    let actor = server.actor;
    let backend = server.backend.clone();
    let result: Result<(), Box<dyn Error + Send + Sync>> = async {
        server.serve(stdio()).await?.waiting().await?;
        Ok(())
    }
    .await;
    let _ = backend
        .terminal_request(OwnedTerminalRequest {
            actor,
            request: TerminalRequest::Release,
        })
        .await;
    result?;
    Ok(())
}

const BRIDGE_CONNECTION_FILE: &str = "mcp-bridge.json";
pub(crate) const BRIDGE_CONNECTION_SCHEMA: u8 = 2;
const BRIDGE_PROTOCOL: &str = "secretbridge-native-ipc-v1";
const MAX_BRIDGE_REQUEST_BYTES: usize = 16 * 1024;
#[cfg(windows)]
const MAX_BRIDGE_PIPE_BUFFER_BYTES: u32 = 16 * 1024;
const MAX_BRIDGE_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_BRIDGE_CONNECTION_BYTES: u64 = 4 * 1024;
const MAX_BRIDGE_CONNECTIONS: usize = 32;
#[cfg(windows)]
const MAX_BRIDGE_PIPE_INSTANCES: usize = MAX_BRIDGE_CONNECTIONS + 1;
const BRIDGE_IO_TIMEOUT: Duration = Duration::from_secs(10);

const OP_HEALTH: &str = "health";
const OP_BEGIN_CONVERSATION: &str = "begin_conversation";
const OP_LIST_TEMPLATES: &str = "list_action_templates";
const OP_LIST_CATALOG: &str = "list_catalog";
const OP_EVALUATE_POLICY: &str = "evaluate_policy";
const OP_REQUEST_APPROVAL: &str = "request_approval";
const OP_CONFIRM_APPROVAL: &str = "confirm_approval";
const OP_REQUEST_COMMAND: &str = "request_command";
const OP_REQUEST_SSH: &str = "request_ssh";
const OP_GET_APPROVAL: &str = "get_approval";
const OP_CREATE_RUN: &str = "create_run";
const OP_GET_RUN: &str = "get_run";
const OP_READ_OUTPUT: &str = "read_run_output";
const OP_CANCEL_RUN: &str = "cancel_run";
const OP_LIST_RUN_EVENTS: &str = "list_run_events";
const OP_TERMINAL: &str = "terminal";
const OP_RUNTIME: &str = "runtime_control";

/// Authenticated lifecycle client for the local CLI; not advertised as an MCP tool.
pub struct BrokerController {
    client: BridgeClient,
}
impl BrokerController {
    /// Checks the authenticated bridge even if an older broker lacks runtime control.
    pub async fn is_reachable(&self) -> bool {
        self.client.health().await.is_ok()
    }
    #[must_use]
    pub fn new(data_directory: &Path) -> Self {
        Self {
            client: BridgeClient::from_file(data_directory.join(BRIDGE_CONNECTION_FILE)),
        }
    }
    /// Reads authenticated runtime state without returning connection or pairing tokens.
    /// # Errors
    /// Returns an error if the broker cannot be reached or rejects the request.
    pub async fn status(&self) -> Result<crate::RuntimeStatus, ErrorData> {
        self.client
            .call(OP_RUNTIME, &crate::runtime::RuntimeRequest::Status)
            .await
    }
    /// Opens a fresh one-time pairing URL in the broker's browser.
    /// # Errors
    /// Returns an error if the broker or browser is unavailable.
    pub async fn open(&self) -> Result<crate::RuntimeStatus, ErrorData> {
        self.client
            .call(OP_RUNTIME, &crate::runtime::RuntimeRequest::Open)
            .await
    }
    /// Requests graceful broker shutdown without acting on a saved PID.
    /// # Errors
    /// Returns an error if authenticated control is unavailable.
    pub async fn stop(&self) -> Result<crate::RuntimeStatus, ErrorData> {
        self.client
            .call(OP_RUNTIME, &crate::runtime::RuntimeRequest::Stop)
            .await
    }
}

#[derive(Clone)]
struct BridgeClient {
    connection_file: Arc<PathBuf>,
}

struct BridgeConnection {
    endpoint: BridgeEndpoint,
    token: Zeroizing<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum BridgeEndpoint {
    #[cfg(unix)]
    UnixSocket { path: PathBuf },
    #[cfg(windows)]
    WindowsNamedPipe { name: String },
}

pub struct LocalMcpBridge {
    listener: BridgeListener,
    state: AppState,
    token_digest: [u8; 32],
    _connection_guard: BridgeConnectionGuard,
}

enum BridgeListener {
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        owner_uid: u32,
    },
    #[cfg(windows)]
    Windows {
        server: NamedPipeServer,
        name: String,
    },
}

impl BridgeClient {
    fn from_file(path: PathBuf) -> Self {
        Self {
            connection_file: Arc::new(path),
        }
    }

    async fn connection(&self) -> Result<BridgeConnection, ErrorData> {
        let path = Arc::clone(&self.connection_file);
        task::spawn_blocking(move || read_bridge_connection(&path))
            .await
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))
    }

    async fn health(&self) -> Result<(), ErrorData> {
        let health: BridgeHealth = self.call(OP_HEALTH, &BridgeEmpty {}).await?;
        if health.status == "ready" && health.protocol == BRIDGE_PROTOCOL {
            Ok(())
        } else {
            Err(ErrorData::internal_error(
                "secretbridge_bridge_unavailable",
                None,
            ))
        }
    }

    async fn call<T, B>(&self, operation: &str, payload: &B) -> Result<T, ErrorData>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let connection = self.connection().await?;
        let request = BridgeRequestRef {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            token: connection.token.as_str(),
            operation,
            payload,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| {
            ErrorData::internal_error("secretbridge_bridge_request_rejected", None)
        })?);
        if encoded.len() > MAX_BRIDGE_REQUEST_BYTES {
            return Err(ErrorData::invalid_params(
                "secretbridge_bridge_request_rejected",
                None,
            ));
        }
        let exchange = async {
            let mut stream = connect_bridge(&connection.endpoint).await?;
            write_frame(&mut stream, &encoded, MAX_BRIDGE_REQUEST_BYTES).await?;
            read_frame(&mut stream, MAX_BRIDGE_RESPONSE_BYTES).await
        };
        let response = time::timeout(BRIDGE_IO_TIMEOUT, exchange)
            .await
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?;
        let response = serde_json::from_slice::<BridgeResponse>(&response).map_err(|_| {
            ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
        })?;
        if response.schema_version != BRIDGE_CONNECTION_SCHEMA {
            return Err(ErrorData::internal_error(
                "secretbridge_bridge_response_rejected",
                None,
            ));
        }
        if response.ok {
            let payload = response.payload.ok_or_else(|| {
                ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
            })?;
            if response.error.is_some() {
                return Err(ErrorData::internal_error(
                    "secretbridge_bridge_response_rejected",
                    None,
                ));
            }
            serde_json::from_value(payload).map_err(|_| {
                ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
            })
        } else {
            if response.payload.is_some() {
                return Err(ErrorData::internal_error(
                    "secretbridge_bridge_response_rejected",
                    None,
                ));
            }
            Err(remote_error(
                response.error.as_deref().unwrap_or_default(),
                response.error_data,
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeConnectionDocument {
    schema_version: u8,
    #[serde(rename = "instance_id")]
    _instance_id: Uuid,
    endpoint: BridgeEndpoint,
    token: String,
}

fn read_bridge_connection(path: &Path) -> io::Result<BridgeConnection> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the SecretBridge broker connection file is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_BRIDGE_CONNECTION_BYTES
        || !valid_bridge_connection_metadata(&metadata, path)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        ));
    }
    let contents = Zeroizing::new(fs::read_to_string(path)?);
    let document = serde_json::from_str::<BridgeConnectionDocument>(&contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        )
    })?;
    if document.schema_version != BRIDGE_CONNECTION_SCHEMA
        || !valid_bridge_endpoint(&document.endpoint, path)
        || document.token.len() != 64
        || !document.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        ));
    }
    Ok(BridgeConnection {
        endpoint: document.endpoint,
        token: Zeroizing::new(document.token),
    })
}

#[derive(Serialize)]
struct BridgeConnectionDocumentRef<'a> {
    schema_version: u8,
    instance_id: Uuid,
    endpoint: &'a BridgeEndpoint,
    token: &'a str,
}

#[derive(Deserialize)]
struct BridgeConnectionIdentity {
    instance_id: Uuid,
}

#[derive(Serialize)]
struct BridgeRequestRef<'a, T: Serialize + ?Sized> {
    schema_version: u8,
    token: &'a str,
    operation: &'a str,
    payload: &'a T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeRequest {
    schema_version: u8,
    token: String,
    operation: String,
    payload: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BridgeResponse {
    schema_version: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_data: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BridgeEmpty {}

#[derive(Deserialize, Serialize)]
struct BridgeHealth {
    status: String,
    protocol: String,
}

impl LocalMcpBridge {
    /// Creates the native bridge endpoint and publishes its ephemeral connection document.
    ///
    /// # Errors
    ///
    /// Returns an error when the data directory is not a private absolute directory, the
    /// platform endpoint cannot be created, or another bridge owns the connection document.
    pub fn bind(data_directory: &Path, state: AppState) -> Result<Self, Box<dyn Error>> {
        validate_bridge_data_directory(data_directory)?;
        let connection_path = data_directory.join(BRIDGE_CONNECTION_FILE);
        prepare_bridge_connection_path(&connection_path)?;
        let instance_id = Uuid::new_v4();
        let token = Zeroizing::new(new_bridge_token());
        let token_digest = token_digest(token.as_str());
        let (listener, endpoint, socket_path) = bind_bridge_listener(data_directory, instance_id)?;
        let connection_guard = match BridgeConnectionGuard::create(
            &connection_path,
            instance_id,
            &endpoint,
            token.as_str(),
            socket_path.as_deref(),
        ) {
            Ok(guard) => guard,
            Err(error) => {
                #[cfg(unix)]
                if let Some(socket_path) = socket_path {
                    let _ = fs::remove_file(socket_path);
                }
                return Err(error);
            }
        };
        crate::command::cleanup_files(&state.command_directory)?;
        Ok(Self {
            listener,
            state,
            token_digest,
            _connection_guard: connection_guard,
        })
    }

    /// Serves bounded native bridge requests until cancellation or a listener error.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when accepting a connection or creating the next Windows pipe
    /// instance fails.
    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let Self {
            listener,
            state,
            token_digest,
            _connection_guard,
        } = self;
        let capacity = Arc::new(Semaphore::new(MAX_BRIDGE_CONNECTIONS));
        let controls = state.terminal_controls.clone();
        tokio::select! {
            result = serve_bridge_listener(listener, state, token_digest, capacity, cancellation) => result,
            () = async move {
                loop {
                    time::sleep(Duration::from_secs(5)).await;
                    controls.expire();
                }
            } => Ok(()),
        }
    }
}

struct BridgeConnectionGuard {
    path: PathBuf,
    instance_id: Uuid,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl BridgeConnectionGuard {
    fn create(
        path: &Path,
        instance_id: Uuid,
        endpoint: &BridgeEndpoint,
        token: &str,
        socket_path: Option<&Path>,
    ) -> Result<Self, Box<dyn Error>> {
        #[cfg(windows)]
        let _ = &socket_path;
        let document = BridgeConnectionDocumentRef {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            instance_id,
            endpoint,
            token,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&document)?);
        let temporary_path = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
        let write_result = write_private_file(&temporary_path, &encoded)
            .and_then(|()| fs::hard_link(&temporary_path, path));
        let _ = fs::remove_file(&temporary_path);
        write_result?;
        Ok(Self {
            path: path.to_owned(),
            instance_id,
            #[cfg(unix)]
            socket_path: socket_path
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing Unix socket path")
                })?
                .to_owned(),
        })
    }
}

impl Drop for BridgeConnectionGuard {
    fn drop(&mut self) {
        if let Ok(contents) = fs::read_to_string(&self.path) {
            let contents = Zeroizing::new(contents);
            if serde_json::from_str::<BridgeConnectionIdentity>(&contents)
                .is_ok_and(|document| document.instance_id == self.instance_id)
            {
                let _ = fs::remove_file(&self.path);
            }
        }
        #[cfg(unix)]
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    let mut file = secretbridge_windows_pipe_acl::create_private_file(path)?;
    #[cfg(unix)]
    let mut file = {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        options.mode(0o600);
        options.open(path)?
    };
    file.write_all(contents)?;
    file.sync_all()
}

fn validate_bridge_data_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the SecretBridge data directory is invalid",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the SecretBridge data directory permissions are too broad",
        ));
    }
    #[cfg(windows)]
    if !secretbridge_windows_pipe_acl::is_private_path(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the SecretBridge data directory permissions are too broad",
        ));
    }
    Ok(())
}

fn prepare_bridge_connection_path(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection = read_bridge_connection(path)?;
    if bridge_endpoint_is_active(&connection.endpoint) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "another SecretBridge broker owns the data directory",
        ));
    }
    #[cfg(unix)]
    {
        let BridgeEndpoint::UnixSocket { path: socket_path } = &connection.endpoint;
        match fs::remove_file(socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::remove_file(path)
}

#[cfg(unix)]
fn bridge_endpoint_is_active(endpoint: &BridgeEndpoint) -> bool {
    use std::os::unix::net::UnixStream as StdUnixStream;

    let BridgeEndpoint::UnixSocket { path } = endpoint;
    StdUnixStream::connect(path).is_ok()
}

#[cfg(windows)]
fn bridge_endpoint_is_active(endpoint: &BridgeEndpoint) -> bool {
    let BridgeEndpoint::WindowsNamedPipe { name } = endpoint;
    match ClientOptions::new().open(name) {
        Ok(_) => true,
        Err(error) => error.raw_os_error() == Some(231),
    }
}

#[cfg(unix)]
#[allow(
    clippy::verbose_bit_mask,
    reason = "the security check intentionally names the group/other permission-bit mask"
)]
fn valid_bridge_connection_metadata(metadata: &fs::Metadata, path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    metadata.permissions().mode() & 0o077 == 0
        && fs::metadata(parent).is_ok_and(|parent_metadata| parent_metadata.uid() == metadata.uid())
}

#[cfg(windows)]
fn valid_bridge_connection_metadata(_metadata: &fs::Metadata, path: &Path) -> bool {
    path.parent().is_some_and(|parent| {
        secretbridge_windows_pipe_acl::is_private_path(parent).unwrap_or(false)
            && secretbridge_windows_pipe_acl::is_private_path(path).unwrap_or(false)
    })
}

fn new_bridge_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

async fn handle_bridge_stream<S>(
    mut stream: S,
    state: AppState,
    expected_token: [u8; 32],
    peer_authorized: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let exchange = async {
        let request = read_frame(&mut stream, MAX_BRIDGE_REQUEST_BYTES).await?;
        let response =
            process_bridge_request(&state, expected_token, peer_authorized, &request).await;
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bridge response failed"))?;
        write_frame(&mut stream, &encoded, MAX_BRIDGE_RESPONSE_BYTES).await
    };
    let _ = time::timeout(BRIDGE_IO_TIMEOUT, exchange).await;
}

async fn process_bridge_request(
    state: &AppState,
    expected_token: [u8; 32],
    peer_authorized: bool,
    encoded: &[u8],
) -> BridgeResponse {
    let Ok(mut request) = serde_json::from_slice::<BridgeRequest>(encoded) else {
        return BridgeResponse::error("invalid_request");
    };
    let token = Zeroizing::new(mem::take(&mut request.token));
    if !peer_authorized
        || request.schema_version != BRIDGE_CONNECTION_SCHEMA
        || !constant_time_equal(&token_digest(token.as_str()), &expected_token)
    {
        return BridgeResponse::error("bridge_unauthorized");
    }
    match dispatch_bridge_request(state.clone(), &request.operation, request.payload).await {
        Ok(payload) => BridgeResponse::success(payload),
        Err(error) => {
            let code = safe_bridge_error_code(error.message.as_ref());
            let _ = state.catalog.record_diagnostic_failure(&code);
            let _ = state.catalog.record_encrypted_diagnostic(
                "event",
                serde_json::json!({ "source": "mcp", "code": code }),
            );
            BridgeResponse::from_error(error)
        }
    }
}

async fn dispatch_bridge_request(
    state: AppState,
    operation: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, ErrorData> {
    if operation == OP_RUNTIME {
        return serialize_bridge_payload(
            crate::runtime::handle(&state, parse_bridge_payload(payload)?).await?,
        );
    }
    ensure_bridge_ready(&state, operation)?;
    let backend = McpBackend::Local(state);
    match operation {
        OP_HEALTH => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(BridgeHealth {
                status: "ready".to_owned(),
                protocol: BRIDGE_PROTOCOL.to_owned(),
            })
        }
        OP_BEGIN_CONVERSATION => serialize_bridge_payload(
            backend
                .begin_conversation(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_LIST_TEMPLATES => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(backend.list_action_templates().await?)
        }
        OP_LIST_CATALOG => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(backend.list_catalog().await?)
        }
        OP_EVALUATE_POLICY => serialize_bridge_payload(
            backend
                .evaluate_policy(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_REQUEST_APPROVAL => serialize_bridge_payload(
            backend
                .request_approval(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_CONFIRM_APPROVAL => serialize_bridge_payload(
            backend
                .confirm_approval(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_REQUEST_COMMAND => serialize_bridge_payload(
            backend
                .request_command(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_REQUEST_SSH => {
            serialize_bridge_payload(backend.request_ssh(parse_bridge_payload(payload)?).await?)
        }
        OP_GET_APPROVAL => {
            serialize_bridge_payload(backend.get_approval(parse_bridge_payload(payload)?).await?)
        }
        OP_CREATE_RUN => {
            serialize_bridge_payload(backend.create_run(parse_bridge_payload(payload)?).await?)
        }
        OP_GET_RUN => {
            serialize_bridge_payload(backend.get_run(parse_bridge_payload(payload)?).await?)
        }
        OP_READ_OUTPUT => {
            serialize_bridge_payload(backend.read_output(parse_bridge_payload(payload)?).await?)
        }
        OP_CANCEL_RUN => {
            serialize_bridge_payload(backend.cancel_run(parse_bridge_payload(payload)?).await?)
        }
        OP_LIST_RUN_EVENTS => serialize_bridge_payload(
            backend
                .list_run_events(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_TERMINAL => {
            let _gate = match &backend {
                McpBackend::Local(state) => {
                    let gate = state.configuration_gate.read().await;
                    if state
                        .runtime_control
                        .as_ref()
                        .is_some_and(|control| control.stopping.is_cancelled())
                    {
                        return Err(ErrorData::internal_error("broker_stopping", None));
                    }
                    Some(gate)
                }
                McpBackend::Remote(_) => None,
            };
            backend
                .terminal_request(parse_bridge_payload(payload)?)
                .await
        }
        _ => Err(ErrorData::invalid_params("invalid_request", None)),
    }
}

fn parse_bridge_payload<T: DeserializeOwned>(payload: serde_json::Value) -> Result<T, ErrorData> {
    serde_json::from_value(payload).map_err(|_| ErrorData::invalid_params("invalid_request", None))
}

fn serialize_bridge_payload<T: Serialize>(payload: T) -> Result<serde_json::Value, ErrorData> {
    serde_json::to_value(payload)
        .map_err(|_| ErrorData::internal_error("secretbridge_operation_failed", None))
}

async fn read_frame<S>(stream: &mut S, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid bridge frame"))?;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bridge frame",
        ));
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame<S>(stream: &mut S, payload: &[u8], maximum: usize) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.is_empty() || payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bridge frame",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid bridge frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.shutdown().await
}

#[cfg(unix)]
fn bind_bridge_listener(
    data_directory: &Path,
    instance_id: Uuid,
) -> io::Result<(BridgeListener, BridgeEndpoint, Option<PathBuf>)> {
    let identifier = instance_id.simple().to_string();
    let socket_path = data_directory.join(format!("sb-{}", &identifier[..16]));
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    let owner_uid = fs::metadata(data_directory)?.uid();
    Ok((
        BridgeListener::Unix {
            listener,
            owner_uid,
        },
        BridgeEndpoint::UnixSocket {
            path: socket_path.clone(),
        },
        Some(socket_path),
    ))
}

#[cfg(windows)]
fn bind_bridge_listener(
    _data_directory: &Path,
    instance_id: Uuid,
) -> io::Result<(BridgeListener, BridgeEndpoint, Option<PathBuf>)> {
    let name = format!(r"\\.\pipe\secretbridge-{}", instance_id.simple());
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(MAX_BRIDGE_PIPE_INSTANCES)
        .in_buffer_size(MAX_BRIDGE_PIPE_BUFFER_BYTES)
        .out_buffer_size(64 * 1024);
    let server = secretbridge_windows_pipe_acl::create_private_named_pipe(&options, &name)?;
    Ok((
        BridgeListener::Windows {
            server,
            name: name.clone(),
        },
        BridgeEndpoint::WindowsNamedPipe { name },
        None,
    ))
}

#[cfg(unix)]
async fn serve_bridge_listener(
    listener: BridgeListener,
    state: AppState,
    token_digest: [u8; 32],
    capacity: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let BridgeListener::Unix {
        listener,
        owner_uid,
    } = listener;
    loop {
        let permit = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = Arc::clone(&capacity).acquire_owned() => result.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "bridge capacity closed")
            })?,
        };
        let (stream, _) = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = listener.accept() => result?,
        };
        let peer_authorized = stream
            .peer_cred()
            .is_ok_and(|credentials| credentials.uid() == owner_uid);
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_bridge_stream(stream, state, token_digest, peer_authorized).await;
        });
    }
}

#[cfg(windows)]
async fn serve_bridge_listener(
    listener: BridgeListener,
    state: AppState,
    token_digest: [u8; 32],
    capacity: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let BridgeListener::Windows { mut server, name } = listener;
    loop {
        let permit = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = Arc::clone(&capacity).acquire_owned() => result.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "bridge capacity closed")
            })?,
        };
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = server.connect() => result?,
        }
        let connected = server;
        let mut options = ServerOptions::new();
        options
            .reject_remote_clients(true)
            .max_instances(MAX_BRIDGE_PIPE_INSTANCES)
            .in_buffer_size(MAX_BRIDGE_PIPE_BUFFER_BYTES)
            .out_buffer_size(64 * 1024);
        server = secretbridge_windows_pipe_acl::create_private_named_pipe(&options, &name)?;
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_bridge_stream(connected, state, token_digest, true).await;
        });
    }
}

#[cfg(unix)]
async fn connect_bridge(endpoint: &BridgeEndpoint) -> io::Result<UnixStream> {
    let BridgeEndpoint::UnixSocket { path } = endpoint;
    UnixStream::connect(path).await
}

#[cfg(windows)]
async fn connect_bridge(
    endpoint: &BridgeEndpoint,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let BridgeEndpoint::WindowsNamedPipe { name } = endpoint;
    loop {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(231) => {
                time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn valid_bridge_endpoint(endpoint: &BridgeEndpoint, connection_file: &Path) -> bool {
    let BridgeEndpoint::UnixSocket { path } = endpoint;
    path.is_absolute()
        && path.parent() == connection_file.parent()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("sb-"))
            .is_some_and(|identifier| {
                identifier.len() == 16 && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        && fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

#[cfg(windows)]
fn valid_bridge_endpoint(endpoint: &BridgeEndpoint, _connection_file: &Path) -> bool {
    let BridgeEndpoint::WindowsNamedPipe { name } = endpoint;
    let Some(identifier) = name.strip_prefix(r"\\.\pipe\secretbridge-") else {
        return false;
    };
    identifier.len() == 32 && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn catalog_task<T, F>(operation: F) -> Result<T, ErrorData>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CatalogError> + Send + 'static,
{
    task::spawn_blocking(operation)
        .await
        .map_err(|_| ErrorData::internal_error("secretbridge_operation_failed", None))?
        .map_err(catalog_error)
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentifierParams {
    #[schemars(description = "SecretBridge UUID returned by another tool")]
    id: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestApprovalParams {
    #[serde(default)]
    #[schemars(
        description = "Ordinary non-secret parameter values. Defaults are resolved and frozen in the approval."
    )]
    parameters: crate::parameters::ParameterValues,
    #[serde(default)]
    #[schemars(
        description = "every_run/once consume one run; time_window allows repeated runs of exactly the same confirmed parameters until expiry"
    )]
    authorization_mode: crate::parameters::AuthorizationMode,
    #[schemars(description = "Action-template UUID")]
    action_template_id: String,
    #[serde(default)]
    #[schemars(
        description = "AI conversation UUID from secretbridge_begin_conversation; reuse it for every task in the same chat"
    )]
    conversation_id: Option<String>,
    #[schemars(description = "Approval lifetime in seconds, from 60 through 3600")]
    expires_in_seconds: u64,
    #[serde(default)]
    #[schemars(
        description = "Non-secret reason in the current conversation language, up to 240 characters"
    )]
    reason: Option<String>,
    #[serde(default)]
    language: ConversationLanguage,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConversationLanguage {
    #[default]
    En,
    Zh,
}

impl ConversationLanguage {
    fn default_reason(self, kind: &str) -> String {
        match (self, kind) {
            (Self::Zh, "command") => "通过 MCP 申请一次性命令".to_owned(),
            (Self::Zh, _) => "通过 MCP 申请受控操作".to_owned(),
            (Self::En, "command") => "One-time command requested through MCP".to_owned(),
            (Self::En, _) => "Requested through MCP".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfirmApprovalParams {
    #[schemars(description = "Pending approval UUID returned by SecretBridge")]
    approval_id: String,
    #[schemars(description = "Current optimistic version returned with that pending approval")]
    expected_version: u64,
    #[schemars(
        description = "Six-digit one-time authenticator code supplied by the user for this approval"
    )]
    verification_code: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestCommandParams {
    #[schemars(description = "Short human-readable label for this one-time command draft")]
    name: String,
    #[schemars(description = "Connection UUID returned by secretbridge_list_catalog")]
    connection_id: String,
    #[serde(default)]
    #[schemars(description = "AI conversation UUID from secretbridge_begin_conversation")]
    conversation_id: Option<String>,
    #[schemars(
        description = "Running secure-terminal UUID returned by secretbridge_terminal_list"
    )]
    terminal_id: String,
    #[schemars(description = "Absolute executable path; never a shell command string")]
    program: String,
    #[schemars(description = "Existing absolute working directory")]
    working_directory: String,
    #[schemars(
        description = "Exact argv items; argument/file credential slots require one complete {{secret:slot_name}} item. Other double-brace text such as {{.Names}} is literal"
    )]
    arguments: Vec<String>,
    #[serde(default)]
    #[schemars(description = "Opaque credential bindings and injection modes; no secret values")]
    credential_slots: Vec<DynamicCredentialSlot>,
    #[serde(default)]
    authorization_mode: crate::parameters::AuthorizationMode,
    #[schemars(description = "Pending approval lifetime in seconds, from 60 through 3600")]
    expires_in_seconds: u64,
    #[schemars(description = "Maximum command runtime in seconds, from 1 through 300")]
    timeout_seconds: u64,
    #[serde(default)]
    #[schemars(
        description = "Non-secret reason in the current conversation language, up to 240 characters"
    )]
    reason: Option<String>,
    #[serde(default)]
    language: ConversationLanguage,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestSshParams {
    #[schemars(description = "Saved SSH connection UUID from secretbridge_list_catalog")]
    connection_id: String,
    #[serde(default)]
    #[schemars(description = "AI conversation UUID from secretbridge_begin_conversation")]
    conversation_id: Option<String>,
    #[schemars(description = "Short human-readable label for this one-time operation")]
    name: String,
    #[schemars(
        description = "User-confirmed SHA256 host-key fingerprint; never accept an unknown host automatically"
    )]
    host_key_sha256: String,
    #[serde(default = "default_ssh_port")]
    port: u16,
    #[schemars(description = "Absolute remote executable path, not a shell command string")]
    remote_program: String,
    #[schemars(description = "Remote argv items; sent as individually quoted POSIX words")]
    arguments: Vec<String>,
    #[schemars(description = "Pending approval lifetime in seconds, 60 through 3600")]
    expires_in_seconds: u64,
    #[schemars(description = "Maximum remote runtime in seconds, 1 through 300")]
    timeout_seconds: u64,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    language: ConversationLanguage,
}

const fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct DynamicCredentialSlot {
    name: String,
    #[schemars(description = "Credential UUID returned by secretbridge_list_catalog")]
    credential_id: String,
    injection: DynamicInjection,
    #[serde(default)]
    environment_variable: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
enum DynamicInjection {
    Stdin,
    Environment,
    Argument,
    File,
}

impl From<DynamicInjection> for crate::command::Injection {
    fn from(value: DynamicInjection) -> Self {
        match value {
            DynamicInjection::Stdin => Self::Stdin,
            DynamicInjection::Environment => Self::Environment,
            DynamicInjection::Argument => Self::Argument,
            DynamicInjection::File => Self::File,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateRunParams {
    #[schemars(description = "Approved usable approval UUID")]
    approval_id: String,
    #[schemars(description = "Caller-generated idempotency key, 1 through 96 safe characters")]
    idempotency_key: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelRunParams {
    #[schemars(description = "Queued or running run UUID")]
    run_id: String,
    #[schemars(description = "Current run version returned by get_run")]
    expected_version: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct CatalogSummary {
    credentials: Vec<CredentialSummary>,
    connections: Vec<ConnectionSummary>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct CredentialSummary {
    id: String,
    name: String,
    kind: String,
    address: Option<String>,
    username: Option<String>,
    configured: bool,
    version: u64,
}

impl From<crate::catalog::CredentialReference> for CredentialSummary {
    fn from(value: crate::catalog::CredentialReference) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            kind: match value.kind {
                crate::catalog::CredentialKind::Password => "password",
                crate::catalog::CredentialKind::ApiToken => "api_token",
                crate::catalog::CredentialKind::SshKey => "ssh_key",
            }
            .to_owned(),
            address: value.address,
            username: value.username,
            configured: value.secret_state == crate::catalog::SecretState::Available,
            version: value.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct ConnectionSummary {
    id: String,
    name: String,
    kind: String,
    environment: String,
    address: Option<String>,
    username: Option<String>,
    credential_id: Option<String>,
    insecure_protocol_explicitly_allowed: bool,
    version: u64,
}

impl From<crate::catalog::Target> for ConnectionSummary {
    fn from(value: crate::catalog::Target) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            kind: match value.kind {
                crate::catalog::TargetKind::Database => "database",
                crate::catalog::TargetKind::HttpService => "http_service",
                crate::catalog::TargetKind::SshHost => "ssh_host",
                crate::catalog::TargetKind::TelnetHost => "telnet_host",
            }
            .to_owned(),
            environment: match value.environment {
                crate::catalog::TargetEnvironment::Development => "development",
                crate::catalog::TargetEnvironment::Test => "test",
                crate::catalog::TargetEnvironment::Production => "production",
            }
            .to_owned(),
            address: value.address,
            username: value.username,
            credential_id: value.credential_reference_id.map(|id| id.to_string()),
            insecure_protocol_explicitly_allowed: value.allow_insecure_protocol,
            version: value.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct TemplateList {
    items: Vec<TemplateSummary>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct TemplateSummary {
    execution_kind: String,
    parameters: Vec<crate::parameters::ParameterDefinition>,
    credential_slots: Vec<SlotSummary>,
    id: String,
    name: String,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    timeout_seconds: u64,
    enabled: bool,
    version: u64,
}

impl From<ActionTemplate> for TemplateSummary {
    fn from(template: ActionTemplate) -> Self {
        Self {
            execution_kind: if template
                .command
                .as_ref()
                .is_some_and(|c| c.database.is_some())
            {
                "database"
            } else if template
                .command
                .as_ref()
                .is_some_and(|c| c.ssh.as_ref().is_some_and(|s| s.transfer.is_some()))
            {
                "sftp"
            } else if template.command.as_ref().is_some_and(|c| c.git.is_some()) {
                "git"
            } else if template.command.as_ref().is_some_and(|c| c.ssh.is_some()) {
                "ssh"
            } else if template
                .command
                .as_ref()
                .is_some_and(|c| c.telnet.is_some())
            {
                "telnet"
            } else if template.command.as_ref().is_some_and(|c| c.http.is_some()) {
                "http"
            } else if template.command.is_some() {
                "program"
            } else {
                "builtin"
            }
            .into(),
            parameters: template
                .command
                .as_ref()
                .map_or_else(Vec::new, |c| c.parameters.clone()),
            credential_slots: template.command.as_ref().map_or_else(Vec::new, |config| {
                config
                    .slots
                    .iter()
                    .map(|s| SlotSummary {
                        name: s.name.clone(),
                        injection: format!("{:?}", s.injection).to_lowercase(),
                    })
                    .collect()
            }),
            id: template.id.to_string(),
            name: template.name,
            operation: template.operation,
            result_scope: template.result_scope,
            timeout_seconds: template.timeout_seconds,
            enabled: template.enabled,
            version: template.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct SlotSummary {
    name: String,
    injection: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct PolicySummary {
    policy_version: String,
    decision: PolicyDecision,
    reason_codes: Vec<PolicyReasonCode>,
    requirements: Vec<PolicyRequirement>,
    action_template_id: String,
    action_template_version: u64,
    target_version: u64,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    timeout_seconds: u64,
    execution_mode: String,
}

impl From<PolicyEvaluation> for PolicySummary {
    fn from(evaluation: PolicyEvaluation) -> Self {
        Self {
            policy_version: evaluation.policy_version.to_owned(),
            decision: evaluation.decision,
            reason_codes: evaluation.reason_codes,
            requirements: evaluation.requirements,
            action_template_id: evaluation.action_template_id.to_string(),
            action_template_version: evaluation.action_template_version,
            target_version: evaluation.target_version,
            operation: evaluation.operation,
            result_scope: evaluation.result_scope,
            timeout_seconds: evaluation.timeout_seconds,
            execution_mode: evaluation.execution_mode.to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct ApprovalSummary {
    parameters: crate::parameters::ParameterValues,
    authorization_mode: crate::parameters::AuthorizationMode,
    id: String,
    conversation_id: Option<String>,
    preauthorized: bool,
    action_template_id: Option<String>,
    action_template_version: Option<u64>,
    target_id: String,
    reason: Option<String>,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    state: ApprovalState,
    expires_at_unix_ms: u64,
    version: u64,
    console_url: Option<String>,
    next_actions: Vec<String>,
}

impl From<Approval> for ApprovalSummary {
    fn from(approval: Approval) -> Self {
        Self {
            parameters: approval.parameters,
            authorization_mode: approval.authorization_mode,
            id: approval.id.to_string(),
            conversation_id: approval.conversation_id.map(|id| id.to_string()),
            preauthorized: approval.preauthorized,
            action_template_id: approval.action_template_id.map(|id| id.to_string()),
            action_template_version: approval.action_template_version,
            target_id: approval.target_id.to_string(),
            reason: approval.reason,
            operation: approval.operation,
            result_scope: approval.result_scope,
            state: approval.state,
            expires_at_unix_ms: approval.expires_at_unix_ms,
            version: approval.version,
            console_url: None,
            next_actions: Vec::new(),
        }
    }
}

impl ApprovalSummary {
    fn with_human_action(mut self, state: &AppState) -> Self {
        if self.state == ApprovalState::Pending {
            self.console_url = state
                .runtime_control
                .as_ref()
                .map(|control| control.origin.clone());
            self.next_actions = vec![
                "show_pending_approval_details_to_user".to_owned(),
                "user_approves_in_local_web_console".to_owned(),
                "or_if_totp_configured_submit_current_code_with_secretbridge_confirm_approval"
                    .to_owned(),
            ];
        } else if self.preauthorized {
            self.next_actions = vec![
                "disclose_conversation_preapproval_and_risk_to_user".to_owned(),
                "create_run_if_still_intended".to_owned(),
            ];
        }
        self
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct CreateRunSummary {
    run: RunSummary,
    replayed: bool,
    execution_mode: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct RunSummary {
    id: String,
    approval_id: String,
    action_template_id: String,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    state: RunState,
    result_status: Option<String>,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    started_at_unix_ms: Option<u64>,
    finished_at_unix_ms: Option<u64>,
    version: u64,
}

impl From<SyntheticRun> for RunSummary {
    fn from(run: SyntheticRun) -> Self {
        Self {
            id: run.id.to_string(),
            approval_id: run.approval_id.to_string(),
            action_template_id: run.action_template_id.to_string(),
            operation: run.operation,
            result_scope: run.result_scope,
            state: run.state,
            result_status: run.result_status,
            created_at_unix_ms: run.created_at_unix_ms,
            updated_at_unix_ms: run.updated_at_unix_ms,
            started_at_unix_ms: run.started_at_unix_ms,
            finished_at_unix_ms: run.finished_at_unix_ms,
            version: run.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct EventList {
    payload_policy: String,
    items: Vec<EventSummary>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
struct EventSummary {
    sequence: u64,
    kind: SafeEventKind,
    state: RunState,
    message: String,
    created_at_unix_ms: u64,
}

impl From<SafeEvent> for EventSummary {
    fn from(event: SafeEvent) -> Self {
        Self {
            sequence: event.sequence,
            kind: event.kind,
            state: event.state,
            message: event.message,
            created_at_unix_ms: event.created_at_unix_ms,
        }
    }
}

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
