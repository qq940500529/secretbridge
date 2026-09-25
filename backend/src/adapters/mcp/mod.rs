// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{error::Error, path::PathBuf};

use rmcp::{
    ErrorData, Json as McpJson, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::task;
use uuid::Uuid;

pub(crate) mod bridge_dispatch;
pub(crate) mod bridge_response;
mod contracts;
mod conversation;
pub(crate) mod errors;
mod ready;
use crate::adapters::native_ipc as native_bridge;
use contracts::{
    ApprovalSummary, CancelRunParams, CatalogSummary, ConfirmApprovalParams, ConnectionSummary,
    CreateRunParams, CreateRunSummary, CredentialSummary, DynamicCredentialSlot, DynamicInjection,
    EventList, EventSummary, IdentifierParams, PolicySummary, RequestApprovalParams,
    RequestCommandParams, RequestSshParams, RunSummary, TemplateList, TemplateSummary,
};
use conversation::{BeginConversationParams, resolve_conversation_id};
use errors::{catalog_error, parse_uuid, recoverable_error, validate_dynamic_arguments};
pub(crate) use native_bridge::BRIDGE_CONNECTION_SCHEMA;
use native_bridge::{
    BridgeClient, BridgeEmpty, BridgeResponse, OP_BEGIN_CONVERSATION, OP_CANCEL_RUN,
    OP_CONFIRM_APPROVAL, OP_CREATE_RUN, OP_EVALUATE_POLICY, OP_GET_APPROVAL, OP_GET_RUN, OP_HEALTH,
    OP_LIST_CATALOG, OP_LIST_RUN_EVENTS, OP_LIST_TEMPLATES, OP_READ_OUTPUT, OP_REQUEST_APPROVAL,
    OP_REQUEST_COMMAND, OP_REQUEST_SSH, OP_TERMINAL,
};
#[cfg(test)]
use native_bridge::{process_bridge_request, write_private_file};
use ready::ensure_bridge_ready;

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
    create_run_for_state, run_execution_mode,
};

const SERVER_INSTRUCTIONS: &str = include_str!("guidance.md");

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
            backend: McpBackend::Local(Box::new(state)),
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
    Local(Box<AppState>),
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
                crate::application::notifications::notify_pending_approval(state, &approval);
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
                    return Err(recoverable_error("approval_not_pending"));
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
                    return Err(recoverable_error("secure_terminal_not_running"));
                }
                if terminal.is_some_and(|terminal| terminal.interactive_unverified) {
                    return Err(recoverable_error("terminal_context_unknown"));
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
                        stdin_content: params.stdin_content,
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
                crate::application::notifications::notify_pending_approval(state, &approval);
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
                    return Err(recoverable_error("ssh_connection_required"));
                }
                let host = target
                    .address
                    .ok_or_else(|| recoverable_error("ssh_connection_address_required"))?;
                let username = target
                    .username
                    .ok_or_else(|| recoverable_error("ssh_connection_username_required"))?;
                let credential_id = target
                    .credential_reference_id
                    .ok_or_else(|| recoverable_error("ssh_connection_credential_required"))?;
                let credential = catalog_task({
                    let catalog = catalog.clone();
                    move || catalog.get_credential_reference(credential_id)
                })
                .await?;
                if credential.kind != crate::catalog::CredentialKind::Password {
                    return Err(recoverable_error("ssh_password_credential_required"));
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
                    return Err(recoverable_error("ssh_credential_target_mismatch"));
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
                        working_directory: params.working_directory,
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
                    stdin_content: None,
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
                crate::application::notifications::notify_pending_approval(state, &approval);
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

async fn open_console_for_human(state: &AppState) {
    if state.runtime_control.is_some() {
        let _ = crate::runtime::handle(state, crate::runtime::RuntimeRequest::Open).await;
    }
}

#[tool_router]
impl SecretBridgeMcp {
    #[tool(
        name = "secretbridge_read_run_output",
        description = "Read retained, bounded, sanitized output for an approved run. cursor is the last chunk sequence; next_cursor continues the stream. Use secretbridge_terminal_read for live terminal interaction.",
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
        description = "Create a local AI-conversation ID from a short non-secret summary. The ID scopes subsequent requests to this conversation; this tool cannot change human approval policy.",
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
        description = "Request an exact non-shell command for an existing secure terminal. Accepts opaque credential references, not secret values. A template is not required; this tool cannot set approval policy or execute the draft.",
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
        description = "Request a one-time structured SSH command on a saved connection. The human must verify the SHA-256 host fingerprint through a trusted channel; no automatic trust or host-key bypass. This tool does not execute or save a template.",
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
