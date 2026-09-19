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
    model::{Implementation, ServerCapabilities, ServerInfo},
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

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::terminal::CreateTerminal;
use crate::terminal_control::{
    AttachParams, OwnedTerminalRequest, ReadParams, ResizeParams, TerminalIdParams,
    TerminalRequest, WriteParams,
};
use crate::{
    AppState, cancel_run_for_state,
    catalog::{
        ActionTemplate, Approval, ApprovalOperation, ApprovalResultScope, ApprovalState,
        CancelSyntheticRun, CatalogError, CreateApproval, CreateSyntheticRun, PolicyDecision,
        PolicyEvaluation, PolicyReasonCode, PolicyRequirement, RunState, SafeEvent, SafeEventKind,
        SyntheticRun,
    },
    constant_time_equal, create_run_for_state, run_execution_mode, token_digest,
};

const SERVER_INSTRUCTIONS: &str = "SecretBridge provides approved credential-backed operations and ordinary persistent terminals. For credential-backed operations request approval and wait for the user in the Web console. Ordinary terminals accept non-secret commands only: never submit passwords or tokens, retrieve credential files, or use the shell to bypass credential-backed operations. Attach before reading or writing; input requires request_input=true. Read with next_cursor, not by re-executing commands. Writes are not automatically retried. Detach releases input without stopping the process; close terminates and removes it. The returned terminal exit code is the shell process exit code, not each command's exit code. Terminal bytes are ordinary unfiltered process output; credential injection and streaming redaction are not available on this path.";

#[derive(Clone)]
struct SecretBridgeMcp {
    backend: McpBackend,
    tool_router: ToolRouter<Self>,
    actor: Uuid,
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
                let request = CreateApproval {
                    parameters: params.parameters,
                    authorization_mode: params.authorization_mode,
                    action_template_id: parse_uuid(&params.action_template_id)?,
                    reason: Some("Requested through MCP".to_owned()),
                    expires_in_seconds: params.expires_in_seconds,
                };
                let approval = catalog_task(move || catalog.create_approval(&request)).await?;
                let _ = state.changes.send(());
                Ok(ApprovalSummary::from(approval))
            }
            Self::Remote(client) => client.call(OP_REQUEST_APPROVAL, &params).await,
        }
    }

    async fn get_approval(&self, params: IdentifierParams) -> Result<ApprovalSummary, ErrorData> {
        match self {
            Self::Local(state) => {
                let id = parse_uuid(&params.id)?;
                let catalog = state.catalog.clone();
                let approval = catalog_task(move || catalog.get_approval(id)).await?;
                Ok(ApprovalSummary::from(approval))
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

#[tool_router]
impl SecretBridgeMcp {
    #[tool(
        name = "secretbridge_read_run_output",
        description = "Read sanitized stdout/stderr for an approved credential-backed command run. cursor is the last chunk sequence; continue with next_cursor. wait_ms=0..5000; retention gaps are explicit. Never re-execute a command to recover output."
    )]
    async fn read_run_output(
        &self,
        Parameters(params): Parameters<crate::command::OutputRequest>,
    ) -> Result<McpJson<crate::command::OutputPage>, ErrorData> {
        Ok(McpJson(self.backend.read_output(params).await?))
    }
    #[tool(
        name = "secretbridge_terminal_capabilities",
        description = "Discover supported ordinary system shells and terminal limits. No credentials are injected."
    )]
    async fn terminal_capabilities(&self) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Capabilities).await
    }

    #[tool(
        name = "secretbridge_terminal_list",
        description = "List broker-owned terminal sessions, lifecycle status, process IDs and shell exit codes."
    )]
    async fn terminal_list(&self) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::List).await
    }

    #[tool(
        name = "secretbridge_terminal_create",
        description = "Create a real persistent terminal for ordinary commands. Environment and paths must contain no secrets. Creation does not grant input; attach next."
    )]
    async fn terminal_create(
        &self,
        Parameters(request): Parameters<CreateTerminal>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Create { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_attach",
        description = "Attach this MCP session to a terminal. Request input explicitly; input_granted=false means another client owns it. Idle attachments expire after 60 seconds; detach before yielding to the user."
    )]
    async fn terminal_attach(
        &self,
        Parameters(request): Parameters<AttachParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Attach { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_read",
        description = "Read bounded ordinary output after a byte cursor. max_bytes=1..16384; wait_ms=0..5000. Continue with next_cursor; truncated reports a retention gap; bytes provide lossless decoding and text is a UTF-8 preview. Never re-execute a command to recover output."
    )]
    async fn terminal_read(
        &self,
        Parameters(request): Parameters<ReadParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Read { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_write",
        description = "Write at most 4096 bytes of non-secret input using this MCP session's input lease. Include the shell newline to execute. Failure may mean delivery is uncertain: do not blindly retry."
    )]
    async fn terminal_write(
        &self,
        Parameters(request): Parameters<WriteParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Write { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_resize",
        description = "Resize a terminal using its input lease. Does not restart or re-execute work."
    )]
    async fn terminal_resize(
        &self,
        Parameters(request): Parameters<ResizeParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Resize { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_interrupt",
        description = "Send Ctrl+C using the input lease. This is a best-effort foreground interruption, not guaranteed termination. Read subsequent output to confirm; close if forced termination is required."
    )]
    async fn terminal_interrupt(
        &self,
        Parameters(request): Parameters<TerminalIdParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Interrupt { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_detach",
        description = "Release this MCP session's terminal attachment and input lease without stopping the shell. Safe to repeat."
    )]
    async fn terminal_detach(
        &self,
        Parameters(request): Parameters<TerminalIdParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Detach { request }).await
    }

    #[tool(
        name = "secretbridge_terminal_close",
        description = "Terminate and remove the terminal using this MCP session's input lease. This stops running work; use detach to preserve it."
    )]
    async fn terminal_close(
        &self,
        Parameters(request): Parameters<TerminalIdParams>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.terminal(TerminalRequest::Close { request }).await
    }
    #[tool(
        name = "secretbridge_list_action_templates",
        description = "List configured controlled-action templates without exposing target addresses, descriptions, credential references, or secrets."
    )]
    async fn list_action_templates(&self) -> Result<McpJson<TemplateList>, ErrorData> {
        Ok(McpJson(self.backend.list_action_templates().await?))
    }

    #[tool(
        name = "secretbridge_evaluate_policy",
        description = "Evaluate the current server policy for one action template before requesting approval. Returns fixed reason codes and requirements only."
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
        name = "secretbridge_request_approval",
        description = "Create a pending approval request for one enabled action template. This cannot approve the request; the user must decide in the trusted Web console."
    )]
    async fn request_approval(
        &self,
        Parameters(params): Parameters<RequestApprovalParams>,
    ) -> Result<McpJson<ApprovalSummary>, ErrorData> {
        Ok(McpJson(self.backend.request_approval(params).await?))
    }

    #[tool(
        name = "secretbridge_get_approval",
        description = "Read one approval lifecycle summary by its returned identifier. Reasons, decision notes, target details, credentials, and secrets are omitted."
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
        description = "Create a run from an approved, unexpired authorization. Single-use approvals allow one run; time_window approvals allow repeats of the same frozen parameters. No commands, SQL, addresses or secrets are accepted."
    )]
    async fn create_run(
        &self,
        Parameters(params): Parameters<CreateRunParams>,
    ) -> Result<McpJson<CreateRunSummary>, ErrorData> {
        Ok(McpJson(self.backend.create_run(params).await?))
    }

    #[tool(
        name = "secretbridge_get_run",
        description = "Read one controlled run's bounded lifecycle status. No raw adapter output, database errors, business rows, or credentials are returned."
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
        description = "Cancel one queued or running controlled run using its current optimistic version."
    )]
    async fn cancel_run(
        &self,
        Parameters(params): Parameters<CancelRunParams>,
    ) -> Result<McpJson<RunSummary>, ErrorData> {
        Ok(McpJson(self.backend.cancel_run(params).await?))
    }

    #[tool(
        name = "secretbridge_list_run_events",
        description = "List the fixed safe-event stream for one run. Event messages come from a database-enforced allowlist and contain no adapter output or credentials."
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
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
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
const BRIDGE_CONNECTION_SCHEMA: u8 = 2;
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
const OP_LIST_TEMPLATES: &str = "list_action_templates";
const OP_EVALUATE_POLICY: &str = "evaluate_policy";
const OP_REQUEST_APPROVAL: &str = "request_approval";
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
            Err(remote_error(response.error.as_deref().unwrap_or_default()))
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
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
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
fn valid_bridge_connection_metadata(_metadata: &fs::Metadata, _path: &Path) -> bool {
    true
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
        Err(error) => BridgeResponse::error(&safe_bridge_error_code(error)),
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
    if state
        .runtime_control
        .as_ref()
        .is_some_and(|control| control.stopping.is_cancelled())
    {
        return Err(ErrorData::internal_error("broker_stopping", None));
    }
    let backend = McpBackend::Local(state);
    match operation {
        OP_HEALTH => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(BridgeHealth {
                status: "ready".to_owned(),
                protocol: BRIDGE_PROTOCOL.to_owned(),
            })
        }
        OP_LIST_TEMPLATES => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(backend.list_action_templates().await?)
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

fn safe_bridge_error_code(error: ErrorData) -> String {
    let code = error.message.into_owned();
    match code.as_str() {
        "not_found"
        | "approval_consumed"
        | "approval_not_usable"
        | "capacity_exceeded"
        | "credential_reference_not_found"
        | "invalid_request"
        | "invalid_approval_transition"
        | "invalid_run_transition"
        | "idempotency_conflict"
        | "policy_denied"
        | "resource_in_use"
        | "version_conflict"
        | "terminal_attach_required"
        | "terminal_input_required"
        | "terminal_closed"
        | "terminal_spawn_failed"
        | "terminal_unsupported_shell"
        | "runtime_control_unavailable"
        | "browser_open_failed"
        | "broker_stopping" => code,
        _ => "secretbridge_operation_failed".to_owned(),
    }
}

impl BridgeResponse {
    fn success(payload: serde_json::Value) -> Self {
        Self {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            ok: true,
            payload: Some(payload),
            error: None,
        }
    }

    fn error(code: &str) -> Self {
        Self {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            ok: false,
            payload: None,
            error: Some(code.to_owned()),
        }
    }
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
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(MAX_BRIDGE_PIPE_INSTANCES)
        .in_buffer_size(MAX_BRIDGE_PIPE_BUFFER_BYTES)
        .out_buffer_size(64 * 1024)
        .create(&name)?;
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
        server = ServerOptions::new()
            .reject_remote_clients(true)
            .max_instances(MAX_BRIDGE_PIPE_INSTANCES)
            .in_buffer_size(MAX_BRIDGE_PIPE_BUFFER_BYTES)
            .out_buffer_size(64 * 1024)
            .create(&name)?;
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

fn remote_error(code: &str) -> ErrorData {
    match code {
        "not_found" => ErrorData::resource_not_found("not_found", None),
        "approval_consumed"
        | "approval_not_usable"
        | "capacity_exceeded"
        | "credential_reference_not_found"
        | "invalid_request"
        | "invalid_approval_transition"
        | "invalid_run_transition"
        | "idempotency_conflict"
        | "policy_denied"
        | "resource_in_use"
        | "version_conflict" => ErrorData::invalid_params(code.to_owned(), None),
        "bridge_unauthorized" => {
            ErrorData::internal_error("secretbridge_bridge_authentication_failed", None)
        }
        _ => ErrorData::internal_error("secretbridge_bridge_unavailable", None),
    }
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

fn parse_uuid(value: &str) -> Result<Uuid, ErrorData> {
    Uuid::parse_str(value).map_err(|_| ErrorData::invalid_params("invalid_identifier", None))
}

fn catalog_error(error: CatalogError) -> ErrorData {
    let code = match error {
        CatalogError::ApprovalConsumed => "approval_consumed",
        CatalogError::ApprovalNotUsable => "approval_not_usable",
        CatalogError::Capacity => "capacity_exceeded",
        CatalogError::CredentialReferenceNotFound => "credential_reference_not_found",
        CatalogError::Invalid => "invalid_request",
        CatalogError::InvalidApprovalTransition => "invalid_approval_transition",
        CatalogError::InvalidRunTransition => "invalid_run_transition",
        CatalogError::IdempotencyConflict => "idempotency_conflict",
        CatalogError::NotFound => return ErrorData::resource_not_found("not_found", None),
        CatalogError::PolicyDenied => "policy_denied",
        CatalogError::ResourceInUse => "resource_in_use",
        CatalogError::Storage => {
            return ErrorData::internal_error("secretbridge_operation_failed", None);
        }
        CatalogError::VersionConflict => "version_conflict",
    };
    ErrorData::invalid_params(code, None)
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
    #[schemars(description = "Approval lifetime in seconds, from 60 through 3600")]
    expires_in_seconds: u64,
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
    action_template_id: Option<String>,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    state: ApprovalState,
    expires_at_unix_ms: u64,
    version: u64,
}

impl From<Approval> for ApprovalSummary {
    fn from(approval: Approval) -> Self {
        Self {
            parameters: approval.parameters,
            authorization_mode: approval.authorization_mode,
            id: approval.id.to_string(),
            action_template_id: approval.action_template_id.map(|id| id.to_string()),
            operation: approval.operation,
            result_scope: approval.result_scope,
            state: approval.state,
            expires_at_unix_ms: approval.expires_at_unix_ms,
            version: approval.version,
        }
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
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{collections::BTreeMap, fs, time::Duration};
    use tokio::time;

    use rmcp::{ServiceExt, model::CallToolRequestParams};
    use serde_json::{Map, Value, json};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{
        BridgeClient, LocalMcpBridge, OwnedTerminalRequest, SecretBridgeMcp, TerminalRequest,
    };
    use crate::{
        AppState,
        catalog::{
            ApprovalOperation, ApprovalResultScope, CreateActionTemplate, CreateTarget,
            DecideApproval, TargetEnvironment, TargetKind,
        },
    };

    const SENSITIVE_MARKER: &str = "sensitive-marker-must-not-cross-mcp-boundary";

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
                "secretbridge_create_run",
                "secretbridge_evaluate_policy",
                "secretbridge_get_approval",
                "secretbridge_get_run",
                "secretbridge_list_action_templates",
                "secretbridge_list_run_events",
                "secretbridge_read_run_output",
                "secretbridge_request_approval",
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
            ("secretbridge_evaluate_policy", vec!["id"]),
            (
                "secretbridge_request_approval",
                vec![
                    "action_template_id",
                    "authorization_mode",
                    "expires_in_seconds",
                    "parameters",
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
        let (client, server) = connect_server(SecretBridgeMcp::new_remote(
            BridgeClient::from_file(directory.join("mcp-bridge.json")),
        ))
        .await;
        let templates =
            terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
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
        let (client, server) = connect_server(SecretBridgeMcp::new_remote(
            BridgeClient::from_file(directory.join("mcp-bridge.json")),
        ))
        .await;
        let templates =
            terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
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
        let (client, server) = connect_server(SecretBridgeMcp::new_remote(
            BridgeClient::from_file(directory.join("mcp-bridge.json")),
        ))
        .await;
        let templates =
            terminal_tool(&client, "secretbridge_list_action_templates", json!({})).await;
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
                crate::sftp_task::tests::configure(
                    &state,
                    &ssh,
                    &source,
                    Direction::Upload,
                    false,
                    10,
                )
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
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let (state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
        let bridge = LocalMcpBridge::bind(&directory, state.clone()).expect("bind bridge");
        let cancellation = CancellationToken::new();
        let broker_stop = cancellation.clone();
        let broker = tokio::spawn(async move {
            bridge.serve(broker_stop).await.expect("serve bridge");
        });
        let bridge_client = BridgeClient::from_file(directory.join("mcp-bridge.json"));
        let (client, server) =
            connect_server(SecretBridgeMcp::new_remote(bridge_client.clone())).await;
        let (other, other_server) =
            connect_server(SecretBridgeMcp::new_remote(bridge_client)).await;
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
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755))
            .expect("set broad permissions");
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
                CallToolRequestParams::new("secretbridge_request_approval").with_arguments(
                    arguments(json!({
                        "action_template_id": template.id,
                        "expires_in_seconds": 300
                    })),
                ),
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
        assert!(pending_run.is_err(), "MCP cannot approve its own request");

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
}
