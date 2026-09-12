// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    error::Error,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json as AxumJson, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::Client;
use rmcp::{
    ErrorData, Json as McpJson, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ErrorCode, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::task;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AppState, bearer_token, cancel_run_for_state,
    catalog::{
        ActionTemplate, Approval, ApprovalOperation, ApprovalResultScope, ApprovalState,
        CancelSyntheticRun, CatalogError, CreateApproval, CreateSyntheticRun, PolicyDecision,
        PolicyEvaluation, PolicyReasonCode, PolicyRequirement, RunState, SafeEvent, SafeEventKind,
        SyntheticRun,
    },
    constant_time_equal, create_run_for_state, run_execution_mode, token_digest,
};

const SERVER_INSTRUCTIONS: &str = "SecretBridge exposes fixed controlled operations only. Request approval, wait for the user to approve it in the Web console, then create one run. Never ask for or submit credentials, SQL, connection strings, shell commands, or business data.";

#[derive(Clone)]
struct SecretBridgeMcp {
    backend: McpBackend,
    tool_router: ToolRouter<Self>,
}

impl SecretBridgeMcp {
    #[cfg(test)]
    fn new_local(state: AppState) -> Self {
        Self {
            backend: McpBackend::Local(state),
            tool_router: Self::tool_router(),
        }
    }

    fn new_remote(client: BridgeClient) -> Self {
        Self {
            backend: McpBackend::Remote(client),
            tool_router: Self::tool_router(),
        }
    }
}

#[derive(Clone)]
enum McpBackend {
    Local(AppState),
    Remote(BridgeClient),
}

impl McpBackend {
    async fn list_action_templates(&self) -> Result<TemplateList, ErrorData> {
        match self {
            Self::Local(state) => {
                let catalog = state.catalog.clone();
                let items = catalog_task(move || catalog.list_action_templates()).await?;
                Ok(TemplateList {
                    items: items.into_iter().map(TemplateSummary::from).collect(),
                })
            }
            Self::Remote(client) => client.get("/internal/mcp/templates").await,
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
            Self::Remote(client) => client.post("/internal/mcp/policy", &params).await,
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
                    action_template_id: parse_uuid(&params.action_template_id)?,
                    reason: Some("Requested through MCP".to_owned()),
                    expires_in_seconds: params.expires_in_seconds,
                };
                let approval = catalog_task(move || catalog.create_approval(&request)).await?;
                Ok(ApprovalSummary::from(approval))
            }
            Self::Remote(client) => client.post("/internal/mcp/approval/request", &params).await,
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
            Self::Remote(client) => client.post("/internal/mcp/approval/get", &params).await,
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
                Ok(CreateRunSummary {
                    execution_mode: run_execution_mode(outcome.run.operation).to_owned(),
                    replayed: outcome.replayed,
                    run: RunSummary::from(outcome.run),
                })
            }
            Self::Remote(client) => client.post("/internal/mcp/run/create", &params).await,
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
            Self::Remote(client) => client.post("/internal/mcp/run/get", &params).await,
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
                Ok(RunSummary::from(run))
            }
            Self::Remote(client) => client.post("/internal/mcp/run/cancel", &params).await,
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
            Self::Remote(client) => client.post("/internal/mcp/run/events", &params).await,
        }
    }
}

#[tool_router]
impl SecretBridgeMcp {
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
        description = "Consume one approved, unexpired approval to create its single controlled run. The tool accepts no SQL, command, operation parameters, target address, or credential."
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
    let client = BridgeClient::from_file(connection_file)?;
    client.health().await.map_err(Box::new)?;
    SecretBridgeMcp::new_remote(client)
        .serve(stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}

pub fn bridge_routes() -> Router<AppState> {
    Router::new()
        .route("/internal/mcp/health", get(bridge_health))
        .route("/internal/mcp/templates", get(bridge_list_templates))
        .route("/internal/mcp/policy", post(bridge_evaluate_policy))
        .route(
            "/internal/mcp/approval/request",
            post(bridge_request_approval),
        )
        .route("/internal/mcp/approval/get", post(bridge_get_approval))
        .route("/internal/mcp/run/create", post(bridge_create_run))
        .route("/internal/mcp/run/get", post(bridge_get_run))
        .route("/internal/mcp/run/cancel", post(bridge_cancel_run))
        .route("/internal/mcp/run/events", post(bridge_list_run_events))
}

const MAX_BRIDGE_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_BRIDGE_CONNECTION_BYTES: u64 = 4 * 1024;
const BRIDGE_CONNECTION_SCHEMA: u8 = 1;

#[derive(Clone)]
struct BridgeClient {
    client: Client,
    connection: BridgeConnectionSource,
}

#[derive(Clone)]
enum BridgeConnectionSource {
    File(Arc<PathBuf>),
}

struct BridgeConnection {
    address: SocketAddr,
    token: Zeroizing<String>,
}

impl BridgeClient {
    fn from_file(path: PathBuf) -> Result<Self, reqwest::Error> {
        Self::build(BridgeConnectionSource::File(Arc::new(path)))
    }

    fn build(connection: BridgeConnectionSource) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { client, connection })
    }

    async fn connection(&self) -> Result<BridgeConnection, ErrorData> {
        match &self.connection {
            BridgeConnectionSource::File(path) => {
                let path = Arc::clone(path);
                task::spawn_blocking(move || read_bridge_connection(&path))
                    .await
                    .map_err(|_| {
                        ErrorData::internal_error("secretbridge_bridge_unavailable", None)
                    })?
                    .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))
            }
        }
    }

    async fn health(&self) -> Result<(), ErrorData> {
        let health: BridgeHealth = self.get("/internal/mcp/health").await?;
        if health.status == "ready" && health.protocol == "secretbridge-mcp-bridge-v1" {
            Ok(())
        } else {
            Err(ErrorData::internal_error(
                "secretbridge_bridge_unavailable",
                None,
            ))
        }
    }

    async fn get<T>(&self, path: &str) -> Result<T, ErrorData>
    where
        T: DeserializeOwned,
    {
        let connection = self.connection().await?;
        self.send(
            self.client
                .get(format!("http://{}{path}", connection.address))
                .bearer_auth(connection.token.as_str()),
        )
        .await
    }

    async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, ErrorData>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let connection = self.connection().await?;
        self.send(
            self.client
                .post(format!("http://{}{path}", connection.address))
                .bearer_auth(connection.token.as_str())
                .json(body),
        )
        .await
    }

    async fn send<T>(&self, request: reqwest::RequestBuilder) -> Result<T, ErrorData>
    where
        T: DeserializeOwned,
    {
        let mut response = request
            .send()
            .await
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BRIDGE_RESPONSE_BYTES as u64)
        {
            return Err(ErrorData::internal_error(
                "secretbridge_bridge_response_rejected",
                None,
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BRIDGE_RESPONSE_BYTES {
                return Err(ErrorData::internal_error(
                    "secretbridge_bridge_response_rejected",
                    None,
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|_| {
                ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
            })
        } else {
            let error = serde_json::from_slice::<BridgeErrorBody>(&bytes).unwrap_or_else(|_| {
                BridgeErrorBody {
                    code: "secretbridge_bridge_unavailable".to_owned(),
                }
            });
            Err(remote_error(&error.code))
        }
    }
}

#[derive(Deserialize)]
struct BridgeConnectionDocument {
    schema_version: u8,
    #[serde(rename = "instance_id")]
    _instance_id: Uuid,
    address: SocketAddr,
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
        || !document.address.ip().is_loopback()
        || document.token.len() != 64
        || !document.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        ));
    }
    Ok(BridgeConnection {
        address: document.address,
        token: Zeroizing::new(document.token),
    })
}

#[derive(Deserialize, Serialize)]
struct BridgeHealth {
    status: String,
    protocol: String,
}

#[derive(Deserialize, Serialize)]
struct BridgeErrorBody {
    code: String,
}

struct BridgeHttpError {
    status: StatusCode,
    code: String,
}

impl BridgeHttpError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "bridge_unauthorized".to_owned(),
        }
    }
}

impl From<ErrorData> for BridgeHttpError {
    fn from(error: ErrorData) -> Self {
        let status = if error.code == ErrorCode::RESOURCE_NOT_FOUND {
            StatusCode::NOT_FOUND
        } else if error.code == ErrorCode::INTERNAL_ERROR {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        };
        Self {
            status,
            code: error.message.into_owned(),
        }
    }
}

impl IntoResponse for BridgeHttpError {
    fn into_response(self) -> Response {
        (self.status, AxumJson(BridgeErrorBody { code: self.code })).into_response()
    }
}

async fn authorize_bridge(state: &AppState, headers: &HeaderMap) -> Result<(), BridgeHttpError> {
    if headers.contains_key("origin") {
        return Err(BridgeHttpError::unauthorized());
    }
    let token = bearer_token(headers).ok_or_else(BridgeHttpError::unauthorized)?;
    let presented = token_digest(token);
    let expected = *state.mcp_bridge_token.read().await;
    if expected.is_some_and(|expected| constant_time_equal(&presented, &expected)) {
        Ok(())
    } else {
        Err(BridgeHttpError::unauthorized())
    }
}

async fn bridge_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<AxumJson<BridgeHealth>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    Ok(AxumJson(BridgeHealth {
        status: "ready".to_owned(),
        protocol: "secretbridge-mcp-bridge-v1".to_owned(),
    }))
}

async fn bridge_list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<AxumJson<TemplateList>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .list_action_templates()
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_evaluate_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<IdentifierParams>,
) -> Result<AxumJson<PolicySummary>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .evaluate_policy(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_request_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<RequestApprovalParams>,
) -> Result<AxumJson<ApprovalSummary>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .request_approval(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_get_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<IdentifierParams>,
) -> Result<AxumJson<ApprovalSummary>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .get_approval(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_create_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<CreateRunParams>,
) -> Result<AxumJson<CreateRunSummary>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .create_run(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_get_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<IdentifierParams>,
) -> Result<AxumJson<RunSummary>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .get_run(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_cancel_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<CancelRunParams>,
) -> Result<AxumJson<RunSummary>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .cancel_run(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
}

async fn bridge_list_run_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(params): AxumJson<IdentifierParams>,
) -> Result<AxumJson<EventList>, BridgeHttpError> {
    authorize_bridge(&state, &headers).await?;
    McpBackend::Local(state)
        .list_run_events(params)
        .await
        .map(AxumJson)
        .map_err(BridgeHttpError::from)
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
    #[schemars(description = "Action-template UUID")]
    action_template_id: String,
    #[schemars(description = "Approval lifetime in seconds, from 60 through 3600")]
    expires_in_seconds: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateRunParams {
    #[schemars(description = "Approved and unconsumed approval UUID")]
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
    use std::{collections::BTreeMap, fs, path::Path};

    use axum::http::StatusCode;
    use rmcp::{ServiceExt, model::CallToolRequestParams};
    use serde_json::{Map, Value, json};
    use uuid::Uuid;

    use super::{BridgeClient, SecretBridgeMcp};
    use crate::{
        AppState,
        catalog::{
            ApprovalOperation, ApprovalResultScope, CreateActionTemplate, CreateTarget,
            DecideApproval, TargetEnvironment, TargetKind,
        },
    };

    const SENSITIVE_MARKER: &str = "sensitive-marker-must-not-cross-mcp-boundary";

    fn write_bridge_connection(path: &Path, address: std::net::SocketAddr, token: &str) {
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "instance_id": Uuid::new_v4(),
                "address": address,
                "token": token,
            }))
            .expect("serialize bridge connection"),
        )
        .expect("write bridge connection");
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
            server
                .serve(server_transport)
                .await
                .expect("MCP server starts")
                .waiting()
                .await
                .expect("MCP server stops cleanly");
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
                "secretbridge_request_approval",
            ]
        );

        let expected_properties = BTreeMap::from([
            ("secretbridge_list_action_templates", vec![]),
            ("secretbridge_evaluate_policy", vec!["id"]),
            (
                "secretbridge_request_approval",
                vec!["action_template_id", "expires_in_seconds"],
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
    async fn detached_stdio_bridge_authenticates_reloads_and_does_not_own_broker_lifecycle() {
        let directory =
            std::env::temp_dir().join(format!("secretbridge-detached-mcp-test-{}", Uuid::new_v4()));
        fs::create_dir(&directory).expect("create bridge test directory");
        let connection_file = directory.join("mcp-bridge.json");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind broker");
        let address = listener.local_addr().expect("broker address");
        let origin = format!("http://{address}");
        let (state, _) = AppState::new([origin]);
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        state.install_mcp_bridge_token(token).await;
        let broker = tokio::spawn(async move {
            axum::serve(listener, crate::router(state))
                .await
                .expect("broker serves");
        });

        write_bridge_connection(
            &connection_file,
            address,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let bridge_client =
            BridgeClient::from_file(connection_file.clone()).expect("bridge client");
        assert!(bridge_client.health().await.is_err());

        write_bridge_connection(&connection_file, address, token);
        bridge_client.health().await.expect("authenticated health");
        let browser_origin_response = bridge_client
            .client
            .get(format!("http://{address}/internal/mcp/health"))
            .bearer_auth(token)
            .header("origin", "https://untrusted.example")
            .send()
            .await
            .expect("origin-bearing bridge request returns a response");
        assert_eq!(browser_origin_response.status(), StatusCode::UNAUTHORIZED);
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
        broker.abort();
        let _ = broker.await;

        let replacement_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind replacement broker");
        let replacement_address = replacement_listener
            .local_addr()
            .expect("replacement broker address");
        let (replacement_state, _) = AppState::new([format!("http://{replacement_address}")]);
        let replacement_token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        replacement_state
            .install_mcp_bridge_token(replacement_token)
            .await;
        let replacement_broker = tokio::spawn(async move {
            axum::serve(replacement_listener, crate::router(replacement_state))
                .await
                .expect("replacement broker serves");
        });
        write_bridge_connection(&connection_file, replacement_address, replacement_token);
        bridge_client
            .health()
            .await
            .expect("bridge reloads replacement broker connection");
        replacement_broker.abort();
        let _ = replacement_broker.await;
        fs::remove_file(connection_file).expect("remove bridge connection file");
        fs::remove_dir(directory).expect("remove bridge test directory");
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
