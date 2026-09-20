// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod catalog;
mod command;
mod credential_service;
mod database_task;
mod git_task;
mod http_task;
mod maintenance;
mod maintenance_api;
mod mcp;
mod parameters;
mod postgres;
mod redaction;
mod runtime;
mod secret_store;
#[cfg(test)]
mod security_acceptance;
mod sftp_task;
mod ssh_task;
#[cfg(test)]
mod stability_acceptance;
mod terminal;
mod terminal_control;

pub use maintenance::{BackupReport, inspect_configuration_backup, restore_configuration_backup};
pub use mcp::BrokerController;
pub use mcp::LocalMcpBridge;
pub use runtime::RuntimeStatus;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path as AxumPath, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use secretbridge_core::{ConfigurationStorage, StatusResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Mutex, RwLock, broadcast},
    task,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use uuid::Uuid;

use catalog::{
    ActionTemplate, Approval, BrowserAuthMode, CancelSyntheticRun, Catalog, CatalogError, CatalogOpenError,
    CreateActionTemplate, CreateApproval, CreateCredentialReference, CreateRunOutcome,
    CreateSyntheticRun, CreateTarget, CredentialReference, DecideApproval, PolicyEvaluation,
    PostgresRunResult, SafeEvent, SecretState, SyntheticRun, Target, UpdateActionTemplate,
    UpdateCredentialReference, UpdateTarget,
};
use credential_service::{CredentialService, CredentialServiceError};
use postgres::{PostgresCheckOutcome, PostgresExecutor};
use secret_store::{SecretStore, SecretStoreError};
use terminal::{
    CreateTerminal, TerminalCapabilities, TerminalConnection, TerminalError, TerminalEvent,
    TerminalManager, TerminalShell, TerminalStatus, TerminalSummary,
};

const BEARER_PREFIX: &str = "Bearer ";
const SESSION_TTL: Duration = Duration::from_mins(30);
const BROWSER_PIN_CREDENTIAL_ID: Uuid = Uuid::from_u128(0x5e63_7265_7462_7269_6467_6570_696e_0001);
const WEBSOCKET_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const WEBSOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AppState {
    bootstrap_token: Arc<RwLock<Option<[u8; 32]>>>,
    session_tokens: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    session_revocations: broadcast::Sender<[u8; 32]>,
    pin_attempts: Arc<Mutex<PinAttempts>>,
    trusted_origins: Arc<HashSet<String>>,
    catalog: Catalog,
    configuration_storage: ConfigurationStorage,
    credential_mutations: Arc<Mutex<()>>,
    configuration_gate: Arc<RwLock<()>>,
    postgres_executor: Arc<dyn PostgresExecutor>,
    run_cancellations: RunCancellations,
    secret_store: Arc<dyn SecretStore>,
    terminals: TerminalManager,
    terminal_controls: terminal_control::TerminalControls,
    command_directory: Arc<PathBuf>,
    command_capacity: Arc<tokio::sync::Semaphore>,
    changes: broadcast::Sender<()>,
    runtime_control: Option<Arc<runtime::RuntimeControl>>,
}

#[derive(Debug)]
pub struct AppStateInitializationError(CatalogOpenError);

impl fmt::Display for AppStateInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBridge configuration storage could not initialize")
    }
}

impl Error for AppStateInitializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

impl AppState {
    /// Creates an application state backed by an ephemeral in-memory catalog.
    ///
    /// # Panics
    ///
    /// Panics if the process cannot initialize an in-memory SQLite connection.
    #[must_use]
    pub fn new(trusted_origins: impl IntoIterator<Item = String>) -> (Self, String) {
        Self::build(
            trusted_origins,
            TerminalManager::system(),
            Catalog::in_memory().expect("an in-memory SQLite catalog should initialize"),
            ConfigurationStorage::MemoryOnly,
            Arc::new(secret_store::MemorySecretStore::new()),
            default_postgres_executor(),
        )
    }

    /// Creates an application state backed by the SQLite database at `database_path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened, migrated, or has a schema newer than
    /// this service supports.
    pub fn new_persistent(
        trusted_origins: impl IntoIterator<Item = String>,
        database_path: &Path,
    ) -> Result<(Self, String), AppStateInitializationError> {
        let catalog = Catalog::open(database_path).map_err(AppStateInitializationError)?;
        catalog
            .recover_interrupted_runs()
            .map_err(|_| AppStateInitializationError(CatalogOpenError::Recovery))?;
        let (mut state, token) = Self::build(
            trusted_origins,
            TerminalManager::system(),
            catalog,
            ConfigurationStorage::Sqlite,
            persistent_secret_store(),
            default_postgres_executor(),
        );
        state.command_directory = Arc::new(
            database_path
                .parent()
                .ok_or(AppStateInitializationError(CatalogOpenError::Recovery))?
                .join("command-secrets"),
        );
        Ok((state, token))
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_with_terminal_program(
        trusted_origins: impl IntoIterator<Item = String>,
        program: PathBuf,
    ) -> (Self, String) {
        Self::build(
            trusted_origins,
            TerminalManager::synthetic(program),
            Catalog::in_memory().expect("an in-memory SQLite catalog should initialize"),
            ConfigurationStorage::MemoryOnly,
            Arc::new(secret_store::MemorySecretStore::new()),
            default_postgres_executor(),
        )
    }

    fn build(
        trusted_origins: impl IntoIterator<Item = String>,
        terminals: TerminalManager,
        catalog: Catalog,
        configuration_storage: ConfigurationStorage,
        secret_store: Arc<dyn SecretStore>,
        postgres_executor: Arc<dyn PostgresExecutor>,
    ) -> (Self, String) {
        let bootstrap_token = new_token();
        let (session_revocations, _) = broadcast::channel(64);
        let state = Self {
            bootstrap_token: Arc::new(RwLock::new(Some(token_digest(&bootstrap_token)))),
            session_tokens: Arc::new(RwLock::new(HashMap::new())),
            session_revocations,
            pin_attempts: Arc::new(Mutex::new(PinAttempts::default())),
            trusted_origins: Arc::new(trusted_origins.into_iter().collect()),
            catalog,
            configuration_storage,
            credential_mutations: Arc::new(Mutex::new(())),
            configuration_gate: Arc::new(RwLock::new(())),
            postgres_executor,
            run_cancellations: RunCancellations::default(),
            secret_store,
            changes: terminals.change_notifier(),
            runtime_control: None,
            terminals,
            terminal_controls: terminal_control::TerminalControls::default(),
            command_directory: Arc::new(
                std::env::temp_dir().join(format!("secretbridge-command-{}", Uuid::new_v4())),
            ),
            command_capacity: Arc::new(tokio::sync::Semaphore::new(4)),
        };
        (state, bootstrap_token)
    }

    async fn issue_session(&self) -> (String, u64) {
        let token = new_token();
        self.session_tokens
            .write()
            .await
            .insert(token_digest(&token), Instant::now() + SESSION_TTL);
        (token, SESSION_TTL.as_secs())
    }

    /// Enables authenticated native lifecycle control without exposing it as an MCP tool.
    pub fn enable_runtime_control(&mut self, origin: String, cancellation: CancellationToken) {
        self.runtime_control = Some(Arc::new(runtime::RuntimeControl {
            origin,
            cancellation,
            stopping: CancellationToken::new(),
        }));
    }

    /// Cancels running operations and stops owned terminal processes during broker shutdown.
    pub async fn shutdown_operations(&self) {
        if let Some(control) = &self.runtime_control {
            control.stopping.cancel();
        }
        let sessions: Vec<_> = self
            .session_tokens
            .write()
            .await
            .drain()
            .map(|(digest, _)| digest)
            .collect();
        for digest in sessions {
            let _ = self.session_revocations.send(digest);
        }
        for (_, token) in self.run_cancellations.active.lock().await.values() {
            token.cancel();
        }
        // Cancel running readers before acquiring the configuration writer.
        // Then include creations which were already in flight when stopping began.
        let gate = self.configuration_gate.write().await;
        for (_, token) in self.run_cancellations.active.lock().await.values() {
            token.cancel();
        }
        drop(gate);
        for terminal in self.terminals.list() {
            let _ = self.terminals.remove(terminal.id);
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            while !self.run_cancellations.active.lock().await.is_empty() {
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
    }

    async fn authenticate(&self, token: &str) -> Option<u64> {
        self.authenticate_digest(&token_digest(token)).await
    }

    async fn authenticate_digest(&self, digest: &[u8; 32]) -> Option<u64> {
        let now = Instant::now();
        let mut sessions = self.session_tokens.write().await;
        sessions.retain(|_, expires_at| *expires_at > now);
        sessions
            .get(digest)
            .map(|expires_at| expires_at.saturating_duration_since(now).as_secs())
    }

    async fn revoke(&self, token: &str) -> bool {
        let digest = token_digest(token);
        let removed = self.session_tokens.write().await.remove(&digest).is_some();
        if removed {
            let _ = self.session_revocations.send(digest);
        }
        removed
    }

    async fn active_session_count(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.session_tokens.write().await;
        sessions.retain(|_, expires_at| *expires_at > now);
        sessions.len()
    }
}

#[derive(Default)]
struct PinAttempts {
    failures: u8,
    blocked_until: Option<Instant>,
}

#[derive(Clone, Default)]
struct RunCancellations {
    active: Arc<Mutex<HashMap<Uuid, (Uuid, CancellationToken)>>>,
}

impl RunCancellations {
    async fn register(&self, run_id: Uuid, approval_id: Uuid, token: CancellationToken) {
        self.active
            .lock()
            .await
            .insert(run_id, (approval_id, token));
    }

    async fn cancel_run(&self, run_id: Uuid) {
        if let Some((_, token)) = self.active.lock().await.get(&run_id) {
            token.cancel();
        }
    }

    async fn cancel_approval(&self, approval_id: Uuid) {
        let active = self.active.lock().await;
        for (registered_approval, token) in active.values() {
            if *registered_approval == approval_id {
                token.cancel();
            }
        }
    }

    async fn remove(&self, run_id: Uuid) {
        self.active.lock().await.remove(&run_id);
    }
}

fn persistent_secret_store() -> Arc<dyn SecretStore> {
    #[cfg(test)]
    {
        Arc::new(secret_store::MemorySecretStore::new())
    }
    #[cfg(not(test))]
    {
        Arc::new(secret_store::NativeSecretStore)
    }
}

fn default_postgres_executor() -> Arc<dyn PostgresExecutor> {
    Arc::new(postgres::NativePostgresExecutor)
}

#[derive(Serialize)]
struct PairResponse {
    session_token: String,
    token_type: &'static str,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct BrowserAuthMethodsResponse {
    pin_enabled: bool,
    pairing_link_enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinPairRequest {
    pin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum BrowserAuthMethod {
    PairingLink,
    Pin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBrowserAuthMethodRequest {
    method: BrowserAuthMethod,
    #[serde(default)]
    pin: Option<String>,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    mode: &'static str,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct TerminalListResponse {
    terminals: Vec<TerminalSummary>,
}

#[derive(Serialize)]
struct CredentialReferenceListResponse {
    items: Vec<CredentialReference>,
    storage: ConfigurationStorage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetCredentialSecretRequest {
    secret: String,
    expected_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearCredentialSecretRequest {
    expected_version: u64,
}

#[derive(Serialize)]
struct TargetListResponse {
    items: Vec<Target>,
    storage: ConfigurationStorage,
}

#[derive(Serialize)]
struct ApprovalListResponse {
    items: Vec<Approval>,
    storage: ConfigurationStorage,
    execution_enabled: bool,
}

#[derive(Serialize)]
struct ActionTemplateListResponse {
    items: Vec<ActionTemplate>,
    storage: ConfigurationStorage,
    execution_enabled: bool,
}

#[derive(Serialize)]
struct SyntheticRunListResponse {
    items: Vec<SyntheticRun>,
    execution_mode: &'static str,
}

#[derive(Serialize)]
struct CreateSyntheticRunResponse {
    run: SyntheticRun,
    replayed: bool,
    execution_mode: &'static str,
}

#[derive(Serialize)]
struct SafeEventListResponse {
    items: Vec<SafeEvent>,
    payload_policy: &'static str,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientTerminalMessage {
    Authenticate {
        token: String,
        client_id: Uuid,
        request_input: bool,
        cursor: Option<u64>,
    },
    Input {
        data: String,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
    Terminate,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerTerminalMessage {
    Ready {
        terminal_id: Uuid,
        mode: &'static str,
        shell: TerminalShell,
        status: TerminalStatus,
        replay_from: u64,
        next_cursor: u64,
        replay_truncated: bool,
        retained_bytes: usize,
        retention_capacity: usize,
        input_granted: bool,
    },
    Exited {
        exit_code: u32,
    },
    Terminated,
    Error {
        code: &'static str,
        message: &'static str,
    },
    OutputLagged {
        oldest_cursor: u64,
        next_cursor: u64,
    },
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

enum ApiError {
    ApprovalConsumed,
    ApprovalNotUsable,
    BadRequest,
    CatalogCapacity,
    Internal,
    InvalidApprovalTransition,
    InvalidRunTransition,
    IdempotencyConflict,
    InvalidOrigin,
    NotFound,
    PolicyDenied,
    ResourceInUse,
    SecretEntryNotFound,
    SecretStoreLocked,
    SecretStoreUnavailable,
    TerminalCapacity,
    Unauthorized,
    VersionConflict,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::ApprovalConsumed => (
                StatusCode::CONFLICT,
                "approval_consumed",
                "The approval already has a run.",
            ),
            Self::ApprovalNotUsable => (
                StatusCode::CONFLICT,
                "approval_not_usable",
                "The approval is not active and approved.",
            ),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                "The request is invalid.",
            ),
            Self::CatalogCapacity => (
                StatusCode::CONFLICT,
                "catalog_capacity_reached",
                "The configuration catalog limit has been reached.",
            ),
            Self::TerminalCapacity => (
                StatusCode::CONFLICT,
                "capacity_reached",
                "The terminal session limit has been reached.",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "The local operation failed.",
            ),
            Self::InvalidApprovalTransition => (
                StatusCode::CONFLICT,
                "invalid_approval_transition",
                "The approval cannot make that state transition.",
            ),
            Self::InvalidRunTransition => (
                StatusCode::CONFLICT,
                "invalid_run_transition",
                "The run cannot make that state transition.",
            ),
            Self::IdempotencyConflict => (
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "The idempotency key belongs to another request.",
            ),
            Self::InvalidOrigin => (
                StatusCode::FORBIDDEN,
                "invalid_origin",
                "The request origin is not trusted.",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "The requested resource was not found.",
            ),
            Self::PolicyDenied => (
                StatusCode::CONFLICT,
                "policy_denied",
                "The current synthetic policy does not allow this transition.",
            ),
            Self::ResourceInUse => (
                StatusCode::CONFLICT,
                "resource_in_use",
                "The resource is still referenced and cannot be deleted.",
            ),
            Self::SecretEntryNotFound => (
                StatusCode::CONFLICT,
                "secret_entry_not_found",
                "The credential entry is missing. Set the secret again to repair it.",
            ),
            Self::SecretStoreLocked => (
                StatusCode::LOCKED,
                "secret_store_locked",
                "The operating-system credential store is locked or access was denied.",
            ),
            Self::SecretStoreUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "secret_store_unavailable",
                "The operating-system credential store is unavailable.",
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication failed.",
            ),
            Self::VersionConflict => (
                StatusCode::CONFLICT,
                "version_conflict",
                "The record changed after it was loaded. Reload it before saving.",
            ),
        };
        (status, Json(ErrorResponse { code, message })).into_response()
    }
}

const fn map_secret_store_error(error: SecretStoreError) -> ApiError {
    match error {
        SecretStoreError::NotFound => ApiError::SecretEntryNotFound,
        SecretStoreError::LockedOrDenied => ApiError::SecretStoreLocked,
        SecretStoreError::Unavailable => ApiError::SecretStoreUnavailable,
    }
}

fn map_credential_service_error(error: CredentialServiceError) -> ApiError {
    match error {
        CredentialServiceError::Catalog(error) => map_catalog_error(error),
        CredentialServiceError::NotConfigured => ApiError::BadRequest,
        CredentialServiceError::Store(error) => map_secret_store_error(error),
        CredentialServiceError::Worker => ApiError::Internal,
    }
}

pub fn router(state: AppState) -> Router {
    apply_security_headers(api_router(state))
}

pub fn router_with_web(state: AppState, web_root: impl AsRef<Path>) -> Router {
    apply_security_headers(
        api_router(state)
            .fallback_service(ServeDir::new(web_root).append_index_html_on_directories(true)),
    )
}

fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/runtime/stop", post(runtime::stop_http))
        .route("/api/v1/session/pair", post(pair))
        .route("/api/v1/session/pin", post(pair_with_pin))
        .route("/api/v1/session/methods", get(browser_auth_methods))
        .route("/api/v1/session/method", put(set_browser_auth_method))
        .route("/api/v1/session", get(session).delete(revoke_session))
        .route(
            "/api/v1/credential-references",
            get(list_credential_references).post(create_credential_reference),
        )
        .route(
            "/api/v1/credential-references/{id}",
            delete(delete_credential_reference).put(update_credential_reference),
        )
        .route(
            "/api/v1/credential-references/{id}/secret",
            put(set_credential_secret).delete(clear_credential_secret),
        )
        .route("/api/v1/targets", get(list_targets).post(create_target))
        .route(
            "/api/v1/targets/{id}",
            delete(delete_target).put(update_target),
        )
        .route(
            "/api/v1/action-templates",
            get(list_action_templates).post(create_action_template),
        )
        .route(
            "/api/v1/action-templates/{id}",
            delete(delete_action_template).put(update_action_template),
        )
        .route(
            "/api/v1/action-templates/{id}/policy-evaluation",
            get(evaluate_action_template),
        )
        .route(
            "/api/v1/approvals",
            get(list_approvals).post(create_approval),
        )
        .route("/api/v1/approvals/{id}/approve", post(approve_approval))
        .route("/api/v1/approvals/{id}/deny", post(deny_approval))
        .route("/api/v1/approvals/{id}/revoke", post(revoke_approval))
        .route(
            "/api/v1/runs",
            get(list_synthetic_runs).post(create_synthetic_run),
        )
        .route("/api/v1/runs/{id}", get(get_synthetic_run))
        .route("/api/v1/runs/{id}/cancel", post(cancel_synthetic_run))
        .route("/api/v1/runs/{id}/events", get(list_run_safe_events))
        .route("/api/v1/runs/{id}/output", post(get_run_output))
        .route("/api/v1/safe-events", get(list_safe_events))
        .route(
            "/api/v1/terminals",
            get(list_terminals).post(create_terminal),
        )
        .route(
            "/api/v1/terminals/capabilities",
            get(get_terminal_capabilities),
        )
        .route("/api/v1/terminals/{id}", delete(delete_terminal))
        .route("/api/v1/terminals/{id}/attach", get(attach_terminal))
        .route("/api/v1/events", get(attach_events))
        .merge(maintenance_api::routes(state.clone()))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            notify_mutations,
        ))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRunOutput {
    cursor: u64,
    #[serde(default)]
    wait_ms: u64,
}

async fn get_run_output(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<Uuid>,
    Json(request): Json<ReadRunOutput>,
) -> Result<Json<command::OutputPage>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    Ok(Json(
        command::read_output(
            &state,
            command::OutputRequest {
                id: id.to_string(),
                cursor: request.cursor,
                wait_ms: request.wait_ms,
            },
        )
        .await
        .map_err(map_catalog_error)?,
    ))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

async fn notify_mutations(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mutation = !request.uri().path().ends_with("/output")
        && !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        );
    if mutation
        && state
            .runtime_control
            .as_ref()
            .is_some_and(|control| control.stopping.is_cancelled())
    {
        return ApiError::PolicyDenied.into_response();
    }
    let response = next.run(request).await;
    if mutation && response.status().is_success() {
        let _ = state.changes.send(());
    }
    response
}

async fn attach_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    validate_origin(&headers, &state)?;
    Ok(upgrade
        .max_message_size(1024)
        .on_upgrade(move |socket| events_socket(socket, state))
        .into_response())
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum EventAuthentication {
    Authenticate { token: String },
}

async fn events_socket(mut socket: WebSocket, state: AppState) {
    let mut changes = state.changes.subscribe();
    let mut revocations = state.session_revocations.subscribe();
    let auth = timeout(WEBSOCKET_AUTH_TIMEOUT, socket.recv()).await;
    let Ok(Some(Ok(Message::Text(text)))) = auth else {
        let _ = send_socket_message(&mut socket, Message::Close(None)).await;
        return;
    };
    let Ok(EventAuthentication::Authenticate { token }) =
        serde_json::from_str::<EventAuthentication>(&text)
    else {
        let _ = send_socket_message(&mut socket, Message::Close(None)).await;
        return;
    };
    let digest = token_digest(&token);
    let Some(expires) = state.authenticate_digest(&digest).await else {
        let _ = send_socket_message(&mut socket, Message::Close(None)).await;
        return;
    };
    if send_socket_message(&mut socket, Message::Text("{\"type\":\"ready\"}".into()))
        .await
        .is_err()
    {
        return;
    }
    let expiry = sleep(Duration::from_secs(expires));
    tokio::pin!(expiry);
    loop {
        tokio::select! {
            () = &mut expiry => break,
            revoked = revocations.recv() => {
                if !matches!(revoked, Ok(other) if other != digest) { break; }
            }
            event = changes.recv() => {
                if matches!(event, Err(broadcast::error::RecvError::Closed)) { break; }
                if state.authenticate_digest(&digest).await.is_none() { break; }
                if send_socket_message(&mut socket, Message::Text("{\"type\":\"changed\"}".into())).await.is_err() { break; }
            }
            received = socket.recv() => match received {
                Some(Ok(Message::Ping(bytes))) => {
                    if send_socket_message(&mut socket, Message::Pong(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Pong(_))) => {},
                _ => break,
            }
        }
    }
    let _ = send_socket_message(&mut socket, Message::Close(None)).await;
}

fn apply_security_headers(router: Router) -> Router {
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
                 script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                 form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let paired = state.active_session_count().await > 0;
    let mut status = StatusResponse::controlled_operations(paired, state.configuration_storage);
    status.background_control_enabled = state.runtime_control.is_some();
    Json(status)
}

async fn pair(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let mut bootstrap = state.bootstrap_token.write().await;
    let Some(expected) = bootstrap.as_ref() else {
        return Err(ApiError::Unauthorized);
    };
    if !constant_time_equal(&token_digest(presented), expected) {
        return Err(ApiError::Unauthorized);
    }
    bootstrap.take();
    drop(bootstrap);

    let (session_token, expires_in_seconds) = state.issue_session().await;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

async fn browser_auth_methods(
    State(state): State<AppState>,
) -> Result<Json<BrowserAuthMethodsResponse>, ApiError> {
    let mode = state.catalog.browser_auth_mode().map_err(map_catalog_error)?;
    Ok(Json(BrowserAuthMethodsResponse {
        pin_enabled: mode == BrowserAuthMode::Pin,
        pairing_link_enabled: true,
    }))
}

fn valid_browser_pin(pin: &str) -> bool {
    let length = pin.chars().count();
    (6..=64).contains(&length) && !pin.chars().any(char::is_control)
}

async fn pair_with_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PinPairRequest>,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    if state.catalog.browser_auth_mode().map_err(map_catalog_error)? != BrowserAuthMode::Pin
        || !valid_browser_pin(&request.pin)
    {
        return Err(ApiError::Unauthorized);
    }
    {
        let attempts = state.pin_attempts.lock().await;
        if attempts.blocked_until.is_some_and(|until| until > Instant::now()) {
            return Err(ApiError::Unauthorized);
        }
    }
    let store = state.secret_store.clone();
    let expected = task::spawn_blocking(move || store.get(BROWSER_PIN_CREDENTIAL_ID))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_secret_store_error)?;
    let matches: bool = token_digest(&request.pin)
        .ct_eq(&token_digest(expected.as_str()))
        .into();
    if !matches {
        let mut attempts = state.pin_attempts.lock().await;
        attempts.failures = attempts.failures.saturating_add(1);
        if attempts.failures >= 5 {
            attempts.blocked_until = Some(Instant::now() + Duration::from_secs(60));
            attempts.failures = 0;
        }
        return Err(ApiError::Unauthorized);
    }
    *state.pin_attempts.lock().await = PinAttempts::default();
    let (session_token, expires_in_seconds) = state.issue_session().await;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

async fn set_browser_auth_method(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SetBrowserAuthMethodRequest>,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let store = state.secret_store.clone();
    match request.method {
        BrowserAuthMethod::Pin => {
            let pin = request.pin.filter(|value| valid_browser_pin(value)).ok_or(ApiError::BadRequest)?;
            task::spawn_blocking(move || store.set(BROWSER_PIN_CREDENTIAL_ID, &pin))
                .await
                .map_err(|_| ApiError::Internal)?
                .map_err(map_secret_store_error)?;
            state
                .catalog
                .set_browser_auth_mode(BrowserAuthMode::Pin)
                .map_err(map_catalog_error)?;
        }
        BrowserAuthMethod::PairingLink => {
            state
                .catalog
                .set_browser_auth_mode(BrowserAuthMode::PairingLink)
                .map_err(map_catalog_error)?;
            let _ = task::spawn_blocking(move || store.delete(BROWSER_PIN_CREDENTIAL_ID)).await;
        }
    }
    *state.pin_attempts.lock().await = PinAttempts::default();
    Ok(StatusCode::NO_CONTENT)
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let expires_in_seconds = state
        .authenticate(presented)
        .await
        .ok_or(ApiError::Unauthorized)?;
    Ok(Json(SessionResponse {
        authenticated: true,
        mode: "controlled_operations",
        expires_in_seconds,
    }))
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    state
        .revoke(presented)
        .await
        .then_some(StatusCode::NO_CONTENT)
        .ok_or(ApiError::Unauthorized)
}

async fn list_credential_references(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CredentialReferenceListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_credential_references())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(CredentialReferenceListResponse {
        items,
        storage: state.configuration_storage,
    }))
}

async fn create_credential_reference(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCredentialReference>,
) -> Result<(StatusCode, Json<CredentialReference>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let item = task::spawn_blocking(move || catalog.create_credential_reference(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(item)))
}

async fn update_credential_reference(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateCredentialReference>,
) -> Result<Json<CredentialReference>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let catalog = state.catalog.clone();
    let item = task::spawn_blocking(move || catalog.update_credential_reference(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(item))
}

async fn delete_credential_reference(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    CredentialService::new(state.catalog.clone(), state.secret_store.clone())
        .delete(id)
        .await
        .map_err(map_credential_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_credential_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<SetCredentialSecretRequest>,
) -> Result<Json<CredentialReference>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    if request.secret.is_empty() || request.secret.len() > 8 * 1024 || request.secret.contains('\0')
    {
        return Err(ApiError::BadRequest);
    }
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let secret = zeroize::Zeroizing::new(request.secret);
    let updated = CredentialService::new(state.catalog.clone(), state.secret_store.clone())
        .set(id, request.expected_version, secret)
        .await
        .map_err(map_credential_service_error)?;
    Ok(Json(updated))
}

async fn clear_credential_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ClearCredentialSecretRequest>,
) -> Result<Json<CredentialReference>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let updated = CredentialService::new(state.catalog.clone(), state.secret_store.clone())
        .clear(id, request.expected_version)
        .await
        .map_err(map_credential_service_error)?;
    Ok(Json(updated))
}

async fn list_targets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TargetListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_targets())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(TargetListResponse {
        items,
        storage: state.configuration_storage,
    }))
}

async fn create_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTarget>,
) -> Result<(StatusCode, Json<Target>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let target = task::spawn_blocking(move || catalog.create_target(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(target)))
}

async fn update_target(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateTarget>,
) -> Result<Json<Target>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let catalog = state.catalog.clone();
    let target = task::spawn_blocking(move || catalog.update_target(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(target))
}

async fn delete_target(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.delete_target(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_action_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ActionTemplateListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_action_templates())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(ActionTemplateListResponse {
        items,
        storage: state.configuration_storage,
        execution_enabled: true,
    }))
}

async fn evaluate_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<PolicyEvaluation>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let evaluation = task::spawn_blocking(move || catalog.evaluate_action_template(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(evaluation))
}

async fn create_action_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateActionTemplate>,
) -> Result<(StatusCode, Json<ActionTemplate>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let template = task::spawn_blocking(move || catalog.create_action_template(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(template)))
}

async fn update_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateActionTemplate>,
) -> Result<Json<ActionTemplate>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let catalog = state.catalog.clone();
    let template = task::spawn_blocking(move || catalog.update_action_template(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(template))
}

async fn delete_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.delete_action_template(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApprovalListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_approvals())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(ApprovalListResponse {
        items,
        storage: state.configuration_storage,
        execution_enabled: true,
    }))
}

async fn create_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateApproval>,
) -> Result<(StatusCode, Json<Approval>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let approval = task::spawn_blocking(move || catalog.create_approval(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(approval)))
}

async fn approve_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DecideApproval>,
) -> Result<Json<Approval>, ApiError> {
    transition_approval(state, headers, id, request, ApprovalDecision::Approve).await
}

async fn deny_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DecideApproval>,
) -> Result<Json<Approval>, ApiError> {
    transition_approval(state, headers, id, request, ApprovalDecision::Deny).await
}

async fn revoke_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DecideApproval>,
) -> Result<Json<Approval>, ApiError> {
    transition_approval(state, headers, id, request, ApprovalDecision::Revoke).await
}

#[derive(Clone, Copy)]
enum ApprovalDecision {
    Approve,
    Deny,
    Revoke,
}

async fn transition_approval(
    state: AppState,
    headers: HeaderMap,
    id: Uuid,
    request: DecideApproval,
    decision: ApprovalDecision,
) -> Result<Json<Approval>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let approval = task::spawn_blocking(move || match decision {
        ApprovalDecision::Approve => catalog.approve_approval(id, &request),
        ApprovalDecision::Deny => catalog.deny_approval(id, &request),
        ApprovalDecision::Revoke => catalog.revoke_approval(id, &request),
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(map_catalog_error)?;
    if matches!(decision, ApprovalDecision::Revoke) {
        state.run_cancellations.cancel_approval(approval.id).await;
    }
    Ok(Json(approval))
}

async fn list_synthetic_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SyntheticRunListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_synthetic_runs())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(SyntheticRunListResponse {
        items,
        execution_mode: "controlled_operations",
    }))
}

async fn get_synthetic_run(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SyntheticRun>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let run = task::spawn_blocking(move || catalog.get_synthetic_run(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(run))
}

async fn create_synthetic_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSyntheticRun>,
) -> Result<(StatusCode, Json<CreateSyntheticRunResponse>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let outcome = create_run_for_state(&state, request)
        .await
        .map_err(map_catalog_error)?;
    let status = if outcome.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let execution_mode = run_execution_mode(outcome.run.operation);
    Ok((
        status,
        Json(CreateSyntheticRunResponse {
            run: outcome.run,
            replayed: outcome.replayed,
            execution_mode,
        }),
    ))
}

async fn create_run_for_state(
    state: &AppState,
    request: CreateSyntheticRun,
) -> Result<CreateRunOutcome, CatalogError> {
    let _lifecycle = state.configuration_gate.read().await;
    if state
        .runtime_control
        .as_ref()
        .is_some_and(|control| control.stopping.is_cancelled())
    {
        return Err(CatalogError::PolicyDenied);
    }
    let catalog = state.catalog.clone();
    let outcome = task::spawn_blocking(move || catalog.create_synthetic_run(&request))
        .await
        .map_err(|_| CatalogError::Storage)??;
    if !outcome.replayed {
        let run_id = outcome.run.id;
        let approval_id = outcome.run.approval_id;
        let cancellation = CancellationToken::new();
        state
            .run_cancellations
            .register(run_id, approval_id, cancellation.clone())
            .await;
        let drive_state = state.clone();
        tokio::spawn(async move {
            drive_run(drive_state.clone(), run_id, cancellation).await;
            drive_state.run_cancellations.remove(run_id).await;
            let _ = drive_state.changes.send(());
        });
    }
    Ok(outcome)
}

const fn run_execution_mode(operation: catalog::ApprovalOperation) -> &'static str {
    if matches!(operation, catalog::ApprovalOperation::CommandExecution) {
        "credential_command"
    } else if matches!(
        operation,
        catalog::ApprovalOperation::PostgresConnectionCheck
    ) {
        "controlled_postgres"
    } else {
        "synthetic_simulation"
    }
}

async fn drive_run(state: AppState, run_id: Uuid, cancellation: CancellationToken) {
    tokio::select! {
        () = cancellation.cancelled() => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        },
        () = sleep(Duration::from_millis(100)) => {}
    }
    let start_catalog = state.catalog.clone();
    let started = task::spawn_blocking(move || start_catalog.start_run(run_id)).await;
    let started = match started {
        Ok(Ok(run)) => run,
        Ok(Err(CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied)) => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        }
        _ => return,
    };
    let _ = state.changes.send(());
    if started.operation == catalog::ApprovalOperation::CommandExecution {
        command::drive(&state, run_id, &cancellation).await;
    } else if started.operation == catalog::ApprovalOperation::PostgresConnectionCheck {
        drive_postgres_check(&state, run_id, &cancellation).await;
    } else {
        tokio::select! {
            () = cancellation.cancelled() => {
                invalidate_synthetic_run(state.catalog.clone(), run_id).await;
                return;
            },
            () = sleep(Duration::from_millis(750)) => {}
        }
        let complete_catalog = state.catalog.clone();
        let completed =
            task::spawn_blocking(move || complete_catalog.complete_synthetic_run(run_id)).await;
        if matches!(
            completed,
            Ok(Err(
                CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied
            ))
        ) {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
        }
    }
}

async fn drive_postgres_check(state: &AppState, run_id: Uuid, cancellation: &CancellationToken) {
    let _configuration = state.configuration_gate.read().await;
    let context_catalog = state.catalog.clone();
    let context = task::spawn_blocking(move || context_catalog.run_execution_context(run_id)).await;
    let context = match context {
        Ok(Ok(context)) => context,
        Ok(Err(CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied)) => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        }
        _ => return,
    };
    let Some(postgres_target) = context.target.postgres.as_ref() else {
        finish_postgres_check(state, run_id, PostgresRunResult::ConfigurationInvalid).await;
        return;
    };
    let Some(credential) = context.credential.as_ref() else {
        finish_postgres_check(state, run_id, PostgresRunResult::CredentialUnavailable).await;
        return;
    };
    let credential_id = credential.id;
    let store = state.secret_store.clone();
    let password = task::spawn_blocking(move || store.get(credential_id)).await;
    let Ok(Ok(password)) = password else {
        finish_postgres_check(state, run_id, PostgresRunResult::CredentialUnavailable).await;
        return;
    };
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let approval_remaining = Duration::from_millis(
        context
            .approval
            .expires_at_unix_ms
            .saturating_sub(now_unix_ms),
    );
    let operation_timeout = Duration::from_secs(context.template.timeout_seconds);
    let effective_timeout = operation_timeout.min(approval_remaining);
    if effective_timeout.is_zero() {
        invalidate_synthetic_run(state.catalog.clone(), run_id).await;
        return;
    }
    let check = state
        .postgres_executor
        .connection_check(postgres_target, &password);
    let result = tokio::select! {
        () = cancellation.cancelled() => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        },
        result = timeout(effective_timeout, check) => match result {
            Ok(PostgresCheckOutcome::ConnectionOk) => PostgresRunResult::ConnectionOk,
            Ok(PostgresCheckOutcome::ConnectionFailed) => PostgresRunResult::ConnectionFailed,
            Ok(PostgresCheckOutcome::ConfigurationInvalid) => PostgresRunResult::ConfigurationInvalid,
            Err(_) => PostgresRunResult::TimedOut,
        }
    };
    finish_postgres_check(state, run_id, result).await;
}

async fn finish_postgres_check(state: &AppState, run_id: Uuid, result: PostgresRunResult) {
    let complete_catalog = state.catalog.clone();
    let completed =
        task::spawn_blocking(move || complete_catalog.complete_postgres_run(run_id, result)).await;
    if matches!(
        completed,
        Ok(Err(
            CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied
        ))
    ) {
        invalidate_synthetic_run(state.catalog.clone(), run_id).await;
    }
}

async fn invalidate_synthetic_run(catalog: Catalog, run_id: Uuid) {
    let _ = task::spawn_blocking(move || catalog.invalidate_synthetic_run(run_id)).await;
}

async fn cancel_synthetic_run(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CancelSyntheticRun>,
) -> Result<Json<SyntheticRun>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let run = cancel_run_for_state(&state, id, request)
        .await
        .map_err(map_catalog_error)?;
    Ok(Json(run))
}

async fn cancel_run_for_state(
    state: &AppState,
    id: Uuid,
    request: CancelSyntheticRun,
) -> Result<SyntheticRun, CatalogError> {
    let catalog = state.catalog.clone();
    let run = task::spawn_blocking(move || catalog.cancel_synthetic_run(id, &request))
        .await
        .map_err(|_| CatalogError::Storage)??;
    state.run_cancellations.cancel_run(id).await;
    Ok(run)
}

/// Serves the bounded MCP tool surface over stdio by connecting to a running local broker.
///
/// # Errors
///
/// Returns an error when the authenticated broker connection or stdio transport cannot initialize,
/// or when the MCP service terminates with a protocol or I/O failure.
pub async fn serve_mcp_stdio_bridge(
    connection_file: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    mcp::serve_stdio_bridge(connection_file).await
}

async fn list_run_safe_events(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SafeEventListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_safe_events(Some(id)))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(SafeEventListResponse {
        items,
        payload_policy: "fixed_safe_messages_only",
    }))
}

async fn list_safe_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SafeEventListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_safe_events(None))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(SafeEventListResponse {
        items,
        payload_policy: "fixed_safe_messages_only",
    }))
}

async fn list_terminals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TerminalListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    Ok(Json(TerminalListResponse {
        terminals: state.terminals.list(),
    }))
}

async fn get_terminal_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TerminalCapabilities>, ApiError> {
    require_session(&state, &headers).await?;
    Ok(Json(state.terminals.capabilities()))
}

async fn create_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTerminal>,
) -> Result<(StatusCode, Json<TerminalSummary>), ApiError> {
    let _lifecycle = state.configuration_gate.read().await;
    if state
        .runtime_control
        .as_ref()
        .is_some_and(|control| control.stopping.is_cancelled())
    {
        return Err(ApiError::PolicyDenied);
    }
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let terminals = state.terminals.clone();
    let summary = task::spawn_blocking(move || terminals.create(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_terminal_error)?;
    Ok((StatusCode::CREATED, Json(summary)))
}

async fn delete_terminal(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let terminals = state.terminals.clone();
    task::spawn_blocking(move || terminals.remove(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_terminal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn attach_terminal(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    validate_origin(&headers, &state)?;
    Ok(upgrade
        .max_message_size(MAX_WEBSOCKET_MESSAGE_BYTES)
        .on_upgrade(move |socket| terminal_socket(socket, state, id))
        .into_response())
}

async fn terminal_socket(mut socket: WebSocket, state: AppState, terminal_id: Uuid) {
    let mut revocations = state.session_revocations.subscribe();
    let Some(prepared) = prepare_terminal_socket(&mut socket, &state, terminal_id).await else {
        return;
    };
    if !prepared.running {
        return;
    }
    let terminal = prepared.terminal;
    let mut events = prepared.events;
    let mut expected_cursor = prepared.expected_cursor;
    let authentication = prepared.authentication;
    let session_expiry = tokio::time::sleep(Duration::from_secs(authentication.expires_in_seconds));
    tokio::pin!(session_expiry);

    loop {
        tokio::select! {
            () = &mut session_expiry => {
                let _ = send_server_message(
                    &mut socket,
                    &ServerTerminalMessage::Error {
                        code: "session_expired",
                        message: "The browser session expired.",
                    },
                ).await;
                break;
            }
            revoked = revocations.recv() => {
                let is_revoked = match revoked {
                    Ok(revoked_digest) => {
                        constant_time_equal(&authentication.session_digest, &revoked_digest)
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state
                            .authenticate_digest(&authentication.session_digest)
                            .await
                            .is_none()
                    }
                    Err(broadcast::error::RecvError::Closed) => true,
                };
                if is_revoked {
                    let _ = send_server_message(
                        &mut socket,
                        &ServerTerminalMessage::Error {
                            code: "session_revoked",
                            message: "The browser session was revoked.",
                        },
                    ).await;
                    break;
                }
            }
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else { break };
                if !handle_client_message(&mut socket, &terminal, message).await {
                    break;
                }
            }
            event = events.recv() => {
                if !handle_terminal_event(
                    &mut socket,
                    &terminal,
                    &mut expected_cursor,
                    event,
                ).await {
                    break;
                }
            }
        }
    }
    // Flush a closing frame after lag, revocation or process exit rather than
    // dropping the upgraded socket with an unexpected protocol reset.
    let _ = send_socket_message(&mut socket, Message::Close(None)).await;
}

struct PreparedTerminal {
    terminal: Arc<TerminalConnection>,
    events: broadcast::Receiver<TerminalEvent>,
    expected_cursor: u64,
    authentication: SocketAuthentication,
    running: bool,
}

async fn prepare_terminal_socket(
    socket: &mut WebSocket,
    state: &AppState,
    terminal_id: Uuid,
) -> Option<PreparedTerminal> {
    let authentication = authenticate_terminal_socket(socket, state).await?;
    let terminal = state.terminals.attach(
        terminal_id,
        authentication.client_id,
        authentication.request_input,
        authentication.cursor,
    );
    let Ok((terminal, snapshot)) = terminal else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "terminal_not_found",
                message: "The terminal session does not exist.",
            },
        )
        .await;
        return None;
    };
    if send_server_message(
        socket,
        &ServerTerminalMessage::Ready {
            terminal_id: snapshot.summary.id,
            mode: if snapshot.summary.shell == TerminalShell::Synthetic {
                "synthetic_test"
            } else {
                "system_shell"
            },
            shell: snapshot.summary.shell,
            status: snapshot.summary.status,
            replay_from: snapshot.replay_from,
            next_cursor: snapshot.next_cursor,
            replay_truncated: snapshot.replay_truncated,
            retained_bytes: snapshot.retained_bytes,
            retention_capacity: snapshot.retention_capacity,
            input_granted: snapshot.input_granted,
        },
    )
    .await
    .is_err()
    {
        return None;
    }
    if !snapshot.output.is_empty()
        && send_socket_message(socket, Message::Binary(snapshot.output.into()))
            .await
            .is_err()
    {
        return None;
    }
    Some(PreparedTerminal {
        terminal: Arc::new(terminal),
        events: snapshot.events,
        expected_cursor: snapshot.next_cursor,
        authentication,
        running: snapshot.summary.status == TerminalStatus::Running,
    })
}

struct SocketAuthentication {
    session_digest: [u8; 32],
    expires_in_seconds: u64,
    client_id: Uuid,
    request_input: bool,
    cursor: Option<u64>,
}

async fn authenticate_terminal_socket(
    socket: &mut WebSocket,
    state: &AppState,
) -> Option<SocketAuthentication> {
    let authenticated = match timeout(WEBSOCKET_AUTH_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            serde_json::from_str::<ClientTerminalMessage>(&text).ok()
        }
        _ => None,
    };
    let Some(ClientTerminalMessage::Authenticate {
        token,
        client_id,
        request_input,
        cursor,
    }) = authenticated
    else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "authentication_required",
                message: "Authenticate in the first WebSocket message.",
            },
        )
        .await;
        let _ = send_socket_message(socket, Message::Close(None)).await;
        return None;
    };
    let digest = token_digest(&token);
    let Some(expires_in_seconds) = state.authenticate_digest(&digest).await else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "unauthorized",
                message: "The session token is invalid or expired.",
            },
        )
        .await;
        let _ = send_socket_message(socket, Message::Close(None)).await;
        return None;
    };
    Some(SocketAuthentication {
        session_digest: digest,
        expires_in_seconds,
        client_id,
        request_input,
        cursor,
    })
}

async fn handle_terminal_event(
    socket: &mut WebSocket,
    terminal: &TerminalConnection,
    expected_cursor: &mut u64,
    event: Result<TerminalEvent, broadcast::error::RecvError>,
) -> bool {
    match event {
        Ok(TerminalEvent::Output { cursor, data }) => {
            if cursor != *expected_cursor {
                return send_output_gap(socket, terminal).await;
            }
            let sent = send_socket_message(socket, Message::Binary(data.to_vec().into()))
                .await
                .is_ok();
            if sent {
                *expected_cursor = (*expected_cursor)
                    .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
            }
            sent
        }
        Ok(TerminalEvent::Exited(exit_code)) => {
            let _ = send_server_message(socket, &ServerTerminalMessage::Exited { exit_code }).await;
            false
        }
        Ok(TerminalEvent::Terminated) => {
            let _ = send_server_message(socket, &ServerTerminalMessage::Terminated).await;
            false
        }
        Ok(TerminalEvent::Failed) => {
            let _ = send_server_message(
                socket,
                &ServerTerminalMessage::Error {
                    code: "terminal_failed",
                    message: "The terminal process failed.",
                },
            )
            .await;
            false
        }
        Err(broadcast::error::RecvError::Lagged(_)) => send_output_gap(socket, terminal).await,
        Err(broadcast::error::RecvError::Closed) => false,
    }
}

async fn send_output_gap(socket: &mut WebSocket, terminal: &TerminalConnection) -> bool {
    let (oldest_cursor, next_cursor) = terminal.output_bounds();
    let _ = send_server_message(
        socket,
        &ServerTerminalMessage::OutputLagged {
            oldest_cursor,
            next_cursor,
        },
    )
    .await;
    false
}

async fn handle_client_message(
    socket: &mut WebSocket,
    terminal: &Arc<TerminalConnection>,
    message: Message,
) -> bool {
    let Message::Text(text) = message else {
        return !matches!(message, Message::Close(_));
    };
    let Ok(message) = serde_json::from_str::<ClientTerminalMessage>(&text) else {
        let _ = send_server_message(
            socket,
            &ServerTerminalMessage::Error {
                code: "invalid_message",
                message: "The WebSocket message is invalid.",
            },
        )
        .await;
        return true;
    };

    let terminal = Arc::clone(terminal);
    let result = match message {
        ClientTerminalMessage::Input { data } => {
            task::spawn_blocking(move || terminal.write(data.as_bytes())).await
        }
        ClientTerminalMessage::Resize { rows, cols } => {
            task::spawn_blocking(move || terminal.resize(rows, cols)).await
        }
        ClientTerminalMessage::Terminate => {
            task::spawn_blocking(move || terminal.terminate()).await
        }
        ClientTerminalMessage::Authenticate { .. } => {
            let _ = send_server_message(
                socket,
                &ServerTerminalMessage::Error {
                    code: "already_authenticated",
                    message: "The WebSocket is already authenticated.",
                },
            )
            .await;
            return true;
        }
    };

    let error = match result {
        Ok(Ok(())) => return true,
        Ok(Err(TerminalError::InputLeaseRequired)) => ServerTerminalMessage::Error {
            code: "input_lease_required",
            message: "This connection has read-only access.",
        },
        Ok(Err(TerminalError::InvalidInput)) => ServerTerminalMessage::Error {
            code: "input_too_large",
            message: "The terminal input is too large.",
        },
        _ => ServerTerminalMessage::Error {
            code: "terminal_operation_failed",
            message: "The terminal operation failed.",
        },
    };
    let _ = send_server_message(socket, &error).await;
    true
}

async fn send_server_message(
    socket: &mut WebSocket,
    message: &ServerTerminalMessage,
) -> Result<(), ()> {
    let text = serde_json::to_string(message).expect("server terminal message is serializable");
    send_socket_message(socket, Message::Text(text.into())).await
}

async fn send_socket_message(socket: &mut WebSocket, message: Message) -> Result<(), ()> {
    match timeout(WEBSOCKET_SEND_TIMEOUT, socket.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn require_session(state: &AppState, headers: &HeaderMap) -> Result<u64, ApiError> {
    let token = bearer_token(headers).ok_or(ApiError::Unauthorized)?;
    state
        .authenticate(token)
        .await
        .ok_or(ApiError::Unauthorized)
}

fn map_terminal_error(error: TerminalError) -> ApiError {
    match error {
        TerminalError::Capacity => ApiError::TerminalCapacity,
        TerminalError::InvalidInput
        | TerminalError::InvalidSize
        | TerminalError::InvalidEnvironment
        | TerminalError::InvalidName
        | TerminalError::InvalidWorkingDirectory
        | TerminalError::UnsupportedShell
        | TerminalError::InputLeaseRequired
        | TerminalError::Closed => ApiError::BadRequest,
        TerminalError::NotFound => ApiError::NotFound,
        TerminalError::SpawnFailed => ApiError::Internal,
    }
}

fn map_catalog_error(error: CatalogError) -> ApiError {
    match error {
        CatalogError::ApprovalConsumed => ApiError::ApprovalConsumed,
        CatalogError::ApprovalNotUsable => ApiError::ApprovalNotUsable,
        CatalogError::Capacity => ApiError::CatalogCapacity,
        CatalogError::CredentialReferenceNotFound | CatalogError::NotFound => ApiError::NotFound,
        CatalogError::Invalid => ApiError::BadRequest,
        CatalogError::InvalidApprovalTransition => ApiError::InvalidApprovalTransition,
        CatalogError::InvalidRunTransition => ApiError::InvalidRunTransition,
        CatalogError::IdempotencyConflict => ApiError::IdempotencyConflict,
        CatalogError::PolicyDenied => ApiError::PolicyDenied,
        CatalogError::ResourceInUse => ApiError::ResourceInUse,
        CatalogError::Storage => ApiError::Internal,
        CatalogError::VersionConflict => ApiError::VersionConflict,
    }
}

fn validate_origin(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidOrigin)?;
    state
        .trusted_origins
        .contains(origin)
        .then_some(())
        .ok_or(ApiError::InvalidOrigin)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix(BEARER_PREFIX)
        .filter(|token| !token.is_empty())
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_equal(presented: &[u8; 32], expected: &[u8; 32]) -> bool {
    bool::from(presented.ct_eq(expected))
}

fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
