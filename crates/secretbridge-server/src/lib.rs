// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod catalog;
mod terminal;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{
        Path as AxumPath, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY},
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use secretbridge_core::{ConfigurationStorage, StatusResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{RwLock, broadcast},
    task,
    time::{sleep, timeout},
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use uuid::Uuid;

use catalog::{
    ActionTemplate, Approval, CancelSyntheticRun, Catalog, CatalogError, CatalogOpenError,
    CreateActionTemplate, CreateApproval, CreateCredentialReference, CreateSyntheticRun,
    CreateTarget, CredentialReference, DecideApproval, SafeEvent, SyntheticRun, Target,
    UpdateActionTemplate, UpdateCredentialReference, UpdateTarget,
};
use terminal::{
    TerminalConnection, TerminalError, TerminalEvent, TerminalManager, TerminalStatus,
    TerminalSummary,
};

const BEARER_PREFIX: &str = "Bearer ";
const SESSION_TTL: Duration = Duration::from_mins(30);
const WEBSOCKET_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const WEBSOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AppState {
    bootstrap_token: Arc<RwLock<Option<[u8; 32]>>>,
    session_tokens: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    session_revocations: broadcast::Sender<[u8; 32]>,
    trusted_origins: Arc<HashSet<String>>,
    catalog: Catalog,
    configuration_storage: ConfigurationStorage,
    terminals: TerminalManager,
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
        let program =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("secretbridge-server"));
        Self::build(
            trusted_origins,
            program,
            Catalog::in_memory().expect("an in-memory SQLite catalog should initialize"),
            ConfigurationStorage::MemoryOnly,
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
        let program =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("secretbridge-server"));
        let catalog = Catalog::open(database_path).map_err(AppStateInitializationError)?;
        catalog
            .recover_interrupted_runs()
            .map_err(|_| AppStateInitializationError(CatalogOpenError::Recovery))?;
        Ok(Self::build(
            trusted_origins,
            program,
            catalog,
            ConfigurationStorage::Sqlite,
        ))
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_with_terminal_program(
        trusted_origins: impl IntoIterator<Item = String>,
        program: PathBuf,
    ) -> (Self, String) {
        Self::build(
            trusted_origins,
            program,
            Catalog::in_memory().expect("an in-memory SQLite catalog should initialize"),
            ConfigurationStorage::MemoryOnly,
        )
    }

    fn build(
        trusted_origins: impl IntoIterator<Item = String>,
        program: PathBuf,
        catalog: Catalog,
        configuration_storage: ConfigurationStorage,
    ) -> (Self, String) {
        let bootstrap_token = new_token();
        let (session_revocations, _) = broadcast::channel(64);
        let state = Self {
            bootstrap_token: Arc::new(RwLock::new(Some(token_digest(&bootstrap_token)))),
            session_tokens: Arc::new(RwLock::new(HashMap::new())),
            session_revocations,
            trusted_origins: Arc::new(trusted_origins.into_iter().collect()),
            catalog,
            configuration_storage,
            terminals: TerminalManager::new(program),
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

#[derive(Serialize)]
struct PairResponse {
    session_token: String,
    token_type: &'static str,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    mode: &'static str,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTerminalRequest {
    rows: u16,
    cols: u16,
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
    ResourceInUse,
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
                "The synthetic terminal limit has been reached.",
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
            Self::ResourceInUse => (
                StatusCode::CONFLICT,
                "resource_in_use",
                "The resource is still referenced and cannot be deleted.",
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
        .route("/api/v1/session/pair", post(pair))
        .route("/api/v1/session", get(session).delete(revoke_session))
        .route(
            "/api/v1/credential-references",
            get(list_credential_references).post(create_credential_reference),
        )
        .route(
            "/api/v1/credential-references/{id}",
            delete(delete_credential_reference).put(update_credential_reference),
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
        .route("/api/v1/safe-events", get(list_safe_events))
        .route(
            "/api/v1/terminals",
            get(list_terminals).post(create_terminal),
        )
        .route("/api/v1/terminals/{id}", delete(delete_terminal))
        .route("/api/v1/terminals/{id}/attach", get(attach_terminal))
        .with_state(state)
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
    Json(StatusResponse::synthetic_only(
        paired,
        state.configuration_storage,
    ))
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
        mode: "synthetic_only",
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
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.delete_credential_reference(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
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
        execution_enabled: false,
    }))
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
        execution_enabled: false,
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
        execution_mode: "synthetic_simulation",
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
    let catalog = state.catalog.clone();
    let outcome = task::spawn_blocking(move || catalog.create_synthetic_run(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    let status = if outcome.replayed {
        StatusCode::OK
    } else {
        let run_id = outcome.run.id;
        let catalog = state.catalog.clone();
        tokio::spawn(drive_synthetic_run(catalog, run_id));
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(CreateSyntheticRunResponse {
            run: outcome.run,
            replayed: outcome.replayed,
            execution_mode: "synthetic_simulation",
        }),
    ))
}

async fn drive_synthetic_run(catalog: Catalog, run_id: Uuid) {
    sleep(Duration::from_millis(100)).await;
    let start_catalog = catalog.clone();
    let started = task::spawn_blocking(move || start_catalog.start_synthetic_run(run_id)).await;
    match started {
        Ok(Ok(_)) => {}
        Ok(Err(CatalogError::ApprovalNotUsable)) => {
            invalidate_synthetic_run(catalog, run_id).await;
            return;
        }
        _ => return,
    }
    sleep(Duration::from_millis(750)).await;
    let complete_catalog = catalog.clone();
    let completed =
        task::spawn_blocking(move || complete_catalog.complete_synthetic_run(run_id)).await;
    if matches!(completed, Ok(Err(CatalogError::ApprovalNotUsable))) {
        invalidate_synthetic_run(catalog, run_id).await;
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
    let catalog = state.catalog.clone();
    let run = task::spawn_blocking(move || catalog.cancel_synthetic_run(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(run))
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

async fn create_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTerminalRequest>,
) -> Result<(StatusCode, Json<TerminalSummary>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let terminals = state.terminals.clone();
    let summary = task::spawn_blocking(move || terminals.create(request.rows, request.cols))
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
                message: "The synthetic terminal does not exist.",
            },
        )
        .await;
        return None;
    };
    if send_server_message(
        socket,
        &ServerTerminalMessage::Ready {
            terminal_id: snapshot.summary.id,
            mode: "synthetic_only",
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
                    message: "The synthetic terminal process failed.",
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
            message: "The synthetic terminal operation failed.",
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
mod tests {
    use std::fs;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header::AUTHORIZATION},
    };
    use http_body_util::BodyExt;
    use secretbridge_core::ConfigurationStorage;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::{AppState, SESSION_TTL, apply_security_headers, router};

    const ORIGIN: &str = "http://127.0.0.1:8787";

    fn test_app() -> (axum::Router, String) {
        let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
        (router(state), bootstrap)
    }

    #[test]
    fn persistent_state_reports_sqlite_storage() {
        let path = std::env::temp_dir().join(format!(
            "secretbridge-state-test-{}.sqlite3",
            Uuid::new_v4()
        ));
        let (state, _) = AppState::new_persistent([ORIGIN.to_owned()], &path)
            .expect("persistent application state");

        assert_eq!(state.configuration_storage, ConfigurationStorage::Sqlite);
        drop(state);
        fs::remove_file(path).expect("remove temporary database");
    }

    #[tokio::test]
    async fn status_is_explicitly_synthetic_only() {
        let (app, _) = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let status: serde_json::Value = serde_json::from_slice(&bytes).expect("status JSON");
        assert_eq!(status["mode"], "synthetic_only");
        assert_eq!(status["identity_boundary"], "unverified_same_user");
        assert_eq!(status["configuration_storage"], "memory_only");
        assert_eq!(status["real_credentials_enabled"], false);
    }

    #[tokio::test]
    async fn pairing_rejects_missing_origin() {
        let (app, bootstrap) = test_app();
        let response = app
            .oneshot(pair_request(&bootstrap, None))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pairing_rejects_wrong_token() {
        let (app, _) = test_app();
        let response = app
            .oneshot(pair_request("synthetic-wrong-token", Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_token_can_only_be_used_once() {
        let (app, bootstrap) = test_app();
        let first = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(first.status(), StatusCode::OK);
        let body = first
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        assert_eq!(pair["token_type"], "Bearer");
        assert_eq!(pair["expires_in_seconds"], SESSION_TTL.as_secs());
        assert!(
            pair["session_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );

        let replay = app
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_can_be_checked_and_revoked() {
        let (app, bootstrap) = test_app();
        let paired = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        let body = paired
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        let token = pair["session_token"]
            .as_str()
            .expect("session token")
            .to_owned();

        let session = app
            .clone()
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/session",
                &token,
                None,
            ))
            .await
            .expect("router response");
        assert_eq!(session.status(), StatusCode::OK);

        let revoked = app
            .clone()
            .oneshot(authenticated_request(
                "DELETE",
                "/api/v1/session",
                &token,
                Some(ORIGIN),
            ))
            .await
            .expect("router response");
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

        let rejected = app
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/session",
                &token,
                None,
            ))
            .await
            .expect("router response");
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn terminal_creation_requires_a_trusted_origin() {
        let (app, bootstrap) = test_app();
        let paired = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        let body = paired
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        let token = pair["session_token"].as_str().expect("session token");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/terminals")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":24,"cols":80}"#))
                    .expect("valid request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn catalog_relationships_are_session_protected_and_deletable_in_order() {
        let (app, bootstrap) = test_app();
        let token = pair_test_session(&app, &bootstrap).await;

        let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/credential-references",
                &token,
                ORIGIN,
                r#"{"name":"Synthetic database operator","kind":"password","purpose":"Test-only metadata"}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(created.status(), StatusCode::CREATED);
        let credential = response_json(created).await;
        assert_eq!(credential["secret_state"], "not_configured");
        assert!(credential.get("secret").is_none());
        let credential_id = credential["id"].as_str().expect("credential id");

        let target_body = serde_json::json!({
            "name": "Synthetic reporting database",
            "kind": "database",
            "environment": "test",
            "description": "No network address is accepted in this alpha",
            "credential_reference_id": credential_id,
        })
        .to_string();
        let target = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/targets",
                &token,
                ORIGIN,
                &target_body,
            ))
            .await
            .expect("router response");
        assert_eq!(target.status(), StatusCode::CREATED);
        let target = response_json(target).await;
        let target_id = target["id"].as_str().expect("target id");

        let in_use = app
            .clone()
            .oneshot(authenticated_request(
                "DELETE",
                &format!("/api/v1/credential-references/{credential_id}"),
                &token,
                Some(ORIGIN),
            ))
            .await
            .expect("router response");
        assert_eq!(in_use.status(), StatusCode::CONFLICT);

        let targets = app
            .clone()
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/targets",
                &token,
                None,
            ))
            .await
            .expect("router response");
        assert_eq!(targets.status(), StatusCode::OK);
        let body = targets
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let targets: serde_json::Value = serde_json::from_slice(&body).expect("targets JSON");
        assert_eq!(targets["storage"], "memory_only");
        assert_eq!(targets["items"].as_array().map(Vec::len), Some(1));

        let deleted_target = app
            .clone()
            .oneshot(authenticated_request(
                "DELETE",
                &format!("/api/v1/targets/{target_id}"),
                &token,
                Some(ORIGIN),
            ))
            .await
            .expect("router response");
        assert_eq!(deleted_target.status(), StatusCode::NO_CONTENT);

        let deleted_credential = app
            .oneshot(authenticated_request(
                "DELETE",
                &format!("/api/v1/credential-references/{credential_id}"),
                &token,
                Some(ORIGIN),
            ))
            .await
            .expect("router response");
        assert_eq!(deleted_credential.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn credential_reference_api_rejects_secret_fields() {
        let (app, bootstrap) = test_app();
        let token = pair_test_session(&app, &bootstrap).await;
        let response = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/credential-references",
                &token,
                ORIGIN,
                r#"{"name":"Rejected input","kind":"api_token","secret":"synthetic-placeholder"}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let list = app
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/credential-references",
                &token,
                None,
            ))
            .await
            .expect("router response");
        let body = list
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let list: serde_json::Value = serde_json::from_slice(&body).expect("list JSON");
        assert_eq!(list["storage"], "memory_only");
        assert_eq!(list["items"].as_array().map(Vec::len), Some(0));
    }

    #[tokio::test]
    async fn catalog_update_requires_origin_and_increments_version() {
        let (app, bootstrap) = test_app();
        let token = pair_test_session(&app, &bootstrap).await;
        let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/credential-references",
                &token,
                ORIGIN,
                r#"{"name":"Synthetic reference","kind":"password"}"#,
            ))
            .await
            .expect("router response");
        let item = response_json(created).await;
        let id = item["id"].as_str().expect("credential id");
        assert_eq!(item["version"], 1);

        let missing_origin = app
            .clone()
            .oneshot(authenticated_request_with_body(
                "PUT",
                &format!("/api/v1/credential-references/{id}"),
                &token,
                None,
                r#"{"name":"Blocked update","kind":"api_token","expected_version":1}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

        let updated = app
            .clone()
            .oneshot(authenticated_json_request(
                "PUT",
                &format!("/api/v1/credential-references/{id}"),
                &token,
                ORIGIN,
                r#"{"name":"Updated reference","kind":"api_token","purpose":"Synthetic metadata","expected_version":1}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(updated.status(), StatusCode::OK);
        let item = response_json(updated).await;
        assert_eq!(item["name"], "Updated reference");
        assert_eq!(item["version"], 2);
        assert_eq!(item["secret_state"], "not_configured");

        let stale = app
            .oneshot(authenticated_json_request(
                "PUT",
                &format!("/api/v1/credential-references/{id}"),
                &token,
                ORIGIN,
                r#"{"name":"Stale update","kind":"password","expected_version":1}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let error = response_json(stale).await;
        assert_eq!(error["code"], "version_conflict");
    }

    #[tokio::test]
    async fn approval_api_is_scoped_versioned_and_never_executes() {
        let (app, bootstrap) = test_app();
        let token = pair_test_session(&app, &bootstrap).await;
        let template_id = create_test_action_template(&app, &token).await;
        let create_body = serde_json::json!({
            "action_template_id": template_id,
            "reason": "Verify approval lifecycle without an operation",
            "expires_in_seconds": 300
        })
        .to_string();

        let missing_origin = app
            .clone()
            .oneshot(authenticated_request_with_body(
                "POST",
                "/api/v1/approvals",
                &token,
                None,
                &create_body,
            ))
            .await
            .expect("router response");
        assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

        let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/approvals",
                &token,
                ORIGIN,
                &create_body,
            ))
            .await
            .expect("router response");
        assert_eq!(created.status(), StatusCode::CREATED);
        let approval = response_json(created).await;
        assert_eq!(approval["state"], "pending");
        assert_eq!(approval["version"], 1);
        assert_eq!(approval["action_template_id"], template_id);
        assert_eq!(approval["action_template_version"], 1);
        let approval_id = approval["id"].as_str().expect("approval id");

        let approved = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                &format!("/api/v1/approvals/{approval_id}/approve"),
                &token,
                ORIGIN,
                r#"{"expected_version":1,"note":"Scope reviewed"}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(approved.status(), StatusCode::OK);
        let approved = response_json(approved).await;
        assert_eq!(approved["state"], "approved");
        assert_eq!(approved["version"], 2);

        let invalid = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                &format!("/api/v1/approvals/{approval_id}/deny"),
                &token,
                ORIGIN,
                r#"{"expected_version":2}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(invalid.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(invalid).await["code"],
            "invalid_approval_transition"
        );

        let revoked = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                &format!("/api/v1/approvals/{approval_id}/revoke"),
                &token,
                ORIGIN,
                r#"{"expected_version":2,"note":"No longer needed"}"#,
            ))
            .await
            .expect("router response");
        let revoked = response_json(revoked).await;
        assert_eq!(revoked["state"], "revoked");
        assert_eq!(revoked["version"], 3);

        let list = app
            .oneshot(authenticated_request(
                "GET",
                "/api/v1/approvals",
                &token,
                None,
            ))
            .await
            .expect("router response");
        let list = response_json(list).await;
        assert_eq!(list["execution_enabled"], false);
        assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn synthetic_run_api_is_idempotent_observable_and_origin_protected() {
        let (app, bootstrap) = test_app();
        let token = pair_test_session(&app, &bootstrap).await;
        let approval_id = create_test_approved_approval(&app, &token).await;
        let body = serde_json::json!({
            "approval_id": approval_id,
            "idempotency_key": "integration-run-001"
        })
        .to_string();

        let rejected = app
            .clone()
            .oneshot(authenticated_request_with_body(
                "POST",
                "/api/v1/runs",
                &token,
                None,
                &body,
            ))
            .await
            .expect("router response");
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/runs",
                &token,
                ORIGIN,
                &body,
            ))
            .await
            .expect("router response");
        assert_eq!(created.status(), StatusCode::CREATED);
        let created = response_json(created).await;
        assert_eq!(created["execution_mode"], "synthetic_simulation");
        assert_eq!(created["replayed"], false);
        let run_id = created["run"]["id"].as_str().expect("run id");

        let replayed = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/runs",
                &token,
                ORIGIN,
                &body,
            ))
            .await
            .expect("router response");
        assert_eq!(replayed.status(), StatusCode::OK);
        let replayed = response_json(replayed).await;
        assert_eq!(replayed["replayed"], true);
        assert_eq!(replayed["run"]["id"], run_id);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let completed = app
            .clone()
            .oneshot(authenticated_request(
                "GET",
                &format!("/api/v1/runs/{run_id}"),
                &token,
                None,
            ))
            .await
            .expect("router response");
        let completed = response_json(completed).await;
        assert_eq!(completed["state"], "succeeded");
        assert_eq!(completed["result_status"], "synthetic_ok");

        let events = app
            .clone()
            .oneshot(authenticated_request(
                "GET",
                &format!("/api/v1/runs/{run_id}/events"),
                &token,
                None,
            ))
            .await
            .expect("router response");
        let events = response_json(events).await;
        assert_eq!(events["payload_policy"], "fixed_safe_messages_only");
        assert_eq!(events["items"].as_array().map(Vec::len), Some(3));

        let consumed_body = serde_json::json!({
            "approval_id": approval_id,
            "idempotency_key": "integration-run-002"
        })
        .to_string();
        let consumed = app
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/runs",
                &token,
                ORIGIN,
                &consumed_body,
            ))
            .await
            .expect("router response");
        assert_eq!(consumed.status(), StatusCode::CONFLICT);
        assert_eq!(response_json(consumed).await["code"], "approval_consumed");
    }

    #[tokio::test]
    async fn synthetic_run_driver_stops_after_approval_revocation() {
        let (app, bootstrap) = test_app();
        let token = pair_test_session(&app, &bootstrap).await;
        let approval_id = create_test_approved_approval(&app, &token).await;
        let body = serde_json::json!({
            "approval_id": approval_id,
            "idempotency_key": "integration-revocation-001"
        })
        .to_string();
        let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/runs",
                &token,
                ORIGIN,
                &body,
            ))
            .await
            .expect("router response");
        let created = response_json(created).await;
        let run_id = created["run"]["id"].as_str().expect("run id");

        let revoked = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                &format!("/api/v1/approvals/{approval_id}/revoke"),
                &token,
                ORIGIN,
                r#"{"expected_version":2,"note":"Authorization withdrawn during integration test"}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(revoked.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let stopped = app
            .clone()
            .oneshot(authenticated_request(
                "GET",
                &format!("/api/v1/runs/{run_id}"),
                &token,
                None,
            ))
            .await
            .expect("router response");
        let stopped = response_json(stopped).await;
        assert_eq!(stopped["state"], "cancelled");
        assert_eq!(stopped["result_status"], "authorization_revoked");

        let events = app
            .oneshot(authenticated_request(
                "GET",
                &format!("/api/v1/runs/{run_id}/events"),
                &token,
                None,
            ))
            .await
            .expect("router response");
        let events = response_json(events).await;
        let last_event = events["items"].as_array().and_then(|items| items.last());
        assert_eq!(
            last_event.and_then(|event| event["kind"].as_str()),
            Some("authorization_revoked")
        );
    }

    #[tokio::test]
    async fn security_headers_cover_web_fallbacks() {
        let app = apply_security_headers(axum::Router::new().fallback(|| async { "web" }));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(response.headers().contains_key("content-security-policy"));
    }

    fn pair_request(token: &str, origin: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/session/pair")
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(Body::empty()).expect("valid request")
    }

    async fn pair_test_session(app: &axum::Router, bootstrap: &str) -> String {
        let paired = app
            .clone()
            .oneshot(pair_request(bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        let body = paired
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        pair["session_token"]
            .as_str()
            .expect("session token")
            .to_owned()
    }

    async fn create_test_action_template(app: &axum::Router, token: &str) -> String {
        let target = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/targets",
                token,
                ORIGIN,
                r#"{"name":"Synthetic health target","kind":"http_service","environment":"test"}"#,
            ))
            .await
            .expect("router response");
        let target = response_json(target).await;
        let body = serde_json::json!({
            "target_id": target["id"],
            "name": "Synthetic target health",
            "operation": "synthetic_health_check",
            "result_scope": "status_only",
            "description": "Fixed synthetic template",
            "timeout_seconds": 15
        })
        .to_string();
        let template = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/action-templates",
                token,
                ORIGIN,
                &body,
            ))
            .await
            .expect("router response");
        assert_eq!(template.status(), StatusCode::CREATED);
        response_json(template).await["id"]
            .as_str()
            .expect("template id")
            .to_owned()
    }

    async fn create_test_approved_approval(app: &axum::Router, token: &str) -> String {
        let template_id = create_test_action_template(app, token).await;
        let body = serde_json::json!({
            "action_template_id": template_id,
            "reason": "Synthetic integration run",
            "expires_in_seconds": 300
        })
        .to_string();
        let created = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                "/api/v1/approvals",
                token,
                ORIGIN,
                &body,
            ))
            .await
            .expect("router response");
        let approval = response_json(created).await;
        let id = approval["id"].as_str().expect("approval id").to_owned();
        let approved = app
            .clone()
            .oneshot(authenticated_json_request(
                "POST",
                &format!("/api/v1/approvals/{id}/approve"),
                token,
                ORIGIN,
                r#"{"expected_version":1,"note":"Integration scope approved"}"#,
            ))
            .await
            .expect("router response");
        assert_eq!(approved.status(), StatusCode::OK);
        id
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let body = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        serde_json::from_slice(&body).expect("response JSON")
    }

    fn authenticated_json_request(
        method: &str,
        uri: &str,
        token: &str,
        origin: &str,
        body: &str,
    ) -> Request<Body> {
        authenticated_request_with_body(method, uri, token, Some(origin), body)
    }

    fn authenticated_request_with_body(
        method: &str,
        uri: &str,
        token: &str,
        origin: Option<&str>,
        body: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("content-type", "application/json");
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder
            .body(Body::from(body.to_owned()))
            .expect("valid request")
    }

    fn authenticated_request(
        method: &str,
        uri: &str,
        token: &str,
        origin: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(Body::empty()).expect("valid request")
    }
}
