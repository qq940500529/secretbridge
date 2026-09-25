// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::adapters::mcp;
use crate::{
    AUTHORIZATION, ActionTemplate, AppState, Approval, Arc, AxumPath, BEARER_PREFIX,
    BrowserAuthMode, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CancelSyntheticRun, CancellationToken,
    Catalog, CatalogError, ConfigurationStorage, ConstantTimeEq, CreateActionTemplate,
    CreateApproval, CreateCredentialReference, CreateRunOutcome, CreateSyntheticRun, CreateTarget,
    CreateTerminal, CredentialReference, CredentialService, CredentialServiceError, DecideApproval,
    DefaultBodyLimit, Deserialize, Digest, Duration, Error, HeaderMap, HeaderName, HeaderValue,
    Instant, IntoResponse, Json, MAX_WEBSOCKET_MESSAGE_BYTES, Message, Method, Next, Path, PathBuf,
    PolicyEvaluation, Request, Response, Router, SafeEvent, SecretStoreError, Serialize, ServeDir,
    SetResponseHeaderLayer, Sha256, State, StatusCode, StatusResponse, SyntheticRun, SystemTime,
    Target, TerminalCapabilities, TerminalConnection, TerminalError, TerminalEvent, TerminalShell,
    TerminalStatus, TerminalSummary, UNIX_EPOCH, UpdateActionTemplate, UpdateCredentialReference,
    UpdateTarget, Uuid, WEBSOCKET_AUTH_TIMEOUT, WEBSOCKET_SEND_TIMEOUT, WebSocket,
    WebSocketUpgrade, Zeroize, broadcast, catalog, command, credential_service, delete,
    drive_postgres_check, get, middleware, post, put, runtime, sleep, task, timeout, totp_auth,
};

mod auth;
mod auth_events;
mod catalog_routes;
mod conversations;
mod maintenance;
pub(crate) mod notifications;
mod pin;
mod runs;
mod terminal_routes;
pub(crate) mod totp;

use auth_events as browser_auth_events_api;
use conversations as conversation_api;
use maintenance as maintenance_api;

pub(crate) use auth::{
    authentication_attempt_allowed, record_authentication_failure, reset_authentication_attempts,
};
use auth::{browser_auth_methods, pair, revoke_session, session, status};
use catalog_routes::{
    approve_approval, clear_credential_secret, create_action_template, create_approval,
    create_credential_reference, create_target, delete_action_template,
    delete_credential_reference, delete_target, deny_approval, evaluate_action_template,
    get_action_template, list_action_templates, list_approvals, list_credential_references,
    list_targets, revoke_approval, set_credential_secret, update_action_template,
    update_credential_reference, update_target,
};
use pin::{pair_with_pin, recover_pin, regenerate_recovery_key, set_browser_auth_method};
pub(crate) use pin::{valid_browser_pin, verify_current_browser_auth};
pub use runs::serve_mcp_stdio_bridge;
pub(crate) use runs::{
    cancel_run_for_state, create_run_for_state, invalidate_synthetic_run, run_execution_mode,
};
use runs::{
    cancel_synthetic_run, create_synthetic_run, get_synthetic_run, list_run_safe_events,
    list_safe_events, list_synthetic_runs,
};
use terminal_routes::{
    attach_terminal, create_terminal, delete_terminal, get_terminal_capabilities, list_terminals,
    send_socket_message,
};

#[derive(Serialize)]
pub(crate) struct PairResponse {
    pub(crate) session_token: String,
    pub(crate) token_type: &'static str,
    pub(crate) expires_in_seconds: u64,
}

#[derive(Serialize)]
struct BrowserAuthMethodsResponse {
    pin_enabled: bool,
    totp_enabled: bool,
    pairing_link_enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinPairRequest {
    pin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverPinRequest {
    recovery_key: String,
    new_pin: String,
}

#[derive(Serialize)]
struct RecoveryKeyResponse {
    recovery_key: String,
}

#[derive(Serialize)]
struct RecoveredSessionResponse {
    recovery_key: String,
    session_token: String,
    token_type: &'static str,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpCodeRequest {
    pub(crate) code: String,
}

#[derive(Serialize)]
pub(crate) struct TotpSetupResponse {
    pub(crate) manual_key: String,
    pub(crate) qr_code_data_url: String,
    pub(crate) expires_in_seconds: u64,
    pub(crate) accepted_past_steps: u64,
}

impl Drop for TotpSetupResponse {
    fn drop(&mut self) {
        self.manual_key.zeroize();
        self.qr_code_data_url.zeroize();
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum BrowserAuthMethod {
    PairingLink,
    Pin,
    DisableTotp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBrowserAuthMethodRequest {
    method: BrowserAuthMethod,
    #[serde(default)]
    pin: Option<String>,
    #[serde(default)]
    current_pin: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentBrowserAuthProof {
    #[serde(default)]
    pub(crate) current_pin: Option<String>,
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

#[derive(Debug)]
pub(crate) enum ApiError {
    ApprovalConsumed,
    ApprovalNotUsable,
    BadRequest,
    CatalogCapacity,
    Internal,
    InvalidApprovalTransition,
    InvalidRunTransition,
    IdempotencyConflict,
    InitializationRequired,
    InvalidOrigin,
    NotFound,
    PolicyDenied,
    ResourceInUse,
    RateLimited(u64),
    SecretEntryNotFound,
    SecretStoreLocked,
    SecretStoreUnavailable,
    SecretStoreTimedOut,
    TerminalCapacity,
    Unauthorized,
    VersionConflict,
}

impl IntoResponse for ApiError {
    #[expect(
        clippy::too_many_lines,
        reason = "fixed public error codes remain auditable in one response mapping"
    )]
    fn into_response(self) -> Response {
        if let Self::RateLimited(seconds) = self {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    code: "rate_limited",
                    message: "Wait before trying again.",
                }),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert("retry-after", value);
            }
            return response;
        }
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
            Self::InitializationRequired => (
                StatusCode::CONFLICT,
                "initialization_required",
                "Set a PIN in the local management page before using the broker.",
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
            Self::RateLimited(_) => unreachable!("handled above"),
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
            Self::SecretStoreTimedOut => (
                StatusCode::GATEWAY_TIMEOUT,
                "secret_store_timed_out",
                "The operating-system credential store did not respond in time.",
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

pub(crate) const fn map_secret_store_error(error: SecretStoreError) -> ApiError {
    match error {
        SecretStoreError::NotFound => ApiError::SecretEntryNotFound,
        SecretStoreError::LockedOrDenied => ApiError::SecretStoreLocked,
        SecretStoreError::Unavailable => ApiError::SecretStoreUnavailable,
    }
}

pub(crate) fn map_credential_service_error(error: CredentialServiceError) -> ApiError {
    match error {
        CredentialServiceError::Catalog(error) => map_catalog_error(error),
        CredentialServiceError::NotConfigured => ApiError::BadRequest,
        CredentialServiceError::Store(error) => map_secret_store_error(error),
        CredentialServiceError::TimedOut => ApiError::SecretStoreTimedOut,
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
        .route("/api/v1/session/recover", post(recover_pin))
        .route(
            "/api/v1/session/recovery-key",
            post(regenerate_recovery_key),
        )
        .route("/api/v1/session/totp", post(totp_auth::pair))
        .route("/api/v1/session/totp/setup", post(totp_auth::start_setup))
        .route(
            "/api/v1/session/totp/confirm",
            post(totp_auth::confirm_setup),
        )
        .route("/api/v1/session/methods", get(browser_auth_methods))
        .route(
            "/api/v1/session/auth-events",
            get(browser_auth_events_api::list),
        )
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
            get(get_action_template)
                .delete(delete_action_template)
                .put(update_action_template),
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
        .route(
            "/api/v1/runs/{id}/output",
            post(get_run_output).delete(delete_run_output),
        )
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
        .merge(conversation_api::routes())
        .merge(notifications::routes())
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            notify_mutations,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_initialization,
        ))
        .with_state(state)
}

async fn require_initialization(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let path = request.uri().path();
    if state.runtime_control.is_some()
        && path.starts_with("/api/v1/")
        && !path.starts_with("/api/v1/session")
        && path != "/api/v1/status"
        && path != "/api/v1/runtime/stop"
        && !state
            .catalog
            .diagnostic_vault_ready()
            .map_err(map_catalog_error)?
    {
        return Err(ApiError::InitializationRequired);
    }
    Ok(next.run(request).await)
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

async fn delete_run_output(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.clear_output(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    let _ = state.changes.send(());
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn now_unix_ms() -> u64 {
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

pub(crate) fn apply_security_headers(router: Router) -> Router {
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

pub(crate) async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<u64, ApiError> {
    let token = bearer_token(headers).ok_or(ApiError::Unauthorized)?;
    state
        .authenticate(token)
        .await
        .ok_or(ApiError::Unauthorized)
}

pub(crate) fn map_terminal_error(error: TerminalError) -> ApiError {
    match error {
        TerminalError::Capacity => ApiError::TerminalCapacity,
        TerminalError::Busy
        | TerminalError::ContextUnknown
        | TerminalError::InvalidInput
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

pub(crate) fn map_catalog_error(error: CatalogError) -> ApiError {
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

pub(crate) fn validate_origin(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
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

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix(BEARER_PREFIX)
        .filter(|token| !token.is_empty())
}

pub(crate) fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub(crate) fn constant_time_equal(presented: &[u8; 32], expected: &[u8; 32]) -> bool {
    bool::from(presented.ct_eq(expected))
}

pub(crate) fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
