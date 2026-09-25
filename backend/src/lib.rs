// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod adapters;
mod application;
mod domain;
pub(crate) use domain::parameters;
#[cfg(test)]
mod security_acceptance;
#[cfg(test)]
mod stability_acceptance;

pub(crate) use adapters::http::totp as totp_auth;
pub(crate) use adapters::persistence as catalog;
pub(crate) use adapters::secrets as secret_store;
pub(crate) use adapters::terminal::{self, control as terminal_control};
pub(crate) use application::{
    backup_restore as maintenance, manage_credentials as credential_service,
    postgres_check as postgres_run,
};
mod runtime;
pub(crate) use adapters::executors::{
    command, database as database_task, git as git_task, http as http_task, postgres,
    sftp as sftp_task, ssh as ssh_task, telnet as telnet_task,
};

pub use adapters::native_ipc::{BrokerController, LocalMcpBridge};
pub use application::status::{ConfigurationStorage, RuntimeMode, StatusResponse};
pub use maintenance::{BackupReport, inspect_configuration_backup, restore_configuration_backup};
pub use runtime::RuntimeStatus;
pub const SCHEMA_VERSION: i64 = catalog::SCHEMA_VERSION;

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
use zeroize::Zeroize;

use catalog::{
    ActionTemplate, Approval, BrowserAuthChannel, BrowserAuthEventKind, BrowserAuthMode,
    CancelSyntheticRun, Catalog, CatalogError, CatalogOpenError, CreateActionTemplate,
    CreateApproval, CreateCredentialReference, CreateRunOutcome, CreateSyntheticRun, CreateTarget,
    CredentialReference, DecideApproval, PolicyEvaluation, SafeEvent, SecretState, SyntheticRun,
    Target, UpdateActionTemplate, UpdateCredentialReference, UpdateTarget,
};
use credential_service::{CredentialService, CredentialServiceError};
use postgres::PostgresExecutor;
use postgres_run::drive_postgres_check;
use secret_store::{SecretReadGate, SecretStore, SecretStoreError};
use terminal::{
    CreateTerminal, TerminalCapabilities, TerminalConnection, TerminalError, TerminalEvent,
    TerminalManager, TerminalShell, TerminalStatus, TerminalSummary,
};

const BEARER_PREFIX: &str = "Bearer ";
const SESSION_TTL: Duration = Duration::from_mins(30);
const BROWSER_TOTP_CREDENTIAL_ID: Uuid = Uuid::from_u128(0x5e63_7265_7462_7269_6467_6574_6f74_7001);
const WEBSOCKET_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const WEBSOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AppState {
    bootstrap_token: Arc<RwLock<Option<[u8; 32]>>>,
    session_tokens: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    session_revocations: broadcast::Sender<[u8; 32]>,
    pin_attempts: Arc<Mutex<PinAttempts>>,
    pin_verification_gate: Arc<Mutex<()>>,
    trusted_origins: Arc<HashSet<String>>,
    catalog: Catalog,
    configuration_storage: ConfigurationStorage,
    credential_mutations: Arc<Mutex<()>>,
    native_secret_mutations: Arc<Mutex<()>>,
    configuration_gate: Arc<RwLock<()>>,
    postgres_executor: Arc<dyn PostgresExecutor>,
    run_cancellations: RunCancellations,
    secret_store: Arc<dyn SecretStore>,
    secret_reads: SecretReadGate,
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
            pin_verification_gate: Arc::new(Mutex::new(())),
            trusted_origins: Arc::new(trusted_origins.into_iter().collect()),
            catalog,
            configuration_storage,
            credential_mutations: Arc::new(Mutex::new(())),
            native_secret_mutations: Arc::new(Mutex::new(())),
            configuration_gate: Arc::new(RwLock::new(())),
            postgres_executor,
            run_cancellations: RunCancellations::default(),
            secret_store,
            secret_reads: SecretReadGate::new(),
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

    async fn issue_session(&self) -> Result<(String, u64), ApiError> {
        let token = new_token();
        let digest = token_digest(&token);
        let expires_at_unix_ms = now_unix_ms().saturating_add(
            u64::try_from(SESSION_TTL.as_millis()).map_err(|_| ApiError::Internal)?,
        );
        self.catalog
            .store_browser_session(&digest, expires_at_unix_ms)
            .map_err(map_catalog_error)?;
        self.session_tokens
            .write()
            .await
            .insert(digest, Instant::now() + SESSION_TTL);
        Ok((token, SESSION_TTL.as_secs()))
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
        if let Some(remaining) = sessions
            .get(digest)
            .map(|expires_at| expires_at.saturating_duration_since(now).as_secs())
        {
            return Some(remaining);
        }
        let remaining = self
            .catalog
            .browser_session_remaining(digest, now_unix_ms())
            .ok()
            .flatten()?;
        sessions.insert(*digest, now + Duration::from_secs(remaining));
        Some(remaining)
    }

    async fn revoke(&self, token: &str) -> bool {
        let digest = token_digest(token);
        let cached = self.session_tokens.write().await.remove(&digest).is_some();
        let persisted = self
            .catalog
            .revoke_browser_session(&digest)
            .unwrap_or(false);
        let removed = cached || persisted;
        if removed {
            let _ = self.session_revocations.send(digest);
        }
        removed
    }

    fn active_session_count(&self) -> usize {
        self.catalog
            .active_browser_session_count(now_unix_ms())
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct PinAttempts {
    failures: u8,
    blocked_until: Option<Instant>,
    pending_totp_setup: Option<totp_auth::PendingSetup>,
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

#[cfg(test)]
use adapters::http::apply_security_headers;
pub use adapters::http::serve_mcp_stdio_bridge;
pub(crate) use adapters::http::{
    ApiError, CurrentBrowserAuthProof, PairResponse, TotpCodeRequest, TotpSetupResponse,
    authentication_attempt_allowed, cancel_run_for_state, create_run_for_state,
    invalidate_synthetic_run, map_catalog_error, map_secret_store_error, now_unix_ms,
    record_authentication_failure, require_session, reset_authentication_attempts,
    run_execution_mode, validate_origin, verify_current_browser_auth,
};
use adapters::http::{constant_time_equal, new_token, token_digest};
pub use adapters::http::{router, router_with_web};

#[cfg(test)]
#[path = "adapters/http/tests.rs"]
mod tests;
