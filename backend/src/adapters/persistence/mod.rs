// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::parameters::{AuthorizationMode, ParameterValues};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod ai_conversations;
mod approval_rows;
mod approvals;
mod browser_auth;
mod browser_session;
mod credentials;
pub(crate) mod diagnostic_vault;
mod diagnostics;
mod helpers;
pub(crate) mod maintenance;
mod notification_settings;
mod one_time;
mod rows;
mod runs;
mod safe_events;
mod schema;
mod targets;
mod templates;

pub use ai_conversations::AiConversation;
pub use ai_conversations::SetAiConversationPolicy;
use approval_rows::{approval_by_id, approval_from_row};
pub use browser_auth::{
    BrowserAuthChannel, BrowserAuthEvent, BrowserAuthEventKind, BrowserAuthMode,
};
use helpers::{
    credential_by_id, ensure_approval_policy, ensure_capacity, ensure_credential_exists,
    ensure_credential_reference_unlinked, ensure_target_exists, insert_safe_event,
    normalize_idempotency_key, normalize_optional, normalize_postgres_config, normalize_required,
    now_unix_ms_i64, policy_evaluation, save_command_slots, synthetic_run_by_approval,
    synthetic_run_by_id, synthetic_run_by_idempotency_key_hash, synthetic_run_from_row,
    target_by_id, u64_from_row, uuid_from_row, validate_command,
};
pub use notification_settings::ApprovalNotificationChannel;
use one_time::expire_approvals;
use rows::{action_template_by_id, action_template_from_row, credential_from_row, target_from_row};

pub(crate) use schema::SCHEMA_VERSION;
const SYNTHETIC_POLICY_VERSION: &str = "synthetic-policy-v1";
const POSTGRES_POLICY_VERSION: &str = "postgres-readonly-policy-v1";
const MAX_CREDENTIAL_REFERENCES: i64 = 128;
const MAX_TARGETS: i64 = 128;
const MAX_ACTIVE_APPROVALS: i64 = 512;
const MAX_ACTION_TEMPLATES: i64 = 256;
const MAX_ACTIVE_RUNS: i64 = 1_024;
const MAX_NAME_CHARS: usize = 80;
const MAX_DESCRIPTION_CHARS: usize = 240;
const MAX_ADDRESS_CHARS: usize = 2_048;
const MAX_USERNAME_CHARS: usize = 256;
const MIN_APPROVAL_TTL_SECONDS: u64 = 60;
const MAX_APPROVAL_TTL_SECONDS: u64 = 3_600;
const MAX_IDEMPOTENCY_KEY_CHARS: usize = 96;

#[derive(Clone)]
pub struct Catalog {
    connection: Arc<Mutex<Connection>>,
}

pub use diagnostics::DiagnosticFailure;

#[derive(Debug)]
pub enum CatalogOpenError {
    Database(rusqlite::Error),
    Recovery,
    UnsupportedSchema(i64),
}

impl fmt::Display for CatalogOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("the configuration database could not open"),
            Self::Recovery => formatter.write_str("interrupted runs could not be recovered"),
            Self::UnsupportedSchema(version) => {
                write!(
                    formatter,
                    "configuration schema version {version} is newer than supported"
                )
            }
        }
    }
}

impl Error for CatalogOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Recovery | Self::UnsupportedSchema(_) => None,
        }
    }
}

impl From<rusqlite::Error> for CatalogOpenError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub use crate::domain::approvals::{
    Approval, ApprovalOperation, ApprovalResultScope, ApprovalState, CreateApproval,
    DecideApproval, PolicyDecision, PolicyEvaluation, PolicyReasonCode, PolicyRequirement,
};
pub use crate::domain::runs::{
    CancelSyntheticRun, CreateSyntheticRun, RunState, SafeEvent, SafeEventKind, SyntheticRun,
};

impl ApprovalOperation {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::InspectMetadata => "inspect_metadata",
            Self::SyntheticHealthCheck => "synthetic_health_check",
            Self::PostgresConnectionCheck => "postgres_connection_check",
            Self::CommandExecution => "command_execution",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "inspect_metadata" => Ok(Self::InspectMetadata),
            "synthetic_health_check" => Ok(Self::SyntheticHealthCheck),
            "postgres_connection_check" => Ok(Self::PostgresConnectionCheck),
            "command_execution" => Ok(Self::CommandExecution),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl ApprovalResultScope {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::StatusOnly => "status_only",
            Self::MetadataSummary => "metadata_summary",
            Self::SanitizedOutput => "sanitized_output",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "status_only" => Ok(Self::StatusOnly),
            "metadata_summary" => Ok(Self::MetadataSummary),
            "sanitized_output" => Ok(Self::SanitizedOutput),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl ApprovalState {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl RunState {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl SafeEventKind {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::AuthorizationRevoked => "authorization_revoked",
            Self::Requested => "requested",
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
            Self::Failed => "failed",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "authorization_revoked" => Ok(Self::AuthorizationRevoked),
            "requested" => Ok(Self::Requested),
            "started" => Ok(Self::Started),
            "succeeded" => Ok(Self::Succeeded),
            "cancelled" => Ok(Self::Cancelled),
            "interrupted" => Ok(Self::Interrupted),
            "failed" => Ok(Self::Failed),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

pub use crate::domain::credentials::{
    CreateCredentialReference, CredentialKind, CredentialReference, SecretState,
    UpdateCredentialReference,
};
pub use crate::domain::targets::{
    CreateTarget, PostgresTargetConfig, PostgresTlsMode, Target, TargetEnvironment, TargetKind,
    UpdateTarget,
};

impl CredentialKind {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ApiToken => "api_token",
            Self::SshKey => "ssh_key",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "password" => Ok(Self::Password),
            "api_token" => Ok(Self::ApiToken),
            "ssh_key" => Ok(Self::SshKey),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl PostgresTlsMode {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::VerifyFull => "verify_full",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "verify_full" => Ok(Self::VerifyFull),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl TargetKind {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::HttpService => "http_service",
            Self::SshHost => "ssh_host",
            Self::TelnetHost => "telnet_host",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "database" => Ok(Self::Database),
            "http_service" => Ok(Self::HttpService),
            "ssh_host" => Ok(Self::SshHost),
            "telnet_host" => Ok(Self::TelnetHost),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

impl TargetEnvironment {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" => Ok(Self::Production),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ActionTemplate {
    pub command: Option<crate::command::CommandConfig>,
    pub one_time: bool,
    pub terminal_available: bool,
    pub id: Uuid,
    pub target_id: Uuid,
    pub name: String,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub description: Option<String>,
    pub timeout_seconds: u64,
    pub enabled: bool,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateActionTemplate {
    #[serde(default)]
    pub(crate) command: Option<crate::command::CommandConfig>,
    pub(crate) target_id: Uuid,
    pub(crate) name: String,
    pub(crate) operation: ApprovalOperation,
    pub(crate) result_scope: ApprovalResultScope,
    pub(crate) description: Option<String>,
    pub(crate) timeout_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateActionTemplate {
    #[serde(default)]
    command: Option<crate::command::CommandConfig>,
    target_id: Uuid,
    name: String,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    description: Option<String>,
    timeout_seconds: u64,
    enabled: bool,
    expected_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    ApprovalConsumed,
    ApprovalNotUsable,
    Capacity,
    CredentialReferenceNotFound,
    Invalid,
    InvalidApprovalTransition,
    InvalidRunTransition,
    IdempotencyConflict,
    NotFound,
    PolicyDenied,
    ResourceInUse,
    Storage,
    VersionConflict,
}

impl From<crate::parameters::InvalidParameters> for CatalogError {
    fn from(_: crate::parameters::InvalidParameters) -> Self {
        Self::Invalid
    }
}

pub struct CreateRunOutcome {
    pub run: SyntheticRun,
    pub replayed: bool,
}

#[derive(Clone)]
pub struct RunExecutionContext {
    pub approval: Approval,
    pub template: ActionTemplate,
    pub target: Target,
    pub credential: Option<CredentialReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresRunResult {
    ConnectionOk,
    ConnectionFailed,
    ConfigurationInvalid,
    CredentialUnavailable,
    TimedOut,
}

impl PostgresRunResult {
    const fn status(self) -> &'static str {
        match self {
            Self::ConnectionOk => "postgres_connection_ok",
            Self::ConnectionFailed => "postgres_connection_failed",
            Self::ConfigurationInvalid => "postgres_configuration_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::TimedOut => "timed_out",
        }
    }
}

impl Catalog {
    pub fn open(path: &Path) -> Result<Self, CatalogOpenError> {
        crate::maintenance::open_with_migration_backup(path)
    }

    pub fn in_memory() -> Result<Self, CatalogOpenError> {
        Self::initialize(Connection::open_in_memory()?)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "transactional schema migrations remain auditable when kept together"
    )]
    pub(crate) fn initialize(connection: Connection) -> Result<Self, CatalogOpenError> {
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "busy_timeout", 5_000_i64)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        schema::prepare(&connection)?;
        one_time::repair_lifecycle(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }
}

impl Catalog {
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests;
