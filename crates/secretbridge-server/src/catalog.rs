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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod browser_auth;
mod browser_session;
pub(crate) mod maintenance;
mod rows;
mod schema;

pub use browser_auth::{
    BrowserAuthChannel, BrowserAuthEvent, BrowserAuthEventKind, BrowserAuthMode,
};
use rows::{credential_from_row, target_from_row};

pub(crate) const SCHEMA_VERSION: i64 = secretbridge_core::SCHEMA_VERSION;
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    ApiToken,
    SshKey,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    NotConfigured,
    Available,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialReference {
    pub id: Uuid,
    pub name: String,
    pub kind: CredentialKind,
    pub purpose: Option<String>,
    pub address: Option<String>,
    pub username: Option<String>,
    pub secret_state: SecretState,
    pub secret_updated_at_unix_ms: Option<u64>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresTlsMode {
    VerifyFull,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresTargetConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub tls_mode: PostgresTlsMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredentialReference {
    name: String,
    kind: CredentialKind,
    purpose: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCredentialReference {
    name: String,
    kind: CredentialKind,
    purpose: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    username: Option<String>,
    expected_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Database,
    HttpService,
    SshHost,
    TelnetHost,
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetEnvironment {
    Development,
    Test,
    Production,
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
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub kind: TargetKind,
    pub environment: TargetEnvironment,
    pub description: Option<String>,
    pub address: Option<String>,
    pub username: Option<String>,
    pub allow_insecure_protocol: bool,
    pub credential_reference_id: Option<Uuid>,
    pub postgres: Option<PostgresTargetConfig>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTarget {
    pub(crate) name: String,
    pub(crate) kind: TargetKind,
    pub(crate) environment: TargetEnvironment,
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) address: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) allow_insecure_protocol: bool,
    pub(crate) credential_reference_id: Option<Uuid>,
    pub(crate) postgres: Option<PostgresTargetConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTarget {
    name: String,
    kind: TargetKind,
    environment: TargetEnvironment,
    description: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    allow_insecure_protocol: bool,
    credential_reference_id: Option<Uuid>,
    postgres: Option<PostgresTargetConfig>,
    expected_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOperation {
    InspectMetadata,
    SyntheticHealthCheck,
    PostgresConnectionCheck,
    CommandExecution,
}

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResultScope {
    StatusOnly,
    MetadataSummary,
    SanitizedOutput,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActionTemplate {
    pub command: Option<crate::command::CommandConfig>,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    EligibleForApproval,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasonCode {
    FixedSyntheticScope,
    FixedPostgresConnectionCheck,
    FixedCommandTemplate,
    TemplateDisabled,
    TargetIncompatible,
    PostgresConfigurationMissing,
    CredentialMissing,
    CredentialNotConfigured,
    CredentialKindUnsupported,
    ResultScopeUnsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRequirement {
    ValidatedParameters,
    ScopedAuthorization,
    ExplicitApproval,
    NoParameters,
    SingleUse,
    SyntheticOnly,
    TransitionRevalidation,
    TlsVerifyFull,
    ReadOnlyTransaction,
    StructuredStatusOnly,
    RedactedOutput,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyEvaluation {
    pub policy_version: &'static str,
    pub decision: PolicyDecision,
    pub reason_codes: Vec<PolicyReasonCode>,
    pub requirements: Vec<PolicyRequirement>,
    pub action_template_id: Uuid,
    pub action_template_version: u64,
    pub target_id: Uuid,
    pub target_version: u64,
    pub target_environment: TargetEnvironment,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub timeout_seconds: u64,
    pub execution_mode: &'static str,
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

#[derive(Clone, Debug, Serialize)]
pub struct Approval {
    pub authorization_mode: AuthorizationMode,
    pub parameters: ParameterValues,
    pub id: Uuid,
    pub action_template_id: Option<Uuid>,
    pub action_template_version: Option<u64>,
    pub target_id: Uuid,
    pub target_version: u64,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub reason: Option<String>,
    pub state: ApprovalState,
    pub decision_note: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApproval {
    #[serde(default)]
    pub(crate) authorization_mode: AuthorizationMode,
    #[serde(default)]
    pub(crate) parameters: ParameterValues,
    pub(crate) action_template_id: Uuid,
    pub(crate) reason: Option<String>,
    pub(crate) expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideApproval {
    pub(crate) expected_version: u64,
    pub(crate) note: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Succeeded,
    Cancelled,
    Failed,
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

#[derive(Clone, Debug, Serialize)]
pub struct SyntheticRun {
    pub id: Uuid,
    pub approval_id: Uuid,
    pub action_template_id: Uuid,
    pub target_id: Uuid,
    pub target_version: u64,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub state: RunState,
    pub result_status: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub finished_at_unix_ms: Option<u64>,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSyntheticRun {
    pub(crate) approval_id: Uuid,
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelSyntheticRun {
    pub(crate) expected_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeEventKind {
    AuthorizationRevoked,
    Requested,
    Started,
    Succeeded,
    Cancelled,
    Interrupted,
    Failed,
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

#[derive(Clone, Debug, Serialize)]
pub struct SafeEvent {
    pub id: u64,
    pub run_id: Uuid,
    pub sequence: u64,
    pub kind: SafeEventKind,
    pub state: RunState,
    pub message: String,
    pub created_at_unix_ms: u64,
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
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn list_credential_references(&self) -> Result<Vec<CredentialReference>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, name, kind, purpose, address, username, secret_configured,
                        secret_updated_at_unix_ms, created_at_unix_ms,
                        updated_at_unix_ms, version
                   FROM credential_references
                  ORDER BY created_at_unix_ms, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], credential_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn create_credential_reference(
        &self,
        request: &CreateCredentialReference,
    ) -> Result<CredentialReference, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let purpose = normalize_optional(request.purpose.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let address = normalize_optional(request.address.as_deref(), MAX_ADDRESS_CHARS)?;
        let username = normalize_optional(request.username.as_deref(), MAX_USERNAME_CHARS)?;
        let connection = self.lock();
        ensure_capacity(
            &connection,
            "credential_references",
            MAX_CREDENTIAL_REFERENCES,
        )?;
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        connection
            .execute(
                "INSERT INTO credential_references
                    (id, name, kind, purpose, address, username, secret_state, created_at_unix_ms,
                     updated_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'not_configured', ?7, ?7, 1)",
                params![
                    id.to_string(),
                    name,
                    request.kind.as_storage(),
                    purpose,
                    address,
                    username,
                    now
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        credential_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn update_credential_reference(
        &self,
        id: Uuid,
        request: &UpdateCredentialReference,
    ) -> Result<CredentialReference, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let purpose = normalize_optional(request.purpose.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let address = normalize_optional(request.address.as_deref(), MAX_ADDRESS_CHARS)?;
        let username = normalize_optional(request.username.as_deref(), MAX_USERNAME_CHARS)?;
        let connection = self.lock();
        let current = credential_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        if current.secret_state == SecretState::Available && current.kind != request.kind {
            return Err(CatalogError::Invalid);
        }
        let changed = connection
            .execute(
                "UPDATE credential_references
                    SET name = ?1, kind = ?2, purpose = ?3, address = ?4, username = ?5,
                        updated_at_unix_ms = ?6, version = version + 1
                  WHERE id = ?7 AND version = ?8",
                params![
                    name,
                    request.kind.as_storage(),
                    purpose,
                    address,
                    username,
                    now_unix_ms_i64()?,
                    id.to_string(),
                    i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return if credential_by_id(&connection, id)?.is_some() {
                Err(CatalogError::VersionConflict)
            } else {
                Err(CatalogError::NotFound)
            };
        }
        credential_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn get_credential_reference(&self, id: Uuid) -> Result<CredentialReference, CatalogError> {
        credential_by_id(&self.lock(), id)?.ok_or(CatalogError::NotFound)
    }

    #[cfg(test)]
    pub(crate) fn set_credential_secret_state(
        &self,
        id: Uuid,
        expected_version: u64,
        configured: bool,
    ) -> Result<CredentialReference, CatalogError> {
        let mut connection = self.lock();
        let now = now_unix_ms_i64()?;
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE credential_references
                    SET secret_configured = ?1,
                        secret_updated_at_unix_ms = ?2,
                        updated_at_unix_ms = ?2,
                        version = version + 1
                  WHERE id = ?3 AND version = ?4",
                params![
                    configured,
                    now,
                    id.to_string(),
                    i64::try_from(expected_version).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return if credential_by_id(&transaction, id)?.is_some() {
                Err(CatalogError::VersionConflict)
            } else {
                Err(CatalogError::NotFound)
            };
        }
        transaction
            .execute(
                "UPDATE targets
                    SET updated_at_unix_ms = ?1, version = version + 1
                  WHERE credential_reference_id = ?2",
                params![now, id.to_string()],
            )
            .map_err(|_| CatalogError::Storage)?;
        transaction.execute("UPDATE action_templates SET updated_at_unix_ms=?1, version=version+1 WHERE id IN (SELECT template_id FROM command_slots WHERE credential_id=?2)", params![now,id.to_string()]).map_err(|_|CatalogError::Storage)?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        credential_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    /// Fails closed before an external secret-store mutation. Claiming the mutation advances the
    /// public version so a concurrent writer cannot race the operating-system store operation;
    /// linked targets and templates are versioned immediately so existing approvals become unusable.
    pub fn begin_credential_secret_mutation(
        &self,
        id: Uuid,
        expected_version: u64,
    ) -> Result<CredentialReference, CatalogError> {
        let mut connection = self.lock();
        let now = now_unix_ms_i64()?;
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE credential_references
                    SET secret_configured = 0,
                        updated_at_unix_ms = ?1,
                        version = version + 1
                  WHERE id = ?2 AND version = ?3",
                params![
                    now,
                    id.to_string(),
                    i64::try_from(expected_version).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return if credential_by_id(&transaction, id)?.is_some() {
                Err(CatalogError::VersionConflict)
            } else {
                Err(CatalogError::NotFound)
            };
        }
        transaction
            .execute(
                "UPDATE targets
                    SET updated_at_unix_ms = ?1, version = version + 1
                  WHERE credential_reference_id = ?2",
                params![now, id.to_string()],
            )
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "UPDATE action_templates
                    SET updated_at_unix_ms = ?1, version = version + 1
                  WHERE id IN (SELECT template_id FROM command_slots WHERE credential_id = ?2)",
                params![now, id.to_string()],
            )
            .map_err(|_| CatalogError::Storage)?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        credential_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    /// Finalizes a previously claimed external secret-store mutation without advancing the
    /// public version a second time. The claim already invalidated concurrent writers and linked
    /// approvals; finalization only publishes whether the native entry is now available.
    pub fn finish_credential_secret_mutation(
        &self,
        id: Uuid,
        expected_version: u64,
        configured: bool,
    ) -> Result<CredentialReference, CatalogError> {
        let connection = self.lock();
        let now = now_unix_ms_i64()?;
        let changed = connection
            .execute(
                "UPDATE credential_references
                    SET secret_configured = ?1,
                        secret_updated_at_unix_ms = ?2,
                        updated_at_unix_ms = ?2
                  WHERE id = ?3 AND version = ?4",
                params![
                    configured,
                    now,
                    id.to_string(),
                    i64::try_from(expected_version).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return if credential_by_id(&connection, id)?.is_some() {
                Err(CatalogError::VersionConflict)
            } else {
                Err(CatalogError::NotFound)
            };
        }
        credential_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn ensure_credential_reference_deletable(&self, id: Uuid) -> Result<(), CatalogError> {
        let connection = self.lock();
        if credential_by_id(&connection, id)?.is_none() {
            return Err(CatalogError::NotFound);
        }
        ensure_credential_reference_unlinked(&connection, id)
    }

    pub fn delete_credential_reference(&self, id: Uuid) -> Result<(), CatalogError> {
        let connection = self.lock();
        ensure_credential_reference_unlinked(&connection, id)?;
        let changed = connection
            .execute(
                "DELETE FROM credential_references WHERE id = ?1",
                [id.to_string()],
            )
            .map_err(|_| CatalogError::Storage)?;
        (changed > 0).then_some(()).ok_or(CatalogError::NotFound)
    }

    pub fn list_targets(&self) -> Result<Vec<Target>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, name, kind, environment, description, address, username,
                        allow_insecure_protocol,
                        credential_reference_id, postgres_host, postgres_port,
                        postgres_database, postgres_username, postgres_tls_mode,
                        created_at_unix_ms, updated_at_unix_ms, version
                   FROM targets
                  ORDER BY created_at_unix_ms, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], target_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn get_target(&self, id: Uuid) -> Result<Target, CatalogError> {
        target_by_id(&self.lock(), id)?.ok_or(CatalogError::NotFound)
    }

    pub fn create_target(&self, request: &CreateTarget) -> Result<Target, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let address = normalize_optional(request.address.as_deref(), MAX_ADDRESS_CHARS)?;
        let username = normalize_optional(request.username.as_deref(), MAX_USERNAME_CHARS)?;
        if request.allow_insecure_protocol && request.kind != TargetKind::TelnetHost {
            return Err(CatalogError::Invalid);
        }
        let postgres = normalize_postgres_config(request.kind, request.postgres.as_ref())?;
        let connection = self.lock();
        ensure_capacity(&connection, "targets", MAX_TARGETS)?;
        ensure_credential_exists(&connection, request.credential_reference_id)?;
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        connection
            .execute(
                "INSERT INTO targets
                    (id, name, kind, environment, description, address, username, allow_insecure_protocol,
                     credential_reference_id, postgres_host, postgres_port,
                     postgres_database, postgres_username, postgres_tls_mode,
                     created_at_unix_ms, updated_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15, 1)",
                params![
                    id.to_string(),
                    name,
                    request.kind.as_storage(),
                    request.environment.as_storage(),
                    description,
                    address,
                    username,
                    request.allow_insecure_protocol,
                    request
                        .credential_reference_id
                        .map(|value| value.to_string()),
                    postgres.as_ref().map(|value| value.host.as_str()),
                    postgres.as_ref().map(|value| value.port),
                    postgres.as_ref().map(|value| value.database.as_str()),
                    postgres.as_ref().map(|value| value.username.as_str()),
                    postgres.as_ref().map(|value| value.tls_mode.as_storage()),
                    now
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        target_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn update_target(&self, id: Uuid, request: &UpdateTarget) -> Result<Target, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let address = normalize_optional(request.address.as_deref(), MAX_ADDRESS_CHARS)?;
        let username = normalize_optional(request.username.as_deref(), MAX_USERNAME_CHARS)?;
        if request.allow_insecure_protocol && request.kind != TargetKind::TelnetHost {
            return Err(CatalogError::Invalid);
        }
        let postgres = normalize_postgres_config(request.kind, request.postgres.as_ref())?;
        let connection = self.lock();
        ensure_credential_exists(&connection, request.credential_reference_id)?;
        let changed = connection
            .execute(
                "UPDATE targets
                    SET name = ?1, kind = ?2, environment = ?3,
                        description = ?4, address = ?5, username = ?6,
                        allow_insecure_protocol = ?7, credential_reference_id = ?8,
                        postgres_host = ?9, postgres_port = ?10,
                        postgres_database = ?11, postgres_username = ?12,
                        postgres_tls_mode = ?13,
                        updated_at_unix_ms = ?14, version = version + 1
                  WHERE id = ?15 AND version = ?16",
                params![
                    name,
                    request.kind.as_storage(),
                    request.environment.as_storage(),
                    description,
                    address,
                    username,
                    request.allow_insecure_protocol,
                    request
                        .credential_reference_id
                        .map(|value| value.to_string()),
                    postgres.as_ref().map(|value| value.host.as_str()),
                    postgres.as_ref().map(|value| value.port),
                    postgres.as_ref().map(|value| value.database.as_str()),
                    postgres.as_ref().map(|value| value.username.as_str()),
                    postgres.as_ref().map(|value| value.tls_mode.as_storage()),
                    now_unix_ms_i64()?,
                    id.to_string(),
                    i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return if target_by_id(&connection, id)?.is_some() {
                Err(CatalogError::VersionConflict)
            } else {
                Err(CatalogError::NotFound)
            };
        }
        target_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn list_action_templates(&self) -> Result<Vec<ActionTemplate>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, target_id, name, operation, result_scope, description,
                        timeout_seconds, enabled, created_at_unix_ms,
                        updated_at_unix_ms, version, command_json
                   FROM action_templates
                  ORDER BY created_at_unix_ms, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], action_template_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn evaluate_action_template(&self, id: Uuid) -> Result<PolicyEvaluation, CatalogError> {
        let connection = self.lock();
        let template = action_template_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        let target =
            target_by_id(&connection, template.target_id)?.ok_or(CatalogError::NotFound)?;
        policy_evaluation(&connection, &template, &target)
    }

    pub fn create_action_template(
        &self,
        request: &CreateActionTemplate,
    ) -> Result<ActionTemplate, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        if !(1..=300).contains(&request.timeout_seconds) {
            return Err(CatalogError::Invalid);
        }
        let connection = self.lock();
        validate_command(&connection, request.operation, request.command.as_ref())?;
        ensure_capacity(&connection, "action_templates", MAX_ACTION_TEMPLATES)?;
        ensure_target_exists(&connection, request.target_id)?;
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "INSERT INTO action_templates
                    (id, target_id, name, operation, result_scope, description,
                     timeout_seconds, enabled, created_at_unix_ms,
                     updated_at_unix_ms, version, command_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8, 1, ?9)",
                params![
                    id.to_string(),
                    request.target_id.to_string(),
                    name,
                    request.operation.as_storage(),
                    request.result_scope.as_storage(),
                    description,
                    i64::try_from(request.timeout_seconds).map_err(|_| CatalogError::Invalid)?,
                    now,
                    request
                        .command
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        save_command_slots(&transaction, id, request.command.as_ref())?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        action_template_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn update_action_template(
        &self,
        id: Uuid,
        request: &UpdateActionTemplate,
    ) -> Result<ActionTemplate, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        if !(1..=300).contains(&request.timeout_seconds) {
            return Err(CatalogError::Invalid);
        }
        let connection = self.lock();
        validate_command(&connection, request.operation, request.command.as_ref())?;
        ensure_target_exists(&connection, request.target_id)?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE action_templates
                    SET target_id = ?1, name = ?2, operation = ?3, result_scope = ?4,
                        description = ?5, timeout_seconds = ?6, enabled = ?7,
                        updated_at_unix_ms = ?8, version = version + 1, command_json = ?11
                  WHERE id = ?9 AND version = ?10",
                params![
                    request.target_id.to_string(),
                    name,
                    request.operation.as_storage(),
                    request.result_scope.as_storage(),
                    description,
                    i64::try_from(request.timeout_seconds).map_err(|_| CatalogError::Invalid)?,
                    request.enabled,
                    now_unix_ms_i64()?,
                    id.to_string(),
                    i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?,
                    request
                        .command
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return if action_template_by_id(&connection, id)?.is_some() {
                Err(CatalogError::VersionConflict)
            } else {
                Err(CatalogError::NotFound)
            };
        }
        save_command_slots(&transaction, id, request.command.as_ref())?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        action_template_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn delete_action_template(&self, id: Uuid) -> Result<(), CatalogError> {
        let connection = self.lock();
        let references = connection
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE action_template_id = ?1",
                [id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| CatalogError::Storage)?;
        if references > 0 {
            return Err(CatalogError::ResourceInUse);
        }
        let changed = connection
            .execute(
                "DELETE FROM action_templates WHERE id = ?1",
                [id.to_string()],
            )
            .map_err(|_| CatalogError::Storage)?;
        (changed > 0).then_some(()).ok_or(CatalogError::NotFound)
    }

    pub fn list_approvals(&self) -> Result<Vec<Approval>, CatalogError> {
        let connection = self.lock();
        expire_approvals(&connection, now_unix_ms_i64()?)?;
        let mut statement = connection
            .prepare(
                "SELECT id, action_template_id, action_template_version, target_id, target_version,
                        operation, result_scope, reason, state, decision_note,
                        created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version,
                        authorization_mode, parameters_json
                   FROM approvals
                  ORDER BY created_at_unix_ms DESC, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], approval_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn get_approval(&self, id: Uuid) -> Result<Approval, CatalogError> {
        let connection = self.lock();
        expire_approvals(&connection, now_unix_ms_i64()?)?;
        approval_by_id(&connection, id)?.ok_or(CatalogError::NotFound)
    }

    pub fn create_approval(&self, request: &CreateApproval) -> Result<Approval, CatalogError> {
        if !(MIN_APPROVAL_TTL_SECONDS..=MAX_APPROVAL_TTL_SECONDS)
            .contains(&request.expires_in_seconds)
        {
            return Err(CatalogError::Invalid);
        }
        let reason = normalize_optional(request.reason.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let connection = self.lock();
        ensure_capacity(&connection, "approvals", MAX_ACTIVE_APPROVALS)?;
        let template = action_template_by_id(&connection, request.action_template_id)?
            .filter(|template| template.enabled)
            .ok_or(CatalogError::NotFound)?;
        let target =
            target_by_id(&connection, template.target_id)?.ok_or(CatalogError::NotFound)?;
        let parameters = crate::parameters::resolve(
            template
                .command
                .as_ref()
                .map_or(&[], |c| c.parameters.as_slice()),
            &request.parameters,
        )?;
        if policy_evaluation(&connection, &template, &target)?.decision
            != PolicyDecision::EligibleForApproval
        {
            return Err(CatalogError::PolicyDenied);
        }
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        let ttl_ms = i64::try_from(request.expires_in_seconds)
            .map_err(|_| CatalogError::Invalid)?
            .checked_mul(1_000)
            .ok_or(CatalogError::Invalid)?;
        let expires_at = now.checked_add(ttl_ms).ok_or(CatalogError::Invalid)?;
        connection
            .execute(
                "INSERT INTO approvals
                    (id, action_template_id, action_template_version, target_id, target_version,
                     operation, result_scope, reason, state, decision_note,
                     created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version,
                     authorization_mode, parameters_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', NULL, ?9, ?9, ?10, 1, ?11, ?12)",
                params![
                    id.to_string(),
                    template.id.to_string(),
                    i64::try_from(template.version).map_err(|_| CatalogError::Storage)?,
                    template.target_id.to_string(),
                    i64::try_from(target.version).map_err(|_| CatalogError::Storage)?,
                    template.operation.as_storage(),
                    template.result_scope.as_storage(),
                    reason,
                    now,
                    expires_at,
                    serde_json::to_string(&request.authorization_mode).map_err(|_| CatalogError::Invalid)?,
                    serde_json::to_string(&parameters).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        approval_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn approve_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
    ) -> Result<Approval, CatalogError> {
        self.transition_approval(id, request, ApprovalState::Pending, ApprovalState::Approved)
    }

    pub fn deny_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
    ) -> Result<Approval, CatalogError> {
        self.transition_approval(id, request, ApprovalState::Pending, ApprovalState::Denied)
    }

    pub fn revoke_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
    ) -> Result<Approval, CatalogError> {
        self.transition_approval(id, request, ApprovalState::Approved, ApprovalState::Revoked)
    }

    fn transition_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
        expected_state: ApprovalState,
        next_state: ApprovalState,
    ) -> Result<Approval, CatalogError> {
        let note = normalize_optional(request.note.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let expected_version =
            i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?;
        let connection = self.lock();
        let now = now_unix_ms_i64()?;
        expire_approvals(&connection, now)?;
        let Some(current) = approval_by_id(&connection, id)? else {
            return Err(CatalogError::NotFound);
        };
        if current.version != request.expected_version {
            return Err(CatalogError::VersionConflict);
        }
        if current.state != expected_state {
            return Err(CatalogError::InvalidApprovalTransition);
        }
        if next_state == ApprovalState::Approved {
            ensure_approval_policy(&connection, &current)?;
        }
        let changed = connection
            .execute(
                "UPDATE approvals
                    SET state = ?1, decision_note = ?2, updated_at_unix_ms = ?3,
                        version = version + 1
                  WHERE id = ?4 AND version = ?5 AND state = ?6",
                params![
                    next_state.as_storage(),
                    note,
                    now,
                    id.to_string(),
                    expected_version,
                    expected_state.as_storage()
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return Err(CatalogError::VersionConflict);
        }
        approval_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn list_synthetic_runs(&self) -> Result<Vec<SyntheticRun>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                        result_scope, state, result_status, created_at_unix_ms,
                        updated_at_unix_ms, started_at_unix_ms,
                        finished_at_unix_ms, version
                   FROM synthetic_runs
                  ORDER BY created_at_unix_ms DESC, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], synthetic_run_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn get_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        synthetic_run_by_id(&self.lock(), id)?.ok_or(CatalogError::NotFound)
    }

    pub fn create_synthetic_run(
        &self,
        request: &CreateSyntheticRun,
    ) -> Result<CreateRunOutcome, CatalogError> {
        let idempotency_key = normalize_idempotency_key(&request.idempotency_key)?;
        let idempotency_key_hash = hex::encode(Sha256::digest(idempotency_key.as_bytes()));
        let mut connection = self.lock();
        let now = now_unix_ms_i64()?;
        expire_approvals(&connection, now)?;
        if let Some(existing) =
            synthetic_run_by_idempotency_key_hash(&connection, &idempotency_key_hash)?
        {
            if existing.approval_id != request.approval_id {
                return Err(CatalogError::IdempotencyConflict);
            }
            return Ok(CreateRunOutcome {
                run: existing,
                replayed: true,
            });
        }
        let approval = approval_by_id(&connection, request.approval_id)?
            .filter(|approval| approval.state == ApprovalState::Approved)
            .ok_or(CatalogError::ApprovalNotUsable)?;
        if approval.authorization_mode != AuthorizationMode::TimeWindow
            && synthetic_run_by_approval(&connection, request.approval_id)?.is_some()
        {
            return Err(CatalogError::ApprovalConsumed);
        }
        ensure_approval_policy(&connection, &approval)?;
        let template_id = approval
            .action_template_id
            .ok_or(CatalogError::ApprovalNotUsable)?;
        ensure_capacity(&connection, "synthetic_runs", MAX_ACTIVE_RUNS)?;
        let id = Uuid::new_v4();
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "INSERT INTO synthetic_runs
                    (id, approval_id, idempotency_key_hash, action_template_id, target_id, target_version,
                     operation, result_scope, state, result_status, created_at_unix_ms,
                     updated_at_unix_ms, started_at_unix_ms, finished_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', NULL, ?9, ?9, NULL, NULL, 1)",
                params![
                    id.to_string(),
                    approval.id.to_string(),
                    idempotency_key_hash,
                    template_id.to_string(),
                    approval.target_id.to_string(),
                    i64::try_from(approval.target_version).map_err(|_| CatalogError::Storage)?,
                    approval.operation.as_storage(),
                    approval.result_scope.as_storage(),
                    now
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        insert_safe_event(
            &transaction,
            id,
            1,
            SafeEventKind::Requested,
            RunState::Queued,
            "request accepted",
            now,
        )?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        Ok(CreateRunOutcome {
            run: synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::Storage)?,
            replayed: false,
        })
    }

    pub fn start_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        let current = self.get_synthetic_run(id)?;
        let message = if current.operation == ApprovalOperation::CommandExecution {
            "command run started"
        } else if current.operation == ApprovalOperation::PostgresConnectionCheck {
            "postgres connection check started"
        } else {
            "synthetic run started"
        };
        self.transition_run(
            id,
            None,
            &[RunState::Queued],
            RunState::Running,
            None,
            SafeEventKind::Started,
            message,
            true,
        )
    }

    #[cfg(test)]
    pub fn start_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.start_run(id)
    }

    pub fn complete_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            None,
            &[RunState::Running],
            RunState::Succeeded,
            Some("synthetic_ok"),
            SafeEventKind::Succeeded,
            "synthetic run completed",
            true,
        )
    }

    pub fn complete_postgres_run(
        &self,
        id: Uuid,
        result: PostgresRunResult,
    ) -> Result<SyntheticRun, CatalogError> {
        let succeeded = result == PostgresRunResult::ConnectionOk;
        self.transition_run(
            id,
            None,
            &[RunState::Running],
            if succeeded {
                RunState::Succeeded
            } else {
                RunState::Failed
            },
            Some(result.status()),
            if succeeded {
                SafeEventKind::Succeeded
            } else {
                SafeEventKind::Failed
            },
            if succeeded {
                "postgres connection check succeeded"
            } else {
                "postgres connection check failed"
            },
            true,
        )
    }

    pub fn complete_command_run(
        &self,
        id: Uuid,
        status: &str,
        exit_code: Option<i32>,
    ) -> Result<SyntheticRun, CatalogError> {
        let succeeded = status == "command_ok";
        self.transition_run_with_exit(
            id,
            None,
            &[RunState::Running],
            if status == "cancelled" {
                RunState::Cancelled
            } else if succeeded {
                RunState::Succeeded
            } else {
                RunState::Failed
            },
            Some(status),
            if succeeded {
                SafeEventKind::Succeeded
            } else {
                SafeEventKind::Failed
            },
            if succeeded {
                "command run succeeded"
            } else {
                "command run failed"
            },
            false,
            exit_code,
        )
    }

    pub fn run_execution_context(&self, id: Uuid) -> Result<RunExecutionContext, CatalogError> {
        let connection = self.lock();
        let run = synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        let approval = approval_by_id(&connection, run.approval_id)?
            .filter(|approval| approval.state == ApprovalState::Approved)
            .ok_or(CatalogError::ApprovalNotUsable)?;
        ensure_approval_policy(&connection, &approval)?;
        let template = action_template_by_id(&connection, run.action_template_id)?
            .ok_or(CatalogError::PolicyDenied)?;
        let target = target_by_id(&connection, run.target_id)?.ok_or(CatalogError::PolicyDenied)?;
        let credential = target
            .credential_reference_id
            .map(|credential_id| credential_by_id(&connection, credential_id))
            .transpose()?
            .flatten();
        Ok(RunExecutionContext {
            approval,
            template,
            target,
            credential,
        })
    }

    pub fn cancel_synthetic_run(
        &self,
        id: Uuid,
        request: &CancelSyntheticRun,
    ) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            Some(request.expected_version),
            &[RunState::Queued, RunState::Running],
            RunState::Cancelled,
            Some("cancelled"),
            SafeEventKind::Cancelled,
            "run cancelled",
            false,
        )
    }

    pub fn invalidate_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            None,
            &[RunState::Queued, RunState::Running],
            RunState::Cancelled,
            Some("authorization_revoked"),
            SafeEventKind::AuthorizationRevoked,
            "authorization no longer active",
            false,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "run transitions keep state, result and safe-event data atomic"
    )]
    fn transition_run(
        &self,
        id: Uuid,
        expected_version: Option<u64>,
        allowed_states: &[RunState],
        next_state: RunState,
        result_status: Option<&str>,
        event_kind: SafeEventKind,
        event_message: &str,
        revalidate_authorization: bool,
    ) -> Result<SyntheticRun, CatalogError> {
        self.transition_run_with_exit(
            id,
            expected_version,
            allowed_states,
            next_state,
            result_status,
            event_kind,
            event_message,
            revalidate_authorization,
            None,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "state, result, exit code and event commit atomically"
    )]
    fn transition_run_with_exit(
        &self,
        id: Uuid,
        expected_version: Option<u64>,
        allowed_states: &[RunState],
        next_state: RunState,
        result_status: Option<&str>,
        event_kind: SafeEventKind,
        event_message: &str,
        revalidate_authorization: bool,
        exit_code: Option<i32>,
    ) -> Result<SyntheticRun, CatalogError> {
        let mut connection = self.lock();
        let now = now_unix_ms_i64()?;
        expire_approvals(&connection, now)?;
        let current = synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        if expected_version.is_some_and(|expected| expected != current.version) {
            return Err(CatalogError::VersionConflict);
        }
        if !allowed_states.contains(&current.state) {
            return Err(CatalogError::InvalidRunTransition);
        }
        if revalidate_authorization {
            let approval = approval_by_id(&connection, current.approval_id)?
                .filter(|approval| approval.state == ApprovalState::Approved)
                .ok_or(CatalogError::ApprovalNotUsable)?;
            ensure_approval_policy(&connection, &approval)?;
            if approval.action_template_id != Some(current.action_template_id)
                || approval.target_id != current.target_id
                || approval.target_version != current.target_version
                || approval.operation != current.operation
                || approval.result_scope != current.result_scope
            {
                return Err(CatalogError::PolicyDenied);
            }
        }
        let started_at = (next_state == RunState::Running).then_some(now);
        let finished_at = matches!(
            next_state,
            RunState::Succeeded | RunState::Cancelled | RunState::Failed
        )
        .then_some(now);
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE synthetic_runs
                    SET state = ?1, result_status = ?2, updated_at_unix_ms = ?3,
                        started_at_unix_ms = COALESCE(?4, started_at_unix_ms),
                        finished_at_unix_ms = COALESCE(?5, finished_at_unix_ms),
                        version = version + 1, exit_code = ?8
                  WHERE id = ?6 AND version = ?7",
                params![
                    next_state.as_storage(),
                    result_status,
                    now,
                    started_at,
                    finished_at,
                    id.to_string(),
                    i64::try_from(current.version).map_err(|_| CatalogError::Storage)?,
                    exit_code
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return Err(CatalogError::VersionConflict);
        }
        insert_safe_event(
            &transaction,
            id,
            current.version + 1,
            event_kind,
            next_state,
            event_message,
            now,
        )?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn list_safe_events(&self, run_id: Option<Uuid>) -> Result<Vec<SafeEvent>, CatalogError> {
        let connection = self.lock();
        if let Some(id) = run_id {
            synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        }
        let (query, parameter) = run_id.map_or(
            (
                "SELECT id, run_id, sequence, kind, state, message, created_at_unix_ms
                   FROM safe_events ORDER BY created_at_unix_ms DESC, id DESC",
                None,
            ),
            |id| {
                (
                    "SELECT id, run_id, sequence, kind, state, message, created_at_unix_ms
                       FROM safe_events WHERE run_id = ?1 ORDER BY sequence",
                    Some(id.to_string()),
                )
            },
        );
        let mut statement = connection
            .prepare(query)
            .map_err(|_| CatalogError::Storage)?;
        let mapped = if let Some(parameter) = parameter {
            statement.query_map([parameter], safe_event_from_row)
        } else {
            statement.query_map([], safe_event_from_row)
        }
        .map_err(|_| CatalogError::Storage)?;
        mapped
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn recover_interrupted_runs(&self) -> Result<usize, CatalogError> {
        let ids = {
            let connection = self.lock();
            let mut statement = connection
                .prepare("SELECT id FROM synthetic_runs WHERE state IN ('queued', 'running')")
                .map_err(|_| CatalogError::Storage)?;
            statement
                .query_map([], |row| uuid_from_row(row, 0))
                .map_err(|_| CatalogError::Storage)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| CatalogError::Storage)?
        };
        let mut recovered = 0;
        for id in ids {
            self.transition_run(
                id,
                None,
                &[RunState::Queued, RunState::Running],
                RunState::Failed,
                Some("service_restarted"),
                SafeEventKind::Interrupted,
                "service restarted before completion",
                false,
            )?;
            recovered += 1;
        }
        Ok(recovered)
    }

    pub fn delete_target(&self, id: Uuid) -> Result<(), CatalogError> {
        let connection = self.lock();
        let references = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM approvals WHERE target_id = ?1) +
                    (SELECT COUNT(*) FROM action_templates WHERE target_id = ?1)",
                [id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| CatalogError::Storage)?;
        if references > 0 {
            return Err(CatalogError::ResourceInUse);
        }
        let changed = connection
            .execute("DELETE FROM targets WHERE id = ?1", [id.to_string()])
            .map_err(|_| CatalogError::Storage)?;
        (changed > 0).then_some(()).ok_or(CatalogError::NotFound)
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn validate_command(
    connection: &Connection,
    operation: ApprovalOperation,
    config: Option<&crate::command::CommandConfig>,
) -> Result<(), CatalogError> {
    if (operation == ApprovalOperation::CommandExecution) != config.is_some() {
        return Err(CatalogError::Invalid);
    }
    if let Some(config) = config {
        config.validate()?;
        for slot in &config.slots {
            if credential_by_id(connection, slot.credential_id)?.is_none() {
                return Err(CatalogError::CredentialReferenceNotFound);
            }
        }
    }
    Ok(())
}

fn save_command_slots(
    connection: &Connection,
    id: Uuid,
    config: Option<&crate::command::CommandConfig>,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "DELETE FROM command_slots WHERE template_id=?1",
            [id.to_string()],
        )
        .map_err(|_| CatalogError::Storage)?;
    if let Some(config) = config {
        for slot in &config.slots {
            connection
                .execute(
                    "INSERT OR IGNORE INTO command_slots(template_id,credential_id) VALUES (?1,?2)",
                    params![id.to_string(), slot.credential_id.to_string()],
                )
                .map_err(|_| CatalogError::Storage)?;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "operation-specific policy rules are reviewed together"
)]
fn policy_evaluation(
    connection: &Connection,
    template: &ActionTemplate,
    target: &Target,
) -> Result<PolicyEvaluation, CatalogError> {
    let postgres = template.operation == ApprovalOperation::PostgresConnectionCheck;
    let command = template.operation == ApprovalOperation::CommandExecution;
    let mut reasons = Vec::new();
    if (template.result_scope == ApprovalResultScope::SanitizedOutput) != command {
        reasons.push(PolicyReasonCode::ResultScopeUnsupported);
    }
    if !template.enabled {
        reasons.push(PolicyReasonCode::TemplateDisabled);
    }
    if command {
        if let Some(config) = &template.command {
            if config.validate().is_err() {
                reasons.push(PolicyReasonCode::TargetIncompatible);
            }
            if config
                .telnet
                .as_ref()
                .is_some_and(|telnet| !telnet.matches_target(config, target))
            {
                reasons.push(PolicyReasonCode::TargetIncompatible);
            }
            for slot in &config.slots {
                match credential_by_id(connection, slot.credential_id)? {
                    None => reasons.push(PolicyReasonCode::CredentialMissing),
                    Some(credential) if credential.secret_state != SecretState::Available => {
                        reasons.push(PolicyReasonCode::CredentialNotConfigured);
                    }
                    Some(_) => {}
                }
            }
        } else {
            reasons.push(PolicyReasonCode::TargetIncompatible);
        }
        if reasons.is_empty() {
            reasons.push(PolicyReasonCode::FixedCommandTemplate);
        }
    } else if postgres {
        if target.kind != TargetKind::Database {
            reasons.push(PolicyReasonCode::TargetIncompatible);
        }
        if target.postgres.is_none() {
            reasons.push(PolicyReasonCode::PostgresConfigurationMissing);
        }
        if template.result_scope != ApprovalResultScope::StatusOnly {
            reasons.push(PolicyReasonCode::ResultScopeUnsupported);
        }
        let credential = target
            .credential_reference_id
            .map(|id| credential_by_id(connection, id))
            .transpose()?
            .flatten();
        match credential {
            None => reasons.push(PolicyReasonCode::CredentialMissing),
            Some(credential) => {
                if credential.kind != CredentialKind::Password {
                    reasons.push(PolicyReasonCode::CredentialKindUnsupported);
                }
                if credential.secret_state != SecretState::Available {
                    reasons.push(PolicyReasonCode::CredentialNotConfigured);
                }
            }
        }
        if reasons.is_empty() {
            reasons.push(PolicyReasonCode::FixedPostgresConnectionCheck);
        }
    } else if reasons.is_empty() {
        reasons.push(PolicyReasonCode::FixedSyntheticScope);
    }
    let eligible = reasons.iter().all(|reason| {
        matches!(
            reason,
            PolicyReasonCode::FixedSyntheticScope
                | PolicyReasonCode::FixedPostgresConnectionCheck
                | PolicyReasonCode::FixedCommandTemplate
        )
    });
    Ok(PolicyEvaluation {
        policy_version: if command {
            "credential-command-policy-v1"
        } else if postgres {
            POSTGRES_POLICY_VERSION
        } else {
            SYNTHETIC_POLICY_VERSION
        },
        decision: if eligible {
            PolicyDecision::EligibleForApproval
        } else {
            PolicyDecision::Denied
        },
        reason_codes: reasons,
        requirements: if command {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::ValidatedParameters,
                PolicyRequirement::ScopedAuthorization,
                PolicyRequirement::TransitionRevalidation,
                PolicyRequirement::RedactedOutput,
            ]
        } else if postgres {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::NoParameters,
                PolicyRequirement::ScopedAuthorization,
                PolicyRequirement::TransitionRevalidation,
                PolicyRequirement::TlsVerifyFull,
                PolicyRequirement::ReadOnlyTransaction,
                PolicyRequirement::StructuredStatusOnly,
            ]
        } else {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::NoParameters,
                PolicyRequirement::ScopedAuthorization,
                PolicyRequirement::SyntheticOnly,
                PolicyRequirement::TransitionRevalidation,
            ]
        },
        action_template_id: template.id,
        action_template_version: template.version,
        target_id: target.id,
        target_version: target.version,
        target_environment: target.environment,
        operation: template.operation,
        result_scope: template.result_scope,
        timeout_seconds: template.timeout_seconds,
        execution_mode: if command {
            "credential_command"
        } else if postgres {
            "controlled_postgres"
        } else {
            "synthetic_simulation"
        },
    })
}

fn ensure_approval_policy(
    connection: &Connection,
    approval: &Approval,
) -> Result<(), CatalogError> {
    let template_id = approval
        .action_template_id
        .ok_or(CatalogError::PolicyDenied)?;
    let template_version = approval
        .action_template_version
        .ok_or(CatalogError::PolicyDenied)?;
    let template =
        action_template_by_id(connection, template_id)?.ok_or(CatalogError::PolicyDenied)?;
    let target = target_by_id(connection, approval.target_id)?.ok_or(CatalogError::PolicyDenied)?;
    if !template.enabled
        || template.version != template_version
        || template.target_id != approval.target_id
        || template.operation != approval.operation
        || template.result_scope != approval.result_scope
        || target.version != approval.target_version
    {
        return Err(CatalogError::PolicyDenied);
    }
    if policy_evaluation(connection, &template, &target)?.decision
        != PolicyDecision::EligibleForApproval
    {
        return Err(CatalogError::PolicyDenied);
    }
    Ok(())
}

fn credential_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<CredentialReference>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, purpose, address, username, secret_configured,
                    secret_updated_at_unix_ms, created_at_unix_ms,
                    updated_at_unix_ms, version
               FROM credential_references WHERE id = ?1",
            [id.to_string()],
            credential_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn target_by_id(connection: &Connection, id: Uuid) -> Result<Option<Target>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, environment, description, address, username,
                    allow_insecure_protocol, credential_reference_id, postgres_host, postgres_port,
                    postgres_database, postgres_username, postgres_tls_mode,
                    created_at_unix_ms, updated_at_unix_ms, version
               FROM targets WHERE id = ?1",
            [id.to_string()],
            target_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn action_template_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<ActionTemplate>, CatalogError> {
    connection
        .query_row(
            "SELECT id, target_id, name, operation, result_scope, description,
                    timeout_seconds, enabled, created_at_unix_ms,
                    updated_at_unix_ms, version, command_json
               FROM action_templates WHERE id = ?1",
            [id.to_string()],
            action_template_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn action_template_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionTemplate> {
    Ok(ActionTemplate {
        command: row
            .get::<_, Option<String>>(11)?
            .map(|json| serde_json::from_str(&json).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        id: uuid_from_row(row, 0)?,
        target_id: uuid_from_row(row, 1)?,
        name: row.get(2)?,
        operation: ApprovalOperation::from_storage(&row.get::<_, String>(3)?)?,
        result_scope: ApprovalResultScope::from_storage(&row.get::<_, String>(4)?)?,
        description: row.get(5)?,
        timeout_seconds: u64_from_row(row, 6)?,
        enabled: row.get(7)?,
        created_at_unix_ms: u64_from_row(row, 8)?,
        updated_at_unix_ms: u64_from_row(row, 9)?,
        version: u64_from_row(row, 10)?,
    })
}

fn approval_by_id(connection: &Connection, id: Uuid) -> Result<Option<Approval>, CatalogError> {
    connection
        .query_row(
            "SELECT id, action_template_id, action_template_version, target_id, target_version,
                    operation, result_scope, reason, state, decision_note,
                    created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version,
                    authorization_mode, parameters_json
               FROM approvals WHERE id = ?1",
            [id.to_string()],
            approval_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn approval_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Approval> {
    let template_id = row.get::<_, Option<String>>(1)?;
    Ok(Approval {
        authorization_mode: serde_json::from_str(&row.get::<_, String>(14)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        parameters: serde_json::from_str(&row.get::<_, String>(15)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        id: uuid_from_row(row, 0)?,
        action_template_id: template_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        action_template_version: row
            .get::<_, Option<i64>>(2)?
            .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        target_id: uuid_from_row(row, 3)?,
        target_version: u64_from_row(row, 4)?,
        operation: ApprovalOperation::from_storage(&row.get::<_, String>(5)?)?,
        result_scope: ApprovalResultScope::from_storage(&row.get::<_, String>(6)?)?,
        reason: row.get(7)?,
        state: ApprovalState::from_storage(&row.get::<_, String>(8)?)?,
        decision_note: row.get(9)?,
        created_at_unix_ms: u64_from_row(row, 10)?,
        updated_at_unix_ms: u64_from_row(row, 11)?,
        expires_at_unix_ms: u64_from_row(row, 12)?,
        version: u64_from_row(row, 13)?,
    })
}

fn synthetic_run_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                    result_scope, state, result_status, created_at_unix_ms,
                    updated_at_unix_ms, started_at_unix_ms,
                    finished_at_unix_ms, version
               FROM synthetic_runs WHERE id = ?1",
            [id.to_string()],
            synthetic_run_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn synthetic_run_by_idempotency_key_hash(
    connection: &Connection,
    key: &str,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                    result_scope, state, result_status, created_at_unix_ms,
                    updated_at_unix_ms, started_at_unix_ms,
                    finished_at_unix_ms, version
               FROM synthetic_runs WHERE idempotency_key_hash = ?1",
            [key],
            synthetic_run_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn synthetic_run_by_approval(
    connection: &Connection,
    approval_id: Uuid,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                    result_scope, state, result_status, created_at_unix_ms,
                    updated_at_unix_ms, started_at_unix_ms,
                    finished_at_unix_ms, version
               FROM synthetic_runs WHERE approval_id = ?1",
            [approval_id.to_string()],
            synthetic_run_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn synthetic_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyntheticRun> {
    Ok(SyntheticRun {
        id: uuid_from_row(row, 0)?,
        approval_id: uuid_from_row(row, 1)?,
        action_template_id: uuid_from_row(row, 2)?,
        target_id: uuid_from_row(row, 3)?,
        target_version: u64_from_row(row, 4)?,
        operation: ApprovalOperation::from_storage(&row.get::<_, String>(5)?)?,
        result_scope: ApprovalResultScope::from_storage(&row.get::<_, String>(6)?)?,
        state: RunState::from_storage(&row.get::<_, String>(7)?)?,
        result_status: row.get(8)?,
        created_at_unix_ms: u64_from_row(row, 9)?,
        updated_at_unix_ms: u64_from_row(row, 10)?,
        started_at_unix_ms: optional_u64_from_row(row, 11)?,
        finished_at_unix_ms: optional_u64_from_row(row, 12)?,
        version: u64_from_row(row, 13)?,
    })
}

fn safe_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SafeEvent> {
    Ok(SafeEvent {
        id: u64_from_row(row, 0)?,
        run_id: uuid_from_row(row, 1)?,
        sequence: u64_from_row(row, 2)?,
        kind: SafeEventKind::from_storage(&row.get::<_, String>(3)?)?,
        state: RunState::from_storage(&row.get::<_, String>(4)?)?,
        message: row.get(5)?,
        created_at_unix_ms: u64_from_row(row, 6)?,
    })
}

fn insert_safe_event(
    connection: &Connection,
    run_id: Uuid,
    sequence: u64,
    kind: SafeEventKind,
    state: RunState,
    message: &str,
    created_at: i64,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT INTO safe_events
                (run_id, sequence, kind, state, message, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run_id.to_string(),
                i64::try_from(sequence).map_err(|_| CatalogError::Storage)?,
                kind.as_storage(),
                state.as_storage(),
                message,
                created_at
            ],
        )
        .map(|_| ())
        .map_err(|_| CatalogError::Storage)
}

fn expire_approvals(connection: &Connection, now: i64) -> Result<(), CatalogError> {
    connection
        .execute(
            "UPDATE approvals
                SET state = 'expired', updated_at_unix_ms = ?1, version = version + 1
              WHERE state IN ('pending', 'approved') AND expires_at_unix_ms <= ?1",
            [now],
        )
        .map(|_| ())
        .map_err(|_| CatalogError::Storage)
}

fn uuid_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&row.get::<_, String>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn u64_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    row.get::<_, i64>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn optional_u64_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}

fn ensure_capacity(connection: &Connection, table: &str, maximum: i64) -> Result<(), CatalogError> {
    let statement = match table {
        "credential_references" => "SELECT COUNT(*) FROM credential_references",
        "targets" => "SELECT COUNT(*) FROM targets",
        "approvals" => {
            "SELECT COUNT(*) FROM approvals
            WHERE state = 'pending'
               OR (state = 'approved' AND (
                    authorization_mode = '\"time_window\"'
                    OR NOT EXISTS (
                        SELECT 1 FROM synthetic_runs WHERE synthetic_runs.approval_id = approvals.id
                    )
               ))"
        }
        "action_templates" => "SELECT COUNT(*) FROM action_templates",
        "synthetic_runs" => {
            "SELECT COUNT(*) FROM synthetic_runs WHERE state IN ('queued', 'running')"
        }
        "configuration_imports" => "SELECT COUNT(*) FROM configuration_imports",
        _ => return Err(CatalogError::Storage),
    };
    let count = connection
        .query_row(statement, [], |row| row.get::<_, i64>(0))
        .map_err(|_| CatalogError::Storage)?;
    (count < maximum)
        .then_some(())
        .ok_or(CatalogError::Capacity)
}

fn ensure_credential_reference_unlinked(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogError> {
    let references = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM targets WHERE credential_reference_id = ?1) +
                    (SELECT COUNT(*) FROM command_slots WHERE credential_id = ?1)",
            [id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| CatalogError::Storage)?;
    (references == 0)
        .then_some(())
        .ok_or(CatalogError::ResourceInUse)
}

fn normalize_idempotency_key(value: &str) -> Result<String, CatalogError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
    {
        return Err(CatalogError::Invalid);
    }
    Ok(value.to_owned())
}

fn normalize_postgres_config(
    kind: TargetKind,
    config: Option<&PostgresTargetConfig>,
) -> Result<Option<PostgresTargetConfig>, CatalogError> {
    let Some(config) = config else {
        return Ok(None);
    };
    if kind != TargetKind::Database {
        return Err(CatalogError::Invalid);
    }
    let host = config.host.trim();
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.chars().any(char::is_whitespace)
        || host.contains(['/', '\\', '@'])
        || host.contains("://")
        || !host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-:_[]".contains(character))
    {
        return Err(CatalogError::Invalid);
    }
    if config.port == 0 {
        return Err(CatalogError::Invalid);
    }
    Ok(Some(PostgresTargetConfig {
        host: host.to_ascii_lowercase(),
        port: config.port,
        database: normalize_required(&config.database, 63)?,
        username: normalize_required(&config.username, 63)?,
        tls_mode: config.tls_mode,
    }))
}

fn ensure_target_exists(connection: &Connection, id: Uuid) -> Result<(), CatalogError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM targets WHERE id = ?1",
            [id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| CatalogError::Storage)?
        .is_some();
    exists.then_some(()).ok_or(CatalogError::NotFound)
}

fn ensure_credential_exists(connection: &Connection, id: Option<Uuid>) -> Result<(), CatalogError> {
    let Some(id) = id else {
        return Ok(());
    };
    let exists = connection
        .query_row(
            "SELECT 1 FROM credential_references WHERE id = ?1",
            [id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| CatalogError::Storage)?
        .is_some();
    exists
        .then_some(())
        .ok_or(CatalogError::CredentialReferenceNotFound)
}

fn normalize_required(value: &str, maximum: usize) -> Result<String, CatalogError> {
    let value = value.trim();
    let count = value.chars().count();
    if count == 0 || count > maximum || value.chars().any(char::is_control) {
        return Err(CatalogError::Invalid);
    }
    Ok(value.to_owned())
}

fn normalize_optional(value: Option<&str>, maximum: usize) -> Result<Option<String>, CatalogError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    normalize_required(value, maximum).map(Some)
}

fn now_unix_ms_i64() -> Result<i64, CatalogError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .map_err(|_| CatalogError::Storage)
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
