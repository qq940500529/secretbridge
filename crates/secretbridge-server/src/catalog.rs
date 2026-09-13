// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    error::Error,
    fmt::{self, Write as _},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 9;
const SECURITY_VALIDATION_SUITE_VERSION: &str = "security-validation-v1";
const PILOT_READINESS_PROFILE_VERSION: &str = "pilot-readiness-v1";
const SYNTHETIC_POLICY_VERSION: &str = "synthetic-policy-v1";
const POSTGRES_POLICY_VERSION: &str = "postgres-readonly-policy-v1";
const MAX_CREDENTIAL_REFERENCES: i64 = 128;
const MAX_TARGETS: i64 = 128;
const MAX_APPROVALS: i64 = 512;
const MAX_ACTION_TEMPLATES: i64 = 256;
const MAX_RUNS: i64 = 1_024;
const MAX_SECURITY_VALIDATION_RUNS: i64 = 128;
const MAX_PILOT_READINESS_SNAPSHOTS: i64 = 128;
const MAX_NAME_CHARS: usize = 80;
const MAX_DESCRIPTION_CHARS: usize = 240;
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCredentialReference {
    name: String,
    kind: CredentialKind,
    purpose: Option<String>,
    expected_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Database,
    HttpService,
    SshHost,
}

impl TargetKind {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::HttpService => "http_service",
            Self::SshHost => "ssh_host",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "database" => Ok(Self::Database),
            "http_service" => Ok(Self::HttpService),
            "ssh_host" => Ok(Self::SshHost),
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
}

impl ApprovalOperation {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::InspectMetadata => "inspect_metadata",
            Self::SyntheticHealthCheck => "synthetic_health_check",
            Self::PostgresConnectionCheck => "postgres_connection_check",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "inspect_metadata" => Ok(Self::InspectMetadata),
            "synthetic_health_check" => Ok(Self::SyntheticHealthCheck),
            "postgres_connection_check" => Ok(Self::PostgresConnectionCheck),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResultScope {
    StatusOnly,
    MetadataSummary,
}

impl ApprovalResultScope {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::StatusOnly => "status_only",
            Self::MetadataSummary => "metadata_summary",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "status_only" => Ok(Self::StatusOnly),
            "metadata_summary" => Ok(Self::MetadataSummary),
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
    ExplicitApproval,
    NoParameters,
    SingleUse,
    SyntheticOnly,
    TransitionRevalidation,
    TlsVerifyFull,
    ReadOnlyTransaction,
    StructuredStatusOnly,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityValidationStatus {
    Passed,
    Warning,
    Failed,
}

impl SecurityValidationStatus {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warning => "warning",
            Self::Failed => "failed",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "passed" => Ok(Self::Passed),
            "warning" => Ok(Self::Warning),
            "failed" => Ok(Self::Failed),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityValidationCheck {
    pub code: String,
    pub category: String,
    pub status: SecurityValidationStatus,
    pub summary: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityValidationRun {
    pub id: Uuid,
    pub suite_version: String,
    pub status: SecurityValidationStatus,
    pub application_version: String,
    pub platform: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub evidence_digest_sha256: String,
    pub digest_verified: bool,
    pub checks: Vec<SecurityValidationCheck>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotReadinessStatus {
    Ready,
    Attention,
    Blocked,
}

impl PilotReadinessStatus {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Attention => "attention",
            Self::Blocked => "blocked",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "ready" => Ok(Self::Ready),
            "attention" => Ok(Self::Attention),
            "blocked" => Ok(Self::Blocked),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PilotReadinessCheck {
    pub code: String,
    pub category: String,
    pub status: SecurityValidationStatus,
    pub summary: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PilotReadinessSnapshot {
    pub id: Uuid,
    pub profile_version: String,
    pub status: PilotReadinessStatus,
    pub application_version: String,
    pub platform: String,
    pub created_at_unix_ms: u64,
    pub latest_validation_id: Option<Uuid>,
    pub candidate_test_targets: u64,
    pub eligible_test_targets: u64,
    pub evidence_digest_sha256: String,
    pub digest_verified: bool,
    pub checks: Vec<PilotReadinessCheck>,
}

#[derive(Serialize)]
struct PilotReadinessEvidence<'a> {
    id: Uuid,
    profile_version: &'a str,
    status: PilotReadinessStatus,
    application_version: &'a str,
    platform: &'a str,
    created_at_unix_ms: u64,
    latest_validation_id: Option<Uuid>,
    candidate_test_targets: u64,
    eligible_test_targets: u64,
    checks: &'a [PilotReadinessCheck],
}

#[derive(Serialize)]
struct SecurityValidationEvidence<'a> {
    id: Uuid,
    suite_version: &'a str,
    status: SecurityValidationStatus,
    application_version: &'a str,
    platform: &'a str,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    checks: &'a [SecurityValidationCheck],
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
        Self::initialize(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self, CatalogOpenError> {
        Self::initialize(Connection::open_in_memory()?)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "transactional schema migrations remain auditable when kept together"
    )]
    fn initialize(connection: Connection) -> Result<Self, CatalogOpenError> {
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "busy_timeout", 5_000_i64)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let version =
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        if version > SCHEMA_VERSION {
            return Err(CatalogOpenError::UnsupportedSchema(version));
        }
        if version == 0 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE credential_references (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                    kind TEXT NOT NULL CHECK (kind IN ('password', 'api_token', 'ssh_key')),
                    purpose TEXT CHECK (purpose IS NULL OR length(purpose) <= 240),
                    secret_state TEXT NOT NULL CHECK (secret_state = 'not_configured'),
                    secret_configured INTEGER NOT NULL DEFAULT 0 CHECK (secret_configured IN (0, 1)),
                    secret_updated_at_unix_ms INTEGER,
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE TABLE targets (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                    kind TEXT NOT NULL CHECK (kind IN ('database', 'http_service', 'ssh_host')),
                    environment TEXT NOT NULL CHECK (environment IN ('development', 'test', 'production')),
                    description TEXT CHECK (description IS NULL OR length(description) <= 240),
                    credential_reference_id TEXT REFERENCES credential_references(id) ON DELETE RESTRICT,
                    postgres_host TEXT,
                    postgres_port INTEGER CHECK (postgres_port IS NULL OR postgres_port BETWEEN 1 AND 65535),
                    postgres_database TEXT,
                    postgres_username TEXT,
                    postgres_tls_mode TEXT CHECK (postgres_tls_mode IS NULL OR postgres_tls_mode = 'verify_full'),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX targets_credential_reference_idx
                    ON targets(credential_reference_id);
                 CREATE TABLE action_templates (
                    id TEXT PRIMARY KEY NOT NULL,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    description TEXT CHECK (description IS NULL OR length(description) <= 240),
                    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
                    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX action_templates_target_idx ON action_templates(target_id);
                 CREATE TABLE approvals (
                    id TEXT PRIMARY KEY NOT NULL,
                    action_template_id TEXT REFERENCES action_templates(id) ON DELETE RESTRICT,
                    action_template_version INTEGER,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    target_version INTEGER NOT NULL CHECK (target_version >= 1),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    reason TEXT CHECK (reason IS NULL OR length(reason) <= 240),
                    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
                    decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= 240),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX approvals_target_idx ON approvals(target_id);
                 CREATE INDEX approvals_state_idx ON approvals(state);
                 CREATE TABLE synthetic_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
                    idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
                    action_template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE RESTRICT,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    target_version INTEGER NOT NULL CHECK (target_version >= 1),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                    result_status TEXT CHECK (result_status IS NULL OR result_status IN ('synthetic_ok', 'postgres_connection_ok', 'postgres_connection_failed', 'postgres_configuration_invalid', 'credential_unavailable', 'timed_out', 'cancelled', 'service_restarted', 'authorization_revoked')),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    started_at_unix_ms INTEGER,
                    finished_at_unix_ms INTEGER,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
                 CREATE TABLE safe_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'failed', 'cancelled', 'interrupted', 'authorization_revoked')),
                    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                    message TEXT NOT NULL CHECK (message IN ('request accepted', 'synthetic run started', 'synthetic run completed', 'postgres connection check started', 'postgres connection check succeeded', 'postgres connection check failed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
                    created_at_unix_ms INTEGER NOT NULL,
                    UNIQUE(run_id, sequence)
                 );
                 CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
                 CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
                 CREATE TABLE security_validation_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    suite_version TEXT NOT NULL CHECK (length(suite_version) BETWEEN 1 AND 80),
                    status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
                    application_version TEXT NOT NULL CHECK (length(application_version) BETWEEN 1 AND 80),
                    platform TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 80),
                    started_at_unix_ms INTEGER NOT NULL,
                    finished_at_unix_ms INTEGER NOT NULL,
                    evidence_digest_sha256 TEXT NOT NULL CHECK (length(evidence_digest_sha256) = 64)
                 );
                 CREATE INDEX security_validation_runs_finished_idx
                    ON security_validation_runs(finished_at_unix_ms DESC, id);
                 CREATE TABLE security_validation_checks (
                    run_id TEXT NOT NULL REFERENCES security_validation_runs(id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 64),
                    code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 80),
                    category TEXT NOT NULL CHECK (category IN ('instance', 'isolated_scenario', 'manual_gate')),
                    status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
                    summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 240),
                    evidence TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 240),
                    PRIMARY KEY (run_id, ordinal),
                    UNIQUE (run_id, code)
                 );
                 CREATE TABLE pilot_readiness_snapshots (
                    id TEXT PRIMARY KEY NOT NULL,
                    profile_version TEXT NOT NULL CHECK (length(profile_version) BETWEEN 1 AND 80),
                    status TEXT NOT NULL CHECK (status IN ('ready', 'attention', 'blocked')),
                    application_version TEXT NOT NULL CHECK (length(application_version) BETWEEN 1 AND 80),
                    platform TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 80),
                    created_at_unix_ms INTEGER NOT NULL,
                    latest_validation_id TEXT REFERENCES security_validation_runs(id) ON DELETE RESTRICT,
                    candidate_test_targets INTEGER NOT NULL CHECK (candidate_test_targets >= 0),
                    eligible_test_targets INTEGER NOT NULL CHECK (eligible_test_targets >= 0),
                    evidence_digest_sha256 TEXT NOT NULL CHECK (length(evidence_digest_sha256) = 64)
                 );
                 CREATE INDEX pilot_readiness_snapshots_created_idx
                    ON pilot_readiness_snapshots(created_at_unix_ms DESC, id);
                 CREATE TABLE pilot_readiness_checks (
                    snapshot_id TEXT NOT NULL REFERENCES pilot_readiness_snapshots(id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 64),
                    code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 80),
                    category TEXT NOT NULL CHECK (category IN ('configuration', 'evidence', 'manual_gate')),
                    status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
                    summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 240),
                    evidence TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 240),
                    PRIMARY KEY (snapshot_id, ordinal),
                    UNIQUE (snapshot_id, code)
                 );
                 PRAGMA user_version = 9;
                 COMMIT;",
            )?;
        }
        if version == 1 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE action_templates (
                    id TEXT PRIMARY KEY NOT NULL,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    description TEXT CHECK (description IS NULL OR length(description) <= 240),
                    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
                    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX action_templates_target_idx ON action_templates(target_id);
                 CREATE TABLE approvals (
                    id TEXT PRIMARY KEY NOT NULL,
                    action_template_id TEXT REFERENCES action_templates(id) ON DELETE RESTRICT,
                    action_template_version INTEGER,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    target_version INTEGER NOT NULL CHECK (target_version >= 1),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    reason TEXT CHECK (reason IS NULL OR length(reason) <= 240),
                    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
                    decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= 240),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX approvals_target_idx ON approvals(target_id);
                 CREATE INDEX approvals_state_idx ON approvals(state);
                 CREATE TABLE synthetic_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
                    idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
                    action_template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE RESTRICT,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    target_version INTEGER NOT NULL CHECK (target_version >= 1),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                    result_status TEXT CHECK (result_status IS NULL OR result_status IN ('synthetic_ok', 'cancelled', 'service_restarted', 'authorization_revoked')),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    started_at_unix_ms INTEGER,
                    finished_at_unix_ms INTEGER,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
                 CREATE TABLE safe_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'cancelled', 'interrupted', 'authorization_revoked')),
                    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                    message TEXT NOT NULL CHECK (message IN ('request accepted', 'synthetic run started', 'synthetic run completed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
                    created_at_unix_ms INTEGER NOT NULL,
                    UNIQUE(run_id, sequence)
                 );
                 CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
                 CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
                 PRAGMA user_version = 5;
                 COMMIT;",
            )?;
        }
        if version == 2 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE action_templates (
                    id TEXT PRIMARY KEY NOT NULL,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                    operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                    result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
                    description TEXT CHECK (description IS NULL OR length(description) <= 240),
                    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
                    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1)
                 );
                 CREATE INDEX action_templates_target_idx ON action_templates(target_id);
                 ALTER TABLE approvals ADD COLUMN action_template_id TEXT REFERENCES action_templates(id) ON DELETE RESTRICT;
                 ALTER TABLE approvals ADD COLUMN action_template_version INTEGER;
                 PRAGMA user_version = 3;
                 COMMIT;",
            )?;
        }
        if version == 2 || version == 3 {
            create_run_schema(&connection)?;
        }
        if (2..=4).contains(&version) {
            migrate_policy_snapshot_schema(&connection)?;
        }
        if (1..=5).contains(&version) {
            migrate_native_secret_and_postgres_schema(&connection)?;
        }
        if (1..=6).contains(&version) {
            migrate_controlled_postgres_schema(&connection)?;
        }
        if (1..=7).contains(&version) {
            migrate_security_validation_schema(&connection)?;
        }
        if (1..=8).contains(&version) {
            migrate_pilot_readiness_schema(&connection)?;
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn list_credential_references(&self) -> Result<Vec<CredentialReference>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, name, kind, purpose, secret_configured,
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
                    (id, name, kind, purpose, secret_state, created_at_unix_ms,
                     updated_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, 'not_configured', ?5, ?5, 1)",
                params![
                    id.to_string(),
                    name,
                    request.kind.as_storage(),
                    purpose,
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
        let connection = self.lock();
        let current = credential_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        if current.secret_state == SecretState::Available && current.kind != request.kind {
            return Err(CatalogError::Invalid);
        }
        let changed = connection
            .execute(
                "UPDATE credential_references
                    SET name = ?1, kind = ?2, purpose = ?3,
                        updated_at_unix_ms = ?4, version = version + 1
                  WHERE id = ?5 AND version = ?6",
                params![
                    name,
                    request.kind.as_storage(),
                    purpose,
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

    pub fn set_credential_secret_state(
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
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        credential_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn delete_credential_reference(&self, id: Uuid) -> Result<(), CatalogError> {
        let connection = self.lock();
        let references = connection
            .query_row(
                "SELECT COUNT(*) FROM targets WHERE credential_reference_id = ?1",
                [id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| CatalogError::Storage)?;
        if references > 0 {
            return Err(CatalogError::ResourceInUse);
        }
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
                "SELECT id, name, kind, environment, description,
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

    pub fn create_target(&self, request: &CreateTarget) -> Result<Target, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let postgres = normalize_postgres_config(request.kind, request.postgres.as_ref())?;
        let connection = self.lock();
        ensure_capacity(&connection, "targets", MAX_TARGETS)?;
        ensure_credential_exists(&connection, request.credential_reference_id)?;
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        connection
            .execute(
                "INSERT INTO targets
                    (id, name, kind, environment, description,
                     credential_reference_id, postgres_host, postgres_port,
                     postgres_database, postgres_username, postgres_tls_mode,
                     created_at_unix_ms, updated_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, 1)",
                params![
                    id.to_string(),
                    name,
                    request.kind.as_storage(),
                    request.environment.as_storage(),
                    description,
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
        let postgres = normalize_postgres_config(request.kind, request.postgres.as_ref())?;
        let connection = self.lock();
        ensure_credential_exists(&connection, request.credential_reference_id)?;
        let changed = connection
            .execute(
                "UPDATE targets
                    SET name = ?1, kind = ?2, environment = ?3,
                        description = ?4, credential_reference_id = ?5,
                        postgres_host = ?6, postgres_port = ?7,
                        postgres_database = ?8, postgres_username = ?9,
                        postgres_tls_mode = ?10,
                        updated_at_unix_ms = ?11, version = version + 1
                  WHERE id = ?12 AND version = ?13",
                params![
                    name,
                    request.kind.as_storage(),
                    request.environment.as_storage(),
                    description,
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
                        updated_at_unix_ms, version
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
        ensure_capacity(&connection, "action_templates", MAX_ACTION_TEMPLATES)?;
        ensure_target_exists(&connection, request.target_id)?;
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        connection
            .execute(
                "INSERT INTO action_templates
                    (id, target_id, name, operation, result_scope, description,
                     timeout_seconds, enabled, created_at_unix_ms,
                     updated_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8, 1)",
                params![
                    id.to_string(),
                    request.target_id.to_string(),
                    name,
                    request.operation.as_storage(),
                    request.result_scope.as_storage(),
                    description,
                    i64::try_from(request.timeout_seconds).map_err(|_| CatalogError::Invalid)?,
                    now
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
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
        ensure_target_exists(&connection, request.target_id)?;
        let changed = connection
            .execute(
                "UPDATE action_templates
                    SET target_id = ?1, name = ?2, operation = ?3, result_scope = ?4,
                        description = ?5, timeout_seconds = ?6, enabled = ?7,
                        updated_at_unix_ms = ?8, version = version + 1
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
                    i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?
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
                        created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version
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
        ensure_capacity(&connection, "approvals", MAX_APPROVALS)?;
        let template = action_template_by_id(&connection, request.action_template_id)?
            .filter(|template| template.enabled)
            .ok_or(CatalogError::NotFound)?;
        let target =
            target_by_id(&connection, template.target_id)?.ok_or(CatalogError::NotFound)?;
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
                     created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', NULL, ?9, ?9, ?10, 1)",
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
                    expires_at
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
        let idempotency_key_hash = format!("{:x}", Sha256::digest(idempotency_key.as_bytes()));
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
        if synthetic_run_by_approval(&connection, request.approval_id)?.is_some() {
            return Err(CatalogError::ApprovalConsumed);
        }
        let approval = approval_by_id(&connection, request.approval_id)?
            .filter(|approval| approval.state == ApprovalState::Approved)
            .ok_or(CatalogError::ApprovalNotUsable)?;
        ensure_approval_policy(&connection, &approval)?;
        let template_id = approval
            .action_template_id
            .ok_or(CatalogError::ApprovalNotUsable)?;
        ensure_capacity(&connection, "synthetic_runs", MAX_RUNS)?;
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
        let message = if current.operation == ApprovalOperation::PostgresConnectionCheck {
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
                        version = version + 1
                  WHERE id = ?6 AND version = ?7",
                params![
                    next_state.as_storage(),
                    result_status,
                    now,
                    started_at,
                    finished_at,
                    id.to_string(),
                    i64::try_from(current.version).map_err(|_| CatalogError::Storage)?
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
            if self
                .transition_run(
                    id,
                    None,
                    &[RunState::Queued, RunState::Running],
                    RunState::Failed,
                    Some("service_restarted"),
                    SafeEventKind::Interrupted,
                    "service restarted before completion",
                    false,
                )
                .is_ok()
            {
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    pub fn execute_security_validation(&self) -> Result<SecurityValidationRun, CatalogError> {
        let started_at_unix_ms = now_unix_ms_i64()?;
        let id = Uuid::new_v4();
        let mut checks = self.instance_security_validation_checks();
        checks.extend(isolated_security_validation_checks());
        checks.push(SecurityValidationCheck {
            code: "identity_boundary_review".to_owned(),
            category: "manual_gate".to_owned(),
            status: SecurityValidationStatus::Warning,
            summary: "Operating-system identity isolation requires external verification"
                .to_owned(),
            evidence: "Runtime remains in unverified_same_user compatibility mode".to_owned(),
        });
        let status = if checks
            .iter()
            .any(|check| check.status == SecurityValidationStatus::Failed)
        {
            SecurityValidationStatus::Failed
        } else if checks
            .iter()
            .any(|check| check.status == SecurityValidationStatus::Warning)
        {
            SecurityValidationStatus::Warning
        } else {
            SecurityValidationStatus::Passed
        };
        let finished_at_unix_ms = now_unix_ms_i64()?;
        let mut run = SecurityValidationRun {
            id,
            suite_version: SECURITY_VALIDATION_SUITE_VERSION.to_owned(),
            status,
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            platform: std::env::consts::OS.to_owned(),
            started_at_unix_ms: started_at_unix_ms
                .try_into()
                .map_err(|_| CatalogError::Storage)?,
            finished_at_unix_ms: finished_at_unix_ms
                .try_into()
                .map_err(|_| CatalogError::Storage)?,
            evidence_digest_sha256: String::new(),
            digest_verified: false,
            checks,
        };
        run.evidence_digest_sha256 = security_validation_digest(&run)?;
        run.digest_verified = true;

        let mut connection = self.lock();
        ensure_capacity(
            &connection,
            "security_validation_runs",
            MAX_SECURITY_VALIDATION_RUNS,
        )?;
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "INSERT INTO security_validation_runs
                    (id, suite_version, status, application_version, platform,
                     started_at_unix_ms, finished_at_unix_ms, evidence_digest_sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    run.id.to_string(),
                    run.suite_version,
                    run.status.as_storage(),
                    run.application_version,
                    run.platform,
                    started_at_unix_ms,
                    finished_at_unix_ms,
                    run.evidence_digest_sha256
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        for (index, check) in run.checks.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO security_validation_checks
                        (run_id, ordinal, code, category, status, summary, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        run.id.to_string(),
                        i64::try_from(index + 1).map_err(|_| CatalogError::Storage)?,
                        check.code,
                        check.category,
                        check.status.as_storage(),
                        check.summary,
                        check.evidence
                    ],
                )
                .map_err(|_| CatalogError::Storage)?;
        }
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        Ok(run)
    }

    pub fn list_security_validation_runs(
        &self,
    ) -> Result<Vec<SecurityValidationRun>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, suite_version, status, application_version, platform,
                        started_at_unix_ms, finished_at_unix_ms, evidence_digest_sha256
                   FROM security_validation_runs
                  ORDER BY finished_at_unix_ms DESC, id DESC",
            )
            .map_err(|_| CatalogError::Storage)?;
        let rows = statement
            .query_map([], security_validation_run_header_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)?;
        rows.into_iter()
            .map(|run| security_validation_with_checks(&connection, run))
            .collect()
    }

    pub fn get_security_validation_run(
        &self,
        id: Uuid,
    ) -> Result<SecurityValidationRun, CatalogError> {
        let connection = self.lock();
        let run = connection
            .query_row(
                "SELECT id, suite_version, status, application_version, platform,
                        started_at_unix_ms, finished_at_unix_ms, evidence_digest_sha256
                   FROM security_validation_runs WHERE id = ?1",
                [id.to_string()],
                security_validation_run_header_from_row,
            )
            .optional()
            .map_err(|_| CatalogError::Storage)?
            .ok_or(CatalogError::NotFound)?;
        security_validation_with_checks(&connection, run)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "readiness collection and its transactional evidence write remain auditable together"
    )]
    pub fn execute_pilot_readiness_snapshot(&self) -> Result<PilotReadinessSnapshot, CatalogError> {
        let created_at = now_unix_ms_i64()?;
        let id = Uuid::new_v4();
        let mut connection = self.lock();
        let candidate_test_targets = count_query(
            &connection,
            "SELECT COUNT(*) FROM targets
              WHERE kind = 'database' AND environment = 'test'",
        )?;
        let configured_test_targets = count_query(
            &connection,
            "SELECT COUNT(*) FROM targets
              WHERE kind = 'database' AND environment = 'test'
                AND postgres_host IS NOT NULL AND postgres_port IS NOT NULL
                AND postgres_database IS NOT NULL AND postgres_username IS NOT NULL
                AND postgres_tls_mode = 'verify_full'",
        )?;
        let credential_ready_targets = count_query(
            &connection,
            "SELECT COUNT(DISTINCT targets.id)
               FROM targets
               JOIN credential_references
                 ON credential_references.id = targets.credential_reference_id
              WHERE targets.kind = 'database' AND targets.environment = 'test'
                AND credential_references.secret_configured = 1",
        )?;
        let eligible_test_targets = count_query(
            &connection,
            "SELECT COUNT(DISTINCT targets.id)
               FROM targets
               JOIN credential_references
                 ON credential_references.id = targets.credential_reference_id
               JOIN action_templates ON action_templates.target_id = targets.id
              WHERE targets.kind = 'database' AND targets.environment = 'test'
                AND targets.postgres_host IS NOT NULL AND targets.postgres_port IS NOT NULL
                AND targets.postgres_database IS NOT NULL AND targets.postgres_username IS NOT NULL
                AND targets.postgres_tls_mode = 'verify_full'
                AND credential_references.secret_configured = 1
                AND action_templates.operation = 'postgres_connection_check'
                AND action_templates.result_scope = 'status_only'
                AND action_templates.enabled = 1",
        )?;
        let latest_validation = connection
            .query_row(
                "SELECT id, suite_version, status, application_version, platform,
                        started_at_unix_ms, finished_at_unix_ms, evidence_digest_sha256
                   FROM security_validation_runs
                  ORDER BY finished_at_unix_ms DESC, id DESC LIMIT 1",
                [],
                security_validation_run_header_from_row,
            )
            .optional()
            .map_err(|_| CatalogError::Storage)?
            .map(|run| security_validation_with_checks(&connection, run))
            .transpose()?;

        let mut checks = vec![
            readiness_check(
                "test_target_available",
                "configuration",
                candidate_test_targets > 0,
                "A dedicated test database target is registered",
                format!("{candidate_test_targets} test database target(s) found"),
            ),
            readiness_check(
                "postgres_configuration_complete",
                "configuration",
                configured_test_targets > 0,
                "A test target has complete PostgreSQL TLS configuration",
                format!("{configured_test_targets} fully configured test target(s) found"),
            ),
            readiness_check(
                "credential_available",
                "configuration",
                credential_ready_targets > 0,
                "A test target references an available native credential",
                format!("{credential_ready_targets} credential-ready test target(s) found"),
            ),
            readiness_check(
                "controlled_template_available",
                "configuration",
                eligible_test_targets > 0,
                "A fixed status-only PostgreSQL check is enabled for a test target",
                format!("{eligible_test_targets} technically eligible test target(s) found"),
            ),
        ];
        if let Some(validation) = &latest_validation {
            checks.push(readiness_check(
                "latest_validation_digest",
                "evidence",
                validation.digest_verified,
                "The latest security-validation evidence digest is intact",
                if validation.digest_verified {
                    "Latest validation digest recomputation matched stored evidence".to_owned()
                } else {
                    "Latest validation digest did not match stored evidence".to_owned()
                },
            ));
            checks.push(PilotReadinessCheck {
                code: "latest_validation_result".to_owned(),
                category: "evidence".to_owned(),
                status: match validation.status {
                    SecurityValidationStatus::Failed => SecurityValidationStatus::Failed,
                    SecurityValidationStatus::Warning => SecurityValidationStatus::Warning,
                    SecurityValidationStatus::Passed => SecurityValidationStatus::Passed,
                },
                summary: "The latest complete security-validation result is included".to_owned(),
                evidence: format!(
                    "Validation {} completed with status {}",
                    validation.id,
                    validation.status.as_storage()
                ),
            });
        } else {
            checks.push(readiness_check(
                "latest_validation_digest",
                "evidence",
                false,
                "A digest-verified security-validation run is available",
                "No security-validation evidence has been created".to_owned(),
            ));
            checks.push(readiness_check(
                "latest_validation_result",
                "evidence",
                false,
                "A complete security-validation result is included",
                "No security-validation result is available".to_owned(),
            ));
        }
        checks.extend([
            readiness_manual_gate(
                "identity_boundary_evidence",
                "Installed operating-system identity controls require platform evidence",
                "The runtime still declares unverified_same_user",
            ),
            readiness_manual_gate(
                "pilot_authorization_record",
                "The target owner must authorize a time-bounded non-production pilot",
                "No independent target-owner authorization is recorded by this self-check",
            ),
            readiness_manual_gate(
                "least_privilege_review",
                "Database grants must be independently confirmed as least privilege",
                "Credential availability does not prove the remote account grant set",
            ),
            readiness_manual_gate(
                "independent_security_review",
                "Security-sensitive implementation requires independent review",
                "Product-generated evidence is not an independent certification",
            ),
        ]);
        let status = if checks
            .iter()
            .any(|check| check.status == SecurityValidationStatus::Failed)
        {
            PilotReadinessStatus::Blocked
        } else if checks
            .iter()
            .any(|check| check.status == SecurityValidationStatus::Warning)
        {
            PilotReadinessStatus::Attention
        } else {
            PilotReadinessStatus::Ready
        };
        let mut snapshot = PilotReadinessSnapshot {
            id,
            profile_version: PILOT_READINESS_PROFILE_VERSION.to_owned(),
            status,
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            platform: std::env::consts::OS.to_owned(),
            created_at_unix_ms: created_at.try_into().map_err(|_| CatalogError::Storage)?,
            latest_validation_id: latest_validation.as_ref().map(|run| run.id),
            candidate_test_targets: candidate_test_targets
                .try_into()
                .map_err(|_| CatalogError::Storage)?,
            eligible_test_targets: eligible_test_targets
                .try_into()
                .map_err(|_| CatalogError::Storage)?,
            evidence_digest_sha256: String::new(),
            digest_verified: false,
            checks,
        };
        snapshot.evidence_digest_sha256 = pilot_readiness_digest(&snapshot)?;
        snapshot.digest_verified = true;

        ensure_capacity(
            &connection,
            "pilot_readiness_snapshots",
            MAX_PILOT_READINESS_SNAPSHOTS,
        )?;
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "INSERT INTO pilot_readiness_snapshots
                    (id, profile_version, status, application_version, platform,
                     created_at_unix_ms, latest_validation_id, candidate_test_targets,
                     eligible_test_targets, evidence_digest_sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    snapshot.id.to_string(),
                    snapshot.profile_version,
                    snapshot.status.as_storage(),
                    snapshot.application_version,
                    snapshot.platform,
                    created_at,
                    snapshot.latest_validation_id.map(|value| value.to_string()),
                    candidate_test_targets,
                    eligible_test_targets,
                    snapshot.evidence_digest_sha256
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        for (index, check) in snapshot.checks.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO pilot_readiness_checks
                        (snapshot_id, ordinal, code, category, status, summary, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        snapshot.id.to_string(),
                        i64::try_from(index + 1).map_err(|_| CatalogError::Storage)?,
                        check.code,
                        check.category,
                        check.status.as_storage(),
                        check.summary,
                        check.evidence
                    ],
                )
                .map_err(|_| CatalogError::Storage)?;
        }
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        Ok(snapshot)
    }

    pub fn list_pilot_readiness_snapshots(
        &self,
    ) -> Result<Vec<PilotReadinessSnapshot>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, profile_version, status, application_version, platform,
                        created_at_unix_ms, latest_validation_id, candidate_test_targets,
                        eligible_test_targets, evidence_digest_sha256
                   FROM pilot_readiness_snapshots
                  ORDER BY created_at_unix_ms DESC, id DESC",
            )
            .map_err(|_| CatalogError::Storage)?;
        let rows = statement
            .query_map([], pilot_readiness_header_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)?;
        rows.into_iter()
            .map(|snapshot| pilot_readiness_with_checks(&connection, snapshot))
            .collect()
    }

    pub fn get_pilot_readiness_snapshot(
        &self,
        id: Uuid,
    ) -> Result<PilotReadinessSnapshot, CatalogError> {
        let connection = self.lock();
        let snapshot = connection
            .query_row(
                "SELECT id, profile_version, status, application_version, platform,
                        created_at_unix_ms, latest_validation_id, candidate_test_targets,
                        eligible_test_targets, evidence_digest_sha256
                   FROM pilot_readiness_snapshots WHERE id = ?1",
                [id.to_string()],
                pilot_readiness_header_from_row,
            )
            .optional()
            .map_err(|_| CatalogError::Storage)?
            .ok_or(CatalogError::NotFound)?;
        pilot_readiness_with_checks(&connection, snapshot)
    }

    fn instance_security_validation_checks(&self) -> Vec<SecurityValidationCheck> {
        let connection = self.lock();
        let integrity_ok = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .is_ok_and(|result| result == "ok");
        let foreign_keys_ok = connection
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false);
        let secret_columns_absent = connection
            .query_row(
                "SELECT NOT EXISTS(
                    SELECT 1 FROM pragma_table_info('credential_references')
                     WHERE (lower(name) LIKE '%secret%' OR lower(name) LIKE '%password%'
                            OR lower(name) LIKE '%token%' OR lower(name) LIKE '%cipher%'
                            OR lower(name) LIKE '%private_key%')
                       AND name NOT IN ('secret_state', 'secret_configured', 'secret_updated_at_unix_ms')
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false);
        let safe_events_bounded = connection
            .query_row(
                "SELECT NOT EXISTS(
                    SELECT 1 FROM safe_events WHERE message NOT IN
                    ('request accepted', 'synthetic run started', 'synthetic run completed',
                     'postgres connection check started', 'postgres connection check succeeded',
                     'postgres connection check failed', 'run cancelled',
                     'service restarted before completion', 'authorization no longer active')
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false);
        vec![
            validation_check(
                "catalog_integrity",
                "instance",
                integrity_ok,
                "SQLite catalog integrity check completed",
                "PRAGMA integrity_check returned the expected result",
            ),
            validation_check(
                "foreign_key_integrity",
                "instance",
                foreign_keys_ok,
                "Catalog relationships contain no foreign-key violations",
                "PRAGMA foreign_key_check returned no rows",
            ),
            validation_check(
                "credential_metadata_only",
                "instance",
                secret_columns_absent,
                "Credential catalog stores metadata rather than secret values",
                "Credential schema contains no secret-value storage column",
            ),
            validation_check(
                "bounded_audit_payloads",
                "instance",
                safe_events_bounded,
                "Safe-event payloads use the fixed server vocabulary",
                "No persisted safe event falls outside the fixed message allowlist",
            ),
        ]
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn validation_check(
    code: &str,
    category: &str,
    passed: bool,
    summary: &str,
    evidence: &str,
) -> SecurityValidationCheck {
    SecurityValidationCheck {
        code: code.to_owned(),
        category: category.to_owned(),
        status: if passed {
            SecurityValidationStatus::Passed
        } else {
            SecurityValidationStatus::Failed
        },
        summary: summary.to_owned(),
        evidence: evidence.to_owned(),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete isolated security suite is kept together for auditability"
)]
fn isolated_security_validation_checks() -> Vec<SecurityValidationCheck> {
    let single_use = (|| {
        let (catalog, approval, _) = isolated_approved_catalog()?;
        let first = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "validation-single-use".to_owned(),
        })?;
        let replay = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "validation-single-use".to_owned(),
        })?;
        let second = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "validation-second-use".to_owned(),
        });
        Ok::<_, CatalogError>(
            !first.replayed
                && replay.replayed
                && first.run.id == replay.run.id
                && matches!(second, Err(CatalogError::ApprovalConsumed)),
        )
    })()
    .unwrap_or(false);

    let pending_blocked = (|| {
        let (catalog, approval, _) = isolated_catalog(false)?;
        let result = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "validation-pending-bypass".to_owned(),
        });
        Ok::<_, CatalogError>(matches!(result, Err(CatalogError::ApprovalNotUsable)))
    })()
    .unwrap_or(false);

    let rotation_invalidates = (|| {
        let (catalog, approval, target) = isolated_approved_catalog()?;
        catalog.update_target(
            target.id,
            &UpdateTarget {
                name: target.name,
                kind: target.kind,
                environment: target.environment,
                description: target.description,
                credential_reference_id: target.credential_reference_id,
                postgres: target.postgres,
                expected_version: target.version,
            },
        )?;
        let result = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "validation-stale-approval".to_owned(),
        });
        Ok::<_, CatalogError>(matches!(result, Err(CatalogError::PolicyDenied)))
    })()
    .unwrap_or(false);

    let revocation_blocks = (|| {
        let (catalog, approval, _) = isolated_approved_catalog()?;
        let revoked = catalog.revoke_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )?;
        let result = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: revoked.id,
            idempotency_key: "validation-revoked".to_owned(),
        });
        Ok::<_, CatalogError>(matches!(result, Err(CatalogError::ApprovalNotUsable)))
    })()
    .unwrap_or(false);

    let restart_recovers = (|| {
        let (catalog, approval, _) = isolated_approved_catalog()?;
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "validation-recovery".to_owned(),
            })?
            .run;
        catalog.start_run(run.id)?;
        let recovered = catalog.recover_interrupted_runs()?;
        let recovered_run = catalog.get_synthetic_run(run.id)?;
        let events = catalog.list_safe_events(Some(run.id))?;
        Ok::<_, CatalogError>(
            recovered == 1
                && recovered_run.state == RunState::Failed
                && recovered_run.result_status.as_deref() == Some("service_restarted")
                && events
                    .last()
                    .is_some_and(|event| event.kind == SafeEventKind::Interrupted),
        )
    })()
    .unwrap_or(false);

    vec![
        validation_check(
            "approval_bypass_blocked",
            "isolated_scenario",
            pending_blocked,
            "Unapproved execution requests are rejected",
            "An isolated pending approval could not create a run",
        ),
        validation_check(
            "single_use_and_replay",
            "isolated_scenario",
            single_use,
            "Approval consumption and idempotent replay are enforced",
            "Same-key replay returned one run and second consumption was rejected",
        ),
        validation_check(
            "rotation_invalidates_authorization",
            "isolated_scenario",
            rotation_invalidates,
            "Target rotation invalidates stale authorization",
            "A target version change caused policy revalidation to reject execution",
        ),
        validation_check(
            "revocation_blocks_execution",
            "isolated_scenario",
            revocation_blocks,
            "Revoked approval cannot start a controlled run",
            "An isolated revoked approval was rejected before run creation",
        ),
        validation_check(
            "interrupted_run_recovery",
            "isolated_scenario",
            restart_recovers,
            "Interrupted runs recover to a terminal failed state",
            "Recovery produced service_restarted status and a fixed interrupted event",
        ),
    ]
}

fn isolated_catalog(approve: bool) -> Result<(Catalog, Approval, Target), CatalogError> {
    let catalog = Catalog::in_memory().map_err(|_| CatalogError::Storage)?;
    let target = catalog.create_target(&CreateTarget {
        name: "Security validation target".to_owned(),
        kind: TargetKind::HttpService,
        environment: TargetEnvironment::Test,
        description: Some("Isolated synthetic validation fixture".to_owned()),
        credential_reference_id: None,
        postgres: None,
    })?;
    let template = catalog.create_action_template(&CreateActionTemplate {
        target_id: target.id,
        name: "Security validation action".to_owned(),
        operation: ApprovalOperation::SyntheticHealthCheck,
        result_scope: ApprovalResultScope::StatusOnly,
        description: Some("No business system or credential access".to_owned()),
        timeout_seconds: 30,
    })?;
    let pending = catalog.create_approval(&CreateApproval {
        action_template_id: template.id,
        reason: Some("Isolated security validation scenario".to_owned()),
        expires_in_seconds: 300,
    })?;
    let approval = if approve {
        catalog.approve_approval(
            pending.id,
            &DecideApproval {
                expected_version: pending.version,
                note: Some("Isolated validation only".to_owned()),
            },
        )?
    } else {
        pending
    };
    Ok((catalog, approval, target))
}

fn isolated_approved_catalog() -> Result<(Catalog, Approval, Target), CatalogError> {
    isolated_catalog(true)
}

fn security_validation_digest(run: &SecurityValidationRun) -> Result<String, CatalogError> {
    let payload = SecurityValidationEvidence {
        id: run.id,
        suite_version: &run.suite_version,
        status: run.status,
        application_version: &run.application_version,
        platform: &run.platform,
        started_at_unix_ms: run.started_at_unix_ms,
        finished_at_unix_ms: run.finished_at_unix_ms,
        checks: &run.checks,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| CatalogError::Storage)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn readiness_check(
    code: &str,
    category: &str,
    passed: bool,
    summary: &str,
    evidence: String,
) -> PilotReadinessCheck {
    PilotReadinessCheck {
        code: code.to_owned(),
        category: category.to_owned(),
        status: if passed {
            SecurityValidationStatus::Passed
        } else {
            SecurityValidationStatus::Failed
        },
        summary: summary.to_owned(),
        evidence,
    }
}

fn readiness_manual_gate(code: &str, summary: &str, evidence: &str) -> PilotReadinessCheck {
    PilotReadinessCheck {
        code: code.to_owned(),
        category: "manual_gate".to_owned(),
        status: SecurityValidationStatus::Warning,
        summary: summary.to_owned(),
        evidence: evidence.to_owned(),
    }
}

fn count_query(connection: &Connection, statement: &str) -> Result<i64, CatalogError> {
    connection
        .query_row(statement, [], |row| row.get(0))
        .map_err(|_| CatalogError::Storage)
}

fn pilot_readiness_digest(snapshot: &PilotReadinessSnapshot) -> Result<String, CatalogError> {
    let payload = PilotReadinessEvidence {
        id: snapshot.id,
        profile_version: &snapshot.profile_version,
        status: snapshot.status,
        application_version: &snapshot.application_version,
        platform: &snapshot.platform,
        created_at_unix_ms: snapshot.created_at_unix_ms,
        latest_validation_id: snapshot.latest_validation_id,
        candidate_test_targets: snapshot.candidate_test_targets,
        eligible_test_targets: snapshot.eligible_test_targets,
        checks: &snapshot.checks,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| CatalogError::Storage)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn pilot_readiness_header_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PilotReadinessSnapshot> {
    Ok(PilotReadinessSnapshot {
        id: uuid_from_row(row, 0)?,
        profile_version: row.get(1)?,
        status: PilotReadinessStatus::from_storage(&row.get::<_, String>(2)?)?,
        application_version: row.get(3)?,
        platform: row.get(4)?,
        created_at_unix_ms: u64_from_row(row, 5)?,
        latest_validation_id: row
            .get::<_, Option<String>>(6)?
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        candidate_test_targets: u64_from_row(row, 7)?,
        eligible_test_targets: u64_from_row(row, 8)?,
        evidence_digest_sha256: row.get(9)?,
        digest_verified: false,
        checks: Vec::new(),
    })
}

fn pilot_readiness_with_checks(
    connection: &Connection,
    mut snapshot: PilotReadinessSnapshot,
) -> Result<PilotReadinessSnapshot, CatalogError> {
    let mut statement = connection
        .prepare(
            "SELECT code, category, status, summary, evidence
               FROM pilot_readiness_checks WHERE snapshot_id = ?1 ORDER BY ordinal",
        )
        .map_err(|_| CatalogError::Storage)?;
    snapshot.checks = statement
        .query_map([snapshot.id.to_string()], |row| {
            Ok(PilotReadinessCheck {
                code: row.get(0)?,
                category: row.get(1)?,
                status: SecurityValidationStatus::from_storage(&row.get::<_, String>(2)?)?,
                summary: row.get(3)?,
                evidence: row.get(4)?,
            })
        })
        .map_err(|_| CatalogError::Storage)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| CatalogError::Storage)?;
    snapshot.digest_verified = pilot_readiness_digest(&snapshot)
        .is_ok_and(|digest| digest == snapshot.evidence_digest_sha256);
    Ok(snapshot)
}

fn security_validation_run_header_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecurityValidationRun> {
    Ok(SecurityValidationRun {
        id: uuid_from_row(row, 0)?,
        suite_version: row.get(1)?,
        status: SecurityValidationStatus::from_storage(&row.get::<_, String>(2)?)?,
        application_version: row.get(3)?,
        platform: row.get(4)?,
        started_at_unix_ms: u64_from_row(row, 5)?,
        finished_at_unix_ms: u64_from_row(row, 6)?,
        evidence_digest_sha256: row.get(7)?,
        digest_verified: false,
        checks: Vec::new(),
    })
}

fn security_validation_with_checks(
    connection: &Connection,
    mut run: SecurityValidationRun,
) -> Result<SecurityValidationRun, CatalogError> {
    let mut statement = connection
        .prepare(
            "SELECT code, category, status, summary, evidence
               FROM security_validation_checks WHERE run_id = ?1 ORDER BY ordinal",
        )
        .map_err(|_| CatalogError::Storage)?;
    run.checks = statement
        .query_map([run.id.to_string()], |row| {
            Ok(SecurityValidationCheck {
                code: row.get(0)?,
                category: row.get(1)?,
                status: SecurityValidationStatus::from_storage(&row.get::<_, String>(2)?)?,
                summary: row.get(3)?,
                evidence: row.get(4)?,
            })
        })
        .map_err(|_| CatalogError::Storage)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| CatalogError::Storage)?;
    run.digest_verified = run.verify_digest();
    Ok(run)
}

impl SecurityValidationRun {
    fn verify_digest(&self) -> bool {
        security_validation_digest(self).is_ok_and(|digest| digest == self.evidence_digest_sha256)
    }
}

fn create_run_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE synthetic_runs (
            id TEXT PRIMARY KEY NOT NULL,
            approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
            idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
            action_template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE RESTRICT,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            result_status TEXT CHECK (result_status IS NULL OR result_status IN ('synthetic_ok', 'cancelled', 'service_restarted', 'authorization_revoked')),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            started_at_unix_ms INTEGER,
            finished_at_unix_ms INTEGER,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
         CREATE TABLE safe_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'cancelled', 'interrupted', 'authorization_revoked')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            message TEXT NOT NULL CHECK (message IN ('request accepted', 'synthetic run started', 'synthetic run completed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
            created_at_unix_ms INTEGER NOT NULL,
            UNIQUE(run_id, sequence)
         );
         CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
         CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
         PRAGMA user_version = 4;
         COMMIT;",
    )
}

fn migrate_policy_snapshot_schema(connection: &Connection) -> rusqlite::Result<()> {
    let mut migration = String::from("BEGIN IMMEDIATE;");
    if !column_exists(connection, "approvals", "target_version")? {
        migration.push_str("ALTER TABLE approvals ADD COLUMN target_version INTEGER;");
    }
    if !column_exists(connection, "synthetic_runs", "target_version")? {
        migration.push_str("ALTER TABLE synthetic_runs ADD COLUMN target_version INTEGER;");
    }
    migration.push_str(
        "UPDATE approvals
            SET target_version = (SELECT version FROM targets WHERE targets.id = approvals.target_id)
          WHERE target_version IS NULL;
         UPDATE synthetic_runs
            SET target_version = (SELECT target_version FROM approvals WHERE approvals.id = synthetic_runs.approval_id)
          WHERE target_version IS NULL;
         PRAGMA user_version = 5;
         COMMIT;",
    );
    connection.execute_batch(&migration)
}

fn migrate_native_secret_and_postgres_schema(connection: &Connection) -> rusqlite::Result<()> {
    let mut migration = String::from("BEGIN IMMEDIATE;");
    for (table, column, definition) in [
        (
            "credential_references",
            "secret_configured",
            "INTEGER NOT NULL DEFAULT 0 CHECK (secret_configured IN (0, 1))",
        ),
        (
            "credential_references",
            "secret_updated_at_unix_ms",
            "INTEGER",
        ),
        ("targets", "postgres_host", "TEXT"),
        (
            "targets",
            "postgres_port",
            "INTEGER CHECK (postgres_port IS NULL OR postgres_port BETWEEN 1 AND 65535)",
        ),
        ("targets", "postgres_database", "TEXT"),
        ("targets", "postgres_username", "TEXT"),
        (
            "targets",
            "postgres_tls_mode",
            "TEXT CHECK (postgres_tls_mode IS NULL OR postgres_tls_mode = 'verify_full')",
        ),
    ] {
        if !column_exists(connection, table, column)? {
            write!(
                &mut migration,
                "ALTER TABLE {table} ADD COLUMN {column} {definition};"
            )
            .expect("writing a schema migration to String cannot fail");
        }
    }
    migration.push_str("PRAGMA user_version = 6; COMMIT;");
    connection.execute_batch(&migration)
}

#[allow(
    clippy::too_many_lines,
    reason = "the v7 table rebuild is kept in one auditable transaction"
)]
fn migrate_controlled_postgres_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "PRAGMA foreign_keys = OFF;
         BEGIN IMMEDIATE;
         CREATE TABLE action_templates_v7 (
            id TEXT PRIMARY KEY NOT NULL,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
            description TEXT CHECK (description IS NULL OR length(description) <= 240),
            timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         INSERT INTO action_templates_v7
            (id, target_id, name, operation, result_scope, description,
             timeout_seconds, enabled, created_at_unix_ms, updated_at_unix_ms, version)
         SELECT id, target_id, name, operation, result_scope, description,
                timeout_seconds, enabled, created_at_unix_ms, updated_at_unix_ms, version
           FROM action_templates;
         CREATE TABLE approvals_v7 (
            id TEXT PRIMARY KEY NOT NULL,
            action_template_id TEXT REFERENCES action_templates_v7(id) ON DELETE RESTRICT,
            action_template_version INTEGER,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            target_version INTEGER NOT NULL CHECK (target_version >= 1),
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
            reason TEXT CHECK (reason IS NULL OR length(reason) <= 240),
            state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
            decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= 240),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            expires_at_unix_ms INTEGER NOT NULL,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         INSERT INTO approvals_v7
            (id, action_template_id, action_template_version, target_id, target_version,
             operation, result_scope, reason, state, decision_note,
             created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version)
         SELECT id, action_template_id, action_template_version, target_id, target_version,
                operation, result_scope, reason, state, decision_note,
                created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version
           FROM approvals;
         CREATE TABLE synthetic_runs_v7 (
            id TEXT PRIMARY KEY NOT NULL,
            approval_id TEXT NOT NULL UNIQUE REFERENCES approvals_v7(id) ON DELETE RESTRICT,
            idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
            action_template_id TEXT NOT NULL REFERENCES action_templates_v7(id) ON DELETE RESTRICT,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            target_version INTEGER NOT NULL CHECK (target_version >= 1),
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            result_status TEXT CHECK (result_status IS NULL OR result_status IN ('synthetic_ok', 'postgres_connection_ok', 'postgres_connection_failed', 'postgres_configuration_invalid', 'credential_unavailable', 'timed_out', 'cancelled', 'service_restarted', 'authorization_revoked')),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            started_at_unix_ms INTEGER,
            finished_at_unix_ms INTEGER,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         INSERT INTO synthetic_runs_v7
            (id, approval_id, idempotency_key_hash, action_template_id, target_id,
             target_version, operation, result_scope, state, result_status,
             created_at_unix_ms, updated_at_unix_ms, started_at_unix_ms,
             finished_at_unix_ms, version)
         SELECT id, approval_id, idempotency_key_hash, action_template_id, target_id,
                target_version, operation, result_scope, state, result_status,
                created_at_unix_ms, updated_at_unix_ms, started_at_unix_ms,
                finished_at_unix_ms, version
           FROM synthetic_runs;
         CREATE TABLE safe_events_v7 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES synthetic_runs_v7(id) ON DELETE RESTRICT,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'failed', 'cancelled', 'interrupted', 'authorization_revoked')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            message TEXT NOT NULL CHECK (message IN ('request accepted', 'synthetic run started', 'synthetic run completed', 'postgres connection check started', 'postgres connection check succeeded', 'postgres connection check failed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
            created_at_unix_ms INTEGER NOT NULL,
            UNIQUE(run_id, sequence)
         );
         INSERT INTO safe_events_v7
            (id, run_id, sequence, kind, state, message, created_at_unix_ms)
         SELECT id, run_id, sequence, kind, state, message, created_at_unix_ms
           FROM safe_events;
         DROP TABLE safe_events;
         DROP TABLE synthetic_runs;
         DROP TABLE approvals;
         DROP TABLE action_templates;
         ALTER TABLE action_templates_v7 RENAME TO action_templates;
         ALTER TABLE approvals_v7 RENAME TO approvals;
         ALTER TABLE synthetic_runs_v7 RENAME TO synthetic_runs;
         ALTER TABLE safe_events_v7 RENAME TO safe_events;
         CREATE INDEX action_templates_target_idx ON action_templates(target_id);
         CREATE INDEX approvals_target_idx ON approvals(target_id);
         CREATE INDEX approvals_state_idx ON approvals(state);
         CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
         CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
         CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
         PRAGMA user_version = 7;
         COMMIT;
         PRAGMA foreign_keys = ON;",
    )?;
    if connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .is_some()
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn migrate_security_validation_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS security_validation_runs (
            id TEXT PRIMARY KEY NOT NULL,
            suite_version TEXT NOT NULL CHECK (length(suite_version) BETWEEN 1 AND 80),
            status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
            application_version TEXT NOT NULL CHECK (length(application_version) BETWEEN 1 AND 80),
            platform TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 80),
            started_at_unix_ms INTEGER NOT NULL,
            finished_at_unix_ms INTEGER NOT NULL,
            evidence_digest_sha256 TEXT NOT NULL CHECK (length(evidence_digest_sha256) = 64)
         );
         CREATE INDEX IF NOT EXISTS security_validation_runs_finished_idx
            ON security_validation_runs(finished_at_unix_ms DESC, id);
         CREATE TABLE IF NOT EXISTS security_validation_checks (
            run_id TEXT NOT NULL REFERENCES security_validation_runs(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 64),
            code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 80),
            category TEXT NOT NULL CHECK (category IN ('instance', 'isolated_scenario', 'manual_gate')),
            status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
            summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 240),
            evidence TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 240),
            PRIMARY KEY (run_id, ordinal),
            UNIQUE (run_id, code)
         );
         PRAGMA user_version = 8;
         COMMIT;",
    )
}

fn migrate_pilot_readiness_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS pilot_readiness_snapshots (
            id TEXT PRIMARY KEY NOT NULL,
            profile_version TEXT NOT NULL CHECK (length(profile_version) BETWEEN 1 AND 80),
            status TEXT NOT NULL CHECK (status IN ('ready', 'attention', 'blocked')),
            application_version TEXT NOT NULL CHECK (length(application_version) BETWEEN 1 AND 80),
            platform TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 80),
            created_at_unix_ms INTEGER NOT NULL,
            latest_validation_id TEXT REFERENCES security_validation_runs(id) ON DELETE RESTRICT,
            candidate_test_targets INTEGER NOT NULL CHECK (candidate_test_targets >= 0),
            eligible_test_targets INTEGER NOT NULL CHECK (eligible_test_targets >= 0),
            evidence_digest_sha256 TEXT NOT NULL CHECK (length(evidence_digest_sha256) = 64)
         );
         CREATE INDEX IF NOT EXISTS pilot_readiness_snapshots_created_idx
            ON pilot_readiness_snapshots(created_at_unix_ms DESC, id);
         CREATE TABLE IF NOT EXISTS pilot_readiness_checks (
            snapshot_id TEXT NOT NULL REFERENCES pilot_readiness_snapshots(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 64),
            code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 80),
            category TEXT NOT NULL CHECK (category IN ('configuration', 'evidence', 'manual_gate')),
            status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
            summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 240),
            evidence TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 240),
            PRIMARY KEY (snapshot_id, ordinal),
            UNIQUE (snapshot_id, code)
         );
         PRAGMA user_version = 9;
         COMMIT;",
    )
}

fn column_exists(
    connection: &Connection,
    table: &'static str,
    column: &str,
) -> rusqlite::Result<bool> {
    let query =
        format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)");
    connection.query_row(&query, [column], |row| row.get(0))
}

fn policy_evaluation(
    connection: &Connection,
    template: &ActionTemplate,
    target: &Target,
) -> Result<PolicyEvaluation, CatalogError> {
    let postgres = template.operation == ApprovalOperation::PostgresConnectionCheck;
    let mut reasons = Vec::new();
    if !template.enabled {
        reasons.push(PolicyReasonCode::TemplateDisabled);
    }
    if postgres {
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
            PolicyReasonCode::FixedSyntheticScope | PolicyReasonCode::FixedPostgresConnectionCheck
        )
    });
    Ok(PolicyEvaluation {
        policy_version: if postgres {
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
        requirements: if postgres {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::NoParameters,
                PolicyRequirement::SingleUse,
                PolicyRequirement::TransitionRevalidation,
                PolicyRequirement::TlsVerifyFull,
                PolicyRequirement::ReadOnlyTransaction,
                PolicyRequirement::StructuredStatusOnly,
            ]
        } else {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::NoParameters,
                PolicyRequirement::SingleUse,
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
        execution_mode: if postgres {
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
            "SELECT id, name, kind, purpose, secret_configured,
                    secret_updated_at_unix_ms, created_at_unix_ms,
                    updated_at_unix_ms, version
               FROM credential_references WHERE id = ?1",
            [id.to_string()],
            credential_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialReference> {
    let secret_configured = row.get::<_, bool>(4)?;
    Ok(CredentialReference {
        id: uuid_from_row(row, 0)?,
        name: row.get(1)?,
        kind: CredentialKind::from_storage(&row.get::<_, String>(2)?)?,
        purpose: row.get(3)?,
        secret_state: if secret_configured {
            SecretState::Available
        } else {
            SecretState::NotConfigured
        },
        secret_updated_at_unix_ms: row
            .get::<_, Option<i64>>(5)?
            .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        created_at_unix_ms: u64_from_row(row, 6)?,
        updated_at_unix_ms: u64_from_row(row, 7)?,
        version: u64_from_row(row, 8)?,
    })
}

fn target_by_id(connection: &Connection, id: Uuid) -> Result<Option<Target>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, environment, description,
                    credential_reference_id, postgres_host, postgres_port,
                    postgres_database, postgres_username, postgres_tls_mode,
                    created_at_unix_ms, updated_at_unix_ms, version
               FROM targets WHERE id = ?1",
            [id.to_string()],
            target_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn target_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Target> {
    let credential_id = row.get::<_, Option<String>>(5)?;
    let postgres_host = row.get::<_, Option<String>>(6)?;
    let postgres = postgres_host
        .map(|host| {
            let port = row
                .get::<_, i64>(7)?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok::<PostgresTargetConfig, rusqlite::Error>(PostgresTargetConfig {
                host,
                port,
                database: row.get(8)?,
                username: row.get(9)?,
                tls_mode: PostgresTlsMode::from_storage(&row.get::<_, String>(10)?)?,
            })
        })
        .transpose()?;
    Ok(Target {
        id: uuid_from_row(row, 0)?,
        name: row.get(1)?,
        kind: TargetKind::from_storage(&row.get::<_, String>(2)?)?,
        environment: TargetEnvironment::from_storage(&row.get::<_, String>(3)?)?,
        description: row.get(4)?,
        credential_reference_id: credential_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        postgres,
        created_at_unix_ms: u64_from_row(row, 11)?,
        updated_at_unix_ms: u64_from_row(row, 12)?,
        version: u64_from_row(row, 13)?,
    })
}

fn action_template_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<ActionTemplate>, CatalogError> {
    connection
        .query_row(
            "SELECT id, target_id, name, operation, result_scope, description,
                    timeout_seconds, enabled, created_at_unix_ms,
                    updated_at_unix_ms, version
               FROM action_templates WHERE id = ?1",
            [id.to_string()],
            action_template_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn action_template_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionTemplate> {
    Ok(ActionTemplate {
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
                    created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version
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
        "approvals" => "SELECT COUNT(*) FROM approvals",
        "action_templates" => "SELECT COUNT(*) FROM action_templates",
        "synthetic_runs" => "SELECT COUNT(*) FROM synthetic_runs",
        "security_validation_runs" => "SELECT COUNT(*) FROM security_validation_runs",
        "pilot_readiness_snapshots" => "SELECT COUNT(*) FROM pilot_readiness_snapshots",
        _ => return Err(CatalogError::Storage),
    };
    let count = connection
        .query_row(statement, [], |row| row.get::<_, i64>(0))
        .map_err(|_| CatalogError::Storage)?;
    (count < maximum)
        .then_some(())
        .ok_or(CatalogError::Capacity)
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
mod tests {
    use std::{fs, path::PathBuf};

    use uuid::Uuid;

    use super::{
        ApprovalOperation, ApprovalResultScope, ApprovalState, CancelSyntheticRun, Catalog,
        CatalogError, CreateActionTemplate, CreateApproval, CreateCredentialReference,
        CreateSyntheticRun, CreateTarget, CredentialKind, DecideApproval, POSTGRES_POLICY_VERSION,
        PilotReadinessStatus, PolicyDecision, PolicyReasonCode, PolicyRequirement,
        PostgresRunResult, PostgresTargetConfig, PostgresTlsMode, RunState,
        SYNTHETIC_POLICY_VERSION, SafeEventKind, SecretState, SecurityValidationStatus,
        TargetEnvironment, TargetKind, UpdateActionTemplate, UpdateCredentialReference,
        UpdateTarget,
    };

    #[test]
    fn security_validation_runs_full_isolated_suite_and_persists_evidence() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let run = catalog
            .execute_security_validation()
            .expect("execute security validation");

        assert_eq!(run.status, SecurityValidationStatus::Warning);
        assert_eq!(run.checks.len(), 10);
        assert_eq!(
            run.checks
                .iter()
                .filter(|check| check.status == SecurityValidationStatus::Passed)
                .count(),
            9
        );
        assert_eq!(
            run.checks.last().map(|check| check.code.as_str()),
            Some("identity_boundary_review")
        );
        assert!(run.digest_verified);

        let stored = catalog
            .get_security_validation_run(run.id)
            .expect("stored validation");
        assert!(stored.digest_verified);
        assert_eq!(
            catalog
                .list_security_validation_runs()
                .expect("validation history")
                .len(),
            1
        );
    }

    #[test]
    fn security_validation_digest_detects_evidence_tampering() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let run = catalog
            .execute_security_validation()
            .expect("execute security validation");
        catalog
            .lock()
            .execute(
                "UPDATE security_validation_checks SET evidence = 'tampered' WHERE run_id = ?1 AND ordinal = 1",
                [run.id.to_string()],
            )
            .expect("tamper test evidence");

        let stored = catalog
            .get_security_validation_run(run.id)
            .expect("stored validation");
        assert!(!stored.digest_verified);
    }

    #[test]
    fn pilot_readiness_is_blocked_without_prerequisites_and_persists_evidence() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let snapshot = catalog
            .execute_pilot_readiness_snapshot()
            .expect("pilot readiness snapshot");

        assert_eq!(snapshot.status, PilotReadinessStatus::Blocked);
        assert_eq!(snapshot.candidate_test_targets, 0);
        assert_eq!(snapshot.eligible_test_targets, 0);
        assert_eq!(snapshot.checks.len(), 10);
        assert!(snapshot.digest_verified);
        assert!(
            snapshot
                .checks
                .iter()
                .any(|check| check.code == "latest_validation_digest"
                    && check.status == SecurityValidationStatus::Failed)
        );
        let stored = catalog
            .get_pilot_readiness_snapshot(snapshot.id)
            .expect("stored readiness snapshot");
        assert!(stored.digest_verified);
        assert_eq!(
            catalog
                .list_pilot_readiness_snapshots()
                .expect("readiness history")
                .len(),
            1
        );
    }

    #[test]
    fn pilot_readiness_aggregates_eligible_target_and_latest_validation() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let validation = catalog
            .execute_security_validation()
            .expect("security validation");
        let credential = create_credential(&catalog);
        catalog
            .set_credential_secret_state(credential.id, credential.version, true)
            .expect("configured secret metadata");
        let target = catalog
            .create_target(&CreateTarget {
                name: "Dedicated pilot database".to_owned(),
                kind: TargetKind::Database,
                environment: TargetEnvironment::Test,
                description: None,
                credential_reference_id: Some(credential.id),
                postgres: Some(PostgresTargetConfig {
                    host: "pilot.test.example".to_owned(),
                    port: 5432,
                    database: "pilot".to_owned(),
                    username: "pilot_reader".to_owned(),
                    tls_mode: PostgresTlsMode::VerifyFull,
                }),
            })
            .expect("pilot target");
        catalog
            .create_action_template(&CreateActionTemplate {
                target_id: target.id,
                name: "Pilot connection check".to_owned(),
                operation: ApprovalOperation::PostgresConnectionCheck,
                result_scope: ApprovalResultScope::StatusOnly,
                description: None,
                timeout_seconds: 15,
            })
            .expect("pilot template");

        let snapshot = catalog
            .execute_pilot_readiness_snapshot()
            .expect("pilot readiness snapshot");
        assert_eq!(snapshot.status, PilotReadinessStatus::Attention);
        assert_eq!(snapshot.latest_validation_id, Some(validation.id));
        assert_eq!(snapshot.candidate_test_targets, 1);
        assert_eq!(snapshot.eligible_test_targets, 1);
        assert_eq!(
            snapshot
                .checks
                .iter()
                .filter(|check| check.status == SecurityValidationStatus::Failed)
                .count(),
            0
        );
        assert_eq!(
            snapshot
                .checks
                .iter()
                .filter(|check| check.status == SecurityValidationStatus::Warning)
                .count(),
            5
        );
    }

    #[test]
    fn pilot_readiness_digest_detects_evidence_tampering() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let snapshot = catalog
            .execute_pilot_readiness_snapshot()
            .expect("pilot readiness snapshot");
        catalog
            .lock()
            .execute(
                "UPDATE pilot_readiness_checks SET evidence = 'tampered'
                  WHERE snapshot_id = ?1 AND ordinal = 1",
                [snapshot.id.to_string()],
            )
            .expect("tamper readiness evidence");

        let stored = catalog
            .get_pilot_readiness_snapshot(snapshot.id)
            .expect("stored readiness snapshot");
        assert!(!stored.digest_verified);
    }

    #[test]
    fn linked_reference_cannot_be_deleted_before_its_target() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);

        assert_eq!(
            catalog.delete_credential_reference(credential.id),
            Err(CatalogError::ResourceInUse)
        );
        catalog.delete_target(target.id).expect("delete target");
        catalog
            .delete_credential_reference(credential.id)
            .expect("delete unlinked reference");
    }

    #[test]
    fn updates_increment_versions_and_preserve_relationships() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        let updated_credential = catalog
            .update_credential_reference(
                credential.id,
                &UpdateCredentialReference {
                    name: "Updated synthetic operator".to_owned(),
                    kind: CredentialKind::ApiToken,
                    purpose: Some("Updated metadata only".to_owned()),
                    expected_version: 1,
                },
            )
            .expect("update credential");
        let updated_target = catalog
            .update_target(
                target.id,
                &UpdateTarget {
                    name: "Updated synthetic target".to_owned(),
                    kind: TargetKind::HttpService,
                    environment: TargetEnvironment::Development,
                    description: None,
                    credential_reference_id: None,
                    postgres: None,
                    expected_version: 1,
                },
            )
            .expect("update target");

        assert_eq!(updated_credential.version, 2);
        assert_eq!(updated_credential.name, "Updated synthetic operator");
        assert_eq!(updated_target.version, 2);
        assert!(updated_target.credential_reference_id.is_none());

        let stale = catalog.update_credential_reference(
            credential.id,
            &UpdateCredentialReference {
                name: "Stale edit".to_owned(),
                kind: CredentialKind::Password,
                purpose: None,
                expected_version: 1,
            },
        );
        assert!(matches!(stale, Err(CatalogError::VersionConflict)));
    }

    #[test]
    fn records_survive_database_reopen() {
        let database = TemporaryDatabase::new();
        let credential_id = {
            let catalog = Catalog::open(&database.path).expect("open catalog");
            create_credential(&catalog).id
        };
        let reopened = Catalog::open(&database.path).expect("reopen catalog");
        let items = reopened
            .list_credential_references()
            .expect("list credentials");

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, credential_id);
        assert_eq!(items[0].version, 1);
    }

    #[test]
    fn control_characters_and_unknown_links_are_rejected() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let invalid = catalog.create_credential_reference(&CreateCredentialReference {
            name: "unsafe\nname".to_owned(),
            kind: CredentialKind::ApiToken,
            purpose: None,
        });
        assert!(matches!(invalid, Err(CatalogError::Invalid)));

        let target = catalog.create_target(&CreateTarget {
            name: "Synthetic target".to_owned(),
            kind: TargetKind::HttpService,
            environment: TargetEnvironment::Development,
            description: None,
            credential_reference_id: Some(Uuid::new_v4()),
            postgres: None,
        });
        assert!(matches!(
            target,
            Err(CatalogError::CredentialReferenceNotFound)
        ));
    }

    #[test]
    fn credential_secret_metadata_is_versioned_without_storing_a_secret() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let configured = catalog
            .set_credential_secret_state(credential.id, 1, true)
            .expect("mark configured");
        assert_eq!(configured.secret_state, SecretState::Available);
        assert!(configured.secret_updated_at_unix_ms.is_some());
        assert_eq!(configured.version, 2);

        assert!(matches!(
            catalog.set_credential_secret_state(credential.id, 1, false),
            Err(CatalogError::VersionConflict)
        ));
    }

    #[test]
    fn postgres_target_configuration_is_bounded_and_database_only() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = catalog
            .create_target(&CreateTarget {
                name: "Reporting replica".to_owned(),
                kind: TargetKind::Database,
                environment: TargetEnvironment::Test,
                description: None,
                credential_reference_id: Some(credential.id),
                postgres: Some(PostgresTargetConfig {
                    host: "DB.TEST.EXAMPLE".to_owned(),
                    port: 5432,
                    database: "reporting".to_owned(),
                    username: "secretbridge_reader".to_owned(),
                    tls_mode: PostgresTlsMode::VerifyFull,
                }),
            })
            .expect("PostgreSQL target");
        let postgres = target.postgres.expect("PostgreSQL configuration");
        assert_eq!(postgres.host, "db.test.example");
        assert_eq!(postgres.tls_mode, PostgresTlsMode::VerifyFull);

        assert!(matches!(
            catalog.create_target(&CreateTarget {
                name: "Invalid HTTP target".to_owned(),
                kind: TargetKind::HttpService,
                environment: TargetEnvironment::Test,
                description: None,
                credential_reference_id: None,
                postgres: Some(PostgresTargetConfig {
                    host: "example.test".to_owned(),
                    port: 5432,
                    database: "reporting".to_owned(),
                    username: "reader".to_owned(),
                    tls_mode: PostgresTlsMode::VerifyFull,
                }),
            }),
            Err(CatalogError::Invalid)
        ));
    }

    #[test]
    fn postgres_connection_check_requires_configured_password_and_has_safe_results() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        catalog
            .set_credential_secret_state(credential.id, credential.version, true)
            .expect("configured secret metadata");
        let target = catalog
            .create_target(&CreateTarget {
                name: "Read-only reporting database".to_owned(),
                kind: TargetKind::Database,
                environment: TargetEnvironment::Test,
                description: None,
                credential_reference_id: Some(credential.id),
                postgres: Some(PostgresTargetConfig {
                    host: "db.test.example".to_owned(),
                    port: 5432,
                    database: "reporting".to_owned(),
                    username: "secretbridge_reader".to_owned(),
                    tls_mode: PostgresTlsMode::VerifyFull,
                }),
            })
            .expect("PostgreSQL target");
        let template = catalog
            .create_action_template(&CreateActionTemplate {
                target_id: target.id,
                name: "PostgreSQL connection check".to_owned(),
                operation: ApprovalOperation::PostgresConnectionCheck,
                result_scope: ApprovalResultScope::StatusOnly,
                description: None,
                timeout_seconds: 10,
            })
            .expect("PostgreSQL template");
        let evaluation = catalog
            .evaluate_action_template(template.id)
            .expect("policy evaluation");
        assert_eq!(evaluation.policy_version, POSTGRES_POLICY_VERSION);
        assert_eq!(evaluation.decision, PolicyDecision::EligibleForApproval);
        assert_eq!(evaluation.execution_mode, "controlled_postgres");
        assert!(
            evaluation
                .requirements
                .contains(&PolicyRequirement::TlsVerifyFull)
        );
        assert!(
            evaluation
                .requirements
                .contains(&PolicyRequirement::ReadOnlyTransaction)
        );

        let approval = create_approval(&catalog, template.id);
        let approved = catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: None,
                },
            )
            .expect("approve PostgreSQL check");
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approved.id,
                idempotency_key: "postgres-check-001".to_owned(),
            })
            .expect("create PostgreSQL run")
            .run;
        catalog.start_run(run.id).expect("start PostgreSQL run");
        let completed = catalog
            .complete_postgres_run(run.id, PostgresRunResult::ConnectionFailed)
            .expect("finish PostgreSQL run");
        assert_eq!(completed.state, RunState::Failed);
        assert_eq!(
            completed.result_status.as_deref(),
            Some("postgres_connection_failed")
        );
        let events = catalog.list_safe_events(Some(run.id)).expect("safe events");
        assert_eq!(events[1].message, "postgres connection check started");
        assert_eq!(events[2].kind, SafeEventKind::Failed);
        assert_eq!(events[2].message, "postgres connection check failed");
    }

    #[test]
    fn approvals_are_versioned_and_follow_the_fixed_state_machine() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        let template = create_action_template(&catalog, target.id);
        let approval = create_approval(&catalog, template.id);
        assert_eq!(approval.state, ApprovalState::Pending);
        assert_eq!(approval.action_template_id, Some(template.id));
        assert_eq!(approval.action_template_version, Some(1));

        let approved = catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: 1,
                    note: Some("Synthetic scope reviewed".to_owned()),
                },
            )
            .expect("approve request");
        assert_eq!(approved.state, ApprovalState::Approved);
        assert_eq!(approved.version, 2);

        let stale = catalog.revoke_approval(
            approval.id,
            &DecideApproval {
                expected_version: 1,
                note: None,
            },
        );
        assert!(matches!(stale, Err(CatalogError::VersionConflict)));

        let revoked = catalog
            .revoke_approval(
                approval.id,
                &DecideApproval {
                    expected_version: 2,
                    note: Some("No longer needed".to_owned()),
                },
            )
            .expect("revoke approval");
        assert_eq!(revoked.state, ApprovalState::Revoked);
        assert_eq!(revoked.version, 3);

        let invalid = catalog.approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: 3,
                note: None,
            },
        );
        assert!(matches!(
            invalid,
            Err(CatalogError::InvalidApprovalTransition)
        ));
        assert_eq!(
            catalog.delete_target(target.id),
            Err(CatalogError::ResourceInUse)
        );
    }

    #[test]
    fn listing_expires_active_approvals() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        let template = create_action_template(&catalog, target.id);
        let approval = create_approval(&catalog, template.id);
        catalog
            .lock()
            .execute(
                "UPDATE approvals SET expires_at_unix_ms = 0 WHERE id = ?1",
                [approval.id.to_string()],
            )
            .expect("force expiry");

        let items = catalog.list_approvals().expect("list approvals");
        assert_eq!(items[0].state, ApprovalState::Expired);
        assert_eq!(items[0].version, 2);
    }

    #[test]
    fn version_one_database_migrates_to_the_current_schema() {
        let database = TemporaryDatabase::new();
        {
            let connection = rusqlite::Connection::open(&database.path).expect("open v1 database");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     CREATE TABLE credential_references (
                        id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
                        kind TEXT NOT NULL, purpose TEXT, secret_state TEXT NOT NULL,
                        created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     CREATE TABLE targets (
                        id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
                        kind TEXT NOT NULL, environment TEXT NOT NULL, description TEXT,
                        credential_reference_id TEXT REFERENCES credential_references(id) ON DELETE RESTRICT,
                        created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     CREATE INDEX targets_credential_reference_idx ON targets(credential_reference_id);
                     PRAGMA user_version = 1;",
                )
                .expect("create v1 schema");
        }

        let catalog = Catalog::open(&database.path).expect("migrate catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        let template = create_action_template(&catalog, target.id);
        let approval = create_approval(&catalog, template.id);
        assert_eq!(approval.state, ApprovalState::Pending);
        let version = catalog
            .lock()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("schema version");
        assert_eq!(version, 9);
    }

    #[test]
    fn version_two_approval_records_survive_template_migration() {
        let database = TemporaryDatabase::new();
        let target_id = Uuid::new_v4();
        let approval_id = Uuid::new_v4();
        {
            let connection = rusqlite::Connection::open(&database.path).expect("open v2 database");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     CREATE TABLE credential_references (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                        purpose TEXT, secret_state TEXT NOT NULL, created_at_unix_ms INTEGER NOT NULL,
                        updated_at_unix_ms INTEGER NOT NULL, version INTEGER NOT NULL
                     );
                     CREATE TABLE targets (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                        environment TEXT NOT NULL, description TEXT, credential_reference_id TEXT,
                        created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     CREATE TABLE approvals (
                        id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id),
                        operation TEXT NOT NULL, result_scope TEXT NOT NULL, reason TEXT,
                        state TEXT NOT NULL, decision_note TEXT, created_at_unix_ms INTEGER NOT NULL,
                        updated_at_unix_ms INTEGER NOT NULL, expires_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     PRAGMA user_version = 2;",
                )
                .expect("create v2 schema");
            connection
                .execute(
                    "INSERT INTO targets VALUES (?1, 'Migrated target', 'database', 'test', NULL, NULL, 1, 1, 1)",
                    [target_id.to_string()],
                )
                .expect("insert v2 target");
            connection
                .execute(
                    "INSERT INTO approvals VALUES (?1, ?2, 'inspect_metadata', 'metadata_summary', NULL, 'pending', NULL, 1, 1, 9999999999999, 1)",
                    [approval_id.to_string(), target_id.to_string()],
                )
                .expect("insert v2 approval");
        }

        let catalog = Catalog::open(&database.path).expect("migrate v2 catalog");
        let records = catalog.list_approvals().expect("list migrated approvals");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, approval_id);
        assert_eq!(records[0].action_template_id, None);
        assert_eq!(records[0].action_template_version, None);
        assert_eq!(records[0].target_version, 1);
        assert_eq!(
            catalog
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .expect("schema version"),
            9
        );
    }

    #[test]
    fn version_three_database_migrates_to_synthetic_runs() {
        let database = TemporaryDatabase::new();
        drop(Catalog::open(&database.path).expect("create current catalog"));
        {
            let connection = rusqlite::Connection::open(&database.path).expect("open database");
            connection
                .execute_batch(
                    "DROP TABLE safe_events;
                     DROP TABLE synthetic_runs;
                     PRAGMA user_version = 3;",
                )
                .expect("restore version three layout");
        }

        let catalog = Catalog::open(&database.path).expect("migrate v3 catalog");
        let approval = create_approved_workflow(&catalog);
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "v3-migration-check".to_owned(),
            })
            .expect("create run after migration")
            .run;
        assert_eq!(run.state, RunState::Queued);
        assert_eq!(
            catalog
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .expect("schema version"),
            9
        );
    }

    #[test]
    fn version_four_database_backfills_policy_target_snapshots() {
        let database = TemporaryDatabase::new();
        let (run_id, target_version) = {
            let catalog = Catalog::open(&database.path).expect("create current catalog");
            let approval = create_approved_workflow(&catalog);
            let run = catalog
                .create_synthetic_run(&CreateSyntheticRun {
                    approval_id: approval.id,
                    idempotency_key: "v4-policy-snapshot".to_owned(),
                })
                .expect("create run")
                .run;
            (run.id, approval.target_version)
        };
        {
            let connection = rusqlite::Connection::open(&database.path).expect("open database");
            connection
                .execute_batch(
                    "ALTER TABLE synthetic_runs DROP COLUMN target_version;
                     ALTER TABLE approvals DROP COLUMN target_version;
                     PRAGMA user_version = 4;",
                )
                .expect("restore version four layout");
        }

        let catalog = Catalog::open(&database.path).expect("migrate v4 catalog");
        let run = catalog.get_synthetic_run(run_id).expect("migrated run");
        assert_eq!(run.target_version, target_version);
        assert_eq!(
            catalog
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .expect("schema version"),
            9
        );
    }

    #[test]
    fn version_seven_database_adds_security_evidence_without_losing_history() {
        let database = TemporaryDatabase::new();
        let target_id = {
            let catalog = Catalog::open(&database.path).expect("create current catalog");
            create_target(&catalog, create_credential(&catalog).id).id
        };
        {
            let connection = rusqlite::Connection::open(&database.path).expect("open database");
            connection
                .execute_batch(
                    "DROP TABLE security_validation_checks;
                     DROP TABLE security_validation_runs;
                     PRAGMA user_version = 7;",
                )
                .expect("restore version seven layout");
        }

        let catalog = Catalog::open(&database.path).expect("migrate v7 catalog");
        assert_eq!(
            catalog.list_targets().expect("preserved targets")[0].id,
            target_id
        );
        let validation = catalog
            .execute_security_validation()
            .expect("validation after migration");
        assert!(validation.digest_verified);
        assert_eq!(
            catalog
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .expect("schema version"),
            9
        );
    }

    #[test]
    fn version_eight_database_adds_pilot_readiness_without_losing_validation() {
        let database = TemporaryDatabase::new();
        let validation_id = {
            let catalog = Catalog::open(&database.path).expect("create current catalog");
            catalog
                .execute_security_validation()
                .expect("security validation")
                .id
        };
        {
            let connection = rusqlite::Connection::open(&database.path).expect("open database");
            connection
                .execute_batch(
                    "DROP TABLE pilot_readiness_checks;
                     DROP TABLE pilot_readiness_snapshots;
                     PRAGMA user_version = 8;",
                )
                .expect("restore version eight layout");
        }

        let catalog = Catalog::open(&database.path).expect("migrate v8 catalog");
        assert_eq!(
            catalog
                .list_security_validation_runs()
                .expect("preserved validation")[0]
                .id,
            validation_id
        );
        let readiness = catalog
            .execute_pilot_readiness_snapshot()
            .expect("readiness after migration");
        assert_eq!(readiness.latest_validation_id, Some(validation_id));
        assert!(readiness.digest_verified);
        assert_eq!(
            catalog
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .expect("schema version"),
            9
        );
    }

    #[test]
    fn synthetic_runs_are_idempotent_single_use_and_cancellable() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let approval = create_approved_workflow(&catalog);
        let request = CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "request-001".to_owned(),
        };
        let created = catalog
            .create_synthetic_run(&request)
            .expect("create synthetic run");
        assert!(!created.replayed);
        assert_eq!(created.run.state, RunState::Queued);

        let replayed = catalog
            .create_synthetic_run(&request)
            .expect("replay idempotent request");
        assert!(replayed.replayed);
        assert_eq!(replayed.run.id, created.run.id);
        let other_approval = create_approved_workflow(&catalog);
        assert!(matches!(
            catalog.create_synthetic_run(&CreateSyntheticRun {
                approval_id: other_approval.id,
                idempotency_key: "request-001".to_owned(),
            }),
            Err(CatalogError::IdempotencyConflict)
        ));
        assert!(matches!(
            catalog.create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "request-002".to_owned(),
            }),
            Err(CatalogError::ApprovalConsumed)
        ));

        let running = catalog
            .start_synthetic_run(created.run.id)
            .expect("start synthetic run");
        assert_eq!(running.state, RunState::Running);
        assert_eq!(running.version, 2);
        assert!(matches!(
            catalog.cancel_synthetic_run(
                running.id,
                &CancelSyntheticRun {
                    expected_version: 1,
                },
            ),
            Err(CatalogError::VersionConflict)
        ));
        let cancelled = catalog
            .cancel_synthetic_run(
                running.id,
                &CancelSyntheticRun {
                    expected_version: 2,
                },
            )
            .expect("cancel synthetic run");
        assert_eq!(cancelled.state, RunState::Cancelled);
        assert_eq!(cancelled.result_status.as_deref(), Some("cancelled"));
        assert!(matches!(
            catalog.complete_synthetic_run(cancelled.id),
            Err(CatalogError::InvalidRunTransition)
        ));
        let events = catalog
            .list_safe_events(Some(cancelled.id))
            .expect("list safe events");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, SafeEventKind::Requested);
        assert_eq!(events[2].kind, SafeEventKind::Cancelled);
    }

    #[test]
    fn synthetic_runs_stop_when_authorization_is_no_longer_active() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");

        let queued_approval = create_approved_workflow(&catalog);
        let queued = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: queued_approval.id,
                idempotency_key: "revoked-before-start".to_owned(),
            })
            .expect("create queued run")
            .run;
        catalog
            .revoke_approval(
                queued_approval.id,
                &DecideApproval {
                    expected_version: queued_approval.version,
                    note: Some("Authorization withdrawn".to_owned()),
                },
            )
            .expect("revoke queued authorization");
        assert!(matches!(
            catalog.start_synthetic_run(queued.id),
            Err(CatalogError::ApprovalNotUsable)
        ));
        let stopped = catalog
            .invalidate_synthetic_run(queued.id)
            .expect("stop queued run");
        assert_eq!(stopped.state, RunState::Cancelled);
        assert_eq!(
            stopped.result_status.as_deref(),
            Some("authorization_revoked")
        );

        let running_approval = create_approved_workflow(&catalog);
        let running = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: running_approval.id,
                idempotency_key: "revoked-while-running".to_owned(),
            })
            .expect("create running run")
            .run;
        catalog
            .start_synthetic_run(running.id)
            .expect("start synthetic run");
        catalog
            .revoke_approval(
                running_approval.id,
                &DecideApproval {
                    expected_version: running_approval.version,
                    note: Some("Authorization withdrawn during run".to_owned()),
                },
            )
            .expect("revoke running authorization");
        assert!(matches!(
            catalog.complete_synthetic_run(running.id),
            Err(CatalogError::ApprovalNotUsable)
        ));
        let stopped = catalog
            .invalidate_synthetic_run(running.id)
            .expect("stop running run");
        assert_eq!(stopped.state, RunState::Cancelled);
        let events = catalog
            .list_safe_events(Some(stopped.id))
            .expect("list authorization events");
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].kind, SafeEventKind::AuthorizationRevoked);
        assert_eq!(events[2].message, "authorization no longer active");
    }

    #[test]
    fn active_runs_recover_as_failed_after_restart() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let approval = create_approved_workflow(&catalog);
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "restart-check".to_owned(),
            })
            .expect("create run")
            .run;
        catalog.start_synthetic_run(run.id).expect("start run");

        assert_eq!(catalog.recover_interrupted_runs().expect("recover runs"), 1);
        let recovered = catalog.get_synthetic_run(run.id).expect("recovered run");
        assert_eq!(recovered.state, RunState::Failed);
        assert_eq!(
            recovered.result_status.as_deref(),
            Some("service_restarted")
        );
        assert_eq!(
            catalog.recover_interrupted_runs().expect("repeat recovery"),
            0
        );
    }

    #[test]
    fn disabled_templates_reject_new_approvals_and_preserve_existing_snapshots() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        let template = create_action_template(&catalog, target.id);
        let approval = create_approval(&catalog, template.id);
        let disabled = catalog
            .update_action_template(
                template.id,
                &UpdateActionTemplate {
                    target_id: target.id,
                    name: template.name.clone(),
                    operation: ApprovalOperation::SyntheticHealthCheck,
                    result_scope: ApprovalResultScope::StatusOnly,
                    description: Some("Disabled after review".to_owned()),
                    timeout_seconds: 20,
                    enabled: false,
                    expected_version: 1,
                },
            )
            .expect("disable template");
        assert_eq!(disabled.version, 2);
        assert!(!disabled.enabled);
        assert!(matches!(
            catalog.create_approval(&CreateApproval {
                action_template_id: template.id,
                reason: None,
                expires_in_seconds: 300,
            }),
            Err(CatalogError::NotFound)
        ));
        let stored = catalog.list_approvals().expect("list approvals");
        assert_eq!(stored[0].id, approval.id);
        assert_eq!(stored[0].operation, ApprovalOperation::InspectMetadata);
        assert_eq!(stored[0].action_template_version, Some(1));
        assert_eq!(
            catalog.delete_action_template(template.id),
            Err(CatalogError::ResourceInUse)
        );
    }

    #[test]
    fn policy_evaluation_is_explainable_and_fails_closed_on_version_drift() {
        let catalog = Catalog::in_memory().expect("in-memory catalog");
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        let template = create_action_template(&catalog, target.id);
        let evaluation = catalog
            .evaluate_action_template(template.id)
            .expect("evaluate template");
        assert_eq!(evaluation.policy_version, SYNTHETIC_POLICY_VERSION);
        assert_eq!(evaluation.decision, PolicyDecision::EligibleForApproval);
        assert_eq!(
            evaluation.reason_codes,
            vec![PolicyReasonCode::FixedSyntheticScope]
        );
        assert_eq!(evaluation.target_version, target.version);
        assert!(
            evaluation
                .requirements
                .contains(&PolicyRequirement::TransitionRevalidation)
        );

        let pending = create_approval(&catalog, template.id);
        catalog
            .update_target(
                target.id,
                &UpdateTarget {
                    name: target.name.clone(),
                    kind: target.kind,
                    environment: target.environment,
                    description: Some("Changed after approval request".to_owned()),
                    credential_reference_id: target.credential_reference_id,
                    postgres: target.postgres.clone(),
                    expected_version: target.version,
                },
            )
            .expect("update target");
        assert!(matches!(
            catalog.approve_approval(
                pending.id,
                &DecideApproval {
                    expected_version: pending.version,
                    note: None,
                },
            ),
            Err(CatalogError::PolicyDenied)
        ));

        let second_target = create_target(&catalog, credential.id);
        let second_template = create_action_template(&catalog, second_target.id);
        let approval = create_approval(&catalog, second_template.id);
        let approved = catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: Some("Policy reviewed".to_owned()),
                },
            )
            .expect("approve request");
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approved.id,
                idempotency_key: "policy-drift-run".to_owned(),
            })
            .expect("create run")
            .run;
        catalog
            .update_action_template(
                second_template.id,
                &UpdateActionTemplate {
                    target_id: second_target.id,
                    name: second_template.name.clone(),
                    operation: second_template.operation,
                    result_scope: second_template.result_scope,
                    description: second_template.description.clone(),
                    timeout_seconds: second_template.timeout_seconds,
                    enabled: false,
                    expected_version: second_template.version,
                },
            )
            .expect("disable template");
        let denied = catalog
            .evaluate_action_template(second_template.id)
            .expect("evaluate disabled template");
        assert_eq!(denied.decision, PolicyDecision::Denied);
        assert_eq!(
            denied.reason_codes,
            vec![PolicyReasonCode::TemplateDisabled]
        );
        assert!(matches!(
            catalog.start_synthetic_run(run.id),
            Err(CatalogError::PolicyDenied)
        ));
    }

    fn create_credential(catalog: &Catalog) -> super::CredentialReference {
        catalog
            .create_credential_reference(&CreateCredentialReference {
                name: "Synthetic database operator".to_owned(),
                kind: CredentialKind::Password,
                purpose: None,
            })
            .expect("synthetic reference")
    }

    fn create_target(catalog: &Catalog, credential_id: Uuid) -> super::Target {
        catalog
            .create_target(&CreateTarget {
                name: "Synthetic reporting database".to_owned(),
                kind: TargetKind::Database,
                environment: TargetEnvironment::Test,
                description: None,
                credential_reference_id: Some(credential_id),
                postgres: None,
            })
            .expect("synthetic target")
    }

    fn create_action_template(catalog: &Catalog, target_id: Uuid) -> super::ActionTemplate {
        catalog
            .create_action_template(&CreateActionTemplate {
                target_id,
                name: "Inspect synthetic target metadata".to_owned(),
                operation: ApprovalOperation::InspectMetadata,
                result_scope: ApprovalResultScope::MetadataSummary,
                description: Some("No command or network operation".to_owned()),
                timeout_seconds: 15,
            })
            .expect("synthetic action template")
    }

    fn create_approval(catalog: &Catalog, action_template_id: Uuid) -> super::Approval {
        catalog
            .create_approval(&CreateApproval {
                action_template_id,
                reason: Some("Synthetic workflow validation".to_owned()),
                expires_in_seconds: 300,
            })
            .expect("synthetic approval")
    }

    fn create_approved_workflow(catalog: &Catalog) -> super::Approval {
        let credential = create_credential(catalog);
        let target = create_target(catalog, credential.id);
        let template = create_action_template(catalog, target.id);
        let approval = create_approval(catalog, template.id);
        catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: Some("Approved for synthetic run test".to_owned()),
                },
            )
            .expect("approve synthetic workflow")
    }

    struct TemporaryDatabase {
        path: PathBuf,
    }

    impl TemporaryDatabase {
        fn new() -> Self {
            Self {
                path: std::env::temp_dir().join(format!(
                    "secretbridge-catalog-test-{}.sqlite3",
                    Uuid::new_v4()
                )),
            }
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
