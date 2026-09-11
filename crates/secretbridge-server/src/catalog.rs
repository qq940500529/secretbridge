// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 4;
const MAX_CREDENTIAL_REFERENCES: i64 = 128;
const MAX_TARGETS: i64 = 128;
const MAX_APPROVALS: i64 = 512;
const MAX_ACTION_TEMPLATES: i64 = 256;
const MAX_RUNS: i64 = 1_024;
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    NotConfigured,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialReference {
    pub id: Uuid,
    pub name: String,
    pub kind: CredentialKind,
    pub purpose: Option<String>,
    pub secret_state: SecretState,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
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
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTarget {
    name: String,
    kind: TargetKind,
    environment: TargetEnvironment,
    description: Option<String>,
    credential_reference_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTarget {
    name: String,
    kind: TargetKind,
    environment: TargetEnvironment,
    description: Option<String>,
    credential_reference_id: Option<Uuid>,
    expected_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOperation {
    InspectMetadata,
    SyntheticHealthCheck,
}

impl ApprovalOperation {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::InspectMetadata => "inspect_metadata",
            Self::SyntheticHealthCheck => "synthetic_health_check",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "inspect_metadata" => Ok(Self::InspectMetadata),
            "synthetic_health_check" => Ok(Self::SyntheticHealthCheck),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    target_id: Uuid,
    name: String,
    operation: ApprovalOperation,
    result_scope: ApprovalResultScope,
    description: Option<String>,
    timeout_seconds: u64,
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
    action_template_id: Uuid,
    reason: Option<String>,
    expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideApproval {
    expected_version: u64,
    note: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    approval_id: Uuid,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelSyntheticRun {
    expected_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeEventKind {
    AuthorizationRevoked,
    Requested,
    Started,
    Succeeded,
    Cancelled,
    Interrupted,
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
    ResourceInUse,
    Storage,
    VersionConflict,
}

pub struct CreateRunOutcome {
    pub run: SyntheticRun,
    pub replayed: bool,
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
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn list_credential_references(&self) -> Result<Vec<CredentialReference>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, name, kind, purpose, created_at_unix_ms,
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
                        credential_reference_id, created_at_unix_ms,
                        updated_at_unix_ms, version
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
        let connection = self.lock();
        ensure_capacity(&connection, "targets", MAX_TARGETS)?;
        ensure_credential_exists(&connection, request.credential_reference_id)?;
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        connection
            .execute(
                "INSERT INTO targets
                    (id, name, kind, environment, description,
                     credential_reference_id, created_at_unix_ms,
                     updated_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1)",
                params![
                    id.to_string(),
                    name,
                    request.kind.as_storage(),
                    request.environment.as_storage(),
                    description,
                    request
                        .credential_reference_id
                        .map(|value| value.to_string()),
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
        let connection = self.lock();
        ensure_credential_exists(&connection, request.credential_reference_id)?;
        let changed = connection
            .execute(
                "UPDATE targets
                    SET name = ?1, kind = ?2, environment = ?3,
                        description = ?4, credential_reference_id = ?5,
                        updated_at_unix_ms = ?6, version = version + 1
                  WHERE id = ?7 AND version = ?8",
                params![
                    name,
                    request.kind.as_storage(),
                    request.environment.as_storage(),
                    description,
                    request
                        .credential_reference_id
                        .map(|value| value.to_string()),
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
                "SELECT id, action_template_id, action_template_version, target_id,
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
                    (id, action_template_id, action_template_version, target_id,
                     operation, result_scope, reason, state, decision_note,
                     created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', NULL, ?8, ?8, ?9, 1)",
                params![
                    id.to_string(),
                    template.id.to_string(),
                    i64::try_from(template.version).map_err(|_| CatalogError::Storage)?,
                    template.target_id.to_string(),
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
                "SELECT id, approval_id, action_template_id, target_id, operation,
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
                    (id, approval_id, idempotency_key_hash, action_template_id, target_id,
                     operation, result_scope, state, result_status, created_at_unix_ms,
                     updated_at_unix_ms, started_at_unix_ms, finished_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', NULL, ?8, ?8, NULL, NULL, 1)",
                params![
                    id.to_string(),
                    approval.id.to_string(),
                    idempotency_key_hash,
                    template_id.to_string(),
                    approval.target_id.to_string(),
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

    pub fn start_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            None,
            &[RunState::Queued],
            RunState::Running,
            None,
            SafeEventKind::Started,
            "synthetic run started",
        )
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
        )
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
        if matches!(next_state, RunState::Running | RunState::Succeeded)
            && !approval_by_id(&connection, current.approval_id)?
                .is_some_and(|approval| approval.state == ApprovalState::Approved)
        {
            return Err(CatalogError::ApprovalNotUsable);
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
                )
                .is_ok()
            {
                recovered += 1;
            }
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

fn credential_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<CredentialReference>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, purpose, created_at_unix_ms,
                    updated_at_unix_ms, version
               FROM credential_references WHERE id = ?1",
            [id.to_string()],
            credential_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialReference> {
    Ok(CredentialReference {
        id: uuid_from_row(row, 0)?,
        name: row.get(1)?,
        kind: CredentialKind::from_storage(&row.get::<_, String>(2)?)?,
        purpose: row.get(3)?,
        secret_state: SecretState::NotConfigured,
        created_at_unix_ms: u64_from_row(row, 4)?,
        updated_at_unix_ms: u64_from_row(row, 5)?,
        version: u64_from_row(row, 6)?,
    })
}

fn target_by_id(connection: &Connection, id: Uuid) -> Result<Option<Target>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, environment, description,
                    credential_reference_id, created_at_unix_ms,
                    updated_at_unix_ms, version
               FROM targets WHERE id = ?1",
            [id.to_string()],
            target_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn target_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Target> {
    let credential_id = row.get::<_, Option<String>>(5)?;
    Ok(Target {
        id: uuid_from_row(row, 0)?,
        name: row.get(1)?,
        kind: TargetKind::from_storage(&row.get::<_, String>(2)?)?,
        environment: TargetEnvironment::from_storage(&row.get::<_, String>(3)?)?,
        description: row.get(4)?,
        credential_reference_id: credential_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        created_at_unix_ms: u64_from_row(row, 6)?,
        updated_at_unix_ms: u64_from_row(row, 7)?,
        version: u64_from_row(row, 8)?,
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
            "SELECT id, action_template_id, action_template_version, target_id,
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
        operation: ApprovalOperation::from_storage(&row.get::<_, String>(4)?)?,
        result_scope: ApprovalResultScope::from_storage(&row.get::<_, String>(5)?)?,
        reason: row.get(6)?,
        state: ApprovalState::from_storage(&row.get::<_, String>(7)?)?,
        decision_note: row.get(8)?,
        created_at_unix_ms: u64_from_row(row, 9)?,
        updated_at_unix_ms: u64_from_row(row, 10)?,
        expires_at_unix_ms: u64_from_row(row, 11)?,
        version: u64_from_row(row, 12)?,
    })
}

fn synthetic_run_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, operation,
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
            "SELECT id, approval_id, action_template_id, target_id, operation,
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
            "SELECT id, approval_id, action_template_id, target_id, operation,
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
        operation: ApprovalOperation::from_storage(&row.get::<_, String>(4)?)?,
        result_scope: ApprovalResultScope::from_storage(&row.get::<_, String>(5)?)?,
        state: RunState::from_storage(&row.get::<_, String>(6)?)?,
        result_status: row.get(7)?,
        created_at_unix_ms: u64_from_row(row, 8)?,
        updated_at_unix_ms: u64_from_row(row, 9)?,
        started_at_unix_ms: optional_u64_from_row(row, 10)?,
        finished_at_unix_ms: optional_u64_from_row(row, 11)?,
        version: u64_from_row(row, 12)?,
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
        CreateSyntheticRun, CreateTarget, CredentialKind, DecideApproval, RunState, SafeEventKind,
        TargetEnvironment, TargetKind, UpdateActionTemplate, UpdateCredentialReference,
        UpdateTarget,
    };

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
        });
        assert!(matches!(
            target,
            Err(CatalogError::CredentialReferenceNotFound)
        ));
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
        assert_eq!(version, 4);
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
        assert_eq!(
            catalog
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .expect("schema version"),
            4
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
            4
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
