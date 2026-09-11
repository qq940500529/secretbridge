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
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 1;
const MAX_CREDENTIAL_REFERENCES: i64 = 128;
const MAX_TARGETS: i64 = 128;
const MAX_NAME_CHARS: usize = 80;
const MAX_DESCRIPTION_CHARS: usize = 240;

#[derive(Clone)]
pub struct Catalog {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Debug)]
pub enum CatalogOpenError {
    Database(rusqlite::Error),
    UnsupportedSchema(i64),
}

impl fmt::Display for CatalogOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("the configuration database could not open"),
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
            Self::UnsupportedSchema(_) => None,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    Capacity,
    CredentialReferenceNotFound,
    Invalid,
    NotFound,
    ResourceInUse,
    Storage,
    VersionConflict,
}

impl Catalog {
    pub fn open(path: &Path) -> Result<Self, CatalogOpenError> {
        Self::initialize(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self, CatalogOpenError> {
        Self::initialize(Connection::open_in_memory()?)
    }

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
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
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

    pub fn delete_target(&self, id: Uuid) -> Result<(), CatalogError> {
        let changed = self
            .lock()
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

fn uuid_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&row.get::<_, String>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn u64_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    row.get::<_, i64>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn ensure_capacity(connection: &Connection, table: &str, maximum: i64) -> Result<(), CatalogError> {
    let statement = match table {
        "credential_references" => "SELECT COUNT(*) FROM credential_references",
        "targets" => "SELECT COUNT(*) FROM targets",
        _ => return Err(CatalogError::Storage),
    };
    let count = connection
        .query_row(statement, [], |row| row.get::<_, i64>(0))
        .map_err(|_| CatalogError::Storage)?;
    (count < maximum)
        .then_some(())
        .ok_or(CatalogError::Capacity)
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
        Catalog, CatalogError, CreateCredentialReference, CreateTarget, CredentialKind,
        TargetEnvironment, TargetKind, UpdateCredentialReference, UpdateTarget,
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
