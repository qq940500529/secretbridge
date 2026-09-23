// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
use uuid::Uuid;

use super::{
    ApprovalOperation, ApprovalResultScope, Catalog, CatalogError, CreateActionTemplate,
    CreateCredentialReference, CreateTarget, CredentialKind, PostgresTargetConfig, SCHEMA_VERSION,
    TargetEnvironment, TargetKind, ensure_capacity, now_unix_ms_i64, validate_command,
};

pub(crate) const MAX_CONFIGURATION_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_BACKUP_BYTES: usize = 256 * 1024 * 1024;
const TABLES: [&str; 16] = [
    "credential_references",
    "targets",
    "action_templates",
    "approvals",
    "synthetic_runs",
    "safe_events",
    "command_slots",
    "run_output",
    "configuration_imports",
    "browser_auth_settings",
    "browser_auth_events",
    "browser_sessions",
    "diagnostic_failures",
    "diagnostic_vault",
    "diagnostic_records",
    "ai_conversations",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigurationBundle {
    pub format: String,
    pub format_version: u32,
    pub exported_at_unix_ms: u64,
    pub credentials: Vec<PortableCredential>,
    pub connections: Vec<PortableConnection>,
    pub templates: Vec<PortableTemplate>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortableCredential {
    pub id: Uuid,
    pub name: String,
    pub kind: CredentialKind,
    pub purpose: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortableConnection {
    pub id: Uuid,
    pub name: String,
    pub kind: TargetKind,
    pub environment: TargetEnvironment,
    pub description: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub allow_insecure_protocol: bool,
    pub credential_reference_id: Option<Uuid>,
    pub postgres: Option<PostgresTargetConfig>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortableTemplate {
    pub id: Uuid,
    pub target_id: Uuid,
    pub name: String,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub description: Option<String>,
    pub timeout_seconds: u64,
    pub enabled: bool,
    pub command: Option<crate::command::CommandConfig>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportRequest {
    pub bundle: ConfigurationBundle,
    pub expected_digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ImportReport {
    pub digest: String,
    pub credentials: usize,
    pub connections: usize,
    pub templates: usize,
    pub replayed: bool,
    pub credentials_need_configuration: bool,
}
#[derive(Debug, Serialize)]
pub struct BackupReport {
    pub schema_version: i64,
    pub restore_schema_version: i64,
    pub integrity_ok: bool,
    pub credentials: usize,
    pub connections: usize,
    pub templates: usize,
    pub runs: usize,
    pub requires_secret_reentry: bool,
    pub restores_authorizations: bool,
}

fn storage<T>(result: rusqlite::Result<T>) -> Result<T, CatalogError> {
    result.map_err(|_| CatalogError::Storage)
}
pub(crate) fn copy_database(
    source: &Connection,
    destination: &mut Connection,
) -> Result<(), CatalogError> {
    let pages: i64 = storage(source.query_row("PRAGMA page_count", [], |row| row.get(0)))?;
    let size: i64 = storage(source.query_row("PRAGMA page_size", [], |row| row.get(0)))?;
    if pages
        .checked_mul(size)
        .is_none_or(|bytes| !(0..=268_435_456).contains(&bytes))
    {
        return Err(CatalogError::Invalid);
    }
    let backup = storage(Backup::new(source, destination))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match storage(backup.step(128))? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => std::thread::sleep(Duration::from_millis(5)),
            _ => return Err(CatalogError::Storage),
        }
        if Instant::now() >= deadline {
            return Err(CatalogError::Storage);
        }
    }
}
fn clone_catalog(source: &Connection) -> Result<Catalog, CatalogError> {
    let mut connection = storage(Connection::open_in_memory())?;
    copy_database(source, &mut connection)?;
    Catalog::initialize(connection).map_err(|_| CatalogError::Invalid)
}

impl Catalog {
    pub(crate) fn export_configuration(&self) -> Result<ConfigurationBundle, CatalogError> {
        let snapshot = clone_catalog(&self.lock())?;
        let bundle = ConfigurationBundle {
            format: "secretbridge-configuration".into(),
            format_version: 1,
            exported_at_unix_ms: u64::try_from(now_unix_ms_i64()?)
                .map_err(|_| CatalogError::Storage)?,
            credentials: snapshot
                .list_credential_references()?
                .into_iter()
                .map(|item| PortableCredential {
                    id: item.id,
                    name: item.name,
                    kind: item.kind,
                    purpose: item.purpose,
                    address: item.address,
                    username: item.username,
                })
                .collect(),
            connections: snapshot
                .list_targets()?
                .into_iter()
                .map(|item| PortableConnection {
                    id: item.id,
                    name: item.name,
                    kind: item.kind,
                    environment: item.environment,
                    description: item.description,
                    address: item.address,
                    username: item.username,
                    allow_insecure_protocol: item.allow_insecure_protocol,
                    credential_reference_id: item.credential_reference_id,
                    postgres: item.postgres,
                })
                .collect(),
            templates: snapshot
                .list_action_templates()?
                .into_iter()
                .map(|item| PortableTemplate {
                    id: item.id,
                    target_id: item.target_id,
                    name: item.name,
                    operation: item.operation,
                    result_scope: item.result_scope,
                    description: item.description,
                    timeout_seconds: item.timeout_seconds,
                    enabled: item.enabled,
                    command: item.command,
                })
                .collect(),
        };
        bundle_digest(&bundle)?;
        Ok(bundle)
    }

    pub(crate) fn import_configuration(
        &self,
        bundle: &ConfigurationBundle,
        commit: bool,
        expected_digest: Option<&str>,
    ) -> Result<ImportReport, CatalogError> {
        let digest = bundle_digest(bundle)?;
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(CatalogError::Invalid);
        }
        let mut live = self.lock();
        let prior: Option<String> = storage(
            live.query_row(
                "SELECT report_json FROM configuration_imports WHERE digest=?1",
                [&digest],
                |row| row.get(0),
            )
            .optional(),
        )?;
        if let Some(prior) = prior {
            let mut report: ImportReport =
                serde_json::from_str(&prior).map_err(|_| CatalogError::Storage)?;
            report.replayed = true;
            return Ok(report);
        }
        ensure_capacity(&live, "configuration_imports", 256)?;
        let staged = clone_catalog(&live)?;
        let mut credentials = HashMap::new();
        let mut targets = HashMap::new();
        let mut template_ids = HashSet::new();
        for item in &bundle.credentials {
            if credentials.contains_key(&item.id) || item.id.is_nil() {
                return Err(CatalogError::Invalid);
            }
            let request: CreateCredentialReference = serde_json::from_value(
                serde_json::json!({"name":item.name,"kind":item.kind,"purpose":item.purpose,"address":item.address,"username":item.username}),
            )
            .map_err(|_| CatalogError::Invalid)?;
            credentials.insert(item.id, staged.create_credential_reference(&request)?.id);
        }
        for item in &bundle.connections {
            if targets.contains_key(&item.id) || item.id.is_nil() {
                return Err(CatalogError::Invalid);
            }
            let credential = item
                .credential_reference_id
                .map(|id| credentials.get(&id).copied().ok_or(CatalogError::Invalid))
                .transpose()?;
            let request: CreateTarget = serde_json::from_value(serde_json::json!({"name":item.name,"kind":item.kind,"environment":item.environment,"description":item.description,"address":item.address,"username":item.username,"allow_insecure_protocol":item.allow_insecure_protocol,"credential_reference_id":credential,"postgres":item.postgres})).map_err(|_| CatalogError::Invalid)?;
            targets.insert(item.id, staged.create_target(&request)?.id);
        }
        for item in &bundle.templates {
            if !template_ids.insert(item.id) || item.id.is_nil() {
                return Err(CatalogError::Invalid);
            }
            let mut command = item.command.clone();
            if let Some(command) = &mut command {
                for slot in &mut command.slots {
                    slot.credential_id = *credentials
                        .get(&slot.credential_id)
                        .ok_or(CatalogError::Invalid)?;
                }
            }
            let request = CreateActionTemplate {
                command,
                target_id: *targets.get(&item.target_id).ok_or(CatalogError::Invalid)?,
                name: item.name.clone(),
                operation: item.operation,
                result_scope: item.result_scope,
                description: item.description.clone(),
                timeout_seconds: item.timeout_seconds,
            };
            let created = staged.create_action_template(&request)?;
            if !item.enabled {
                storage(staged.lock().execute(
                    "UPDATE action_templates SET enabled=0 WHERE id=?1",
                    [created.id.to_string()],
                ))?;
            }
        }
        let report = ImportReport {
            digest: digest.clone(),
            credentials: credentials.len(),
            connections: targets.len(),
            templates: template_ids.len(),
            replayed: false,
            credentials_need_configuration: !credentials.is_empty(),
        };
        if commit {
            let json = serde_json::to_string(&report).map_err(|_| CatalogError::Storage)?;
            storage(staged.lock().execute(
                "INSERT INTO configuration_imports(digest,report_json) VALUES(?1,?2)",
                params![digest, json],
            ))?;
            copy_database(&staged.lock(), &mut live)?;
        }
        Ok(report)
    }

    pub(crate) fn backup_bytes(&self) -> Result<Vec<u8>, CatalogError> {
        let mut connection = storage(Connection::open_in_memory())?;
        copy_database(&self.lock(), &mut connection)?;
        storage(connection.execute_batch(
            "DELETE FROM browser_sessions;
             UPDATE browser_auth_settings SET mode='pairing_link';",
        ))?;
        let bytes = storage(connection.serialize("main"))?;
        if bytes.len() > MAX_BACKUP_BYTES {
            return Err(CatalogError::Invalid);
        }
        let mut standalone = bytes.to_vec();
        // Native backup has already incorporated committed WAL pages. Deserialization
        // requires rollback-mode header flags for this standalone snapshot:
        // https://www.sqlite.org/c3ref/deserialize.html
        standalone[18] = 1;
        standalone[19] = 1;
        Ok(standalone)
    }
}

fn bundle_digest(bundle: &ConfigurationBundle) -> Result<String, CatalogError> {
    if bundle.format != "secretbridge-configuration"
        || bundle.format_version != 1
        || bundle.credentials.len() > 128
        || bundle.connections.len() > 128
        || bundle.templates.len() > 256
    {
        return Err(CatalogError::Invalid);
    }
    let bytes = serde_json::to_vec(bundle).map_err(|_| CatalogError::Invalid)?;
    if bytes.len() > MAX_CONFIGURATION_BYTES {
        return Err(CatalogError::Invalid);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn inspect_backup(bytes: &[u8]) -> Result<(BackupReport, Catalog), CatalogError> {
    if bytes.len() < 100
        || bytes.len() > MAX_BACKUP_BYTES
        || !bytes.starts_with(b"SQLite format 3\0")
    {
        return Err(CatalogError::Invalid);
    }
    let mut connection = storage(Connection::open_in_memory())?;
    storage(connection.deserialize_read_exact("main", bytes, bytes.len(), true))?;
    storage(connection.pragma_update(None, "trusted_schema", false))?;
    let schema_version: i64 =
        storage(connection.query_row("PRAGMA user_version", [], |row| row.get(0)))?;
    if schema_version != SCHEMA_VERSION {
        return Err(CatalogError::Invalid);
    }
    let integrity: String =
        storage(connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0)))?;
    if integrity != "ok" {
        return Err(CatalogError::Invalid);
    }
    let foreign_key_errors: i64 = storage(connection.query_row(
        "SELECT COUNT(*) FROM pragma_foreign_key_check",
        [],
        |row| row.get(0),
    ))?;
    if foreign_key_errors != 0 {
        return Err(CatalogError::Invalid);
    }
    {
        let mut statement = storage(connection.prepare("SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','view','trigger') AND name NOT LIKE 'sqlite_%'"))?;
        let entries = storage(statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }))?;
        for entry in entries {
            let (kind, name, sql) = storage(entry)?;
            if kind != "table"
                || !TABLES.contains(&name.as_str())
                || !sql
                    .trim_start()
                    .to_ascii_uppercase()
                    .starts_with("CREATE TABLE")
            {
                return Err(CatalogError::Invalid);
            }
        }
    }
    let catalog = clone_catalog(&connection)?;
    let credentials = catalog.list_credential_references()?.len();
    let connections = catalog.list_targets()?.len();
    let templates = catalog.list_action_templates()?.len();
    let runs = catalog.list_synthetic_runs()?.len();
    catalog.list_approvals()?;
    catalog.list_safe_events(None)?;
    catalog.list_diagnostic_failures()?;
    if credentials > 128 || connections > 128 || templates > 256 || runs > 1024 {
        return Err(CatalogError::Invalid);
    }
    for template in catalog.list_action_templates()? {
        validate_command(
            &catalog.lock(),
            template.operation,
            template.command.as_ref(),
        )?;
    }
    Ok((
        BackupReport {
            schema_version,
            restore_schema_version: SCHEMA_VERSION,
            integrity_ok: true,
            credentials,
            connections,
            templates,
            runs,
            requires_secret_reentry: true,
            restores_authorizations: false,
        },
        catalog,
    ))
}

#[cfg(test)]
mod tests;
