// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use super::{
    ActionTemplate, ApprovalOperation, ApprovalResultScope, CatalogError, CredentialKind,
    CredentialReference, PostgresTargetConfig, PostgresTlsMode, SecretState, Target,
    TargetEnvironment, TargetKind, u64_from_row, uuid_from_row,
};

pub(super) fn credential_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CredentialReference> {
    let secret_configured = row.get::<_, bool>(6)?;
    Ok(CredentialReference {
        id: uuid_from_row(row, 0)?,
        name: row.get(1)?,
        kind: CredentialKind::from_storage(&row.get::<_, String>(2)?)?,
        purpose: row.get(3)?,
        address: row.get(4)?,
        username: row.get(5)?,
        secret_state: if secret_configured {
            SecretState::Available
        } else {
            SecretState::NotConfigured
        },
        secret_updated_at_unix_ms: row
            .get::<_, Option<i64>>(7)?
            .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        created_at_unix_ms: u64_from_row(row, 8)?,
        updated_at_unix_ms: u64_from_row(row, 9)?,
        version: u64_from_row(row, 10)?,
    })
}

pub(super) fn target_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Target> {
    let credential_id = row.get::<_, Option<String>>(8)?;
    let postgres_host = row.get::<_, Option<String>>(9)?;
    let postgres = postgres_host
        .map(|host| {
            let port = row
                .get::<_, i64>(10)?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok::<PostgresTargetConfig, rusqlite::Error>(PostgresTargetConfig {
                host,
                port,
                database: row.get(11)?,
                username: row.get(12)?,
                tls_mode: PostgresTlsMode::from_storage(&row.get::<_, String>(13)?)?,
            })
        })
        .transpose()?;
    Ok(Target {
        id: uuid_from_row(row, 0)?,
        name: row.get(1)?,
        kind: TargetKind::from_storage(&row.get::<_, String>(2)?)?,
        environment: TargetEnvironment::from_storage(&row.get::<_, String>(3)?)?,
        description: row.get(4)?,
        address: row.get(5)?,
        username: row.get(6)?,
        allow_insecure_protocol: row.get(7)?,
        credential_reference_id: credential_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        postgres,
        created_at_unix_ms: u64_from_row(row, 14)?,
        updated_at_unix_ms: u64_from_row(row, 15)?,
        version: u64_from_row(row, 16)?,
    })
}

pub(super) fn action_template_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<ActionTemplate>, CatalogError> {
    connection
        .query_row(
            "SELECT id, target_id, name, operation, result_scope, description,
                    timeout_seconds, enabled, created_at_unix_ms,
                    updated_at_unix_ms, version, command_json, lifecycle
               FROM action_templates WHERE id = ?1",
            [id.to_string()],
            action_template_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(super) fn action_template_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ActionTemplate> {
    Ok(ActionTemplate {
        command: row
            .get::<_, Option<String>>(11)?
            .map(|json| serde_json::from_str(&json).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        one_time: row.get::<_, String>(12)? == "one_time",
        terminal_available: true,
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
