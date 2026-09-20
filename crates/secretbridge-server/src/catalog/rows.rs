// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use uuid::Uuid;

use super::{
    CredentialKind, CredentialReference, PostgresTargetConfig, PostgresTlsMode, SecretState,
    Target, TargetEnvironment, TargetKind, u64_from_row, uuid_from_row,
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
    let credential_id = row.get::<_, Option<String>>(7)?;
    let postgres_host = row.get::<_, Option<String>>(8)?;
    let postgres = postgres_host
        .map(|host| {
            let port = row
                .get::<_, i64>(9)?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok::<PostgresTargetConfig, rusqlite::Error>(PostgresTargetConfig {
                host,
                port,
                database: row.get(10)?,
                username: row.get(11)?,
                tls_mode: PostgresTlsMode::from_storage(&row.get::<_, String>(12)?)?,
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
        credential_reference_id: credential_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        postgres,
        created_at_unix_ms: u64_from_row(row, 13)?,
        updated_at_unix_ms: u64_from_row(row, 14)?,
        version: u64_from_row(row, 15)?,
    })
}
