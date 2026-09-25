// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    Catalog, CatalogError, CreateTarget, MAX_ADDRESS_CHARS, MAX_DESCRIPTION_CHARS, MAX_NAME_CHARS,
    MAX_TARGETS, MAX_USERNAME_CHARS, Target, TargetKind, UpdateTarget, Uuid, ensure_capacity,
    ensure_credential_exists, normalize_optional, normalize_postgres_config, normalize_required,
    now_unix_ms_i64, params, target_by_id, target_from_row,
};

impl Catalog {
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
}
