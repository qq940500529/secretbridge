// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    Catalog, CatalogError, CreateCredentialReference, CredentialReference, MAX_ADDRESS_CHARS,
    MAX_CREDENTIAL_REFERENCES, MAX_DESCRIPTION_CHARS, MAX_NAME_CHARS, MAX_USERNAME_CHARS,
    SecretState, UpdateCredentialReference, Uuid, credential_by_id, credential_from_row,
    ensure_capacity, ensure_credential_reference_unlinked, normalize_optional, normalize_required,
    now_unix_ms_i64, params,
};

impl Catalog {
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
}
