// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ActionTemplate, Catalog, CatalogError, CreateActionTemplate, MAX_ACTION_TEMPLATES,
    MAX_DESCRIPTION_CHARS, MAX_NAME_CHARS, PolicyEvaluation, UpdateActionTemplate, Uuid,
    action_template_by_id, action_template_from_row, ensure_target_exists, normalize_optional,
    normalize_required, now_unix_ms_i64, one_time, params, policy_evaluation, save_command_slots,
    target_by_id, validate_command,
};

impl Catalog {
    pub fn list_action_templates(&self) -> Result<Vec<ActionTemplate>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, target_id, name, operation, result_scope, description,
                        timeout_seconds, enabled, created_at_unix_ms,
                    updated_at_unix_ms, version, command_json, lifecycle
                   FROM action_templates
                  WHERE lifecycle = 'saved'
                  ORDER BY created_at_unix_ms, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], action_template_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn get_action_template(&self, id: Uuid) -> Result<ActionTemplate, CatalogError> {
        action_template_by_id(&self.lock(), id)?.ok_or(CatalogError::NotFound)
    }

    pub fn evaluate_action_template(&self, id: Uuid) -> Result<PolicyEvaluation, CatalogError> {
        let connection = self.lock();
        let template = action_template_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        let target =
            target_by_id(&connection, template.target_id)?.ok_or(CatalogError::NotFound)?;
        policy_evaluation(&connection, &template, &target)
    }

    pub(super) fn create_action_template_with_lifecycle(
        &self,
        request: &CreateActionTemplate,
        lifecycle: &'static str,
    ) -> Result<ActionTemplate, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        if !(1..=300).contains(&request.timeout_seconds) {
            return Err(CatalogError::Invalid);
        }
        let connection = self.lock();
        validate_command(&connection, request.operation, request.command.as_ref())?;
        if lifecycle == "saved" {
            one_time::reject_saved_terminal_binding(request.command.as_ref())?;
        }
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM action_templates WHERE lifecycle = ?1",
                [lifecycle],
                |row| row.get(0),
            )
            .map_err(|_| CatalogError::Storage)?;
        if count
            >= if lifecycle == "saved" {
                MAX_ACTION_TEMPLATES
            } else {
                10_000
            }
        {
            return Err(CatalogError::Capacity);
        }
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
                     updated_at_unix_ms, version, command_json, lifecycle)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8, 1, ?9, ?10)",
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
                        .map_err(|_| CatalogError::Invalid)?,
                    lifecycle,
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
        one_time::reject_saved_terminal_binding(request.command.as_ref())?;
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
}
