// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use super::{Catalog, CatalogError, CreateActionTemplate, now_unix_ms_i64};

pub(super) fn reject_saved_terminal_binding(
    command: Option<&crate::command::CommandConfig>,
) -> Result<(), CatalogError> {
    if command.is_some_and(|command| command.terminal_id.is_some()) {
        return Err(CatalogError::Invalid);
    }
    Ok(())
}

impl Catalog {
    pub fn create_action_template(
        &self,
        request: &CreateActionTemplate,
    ) -> Result<super::ActionTemplate, CatalogError> {
        self.create_action_template_with_lifecycle(request, "saved")
    }

    pub(crate) fn create_one_time_draft(
        &self,
        request: &CreateActionTemplate,
    ) -> Result<super::ActionTemplate, CatalogError> {
        self.create_action_template_with_lifecycle(request, "one_time")
    }
}

pub(super) fn already_requested(connection: &Connection, id: Uuid) -> Result<bool, CatalogError> {
    connection
        .query_row(
            "SELECT 1 FROM approvals WHERE action_template_id = ?1 LIMIT 1",
            [id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|item| item.is_some())
        .map_err(|_| CatalogError::Storage)
}

pub(super) fn retire_draft(
    connection: &Connection,
    id: Option<Uuid>,
    now: i64,
) -> Result<(), CatalogError> {
    let Some(id) = id else {
        return Ok(());
    };
    connection
        .execute(
            "UPDATE action_templates
                SET enabled = 0, updated_at_unix_ms = ?2, version = version + 1
              WHERE id = ?1 AND lifecycle = 'one_time' AND enabled = 1",
            params![id.to_string(), now],
        )
        .map(|_| ())
        .map_err(|_| CatalogError::Storage)
}

pub(super) fn expire_approvals(connection: &Connection, now: i64) -> Result<(), CatalogError> {
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| CatalogError::Storage)?;
    transaction
        .execute(
            "UPDATE approvals
                SET state = 'expired', updated_at_unix_ms = ?1, version = version + 1
              WHERE state IN ('pending', 'approved') AND expires_at_unix_ms <= ?1",
            [now],
        )
        .map_err(|_| CatalogError::Storage)?;
    transaction
        .execute(
            "UPDATE action_templates
                SET enabled = 0, updated_at_unix_ms = ?1, version = version + 1
              WHERE lifecycle = 'one_time' AND enabled = 1
                AND EXISTS (
                    SELECT 1 FROM approvals
                     WHERE approvals.action_template_id = action_templates.id
                       AND approvals.state = 'expired'
                )",
            [now],
        )
        .map_err(|_| CatalogError::Storage)?;
    transaction.commit().map_err(|_| CatalogError::Storage)
}

pub(super) fn repair_lifecycle(connection: &Connection) -> rusqlite::Result<()> {
    let now = now_unix_ms_i64().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "DELETE FROM action_templates
          WHERE lifecycle = 'one_time'
            AND NOT EXISTS (
                SELECT 1 FROM approvals WHERE approvals.action_template_id = action_templates.id
            )",
        [],
    )?;
    transaction.execute(
        "UPDATE action_templates
            SET enabled = 0, updated_at_unix_ms = ?1, version = version + 1
          WHERE lifecycle = 'one_time' AND enabled = 1
            AND (
              EXISTS (SELECT 1 FROM approvals
                       WHERE approvals.action_template_id = action_templates.id
                         AND approvals.state IN ('denied', 'revoked', 'expired'))
              OR EXISTS (SELECT 1 FROM synthetic_runs
                          WHERE synthetic_runs.action_template_id = action_templates.id
                            AND synthetic_runs.state IN ('succeeded', 'cancelled', 'failed'))
            )",
        [now],
    )?;
    transaction.execute(
        "UPDATE action_templates
            SET enabled = 0, updated_at_unix_ms = ?1, version = version + 1
          WHERE lifecycle = 'saved' AND enabled = 1
            AND command_json IS NOT NULL
            AND json_extract(command_json, '$.terminal_id') IS NOT NULL",
        [now],
    )?;
    transaction.commit()
}
