// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use super::{
    Approval, ApprovalOperation, ApprovalResultScope, ApprovalState, CatalogError, u64_from_row,
    uuid_from_row,
};

pub(super) fn approval_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<Approval>, CatalogError> {
    connection
        .query_row(
            "SELECT id, action_template_id, action_template_version, target_id, target_version,
                    operation, result_scope, reason, state, decision_note,
                    created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version,
                    authorization_mode, parameters_json, conversation_id, preauthorized
               FROM approvals WHERE id = ?1",
            [id.to_string()],
            approval_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(super) fn approval_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Approval> {
    let template_id = row.get::<_, Option<String>>(1)?;
    let conversation_id = row.get::<_, Option<String>>(16)?;
    Ok(Approval {
        authorization_mode: serde_json::from_str(&row.get::<_, String>(14)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        parameters: serde_json::from_str(&row.get::<_, String>(15)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        id: uuid_from_row(row, 0)?,
        action_template_id: template_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        conversation_id: conversation_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        preauthorized: row.get(17)?,
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
