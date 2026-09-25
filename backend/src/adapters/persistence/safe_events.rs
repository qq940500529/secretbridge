// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use uuid::Uuid;

use super::{
    Catalog, CatalogError, RunState, SafeEvent, SafeEventKind, synthetic_run_by_id, u64_from_row,
    uuid_from_row,
};

impl Catalog {
    pub fn list_safe_events(&self, run_id: Option<Uuid>) -> Result<Vec<SafeEvent>, CatalogError> {
        let connection = self.lock();
        if let Some(id) = run_id {
            synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        }
        if let Some(id) = run_id {
            let mut statement = connection
                .prepare(
                    "SELECT e.id, e.run_id, e.sequence, e.kind, e.state, e.message, e.created_at_unix_ms,
                            json_extract(t.command_json, '$.terminal_id')
                     FROM safe_events e
                     JOIN synthetic_runs r ON r.id = e.run_id
                     JOIN action_templates t ON t.id = r.action_template_id
                     WHERE e.run_id = ?1 ORDER BY e.sequence",
                )
                .map_err(|_| CatalogError::Storage)?;
            statement
                .query_map([id.to_string()], safe_event_from_row)
                .map_err(|_| CatalogError::Storage)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| CatalogError::Storage)
        } else {
            let mut statement = connection
                .prepare(
                    "SELECT e.id, e.run_id, e.sequence, e.kind, e.state, e.message, e.created_at_unix_ms,
                            json_extract(t.command_json, '$.terminal_id')
                     FROM safe_events e
                     JOIN synthetic_runs r ON r.id = e.run_id
                     JOIN action_templates t ON t.id = r.action_template_id
                     ORDER BY e.created_at_unix_ms DESC, e.id DESC",
                )
                .map_err(|_| CatalogError::Storage)?;
            statement
                .query_map([], safe_event_from_row)
                .map_err(|_| CatalogError::Storage)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| CatalogError::Storage)
        }
    }
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
        terminal_id: row
            .get::<_, Option<String>>(7)?
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
    })
}
