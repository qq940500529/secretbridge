// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{Catalog, CatalogError, now_unix_ms_i64};
use rusqlite::params;
use serde::Serialize;
use uuid::Uuid;

/// Retained, redacted transcript; interactive submissions are input, not a fabricated shell audit.
#[derive(Debug, Serialize)]
pub struct TerminalHistoryEntry {
    pub cursor: i64,
    pub terminal_id: Uuid,
    pub occurred_at_unix_ms: u64,
    pub kind: String,
    pub data: String,
    pub metadata: serde_json::Value,
}

impl Catalog {
    pub(crate) fn record_terminal_history(
        &self,
        terminal_id: Uuid,
        kind: &str,
        data: &str,
        metadata: &serde_json::Value,
    ) -> Result<(), CatalogError> {
        if !["created", "input", "output", "command", "result", "closed"].contains(&kind)
            || data.len() > 65_536
        {
            return Err(CatalogError::Invalid);
        }
        let metadata = serde_json::to_string(metadata).map_err(|_| CatalogError::Invalid)?;
        if metadata.len() > 65_536 {
            return Err(CatalogError::Invalid);
        }
        let connection = self.lock();
        let tx = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        tx.execute("INSERT INTO terminal_history(terminal_id,occurred_at_unix_ms,kind,data,metadata_json) VALUES(?1,?2,?3,?4,?5)",
            params![terminal_id.to_string(), now_unix_ms_i64()?, kind, data, metadata]).map_err(|_| CatalogError::Storage)?;
        // A bounded transcript survives removing a live session and restarting the service.
        tx.execute("DELETE FROM terminal_history WHERE cursor <= (SELECT COALESCE(MAX(cursor),0)-10000 FROM terminal_history)", [])
            .map_err(|_| CatalogError::Storage)?;
        tx.commit().map_err(|_| CatalogError::Storage)
    }
    pub(crate) fn terminal_history(
        &self,
        terminal: Option<Uuid>,
        after: i64,
    ) -> Result<Vec<TerminalHistoryEntry>, CatalogError> {
        if after < 0 {
            return Err(CatalogError::Invalid);
        }
        let connection = self.lock();
        let mut statement = connection.prepare("SELECT cursor,terminal_id,occurred_at_unix_ms,kind,data,metadata_json FROM terminal_history WHERE cursor>?1 AND (?2 IS NULL OR terminal_id=?2) ORDER BY cursor LIMIT 500").map_err(|_| CatalogError::Storage)?;
        let rows = statement
            .query_map(params![after, terminal.map(|id| id.to_string())], |row| {
                let metadata: String = row.get(5)?;
                Ok(TerminalHistoryEntry {
                    cursor: row.get(0)?,
                    terminal_id: super::uuid_from_row(row, 1)?,
                    occurred_at_unix_ms: u64::try_from(row.get::<_, i64>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    kind: row.get(3)?,
                    data: row.get(4)?,
                    metadata: serde_json::from_str(&metadata)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            })
            .map_err(|_| CatalogError::Storage)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }
    pub(crate) fn clear_terminal_history(&self, terminal: Uuid) -> Result<(), CatalogError> {
        self.lock()
            .execute(
                "DELETE FROM terminal_history WHERE terminal_id=?1",
                [terminal.to_string()],
            )
            .map_err(|_| CatalogError::Storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_survives_reopen_without_a_live_terminal() {
        let path = std::env::temp_dir().join(format!("sb-history-{}.sqlite3", Uuid::new_v4()));
        let id = Uuid::new_v4();
        let catalog = Catalog::open(&path).unwrap();
        catalog
            .record_terminal_history(id, "input", "SELECT 1", &serde_json::json!({}))
            .unwrap();
        drop(catalog);
        let catalog = Catalog::open(&path).unwrap();
        let history = catalog.terminal_history(Some(id), 0).unwrap();
        assert_eq!(history[0].data, "SELECT 1");
        assert!(history[0].occurred_at_unix_ms > 0);
        drop(catalog);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn history_has_input_data_timestamps_pagination_and_deletion() {
        let catalog = Catalog::in_memory().unwrap();
        let terminal = Uuid::new_v4();
        let other = Uuid::new_v4();
        catalog
            .record_terminal_history(
                terminal,
                "command",
                "SELECT 1",
                &serde_json::json!({"run_id":"fixture","stdin_content":"SELECT 1"}),
            )
            .unwrap();
        catalog
            .record_terminal_history(other, "output", "other", &serde_json::json!({}))
            .unwrap();
        let rows = catalog.terminal_history(Some(terminal), 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].occurred_at_unix_ms > 0);
        assert_eq!(rows[0].metadata["stdin_content"], "SELECT 1");
        assert!(
            catalog
                .terminal_history(Some(terminal), rows[0].cursor)
                .unwrap()
                .is_empty()
        );
        catalog.clear_terminal_history(terminal).unwrap();
        assert_eq!(catalog.terminal_history(None, 0).unwrap().len(), 1);
    }
}
