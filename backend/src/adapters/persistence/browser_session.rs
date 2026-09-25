// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::{OptionalExtension, params};

use super::{Catalog, CatalogError};

impl Catalog {
    pub fn revoke_all_browser_sessions(&self) -> Result<(), CatalogError> {
        self.lock()
            .execute("DELETE FROM browser_sessions", [])
            .map_err(|_| CatalogError::Storage)?;
        Ok(())
    }

    pub fn store_browser_session(
        &self,
        token_digest: &[u8; 32],
        expires_at_unix_ms: u64,
    ) -> Result<(), CatalogError> {
        let expires = i64::try_from(expires_at_unix_ms).map_err(|_| CatalogError::Storage)?;
        self.lock()
            .execute(
                "INSERT INTO browser_sessions(token_digest, expires_at_unix_ms)
                 VALUES(?1, ?2)
                 ON CONFLICT(token_digest) DO UPDATE SET expires_at_unix_ms=excluded.expires_at_unix_ms",
                params![token_digest.as_slice(), expires],
            )
            .map_err(|_| CatalogError::Storage)
            .and_then(|changed| (changed == 1).then_some(()).ok_or(CatalogError::Storage))
    }

    pub fn browser_session_remaining(
        &self,
        token_digest: &[u8; 32],
        now_unix_ms: u64,
    ) -> Result<Option<u64>, CatalogError> {
        let now = i64::try_from(now_unix_ms).map_err(|_| CatalogError::Storage)?;
        let connection = self.lock();
        connection
            .execute(
                "DELETE FROM browser_sessions WHERE expires_at_unix_ms <= ?1",
                [now],
            )
            .map_err(|_| CatalogError::Storage)?;
        let expires = connection
            .query_row(
                "SELECT expires_at_unix_ms FROM browser_sessions WHERE token_digest=?1",
                [token_digest.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| CatalogError::Storage)?;
        expires
            .map(|value| u64::try_from(value).map_err(|_| CatalogError::Storage))
            .transpose()
            .map(|expires| expires.map(|value| value.saturating_sub(now_unix_ms) / 1_000))
    }

    pub fn revoke_browser_session(&self, token_digest: &[u8; 32]) -> Result<bool, CatalogError> {
        self.lock()
            .execute(
                "DELETE FROM browser_sessions WHERE token_digest=?1",
                [token_digest.as_slice()],
            )
            .map(|changed| changed > 0)
            .map_err(|_| CatalogError::Storage)
    }

    pub fn active_browser_session_count(&self, now_unix_ms: u64) -> Result<usize, CatalogError> {
        let now = i64::try_from(now_unix_ms).map_err(|_| CatalogError::Storage)?;
        let connection = self.lock();
        connection
            .execute(
                "DELETE FROM browser_sessions WHERE expires_at_unix_ms <= ?1",
                [now],
            )
            .map_err(|_| CatalogError::Storage)?;
        connection
            .query_row("SELECT COUNT(*) FROM browser_sessions", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|_| CatalogError::Storage)
            .and_then(|count| usize::try_from(count).map_err(|_| CatalogError::Storage))
    }
}
