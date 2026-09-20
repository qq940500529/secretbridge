// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::{Catalog, CatalogError, now_unix_ms_i64};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAuthMode {
    PairingLink,
    Pin,
}

impl BrowserAuthMode {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::PairingLink => "pairing_link",
            Self::Pin => "pin",
        }
    }
}

impl Catalog {
    pub fn browser_auth_mode(&self) -> Result<BrowserAuthMode, CatalogError> {
        self.lock()
            .query_row(
                "SELECT mode FROM browser_auth_settings WHERE singleton = 1",
                [],
                |row| match row.get::<_, String>(0)?.as_str() {
                    "pairing_link" => Ok(BrowserAuthMode::PairingLink),
                    "pin" => Ok(BrowserAuthMode::Pin),
                    _ => Err(rusqlite::Error::InvalidQuery),
                },
            )
            .map_err(|_| CatalogError::Storage)
    }

    pub fn set_browser_auth_mode(&self, mode: BrowserAuthMode) -> Result<(), CatalogError> {
        self.lock()
            .execute(
                "UPDATE browser_auth_settings SET mode = ?1, updated_at_unix_ms = ?2 WHERE singleton = 1",
                params![mode.as_storage(), now_unix_ms_i64()?],
            )
            .map_err(|_| CatalogError::Storage)
            .and_then(|changed| (changed == 1).then_some(()).ok_or(CatalogError::Storage))
    }
}
