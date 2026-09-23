// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Catalog, CatalogError, now_unix_ms_i64};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAuthMode {
    PairingLink,
    Pin,
    Totp,
}

impl BrowserAuthMode {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::PairingLink => "pairing_link",
            Self::Pin => "pin",
            Self::Totp => "totp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAuthEventKind {
    EnrollmentStarted,
    EnrollmentSucceeded,
    VerificationSucceeded,
    VerificationFailed,
    RateLimited,
    Disabled,
}

impl BrowserAuthEventKind {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::EnrollmentStarted => "enrollment_started",
            Self::EnrollmentSucceeded => "enrollment_succeeded",
            Self::VerificationSucceeded => "verification_succeeded",
            Self::VerificationFailed => "verification_failed",
            Self::RateLimited => "rate_limited",
            Self::Disabled => "disabled",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "enrollment_started" => Ok(Self::EnrollmentStarted),
            "enrollment_succeeded" => Ok(Self::EnrollmentSucceeded),
            "verification_succeeded" => Ok(Self::VerificationSucceeded),
            "verification_failed" => Ok(Self::VerificationFailed),
            "rate_limited" => Ok(Self::RateLimited),
            "disabled" => Ok(Self::Disabled),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAuthChannel {
    Browser,
    Mcp,
    Settings,
}

impl BrowserAuthChannel {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Mcp => "mcp",
            Self::Settings => "settings",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "browser" => Ok(Self::Browser),
            "mcp" => Ok(Self::Mcp),
            "settings" => Ok(Self::Settings),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BrowserAuthEvent {
    pub id: u64,
    pub kind: BrowserAuthEventKind,
    pub channel: BrowserAuthChannel,
    pub approval_id: Option<Uuid>,
    pub created_at_unix_ms: u64,
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
                    "totp" => Ok(BrowserAuthMode::Totp),
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

    #[cfg(test)]
    pub fn reset_totp_replay_guard(&self) -> Result<(), CatalogError> {
        self.lock()
            .execute(
                "UPDATE browser_auth_settings
                    SET last_totp_step = NULL, updated_at_unix_ms = ?1
                  WHERE singleton = 1",
                [now_unix_ms_i64()?],
            )
            .map_err(|_| CatalogError::Storage)
            .and_then(|changed| (changed == 1).then_some(()).ok_or(CatalogError::Storage))
    }

    pub fn consume_totp_step(&self, step: u64) -> Result<(), CatalogError> {
        let step = i64::try_from(step).map_err(|_| CatalogError::Invalid)?;
        let changed = self
            .lock()
            .execute(
                "UPDATE browser_auth_settings
                    SET last_totp_step = ?1, updated_at_unix_ms = ?2
                  WHERE singleton = 1
                    AND (last_totp_step IS NULL OR last_totp_step < ?1)",
                params![step, now_unix_ms_i64()?],
            )
            .map_err(|_| CatalogError::Storage)?;
        (changed == 1)
            .then_some(())
            .ok_or(CatalogError::InvalidApprovalTransition)
    }

    pub fn activate_totp(&self, step: u64) -> Result<(), CatalogError> {
        let step = i64::try_from(step).map_err(|_| CatalogError::Invalid)?;
        self.lock()
            .execute(
                "UPDATE browser_auth_settings
                    SET mode = 'totp', last_totp_step = ?1, updated_at_unix_ms = ?2
                  WHERE singleton = 1",
                params![step, now_unix_ms_i64()?],
            )
            .map_err(|_| CatalogError::Storage)
            .and_then(|changed| (changed == 1).then_some(()).ok_or(CatalogError::Storage))
    }

    pub fn deactivate_totp(&self) -> Result<(), CatalogError> {
        self.lock()
            .execute(
                "UPDATE browser_auth_settings
                    SET mode = 'pin', last_totp_step = NULL, updated_at_unix_ms = ?1
                  WHERE singleton = 1 AND mode = 'totp'",
                [now_unix_ms_i64()?],
            )
            .map_err(|_| CatalogError::Storage)
            .and_then(|changed| (changed == 1).then_some(()).ok_or(CatalogError::Invalid))
    }

    pub fn record_browser_auth_event(
        &self,
        kind: BrowserAuthEventKind,
        channel: BrowserAuthChannel,
        approval_id: Option<Uuid>,
    ) -> Result<(), CatalogError> {
        let mut connection = self.lock();
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "INSERT INTO browser_auth_events
                    (kind, channel, approval_id, created_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    kind.as_storage(),
                    channel.as_storage(),
                    approval_id.map(|id| id.to_string()),
                    now_unix_ms_i64()?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "DELETE FROM browser_auth_events
                  WHERE id NOT IN (
                    SELECT id FROM browser_auth_events ORDER BY id DESC LIMIT 2048
                  )",
                [],
            )
            .map_err(|_| CatalogError::Storage)?;
        transaction.commit().map_err(|_| CatalogError::Storage)
    }

    pub fn list_browser_auth_events(&self) -> Result<Vec<BrowserAuthEvent>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, kind, channel, approval_id, created_at_unix_ms
                   FROM browser_auth_events ORDER BY id DESC LIMIT 200",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], |row| {
                let approval_id = row
                    .get::<_, Option<String>>(3)?
                    .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
                    .transpose()?;
                Ok(BrowserAuthEvent {
                    id: u64::try_from(row.get::<_, i64>(0)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    kind: BrowserAuthEventKind::from_storage(&row.get::<_, String>(1)?)?,
                    channel: BrowserAuthChannel::from_storage(&row.get::<_, String>(2)?)?,
                    approval_id,
                    created_at_unix_ms: u64::try_from(row.get::<_, i64>(4)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            })
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }
}
