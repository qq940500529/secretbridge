// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::{Catalog, CatalogError, now_unix_ms_i64};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalNotificationChannel {
    Browser,
    System,
}

impl Catalog {
    pub fn approval_notification_channel(
        &self,
    ) -> Result<ApprovalNotificationChannel, CatalogError> {
        let connection = self.lock();
        let value: String = connection
            .query_row(
                "SELECT approval_notification_channel FROM browser_auth_settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CatalogError::Storage)?;
        match value.as_str() {
            "browser" => Ok(ApprovalNotificationChannel::Browser),
            "system" => Ok(ApprovalNotificationChannel::System),
            _ => Err(CatalogError::Storage),
        }
    }

    pub fn set_approval_notification_channel(
        &self,
        channel: ApprovalNotificationChannel,
    ) -> Result<(), CatalogError> {
        let value = match channel {
            ApprovalNotificationChannel::Browser => "browser",
            ApprovalNotificationChannel::System => "system",
        };
        self.lock()
            .execute(
                "UPDATE browser_auth_settings SET approval_notification_channel = ?1,
                 updated_at_unix_ms = ?2 WHERE singleton = 1",
                params![value, now_unix_ms_i64()?],
            )
            .map_err(|_| CatalogError::Storage)?;
        Ok(())
    }
}
