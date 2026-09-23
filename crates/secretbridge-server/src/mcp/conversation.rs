// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rmcp::ErrorData;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{catalog_task, parse_uuid};
use crate::catalog::Catalog;

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BeginConversationParams {
    #[schemars(
        description = "Short non-secret summary of this AI chat, up to 160 characters; never include credentials or raw messages"
    )]
    pub(super) summary: String,
}

pub(super) async fn resolve_conversation_id(
    catalog: Catalog,
    value: Option<&str>,
) -> Result<Uuid, ErrorData> {
    if let Some(value) = value {
        return parse_uuid(value);
    }
    // Older clients remain usable; each untagged request gets its own auditable group.
    Ok(
        catalog_task(move || {
            catalog.create_ai_conversation("MCP operation (chat ID not supplied)")
        })
        .await?
        .id,
    )
}
