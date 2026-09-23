// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    ActionTemplate, Catalog, CatalogError, ParameterValues, Target, normalize_required,
    now_unix_ms_i64, u64_from_row, uuid_from_row,
};

pub const ALL_OPERATIONS_ACKNOWLEDGEMENT: &str = "allow_all_operations_in_this_ai_conversation";
const GRANT_SECONDS: i64 = 3_600;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationApprovalPolicy {
    EveryTask,
    SameTaskOnce,
    ConversationOnce,
}

impl ConversationApprovalPolicy {
    const fn as_storage(self) -> &'static str {
        match self {
            Self::EveryTask => "every_task",
            Self::SameTaskOnce => "same_task_once",
            Self::ConversationOnce => "conversation_once",
        }
    }

    fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "every_task" => Ok(Self::EveryTask),
            "same_task_once" => Ok(Self::SameTaskOnce),
            "conversation_once" => Ok(Self::ConversationOnce),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct AiConversation {
    #[schemars(with = "String")]
    pub id: Uuid,
    pub summary: String,
    pub approval_policy: ConversationApprovalPolicy,
    pub grant_expires_at_unix_ms: Option<u64>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAiConversationPolicy {
    pub expected_version: u64,
    pub approval_policy: ConversationApprovalPolicy,
    pub risk_acknowledgement: Option<String>,
}

fn conversation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AiConversation> {
    Ok(AiConversation {
        id: uuid_from_row(row, 0)?,
        summary: row.get(1)?,
        approval_policy: ConversationApprovalPolicy::from_storage(&row.get::<_, String>(2)?)?,
        grant_expires_at_unix_ms: row
            .get::<_, Option<i64>>(3)?
            .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        created_at_unix_ms: u64_from_row(row, 4)?,
        updated_at_unix_ms: u64_from_row(row, 5)?,
        version: u64_from_row(row, 6)?,
    })
}

pub(super) fn conversation_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<AiConversation>, CatalogError> {
    connection
        .query_row(
            "SELECT id, summary, approval_policy, grant_expires_at_unix_ms,
                    created_at_unix_ms, updated_at_unix_ms, version
               FROM ai_conversations WHERE id = ?1",
            [id.to_string()],
            conversation_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(super) fn scope_hash(
    template: &ActionTemplate,
    target: &Target,
    parameters: &ParameterValues,
) -> Result<String, CatalogError> {
    let scope = serde_json::json!({
        "template_id": template.id,
        "template_version": template.version,
        "target_id": target.id,
        "target_version": target.version,
        "operation": template.operation,
        "result_scope": template.result_scope,
        "timeout_seconds": template.timeout_seconds,
        "command": template.command,
        "parameters": parameters,
    });
    let bytes = serde_json::to_vec(&scope).map_err(|_| CatalogError::Storage)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(super) fn may_reuse_approval(
    connection: &Connection,
    conversation: &AiConversation,
    fingerprint: &str,
    now: i64,
) -> Result<bool, CatalogError> {
    if conversation
        .grant_expires_at_unix_ms
        .is_none_or(|expires| expires <= u64::try_from(now).unwrap_or(u64::MAX))
    {
        return Ok(false);
    }
    match conversation.approval_policy {
        ConversationApprovalPolicy::EveryTask => Ok(false),
        ConversationApprovalPolicy::ConversationOnce => Ok(true),
        ConversationApprovalPolicy::SameTaskOnce => connection
            .query_row(
                "SELECT 1 FROM approvals
                  WHERE conversation_id = ?1 AND scope_hash = ?2 AND preauthorized = 0
                    AND state = 'approved' AND expires_at_unix_ms > ?3 LIMIT 1",
                params![conversation.id.to_string(), fingerprint, now],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(|_| CatalogError::Storage),
    }
}

impl Catalog {
    pub fn create_ai_conversation(&self, summary: &str) -> Result<AiConversation, CatalogError> {
        let summary = normalize_required(summary, 160)?;
        let connection = self.lock();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM ai_conversations", [], |row| {
                row.get(0)
            })
            .map_err(|_| CatalogError::Storage)?;
        if count >= 10_000 {
            return Err(CatalogError::Capacity);
        }
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        connection
            .execute(
                "INSERT INTO ai_conversations(id, summary, created_at_unix_ms, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?3)",
                params![id.to_string(), summary, now],
            )
            .map_err(|_| CatalogError::Storage)?;
        conversation_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn get_ai_conversation(&self, id: Uuid) -> Result<AiConversation, CatalogError> {
        conversation_by_id(&self.lock(), id)?.ok_or(CatalogError::NotFound)
    }

    pub fn list_ai_conversations(&self) -> Result<Vec<AiConversation>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, summary, approval_policy, grant_expires_at_unix_ms,
                        created_at_unix_ms, updated_at_unix_ms, version
                   FROM ai_conversations ORDER BY created_at_unix_ms DESC, id DESC",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], conversation_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn set_ai_conversation_policy(
        &self,
        id: Uuid,
        request: &SetAiConversationPolicy,
    ) -> Result<AiConversation, CatalogError> {
        if request.approval_policy == ConversationApprovalPolicy::ConversationOnce
            && request.risk_acknowledgement.as_deref() != Some(ALL_OPERATIONS_ACKNOWLEDGEMENT)
        {
            return Err(CatalogError::Invalid);
        }
        let connection = self.lock();
        let current = conversation_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        if current.version != request.expected_version {
            return Err(CatalogError::VersionConflict);
        }
        let now = now_unix_ms_i64()?;
        let expires_at = if request.approval_policy == ConversationApprovalPolicy::EveryTask {
            None
        } else {
            Some(
                now.checked_add(GRANT_SECONDS * 1_000)
                    .ok_or(CatalogError::Storage)?,
            )
        };
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE ai_conversations SET approval_policy = ?1,
                    grant_expires_at_unix_ms = ?2, updated_at_unix_ms = ?3,
                    version = version + 1 WHERE id = ?4 AND version = ?5",
                params![
                    request.approval_policy.as_storage(),
                    expires_at,
                    now,
                    id.to_string(),
                    i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return Err(CatalogError::VersionConflict);
        }
        match request.approval_policy {
            ConversationApprovalPolicy::EveryTask | ConversationApprovalPolicy::SameTaskOnce => {
                transaction
                    .execute(
                        "UPDATE approvals SET state = 'revoked', updated_at_unix_ms = ?1,
                        version = version + 1
                      WHERE conversation_id = ?2 AND preauthorized = 1 AND state = 'approved'",
                        params![now, id.to_string()],
                    )
                    .map_err(|_| CatalogError::Storage)?;
            }
            ConversationApprovalPolicy::ConversationOnce => {
                transaction
                    .execute(
                        "UPDATE approvals SET state = 'approved', preauthorized = 1,
                        decision_note = 'Conversation-wide approval grant',
                        expires_at_unix_ms = MIN(expires_at_unix_ms, ?1),
                        updated_at_unix_ms = ?2, version = version + 1
                      WHERE conversation_id = ?3 AND state = 'pending'
                        AND expires_at_unix_ms > ?2",
                        params![
                            expires_at.ok_or(CatalogError::Storage)?,
                            now,
                            id.to_string()
                        ],
                    )
                    .map_err(|_| CatalogError::Storage)?;
            }
        }
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        conversation_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }
}
