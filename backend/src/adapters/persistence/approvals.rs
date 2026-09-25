// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    Approval, ApprovalState, Catalog, CatalogError, CreateApproval, DecideApproval,
    MAX_ACTIVE_APPROVALS, MAX_APPROVAL_TTL_SECONDS, MAX_DESCRIPTION_CHARS,
    MIN_APPROVAL_TTL_SECONDS, PolicyDecision, Uuid, action_template_by_id, ai_conversations,
    approval_by_id, approval_from_row, ensure_approval_policy, ensure_capacity, expire_approvals,
    normalize_optional, now_unix_ms_i64, one_time, params, policy_evaluation, target_by_id,
};

impl Catalog {
    pub fn list_approvals(&self) -> Result<Vec<Approval>, CatalogError> {
        let connection = self.lock();
        expire_approvals(&connection, now_unix_ms_i64()?)?;
        let mut statement = connection
            .prepare(
                "SELECT id, action_template_id, action_template_version, target_id, target_version,
                        operation, result_scope, reason, state, decision_note,
                        created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version,
                        authorization_mode, parameters_json, conversation_id, preauthorized
                   FROM approvals
                  ORDER BY created_at_unix_ms DESC, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], approval_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn get_approval(&self, id: Uuid) -> Result<Approval, CatalogError> {
        let connection = self.lock();
        expire_approvals(&connection, now_unix_ms_i64()?)?;
        approval_by_id(&connection, id)?.ok_or(CatalogError::NotFound)
    }

    pub fn create_approval(&self, request: &CreateApproval) -> Result<Approval, CatalogError> {
        if !(MIN_APPROVAL_TTL_SECONDS..=MAX_APPROVAL_TTL_SECONDS)
            .contains(&request.expires_in_seconds)
        {
            return Err(CatalogError::Invalid);
        }
        let reason = normalize_optional(request.reason.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let connection = self.lock();
        let conversation = request
            .conversation_id
            .map(|id| {
                ai_conversations::conversation_by_id(&connection, id)?.ok_or(CatalogError::NotFound)
            })
            .transpose()?;
        ensure_capacity(&connection, "approvals", MAX_ACTIVE_APPROVALS)?;
        let template = action_template_by_id(&connection, request.action_template_id)?
            .filter(|template| template.enabled)
            .ok_or(CatalogError::NotFound)?;
        if template.one_time && one_time::already_requested(&connection, template.id)? {
            return Err(CatalogError::ApprovalConsumed);
        }
        let target =
            target_by_id(&connection, template.target_id)?.ok_or(CatalogError::NotFound)?;
        let parameters = crate::parameters::resolve(
            template
                .command
                .as_ref()
                .map_or(&[], |c| c.parameters.as_slice()),
            &request.parameters,
        )?;
        if policy_evaluation(&connection, &template, &target)?.decision
            != PolicyDecision::EligibleForApproval
        {
            return Err(CatalogError::PolicyDenied);
        }
        let id = Uuid::new_v4();
        let now = now_unix_ms_i64()?;
        let fingerprint = conversation
            .as_ref()
            .map(|_| ai_conversations::scope_hash(&template, &target, &parameters))
            .transpose()?;
        let preauthorized = match (&conversation, &fingerprint) {
            (Some(conversation), Some(fingerprint)) => {
                ai_conversations::may_reuse_approval(&connection, conversation, fingerprint, now)?
            }
            _ => false,
        };
        let ttl_ms = i64::try_from(request.expires_in_seconds)
            .map_err(|_| CatalogError::Invalid)?
            .checked_mul(1_000)
            .ok_or(CatalogError::Invalid)?;
        let expires_at = now.checked_add(ttl_ms).ok_or(CatalogError::Invalid)?;
        connection
            .execute(
                "INSERT INTO approvals
                    (id, action_template_id, action_template_version, target_id, target_version,
                     operation, result_scope, reason, state, decision_note,
                     created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version,
                     authorization_mode, parameters_json, conversation_id, scope_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', NULL, ?9, ?9, ?10, 1, ?11, ?12, ?13, ?14)",
                params![
                    id.to_string(),
                    template.id.to_string(),
                    i64::try_from(template.version).map_err(|_| CatalogError::Storage)?,
                    template.target_id.to_string(),
                    i64::try_from(target.version).map_err(|_| CatalogError::Storage)?,
                    template.operation.as_storage(),
                    template.result_scope.as_storage(),
                    reason,
                    now,
                    expires_at,
                    serde_json::to_string(&request.authorization_mode).map_err(|_| CatalogError::Invalid)?,
                    serde_json::to_string(&parameters).map_err(|_| CatalogError::Invalid)?,
                    request.conversation_id.map(|id| id.to_string()),
                    fingerprint
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if preauthorized {
            let grant_expiry = conversation
                .as_ref()
                .and_then(|item| item.grant_expires_at_unix_ms)
                .ok_or(CatalogError::Storage)?;
            connection
                .execute(
                    "UPDATE approvals SET state = 'approved', preauthorized = 1,
                    decision_note = 'Conversation approval policy',
                    expires_at_unix_ms = MIN(expires_at_unix_ms, ?1),
                    updated_at_unix_ms = ?2, version = version + 1 WHERE id = ?3",
                    params![
                        i64::try_from(grant_expiry).map_err(|_| CatalogError::Storage)?,
                        now,
                        id.to_string()
                    ],
                )
                .map_err(|_| CatalogError::Storage)?;
        }
        approval_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn approve_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
    ) -> Result<Approval, CatalogError> {
        self.transition_approval(id, request, ApprovalState::Pending, ApprovalState::Approved)
    }

    pub fn deny_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
    ) -> Result<Approval, CatalogError> {
        self.transition_approval(id, request, ApprovalState::Pending, ApprovalState::Denied)
    }

    pub fn revoke_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
    ) -> Result<Approval, CatalogError> {
        self.transition_approval(id, request, ApprovalState::Approved, ApprovalState::Revoked)
    }

    fn transition_approval(
        &self,
        id: Uuid,
        request: &DecideApproval,
        expected_state: ApprovalState,
        next_state: ApprovalState,
    ) -> Result<Approval, CatalogError> {
        let note = normalize_optional(request.note.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let expected_version =
            i64::try_from(request.expected_version).map_err(|_| CatalogError::Invalid)?;
        let connection = self.lock();
        let now = now_unix_ms_i64()?;
        expire_approvals(&connection, now)?;
        let Some(current) = approval_by_id(&connection, id)? else {
            return Err(CatalogError::NotFound);
        };
        if current.version != request.expected_version {
            return Err(CatalogError::VersionConflict);
        }
        if current.state != expected_state {
            return Err(CatalogError::InvalidApprovalTransition);
        }
        if next_state == ApprovalState::Approved {
            ensure_approval_policy(&connection, &current)?;
        }
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE approvals
                    SET state = ?1, decision_note = ?2, updated_at_unix_ms = ?3,
                        version = version + 1
                  WHERE id = ?4 AND version = ?5 AND state = ?6",
                params![
                    next_state.as_storage(),
                    note,
                    now,
                    id.to_string(),
                    expected_version,
                    expected_state.as_storage()
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return Err(CatalogError::VersionConflict);
        }
        if matches!(next_state, ApprovalState::Denied | ApprovalState::Revoked) {
            one_time::retire_draft(&transaction, current.action_template_id, now)?;
        }
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        approval_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }
}
