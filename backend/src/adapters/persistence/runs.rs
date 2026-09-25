// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApprovalOperation, ApprovalState, AuthorizationMode, CancelSyntheticRun, Catalog, CatalogError,
    CreateRunOutcome, CreateSyntheticRun, Digest, MAX_ACTIVE_RUNS, PostgresRunResult,
    RunExecutionContext, RunState, SafeEventKind, Sha256, SyntheticRun, Uuid,
    action_template_by_id, approval_by_id, credential_by_id, ensure_approval_policy,
    ensure_capacity, expire_approvals, insert_safe_event, normalize_idempotency_key,
    now_unix_ms_i64, one_time, params, synthetic_run_by_approval, synthetic_run_by_id,
    synthetic_run_by_idempotency_key_hash, synthetic_run_from_row, target_by_id, uuid_from_row,
};

impl Catalog {
    pub fn list_synthetic_runs(&self) -> Result<Vec<SyntheticRun>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                        result_scope, state, result_status, created_at_unix_ms,
                        updated_at_unix_ms, started_at_unix_ms,
                        finished_at_unix_ms, version
                   FROM synthetic_runs
                  ORDER BY created_at_unix_ms DESC, id",
            )
            .map_err(|_| CatalogError::Storage)?;
        statement
            .query_map([], synthetic_run_from_row)
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)
    }

    pub fn get_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        synthetic_run_by_id(&self.lock(), id)?.ok_or(CatalogError::NotFound)
    }

    pub fn create_synthetic_run(
        &self,
        request: &CreateSyntheticRun,
    ) -> Result<CreateRunOutcome, CatalogError> {
        let idempotency_key = normalize_idempotency_key(&request.idempotency_key)?;
        let idempotency_key_hash = hex::encode(Sha256::digest(idempotency_key.as_bytes()));
        let mut connection = self.lock();
        let now = now_unix_ms_i64()?;
        expire_approvals(&connection, now)?;
        if let Some(existing) =
            synthetic_run_by_idempotency_key_hash(&connection, &idempotency_key_hash)?
        {
            if existing.approval_id != request.approval_id {
                return Err(CatalogError::IdempotencyConflict);
            }
            return Ok(CreateRunOutcome {
                run: existing,
                replayed: true,
            });
        }
        let approval = approval_by_id(&connection, request.approval_id)?
            .filter(|approval| approval.state == ApprovalState::Approved)
            .ok_or(CatalogError::ApprovalNotUsable)?;
        if approval.authorization_mode != AuthorizationMode::TimeWindow
            && synthetic_run_by_approval(&connection, request.approval_id)?.is_some()
        {
            return Err(CatalogError::ApprovalConsumed);
        }
        ensure_approval_policy(&connection, &approval)?;
        let template_id = approval
            .action_template_id
            .ok_or(CatalogError::ApprovalNotUsable)?;
        ensure_capacity(&connection, "synthetic_runs", MAX_ACTIVE_RUNS)?;
        let id = Uuid::new_v4();
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        transaction
            .execute(
                "INSERT INTO synthetic_runs
                    (id, approval_id, idempotency_key_hash, action_template_id, target_id, target_version,
                     operation, result_scope, state, result_status, created_at_unix_ms,
                     updated_at_unix_ms, started_at_unix_ms, finished_at_unix_ms, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', NULL, ?9, ?9, NULL, NULL, 1)",
                params![
                    id.to_string(),
                    approval.id.to_string(),
                    idempotency_key_hash,
                    template_id.to_string(),
                    approval.target_id.to_string(),
                    i64::try_from(approval.target_version).map_err(|_| CatalogError::Storage)?,
                    approval.operation.as_storage(),
                    approval.result_scope.as_storage(),
                    now
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        insert_safe_event(
            &transaction,
            id,
            1,
            SafeEventKind::Requested,
            RunState::Queued,
            "request accepted",
            now,
        )?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        Ok(CreateRunOutcome {
            run: synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::Storage)?,
            replayed: false,
        })
    }

    pub fn start_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        let current = self.get_synthetic_run(id)?;
        let message = if current.operation == ApprovalOperation::CommandExecution {
            "command run started"
        } else if current.operation == ApprovalOperation::PostgresConnectionCheck {
            "postgres connection check started"
        } else {
            "synthetic run started"
        };
        self.transition_run(
            id,
            None,
            &[RunState::Queued],
            RunState::Running,
            None,
            SafeEventKind::Started,
            message,
            true,
        )
    }

    #[cfg(test)]
    pub fn start_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.start_run(id)
    }

    pub fn complete_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            None,
            &[RunState::Running],
            RunState::Succeeded,
            Some("synthetic_ok"),
            SafeEventKind::Succeeded,
            "synthetic run completed",
            true,
        )
    }

    pub fn complete_postgres_run(
        &self,
        id: Uuid,
        result: PostgresRunResult,
    ) -> Result<SyntheticRun, CatalogError> {
        let succeeded = result == PostgresRunResult::ConnectionOk;
        self.transition_run(
            id,
            None,
            &[RunState::Running],
            if succeeded {
                RunState::Succeeded
            } else {
                RunState::Failed
            },
            Some(result.status()),
            if succeeded {
                SafeEventKind::Succeeded
            } else {
                SafeEventKind::Failed
            },
            if succeeded {
                "postgres connection check succeeded"
            } else {
                "postgres connection check failed"
            },
            true,
        )
    }

    pub fn complete_command_run(
        &self,
        id: Uuid,
        status: &str,
        exit_code: Option<i32>,
    ) -> Result<SyntheticRun, CatalogError> {
        let succeeded = status == "command_ok";
        self.transition_run_with_exit(
            id,
            None,
            &[RunState::Running],
            if status == "cancelled" {
                RunState::Cancelled
            } else if succeeded {
                RunState::Succeeded
            } else {
                RunState::Failed
            },
            Some(status),
            if status == "cancelled" {
                SafeEventKind::Cancelled
            } else if succeeded {
                SafeEventKind::Succeeded
            } else {
                SafeEventKind::Failed
            },
            if status == "cancelled" {
                "run cancelled"
            } else if succeeded {
                "command run succeeded"
            } else {
                "command run failed"
            },
            false,
            exit_code,
        )
    }

    pub fn run_execution_context(&self, id: Uuid) -> Result<RunExecutionContext, CatalogError> {
        let connection = self.lock();
        let run = synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        let approval = approval_by_id(&connection, run.approval_id)?
            .filter(|approval| approval.state == ApprovalState::Approved)
            .ok_or(CatalogError::ApprovalNotUsable)?;
        ensure_approval_policy(&connection, &approval)?;
        let template = action_template_by_id(&connection, run.action_template_id)?
            .ok_or(CatalogError::PolicyDenied)?;
        let target = target_by_id(&connection, run.target_id)?.ok_or(CatalogError::PolicyDenied)?;
        let credential = target
            .credential_reference_id
            .map(|credential_id| credential_by_id(&connection, credential_id))
            .transpose()?
            .flatten();
        Ok(RunExecutionContext {
            approval,
            template,
            target,
            credential,
        })
    }

    pub fn cancel_synthetic_run(
        &self,
        id: Uuid,
        request: &CancelSyntheticRun,
    ) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            Some(request.expected_version),
            &[RunState::Queued, RunState::Running],
            RunState::Cancelled,
            Some("cancelled"),
            SafeEventKind::Cancelled,
            "run cancelled",
            false,
        )
    }

    pub fn invalidate_synthetic_run(&self, id: Uuid) -> Result<SyntheticRun, CatalogError> {
        self.transition_run(
            id,
            None,
            &[RunState::Queued, RunState::Running],
            RunState::Cancelled,
            Some("authorization_revoked"),
            SafeEventKind::AuthorizationRevoked,
            "authorization no longer active",
            false,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "run transitions keep state, result and safe-event data atomic"
    )]
    pub(super) fn transition_run(
        &self,
        id: Uuid,
        expected_version: Option<u64>,
        allowed_states: &[RunState],
        next_state: RunState,
        result_status: Option<&str>,
        event_kind: SafeEventKind,
        event_message: &str,
        revalidate_authorization: bool,
    ) -> Result<SyntheticRun, CatalogError> {
        self.transition_run_with_exit(
            id,
            expected_version,
            allowed_states,
            next_state,
            result_status,
            event_kind,
            event_message,
            revalidate_authorization,
            None,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "state, result, exit code and event commit atomically"
    )]
    fn transition_run_with_exit(
        &self,
        id: Uuid,
        expected_version: Option<u64>,
        allowed_states: &[RunState],
        next_state: RunState,
        result_status: Option<&str>,
        event_kind: SafeEventKind,
        event_message: &str,
        revalidate_authorization: bool,
        exit_code: Option<i32>,
    ) -> Result<SyntheticRun, CatalogError> {
        let mut connection = self.lock();
        let now = now_unix_ms_i64()?;
        expire_approvals(&connection, now)?;
        let current = synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::NotFound)?;
        if expected_version.is_some_and(|expected| expected != current.version) {
            return Err(CatalogError::VersionConflict);
        }
        if !allowed_states.contains(&current.state) {
            return Err(CatalogError::InvalidRunTransition);
        }
        if revalidate_authorization {
            let approval = approval_by_id(&connection, current.approval_id)?
                .filter(|approval| approval.state == ApprovalState::Approved)
                .ok_or(CatalogError::ApprovalNotUsable)?;
            ensure_approval_policy(&connection, &approval)?;
            if approval.action_template_id != Some(current.action_template_id)
                || approval.target_id != current.target_id
                || approval.target_version != current.target_version
                || approval.operation != current.operation
                || approval.result_scope != current.result_scope
            {
                return Err(CatalogError::PolicyDenied);
            }
        }
        let started_at = (next_state == RunState::Running).then_some(now);
        let finished_at = matches!(
            next_state,
            RunState::Succeeded | RunState::Cancelled | RunState::Failed
        )
        .then_some(now);
        let transaction = connection
            .transaction()
            .map_err(|_| CatalogError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE synthetic_runs
                    SET state = ?1, result_status = ?2, updated_at_unix_ms = ?3,
                        started_at_unix_ms = COALESCE(?4, started_at_unix_ms),
                        finished_at_unix_ms = COALESCE(?5, finished_at_unix_ms),
                        version = version + 1, exit_code = ?8
                  WHERE id = ?6 AND version = ?7",
                params![
                    next_state.as_storage(),
                    result_status,
                    now,
                    started_at,
                    finished_at,
                    id.to_string(),
                    i64::try_from(current.version).map_err(|_| CatalogError::Storage)?,
                    exit_code
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        if changed == 0 {
            return Err(CatalogError::VersionConflict);
        }
        insert_safe_event(
            &transaction,
            id,
            current.version + 1,
            event_kind,
            next_state,
            event_message,
            now,
        )?;
        if finished_at.is_some() {
            one_time::retire_draft(&transaction, Some(current.action_template_id), now)?;
        }
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        synthetic_run_by_id(&connection, id)?.ok_or(CatalogError::Storage)
    }

    pub fn recover_interrupted_runs(&self) -> Result<usize, CatalogError> {
        let ids = {
            let connection = self.lock();
            let mut statement = connection
                .prepare("SELECT id FROM synthetic_runs WHERE state IN ('queued', 'running')")
                .map_err(|_| CatalogError::Storage)?;
            statement
                .query_map([], |row| uuid_from_row(row, 0))
                .map_err(|_| CatalogError::Storage)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| CatalogError::Storage)?
        };
        let mut recovered = 0;
        for id in ids {
            self.transition_run(
                id,
                None,
                &[RunState::Queued, RunState::Running],
                RunState::Failed,
                Some("service_restarted"),
                SafeEventKind::Interrupted,
                "service restarted before completion",
                false,
            )?;
            recovered += 1;
        }
        Ok(recovered)
    }
}
