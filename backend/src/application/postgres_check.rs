// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::{task, time::timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{AppState, CatalogError, invalidate_synthetic_run};
use crate::{
    catalog::PostgresRunResult,
    postgres::PostgresCheckOutcome,
    secret_store::{SECRET_READ_TIMEOUT, SecretReadError},
};

pub(crate) async fn drive_postgres_check(
    state: &AppState,
    run_id: Uuid,
    cancellation: &CancellationToken,
) {
    let _configuration = state.configuration_gate.read().await;
    let context_catalog = state.catalog.clone();
    let context = task::spawn_blocking(move || context_catalog.run_execution_context(run_id)).await;
    let context = match context {
        Ok(Ok(context)) => context,
        Ok(Err(CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied)) => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        }
        _ => return,
    };
    let Some(postgres_target) = context.target.postgres.as_ref() else {
        finish_postgres_check(state, run_id, PostgresRunResult::ConfigurationInvalid).await;
        return;
    };
    let Some(credential) = context.credential.as_ref() else {
        finish_postgres_check(state, run_id, PostgresRunResult::CredentialUnavailable).await;
        return;
    };
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let approval_remaining = Duration::from_millis(
        context
            .approval
            .expires_at_unix_ms
            .saturating_sub(now_unix_ms),
    );
    let operation_timeout = Duration::from_secs(context.template.timeout_seconds);
    let effective_timeout = operation_timeout.min(approval_remaining);
    if effective_timeout.is_zero() {
        invalidate_synthetic_run(state.catalog.clone(), run_id).await;
        return;
    }
    let started = Instant::now();
    let password = state
        .secret_reads
        .get(
            state.secret_store.clone(),
            credential.id,
            effective_timeout.min(SECRET_READ_TIMEOUT),
            Some(cancellation),
        )
        .await;
    let password = match password {
        Ok(password) => password,
        Err(SecretReadError::Cancelled) => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        }
        Err(SecretReadError::TimedOut) => {
            finish_postgres_check(state, run_id, PostgresRunResult::TimedOut).await;
            return;
        }
        Err(SecretReadError::Store(_) | SecretReadError::Worker) => {
            finish_postgres_check(state, run_id, PostgresRunResult::CredentialUnavailable).await;
            return;
        }
    };
    let effective_timeout = effective_timeout.saturating_sub(started.elapsed());
    if effective_timeout.is_zero() {
        finish_postgres_check(state, run_id, PostgresRunResult::TimedOut).await;
        return;
    }
    let check = state
        .postgres_executor
        .connection_check(postgres_target, &password);
    let result = tokio::select! {
        () = cancellation.cancelled() => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        },
        result = timeout(effective_timeout, check) => match result {
            Ok(PostgresCheckOutcome::ConnectionOk) => PostgresRunResult::ConnectionOk,
            Ok(PostgresCheckOutcome::ConnectionFailed) => PostgresRunResult::ConnectionFailed,
            Ok(PostgresCheckOutcome::ConfigurationInvalid) => PostgresRunResult::ConfigurationInvalid,
            Err(_) => PostgresRunResult::TimedOut,
        }
    };
    finish_postgres_check(state, run_id, result).await;
}

async fn finish_postgres_check(state: &AppState, run_id: Uuid, result: PostgresRunResult) {
    let complete_catalog = state.catalog.clone();
    let completed =
        task::spawn_blocking(move || complete_catalog.complete_postgres_run(run_id, result)).await;
    if matches!(
        completed,
        Ok(Err(
            CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied
        ))
    ) {
        invalidate_synthetic_run(state.catalog.clone(), run_id).await;
    }
}
