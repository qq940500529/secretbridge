// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, AxumPath, CancelSyntheticRun, CancellationToken, Catalog, CatalogError,
    CreateRunOutcome, CreateSyntheticRun, CreateSyntheticRunResponse, Duration, Error, HeaderMap,
    Json, PathBuf, SafeEventListResponse, State, StatusCode, SyntheticRun,
    SyntheticRunListResponse, Uuid, catalog, command, drive_postgres_check, map_catalog_error, mcp,
    require_session, sleep, task, validate_origin,
};

pub(crate) async fn list_synthetic_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SyntheticRunListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_synthetic_runs())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(SyntheticRunListResponse {
        items,
        execution_mode: "controlled_operations",
    }))
}

pub(crate) async fn get_synthetic_run(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SyntheticRun>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let run = task::spawn_blocking(move || catalog.get_synthetic_run(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(run))
}

pub(crate) async fn create_synthetic_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSyntheticRun>,
) -> Result<(StatusCode, Json<CreateSyntheticRunResponse>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let outcome = create_run_for_state(&state, request)
        .await
        .map_err(map_catalog_error)?;
    let status = if outcome.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let execution_mode = run_execution_mode(outcome.run.operation);
    Ok((
        status,
        Json(CreateSyntheticRunResponse {
            run: outcome.run,
            replayed: outcome.replayed,
            execution_mode,
        }),
    ))
}

pub(crate) async fn create_run_for_state(
    state: &AppState,
    request: CreateSyntheticRun,
) -> Result<CreateRunOutcome, CatalogError> {
    let _lifecycle = state.configuration_gate.read().await;
    if state
        .runtime_control
        .as_ref()
        .is_some_and(|control| control.stopping.is_cancelled())
    {
        return Err(CatalogError::PolicyDenied);
    }
    let catalog = state.catalog.clone();
    let outcome = task::spawn_blocking(move || catalog.create_synthetic_run(&request))
        .await
        .map_err(|_| CatalogError::Storage)??;
    if !outcome.replayed {
        if let Ok(template) = state
            .catalog
            .get_action_template(outcome.run.action_template_id)
            && let Some(command) = template.command
        {
            let snapshot = serde_json::json!({
                "run_id": outcome.run.id,
                "template_id": template.id,
                "command": command,
            });
            if state
                .catalog
                .record_encrypted_diagnostic("command", snapshot)
                .is_err()
            {
                tracing::error!("encrypted diagnostic command capture failed");
            }
        }
        let run_id = outcome.run.id;
        let approval_id = outcome.run.approval_id;
        let cancellation = CancellationToken::new();
        state
            .run_cancellations
            .register(run_id, approval_id, cancellation.clone())
            .await;
        let drive_state = state.clone();
        tokio::spawn(async move {
            drive_run(drive_state.clone(), run_id, cancellation).await;
            if let Ok(run) = drive_state.catalog.get_synthetic_run(run_id) {
                let event = serde_json::json!({
                    "run_id": run.id,
                    "state": run.state,
                    "result_status": run.result_status,
                    "finished_at_unix_ms": run.finished_at_unix_ms,
                });
                if drive_state
                    .catalog
                    .record_encrypted_diagnostic("event", event)
                    .is_err()
                {
                    tracing::error!("encrypted diagnostic run capture failed");
                }
            }
            drive_state.run_cancellations.remove(run_id).await;
            let _ = drive_state.changes.send(());
        });
    }
    Ok(outcome)
}

pub(crate) const fn run_execution_mode(operation: catalog::ApprovalOperation) -> &'static str {
    if matches!(operation, catalog::ApprovalOperation::CommandExecution) {
        "credential_command"
    } else if matches!(
        operation,
        catalog::ApprovalOperation::PostgresConnectionCheck
    ) {
        "controlled_postgres"
    } else {
        "synthetic_simulation"
    }
}

pub(crate) async fn drive_run(state: AppState, run_id: Uuid, cancellation: CancellationToken) {
    tokio::select! {
        () = cancellation.cancelled() => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        },
        () = sleep(Duration::from_millis(100)) => {}
    }
    let start_catalog = state.catalog.clone();
    let started = task::spawn_blocking(move || start_catalog.start_run(run_id)).await;
    let started = match started {
        Ok(Ok(run)) => run,
        Ok(Err(CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied)) => {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
            return;
        }
        _ => return,
    };
    let _ = state.changes.send(());
    if started.operation == catalog::ApprovalOperation::CommandExecution {
        command::drive(&state, run_id, &cancellation).await;
    } else if started.operation == catalog::ApprovalOperation::PostgresConnectionCheck {
        drive_postgres_check(&state, run_id, &cancellation).await;
    } else {
        tokio::select! {
            () = cancellation.cancelled() => {
                invalidate_synthetic_run(state.catalog.clone(), run_id).await;
                return;
            },
            () = sleep(Duration::from_millis(750)) => {}
        }
        let complete_catalog = state.catalog.clone();
        let completed =
            task::spawn_blocking(move || complete_catalog.complete_synthetic_run(run_id)).await;
        if matches!(
            completed,
            Ok(Err(
                CatalogError::ApprovalNotUsable | CatalogError::PolicyDenied
            ))
        ) {
            invalidate_synthetic_run(state.catalog.clone(), run_id).await;
        }
    }
}

pub(crate) async fn invalidate_synthetic_run(catalog: Catalog, run_id: Uuid) {
    let _ = task::spawn_blocking(move || catalog.invalidate_synthetic_run(run_id)).await;
}

pub(crate) async fn cancel_synthetic_run(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CancelSyntheticRun>,
) -> Result<Json<SyntheticRun>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let run = cancel_run_for_state(&state, id, request)
        .await
        .map_err(map_catalog_error)?;
    Ok(Json(run))
}

pub(crate) async fn cancel_run_for_state(
    state: &AppState,
    id: Uuid,
    request: CancelSyntheticRun,
) -> Result<SyntheticRun, CatalogError> {
    let catalog = state.catalog.clone();
    let run = task::spawn_blocking(move || catalog.cancel_synthetic_run(id, &request))
        .await
        .map_err(|_| CatalogError::Storage)??;
    state.run_cancellations.cancel_run(id).await;
    Ok(run)
}

/// Serves the bounded MCP tool surface over stdio by connecting to a running local broker.
///
/// # Errors
///
/// Returns an error when the authenticated broker connection or stdio transport cannot initialize,
/// or when the MCP service terminates with a protocol or I/O failure.
pub async fn serve_mcp_stdio_bridge(
    connection_file: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    mcp::serve_stdio_bridge(connection_file).await
}

pub(crate) async fn list_run_safe_events(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SafeEventListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_safe_events(Some(id)))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(SafeEventListResponse {
        items,
        payload_policy: "fixed_safe_messages_only",
    }))
}

pub(crate) async fn list_safe_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SafeEventListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_safe_events(None))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(SafeEventListResponse {
        items,
        payload_policy: "fixed_safe_messages_only",
    }))
}
