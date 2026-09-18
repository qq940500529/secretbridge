// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{
    ApiError, AppState, BackupReport, ConfigurationStorage, DefaultBodyLimit, IntoResponse, Json,
    Method, Next, Request, Response, Router, SecretState, Serialize, State, catalog, get,
    map_catalog_error, middleware, post, require_session, task, validate_origin,
};
use axum::body::Bytes;
use catalog::maintenance::{
    ConfigurationBundle, ImportReport, ImportRequest, MAX_BACKUP_BYTES, MAX_CONFIGURATION_BYTES,
};

pub(super) fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/maintenance/configuration", get(export))
        .route(
            "/api/v1/maintenance/configuration/preview",
            post(preview).layer(DefaultBodyLimit::max(MAX_CONFIGURATION_BYTES)),
        )
        .route(
            "/api/v1/maintenance/configuration/import",
            post(import).layer(DefaultBodyLimit::max(MAX_CONFIGURATION_BYTES + 1024)),
        )
        .route("/api/v1/maintenance/backup", get(backup))
        .route(
            "/api/v1/maintenance/backup/preview",
            post(preview_backup).layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES)),
        )
        .route("/api/v1/maintenance/diagnostics", get(diagnostics))
        .route_layer(middleware::from_fn_with_state(state, authenticate))
}

async fn authenticate(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    require_session(&state, request.headers()).await?;
    if request.method() != Method::GET {
        validate_origin(request.headers(), &state)?;
    }
    Ok(next.run(request).await)
}
async fn export(State(state): State<AppState>) -> Result<Json<ConfigurationBundle>, ApiError> {
    task::spawn_blocking(move || state.catalog.export_configuration())
        .await
        .map_err(|_| ApiError::Internal)?
        .map(Json)
        .map_err(map_catalog_error)
}
async fn preview(
    State(state): State<AppState>,
    payload: Result<Json<ConfigurationBundle>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ImportReport>, ApiError> {
    let Json(bundle) = payload.map_err(|_| ApiError::BadRequest)?;
    task::spawn_blocking(move || state.catalog.import_configuration(&bundle, false, None))
        .await
        .map_err(|_| ApiError::Internal)?
        .map(Json)
        .map_err(map_catalog_error)
}
async fn import(
    State(state): State<AppState>,
    payload: Result<Json<ImportRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ImportReport>, ApiError> {
    let Json(request) = payload.map_err(|_| ApiError::BadRequest)?;
    let _gate = state.configuration_gate.write().await;
    task::spawn_blocking(move || {
        state
            .catalog
            .import_configuration(&request.bundle, true, Some(&request.expected_digest))
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map(Json)
    .map_err(map_catalog_error)
}
async fn backup(State(state): State<AppState>) -> Result<Response, ApiError> {
    let bytes = task::spawn_blocking(move || state.catalog.backup_bytes())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((
        [
            ("content-type", "application/vnd.sqlite3"),
            (
                "content-disposition",
                "attachment; filename=secretbridge-backup.sqlite3",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn preview_backup(bytes: Bytes) -> Result<Json<BackupReport>, ApiError> {
    task::spawn_blocking(move || {
        catalog::maintenance::inspect_backup(&bytes).map(|(report, _)| report)
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map(Json)
    .map_err(|_| ApiError::BadRequest)
}
#[derive(Serialize)]
struct Diagnostics {
    format: &'static str,
    version: &'static str,
    platform: &'static str,
    schema_version: i64,
    storage: ConfigurationStorage,
    credentials: usize,
    configured_credentials: usize,
    connections: usize,
    templates: usize,
    pending_authorizations: usize,
    failed_runs: usize,
    terminal_sessions: usize,
    error_codes: std::collections::BTreeMap<&'static str, usize>,
}
async fn diagnostics(State(state): State<AppState>) -> Result<Json<Diagnostics>, ApiError> {
    task::spawn_blocking(move || {
        let credentials = state
            .catalog
            .list_credential_references()
            .map_err(map_catalog_error)?;
        let runs = state
            .catalog
            .list_synthetic_runs()
            .map_err(map_catalog_error)?;
        let mut error_codes = std::collections::BTreeMap::new();
        for run in runs
            .iter()
            .filter(|item| item.state == catalog::RunState::Failed)
        {
            let code = [
                "credential_unavailable",
                "timed_out",
                "service_restarted",
                "command_failed",
                "postgres_connection_failed",
                "postgres_configuration_invalid",
                "database_connection_failed",
                "database_query_failed",
                "http_request_failed",
                "ssh_connection_failed",
                "sftp_transfer_failed",
                "git_failed",
            ]
            .into_iter()
            .find(|code| run.result_status.as_deref() == Some(*code))
            .unwrap_or("other_failure");
            *error_codes.entry(code).or_insert(0) += 1;
        }
        Ok(Json(Diagnostics {
            format: "secretbridge-diagnostics",
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            schema_version: catalog::SCHEMA_VERSION,
            storage: state.configuration_storage,
            credentials: credentials.len(),
            configured_credentials: credentials
                .iter()
                .filter(|item| item.secret_state == SecretState::Available)
                .count(),
            connections: state
                .catalog
                .list_targets()
                .map_err(map_catalog_error)?
                .len(),
            templates: state
                .catalog
                .list_action_templates()
                .map_err(map_catalog_error)?
                .len(),
            pending_authorizations: state
                .catalog
                .list_approvals()
                .map_err(map_catalog_error)?
                .iter()
                .filter(|item| item.state == catalog::ApprovalState::Pending)
                .count(),
            failed_runs: runs
                .iter()
                .filter(|item| item.state == catalog::RunState::Failed)
                .count(),
            terminal_sessions: state.terminals.list().len(),
            error_codes,
        }))
    })
    .await
    .map_err(|_| ApiError::Internal)?
}

#[cfg(test)]
mod tests;
