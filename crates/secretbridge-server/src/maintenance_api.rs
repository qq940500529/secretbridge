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

mod diagnostics;

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
        .route(
            "/api/v1/maintenance/diagnostics/export",
            post(export_diagnostics),
        )
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
    diagnostic_schema_version: u8,
    version: &'static str,
    platform: &'static str,
    bridge_schema_version: u8,
    authentication_mode: &'static str,
    encrypted_diagnostics_ready: bool,
    generated_at_unix_ms: u64,
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
    run_states: std::collections::BTreeMap<&'static str, usize>,
    failure_stages: std::collections::BTreeMap<&'static str, usize>,
    run_failures: Vec<RunFailureWindow>,
    mcp_failures: Vec<catalog::DiagnosticFailure>,
    terminal_states: std::collections::BTreeMap<&'static str, usize>,
    stale_terminal_references: usize,
    state_consistency: diagnostics::StateConsistency,
    state_consistency_issues: usize,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticExportRequest {
    pin: String,
    #[serde(default)]
    include_commands: bool,
    #[serde(default)]
    include_events: bool,
}

#[derive(Serialize)]
struct DiagnosticExport {
    format: &'static str,
    format_version: u8,
    records: Vec<catalog::diagnostic_vault::UnlockedDiagnosticRecord>,
}

async fn export_diagnostics(
    State(state): State<AppState>,
    Json(request): Json<DiagnosticExportRequest>,
) -> Result<Json<DiagnosticExport>, ApiError> {
    if !super::authentication_attempt_allowed(&state).await {
        return Err(ApiError::Unauthorized);
    }
    if !super::valid_browser_pin(&request.pin) {
        super::record_authentication_failure(&state).await;
        return Err(ApiError::Unauthorized);
    }
    let catalog = state.catalog.clone();
    let pin = zeroize::Zeroizing::new(request.pin);
    let result = task::spawn_blocking(move || {
        if !catalog.verify_diagnostic_pin(&pin)? {
            return Ok(None);
        }
        catalog
            .unlock_diagnostic_records(&pin, request.include_commands, request.include_events)
            .map(Some)
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(map_catalog_error)?;
    let Some(records) = result else {
        super::record_authentication_failure(&state).await;
        return Err(ApiError::Unauthorized);
    };
    super::reset_authentication_attempts(&state).await;
    Ok(Json(DiagnosticExport {
        format: "secretbridge-encrypted-diagnostics-export",
        format_version: 1,
        records,
    }))
}

#[derive(Serialize)]
struct RunFailureWindow {
    code: &'static str,
    stage: &'static str,
    recovery_actions: &'static [&'static str],
    occurrences: usize,
    failures_with_later_same_template_success: usize,
    first_at_unix_ms: u64,
    last_at_unix_ms: u64,
}
#[allow(
    clippy::too_many_lines,
    reason = "diagnostic counts are assembled from one consistent catalog snapshot"
)]
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
        let templates = state
            .catalog
            .list_action_templates()
            .map_err(map_catalog_error)?;
        let latest_success_by_template = runs
            .iter()
            .filter(|run| run.state == catalog::RunState::Succeeded)
            .fold(std::collections::HashMap::new(), |mut latest, run| {
                let timestamp = latest.entry(run.action_template_id).or_insert(0_u64);
                *timestamp = (*timestamp).max(run.updated_at_unix_ms);
                latest
            });
        let mut error_codes = std::collections::BTreeMap::new();
        let mut run_states = std::collections::BTreeMap::new();
        let mut failure_stages = std::collections::BTreeMap::new();
        let mut run_failures = std::collections::BTreeMap::<&'static str, RunFailureWindow>::new();
        for run in &runs {
            let state = match run.state {
                catalog::RunState::Queued => "queued",
                catalog::RunState::Running => "running",
                catalog::RunState::Succeeded => "succeeded",
                catalog::RunState::Cancelled => "cancelled",
                catalog::RunState::Failed => "failed",
            };
            *run_states.entry(state).or_insert(0) += 1;
        }
        for run in runs
            .iter()
            .filter(|item| item.state == catalog::RunState::Failed)
        {
            let code = [
                "credential_unavailable",
                "timed_out",
                "service_restarted",
                "authorization_revoked",
                "command_failed",
                "command_cleanup_failed",
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
            let failure_stage = match code {
                "credential_unavailable" => "credential_resolution",
                "authorization_revoked" => "authorization",
                "command_cleanup_failed" => "cleanup",
                "postgres_configuration_invalid" => "configuration",
                "postgres_connection_failed"
                | "database_connection_failed"
                | "ssh_connection_failed" => "connection",
                "timed_out" | "service_restarted" => "lifecycle",
                "database_query_failed"
                | "http_request_failed"
                | "sftp_transfer_failed"
                | "git_failed"
                | "command_failed" => "execution",
                _ => "other",
            };
            *failure_stages.entry(failure_stage).or_insert(0) += 1;
            let entry = run_failures.entry(code).or_insert(RunFailureWindow {
                code,
                stage: failure_stage,
                recovery_actions: diagnostics::run_recovery_actions(code),
                occurrences: 0,
                failures_with_later_same_template_success: 0,
                first_at_unix_ms: run.updated_at_unix_ms,
                last_at_unix_ms: run.updated_at_unix_ms,
            });
            entry.occurrences += 1;
            if latest_success_by_template
                .get(&run.action_template_id)
                .is_some_and(|timestamp| *timestamp > run.updated_at_unix_ms)
            {
                entry.failures_with_later_same_template_success += 1;
            }
            entry.first_at_unix_ms = entry.first_at_unix_ms.min(run.updated_at_unix_ms);
            entry.last_at_unix_ms = entry.last_at_unix_ms.max(run.updated_at_unix_ms);
        }
        let terminals = state.terminals.list();
        let mut terminal_states = std::collections::BTreeMap::new();
        for terminal in &terminals {
            let name = match terminal.status {
                crate::terminal::TerminalStatus::Running => "running",
                crate::terminal::TerminalStatus::Exited => "exited",
                crate::terminal::TerminalStatus::Terminated => "terminated",
                crate::terminal::TerminalStatus::Failed => "failed",
            };
            *terminal_states.entry(name).or_insert(0) += 1;
        }
        let stale_terminal_references = templates
            .iter()
            .filter_map(|template| template.command.as_ref()?.terminal_id)
            .filter(|id| !terminals.iter().any(|terminal| terminal.id == *id))
            .count();
        let state_consistency = diagnostics::check_state_consistency(&runs, &templates, &terminals);
        let state_consistency_issues = state_consistency.total_issues();
        let authentication_mode = match state
            .catalog
            .browser_auth_mode()
            .map_err(map_catalog_error)?
        {
            catalog::BrowserAuthMode::PairingLink => "pairing_link",
            catalog::BrowserAuthMode::Pin => "pin",
            catalog::BrowserAuthMode::Totp => "totp",
        };
        Ok(Json(Diagnostics {
            format: "secretbridge-diagnostics",
            diagnostic_schema_version: 4,
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            bridge_schema_version: crate::mcp::BRIDGE_CONNECTION_SCHEMA,
            authentication_mode,
            encrypted_diagnostics_ready: state
                .catalog
                .diagnostic_vault_ready()
                .map_err(map_catalog_error)?,
            generated_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
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
            templates: templates.len(),
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
            terminal_sessions: terminals.len(),
            error_codes,
            run_states,
            failure_stages,
            run_failures: run_failures.into_values().collect(),
            mcp_failures: state
                .catalog
                .list_diagnostic_failures()
                .map_err(map_catalog_error)?,
            terminal_states,
            stale_terminal_references,
            state_consistency,
            state_consistency_issues,
        }))
    })
    .await
    .map_err(|_| ApiError::Internal)?
}

#[cfg(test)]
mod tests;
