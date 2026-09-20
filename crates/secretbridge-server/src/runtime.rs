// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::AppState;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

pub(crate) async fn stop_http(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::http::StatusCode, crate::ApiError> {
    crate::validate_origin(&headers, &state)?;
    crate::require_session(&state, &headers).await?;
    handle(&state, RuntimeRequest::Stop)
        .await
        .map_err(|_| crate::ApiError::BadRequest)?;
    Ok(axum::http::StatusCode::ACCEPTED)
}

#[derive(Clone)]
pub(crate) struct RuntimeControl {
    pub origin: String,
    pub cancellation: CancellationToken,
    pub stopping: CancellationToken,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatus {
    pub version: String,
    pub process_id: u32,
    pub origin: String,
    pub schema_version: i64,
    pub terminal_sessions: usize,
    pub active_runs: usize,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeRequest {
    Status,
    Open,
    Stop,
}
pub(crate) async fn handle(
    state: &AppState,
    request: RuntimeRequest,
) -> Result<RuntimeStatus, rmcp::ErrorData> {
    let control = state
        .runtime_control
        .as_ref()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("runtime_control_unavailable", None))?;
    let status = RuntimeStatus {
        version: env!("CARGO_PKG_VERSION").into(),
        process_id: std::process::id(),
        origin: control.origin.clone(),
        schema_version: crate::catalog::SCHEMA_VERSION,
        terminal_sessions: state.terminals.list().len(),
        active_runs: state.run_cancellations.active.lock().await.len(),
    };
    match request {
        RuntimeRequest::Status => {}
        RuntimeRequest::Open => {
            if control.stopping.is_cancelled() {
                return Err(rmcp::ErrorData::internal_error("broker_stopping", None));
            }
            // A new one-time bootstrap token is never returned to the CLI or MCP. When the user
            // selected PIN verification, open the stable login page instead of invalidating an
            // unconsumed pairing capability on every MCP request.
            let url =
                if state.catalog.browser_auth_mode().map_err(|_| {
                    rmcp::ErrorData::internal_error("browser_auth_unavailable", None)
                })? == crate::catalog::BrowserAuthMode::Pin
                {
                    format!("{}/#login=pin", control.origin)
                } else {
                    let token = crate::new_token();
                    *state.bootstrap_token.write().await = Some(crate::token_digest(&token));
                    format!("{}/#pair={token}", control.origin)
                };
            tokio::task::spawn_blocking(move || webbrowser::open(&url))
                .await
                .map_err(|_| rmcp::ErrorData::internal_error("browser_open_failed", None))?
                .map_err(|_| rmcp::ErrorData::internal_error("browser_open_failed", None))?;
        }
        RuntimeRequest::Stop => {
            control.stopping.cancel();
            let cancellation = control.cancellation.clone();
            let state = state.clone();
            // Allow the authenticated response to flush before stopping the listener.
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                state.shutdown_operations().await;
                cancellation.cancel();
            });
        }
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ORIGIN: &str = "http://127.0.0.1:8787";

    #[tokio::test]
    async fn runtime_status_does_not_include_connection_or_pairing_secrets() {
        let (mut state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
        state.enable_runtime_control(ORIGIN.into(), CancellationToken::new());
        let status = handle(&state, RuntimeRequest::Status).await.unwrap();
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains(&bootstrap));
        assert!(!json.contains("token"));
        assert_eq!(status.schema_version, crate::catalog::SCHEMA_VERSION);
        assert_eq!(status.process_id, std::process::id());
    }

    #[tokio::test]
    async fn browser_stop_requires_session_and_trusted_origin() {
        let (mut state, _) = AppState::new([ORIGIN.to_owned()]);
        let cancellation = CancellationToken::new();
        state.enable_runtime_control(ORIGIN.into(), cancellation.clone());
        let (session, _) = state.issue_session().await.expect("issue session");
        let app = crate::router(state);
        for (origin, token, expected) in [
            (ORIGIN, "wrong", StatusCode::UNAUTHORIZED),
            (
                "http://untrusted.invalid",
                session.as_str(),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/runtime/stop")
                        .header("origin", origin)
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert!(!cancellation.is_cancelled());
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/runtime/stop")
                    .header("origin", ORIGIN)
                    .header("authorization", format!("Bearer {session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), cancellation.cancelled())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_cancels_owned_runs_preserves_sessions_and_rejects_late_creation() {
        let (mut state, _) = AppState::new([ORIGIN.to_owned()]);
        state.enable_runtime_control(ORIGIN.into(), CancellationToken::new());
        let (session, _) = state.issue_session().await.expect("issue session");
        let run = uuid::Uuid::new_v4();
        let token = CancellationToken::new();
        state
            .run_cancellations
            .register(run, uuid::Uuid::new_v4(), token.clone())
            .await;
        let removals = state.run_cancellations.clone();
        let observation = token.clone();
        tokio::spawn(async move {
            observation.cancelled().await;
            removals.remove(run).await;
        });
        state.shutdown_operations().await;
        assert!(token.is_cancelled());
        assert!(state.authenticate(&session).await.is_some());
        assert!(handle(&state, RuntimeRequest::Open).await.is_err());
        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/terminals")
                    .header("origin", ORIGIN)
                    .header("authorization", format!("Bearer {session}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
