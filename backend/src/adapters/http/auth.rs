// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, BrowserAuthMethodsResponse, BrowserAuthMode, Duration, HeaderMap, Instant,
    Json, PairResponse, SessionResponse, State, StatusCode, StatusResponse, bearer_token,
    constant_time_equal, map_catalog_error, token_digest, validate_origin,
};

pub(crate) async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let paired = state.active_session_count() > 0;
    let mut status = StatusResponse::controlled_operations(paired, state.configuration_storage);
    status.background_control_enabled = state.runtime_control.is_some();
    Json(status)
}

pub(crate) async fn pair(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let mut bootstrap = state.bootstrap_token.write().await;
    let Some(expected) = bootstrap.as_ref() else {
        return Err(ApiError::Unauthorized);
    };
    if !constant_time_equal(&token_digest(presented), expected) {
        return Err(ApiError::Unauthorized);
    }
    bootstrap.take();
    drop(bootstrap);

    let (session_token, expires_in_seconds) = state.issue_session().await?;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

pub(crate) async fn browser_auth_methods(
    State(state): State<AppState>,
) -> Result<Json<BrowserAuthMethodsResponse>, ApiError> {
    let mode = state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?;
    let pin_ready = state
        .catalog
        .diagnostic_vault_ready()
        .map_err(map_catalog_error)?;
    Ok(Json(BrowserAuthMethodsResponse {
        pin_enabled: pin_ready,
        totp_enabled: mode == BrowserAuthMode::Totp,
        pairing_link_enabled: !pin_ready,
    }))
}

pub(crate) async fn authentication_attempt_allowed(state: &AppState) -> bool {
    state
        .pin_attempts
        .lock()
        .await
        .blocked_until
        .is_none_or(|until| until <= Instant::now())
}

pub(crate) async fn record_authentication_failure(state: &AppState) {
    let mut attempts = state.pin_attempts.lock().await;
    attempts.failures = attempts.failures.saturating_add(1);
    if attempts.failures >= 5 {
        attempts.blocked_until = Some(Instant::now() + Duration::from_secs(60));
        attempts.failures = 0;
    }
}

pub(crate) async fn reset_authentication_attempts(state: &AppState) {
    let mut attempts = state.pin_attempts.lock().await;
    attempts.failures = 0;
    attempts.blocked_until = None;
}

pub(crate) async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let expires_in_seconds = state
        .authenticate(presented)
        .await
        .ok_or(ApiError::Unauthorized)?;
    Ok(Json(SessionResponse {
        authenticated: true,
        mode: "controlled_operations",
        expires_in_seconds,
    }))
}

pub(crate) async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    state
        .revoke(presented)
        .await
        .then_some(StatusCode::NO_CONTENT)
        .ok_or(ApiError::Unauthorized)
}
