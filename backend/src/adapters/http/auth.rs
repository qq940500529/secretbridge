// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, BrowserAuthMethod, BrowserAuthMethodsResponse, BrowserAuthMode,
    CatalogError, CurrentBrowserAuthProof, Duration, HeaderMap, Instant, Json, PairResponse,
    PinPairRequest, SessionResponse, SetBrowserAuthMethodRequest, State, StatusCode,
    StatusResponse, Zeroizing, bearer_token, constant_time_equal, credential_service,
    map_catalog_error, require_session, task, token_digest, totp_auth, validate_origin,
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

pub(crate) fn valid_browser_pin(pin: &str) -> bool {
    let length = pin.chars().count();
    (12..=64).contains(&length) && !pin.chars().any(char::is_control)
}

pub(crate) async fn pair_with_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PinPairRequest>,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    if state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?
        == BrowserAuthMode::PairingLink
        || !valid_browser_pin(&request.pin)
    {
        return Err(ApiError::Unauthorized);
    }
    if !authentication_attempt_allowed(&state).await {
        return Err(ApiError::Unauthorized);
    }
    let pin = Zeroizing::new(request.pin);
    let catalog = state.catalog.clone();
    let matches = task::spawn_blocking(move || catalog.verify_diagnostic_pin(&pin))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    if !matches {
        record_authentication_failure(&state).await;
        return Err(ApiError::Unauthorized);
    }
    reset_authentication_attempts(&state).await;
    let (session_token, expires_in_seconds) = state.issue_session().await?;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

pub(crate) async fn set_browser_auth_method(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<SetBrowserAuthMethodRequest>,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let previous_mode = state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?;
    match request.method {
        BrowserAuthMethod::Pin => {
            if previous_mode != BrowserAuthMode::PairingLink {
                verify_pin_proof(&state, request.current_pin.as_deref()).await?;
            }
            let pin = Zeroizing::new(
                request
                    .pin
                    .filter(|value| valid_browser_pin(value))
                    .ok_or(ApiError::BadRequest)?,
            );
            let catalog = state.catalog.clone();
            let old_pin = request.current_pin.take().map(Zeroizing::new);
            task::spawn_blocking(move || {
                if catalog.diagnostic_vault_ready()? {
                    catalog.rotate_diagnostic_vault_pin(
                        old_pin.as_deref().ok_or(CatalogError::Invalid)?,
                        &pin,
                    )
                } else {
                    catalog.initialize_diagnostic_vault(&pin)
                }
            })
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(map_catalog_error)?;
            if previous_mode == BrowserAuthMode::PairingLink {
                state
                    .catalog
                    .set_browser_auth_mode(BrowserAuthMode::Pin)
                    .map_err(map_catalog_error)?;
            }
        }
        BrowserAuthMethod::PairingLink => {
            return Err(ApiError::BadRequest);
        }
        BrowserAuthMethod::DisableTotp => {
            if previous_mode != BrowserAuthMode::Totp {
                return Err(ApiError::BadRequest);
            }
            verify_pin_proof(&state, request.current_pin.as_deref()).await?;
            let native_guard = state.lock_native_secret_mutation().await?;
            totp_auth::disable_totp_secret(
                &state,
                native_guard,
                credential_service::NATIVE_MUTATION_TIMEOUT,
            )
            .await?;
        }
    }
    if matches!(request.method, BrowserAuthMethod::Pin) {
        reset_authentication_attempts(&state).await;
        state.pin_attempts.lock().await.pending_totp_setup = None;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn verify_current_browser_auth(
    state: &AppState,
    mode: BrowserAuthMode,
    proof: CurrentBrowserAuthProof,
) -> Result<(), ApiError> {
    match mode {
        BrowserAuthMode::PairingLink => Ok(()),
        BrowserAuthMode::Totp | BrowserAuthMode::Pin => {
            verify_pin_proof(state, proof.current_pin.as_deref()).await
        }
    }
}

pub(crate) async fn verify_pin_proof(state: &AppState, pin: Option<&str>) -> Result<(), ApiError> {
    if !authentication_attempt_allowed(state).await {
        return Err(ApiError::Unauthorized);
    }
    let pin = pin.ok_or(ApiError::Unauthorized)?;
    if !valid_browser_pin(pin) {
        record_authentication_failure(state).await;
        return Err(ApiError::Unauthorized);
    }
    let catalog = state.catalog.clone();
    let pin = Zeroizing::new(pin.to_owned());
    let matches = task::spawn_blocking(move || catalog.verify_diagnostic_pin(&pin))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    if !matches {
        record_authentication_failure(state).await;
        return Err(ApiError::Unauthorized);
    }
    reset_authentication_attempts(state).await;
    Ok(())
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
