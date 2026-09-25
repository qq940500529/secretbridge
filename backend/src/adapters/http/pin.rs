// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, BrowserAuthMethod, BrowserAuthMode, CatalogError, CurrentBrowserAuthProof,
    PairResponse, PinPairRequest, RecoverPinRequest, RecoveredSessionResponse, RecoveryKeyResponse,
    SetBrowserAuthMethodRequest, credential_service, map_catalog_error, require_session,
    reset_authentication_attempts, totp_auth, validate_origin,
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::task;
use zeroize::Zeroizing;

pub(crate) fn valid_browser_pin(pin: &str) -> bool {
    let length = pin.chars().count();
    (6..=64).contains(&length) && !pin.chars().any(char::is_control)
}

async fn verify_pin_attempt(state: &AppState, candidate: &str) -> Result<(), ApiError> {
    let _gate = state.pin_verification_gate.lock().await;
    let retry_after = state
        .catalog
        .pin_retry_after_seconds()
        .map_err(map_catalog_error)?;
    if retry_after > 0 {
        return Err(ApiError::RateLimited(retry_after));
    }
    let matches = if valid_browser_pin(candidate) {
        let catalog = state.catalog.clone();
        let candidate = Zeroizing::new(candidate.to_owned());
        task::spawn_blocking(move || catalog.verify_diagnostic_pin(&candidate))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(map_catalog_error)?
    } else {
        false
    };
    if matches {
        state
            .catalog
            .reset_failed_pin_attempts()
            .map_err(map_catalog_error)?;
        return Ok(());
    }
    let retry_after = state
        .catalog
        .record_failed_pin_attempt()
        .map_err(map_catalog_error)?;
    if retry_after > 0 {
        Err(ApiError::RateLimited(retry_after))
    } else {
        Err(ApiError::Unauthorized)
    }
}

pub(super) async fn pair_with_pin(
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
    {
        return Err(ApiError::Unauthorized);
    }
    verify_pin_attempt(&state, &request.pin).await?;
    let (session_token, expires_in_seconds) = state.issue_session().await?;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

pub(super) async fn set_browser_auth_method(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<SetBrowserAuthMethodRequest>,
) -> Result<Response, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let previous_mode = state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?;
    let mut issued_recovery_key = None;
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
            issued_recovery_key = task::spawn_blocking(move || {
                if catalog.diagnostic_vault_ready()? {
                    catalog.rotate_diagnostic_vault_pin(
                        old_pin.as_deref().ok_or(CatalogError::Invalid)?,
                        &pin,
                    )?;
                    Ok(None)
                } else {
                    catalog.initialize_diagnostic_vault(&pin).map(Some)
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
    Ok(match issued_recovery_key {
        Some(recovery_key) => Json(RecoveryKeyResponse { recovery_key }).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    })
}

pub(super) async fn regenerate_recovery_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(proof): Json<CurrentBrowserAuthProof>,
) -> Result<Json<RecoveryKeyResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    verify_pin_proof(&state, proof.current_pin.as_deref()).await?;
    let catalog = state.catalog.clone();
    let pin = Zeroizing::new(proof.current_pin.ok_or(ApiError::BadRequest)?);
    let recovery_key =
        task::spawn_blocking(move || catalog.regenerate_diagnostic_recovery_key(&pin))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(map_catalog_error)?;
    Ok(Json(RecoveryKeyResponse { recovery_key }))
}

pub(super) async fn recover_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RecoverPinRequest>,
) -> Result<Json<RecoveredSessionResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    if !valid_browser_pin(&request.new_pin)
        || !state
            .catalog
            .diagnostic_vault_ready()
            .map_err(map_catalog_error)?
    {
        return Err(ApiError::BadRequest);
    }
    let _gate = state.pin_verification_gate.lock().await;
    let retry_after = state
        .catalog
        .pin_retry_after_seconds()
        .map_err(map_catalog_error)?;
    if retry_after > 0 {
        return Err(ApiError::RateLimited(retry_after));
    }
    let catalog = state.catalog.clone();
    let recovery_key = Zeroizing::new(request.recovery_key);
    let new_pin = Zeroizing::new(request.new_pin);
    let outcome =
        task::spawn_blocking(move || catalog.recover_diagnostic_vault_pin(&recovery_key, &new_pin))
            .await
            .map_err(|_| ApiError::Internal)?;
    let next_key = match outcome {
        Ok(key) => key,
        Err(CatalogError::Invalid) => {
            let delay = state
                .catalog
                .record_failed_pin_attempt()
                .map_err(map_catalog_error)?;
            return Err(if delay > 0 {
                ApiError::RateLimited(delay)
            } else {
                ApiError::Unauthorized
            });
        }
        Err(error) => return Err(map_catalog_error(error)),
    };
    state
        .catalog
        .reset_failed_pin_attempts()
        .map_err(map_catalog_error)?;
    state
        .catalog
        .revoke_all_browser_sessions()
        .map_err(map_catalog_error)?;
    let mut sessions = state.session_tokens.write().await;
    for digest in sessions.keys() {
        let _ = state.session_revocations.send(*digest);
    }
    sessions.clear();
    drop(sessions);
    let (session_token, expires_in_seconds) = state.issue_session().await?;
    Ok(Json(RecoveredSessionResponse {
        recovery_key: next_key,
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
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

pub(super) async fn verify_pin_proof(state: &AppState, pin: Option<&str>) -> Result<(), ApiError> {
    let pin = pin.ok_or(ApiError::Unauthorized)?;
    verify_pin_attempt(state, pin).await
}
