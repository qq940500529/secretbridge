// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{
    ApiError, AppState, BROWSER_PIN_CREDENTIAL_ID, BROWSER_TOTP_CREDENTIAL_ID, BrowserAuthChannel,
    BrowserAuthEventKind, BrowserAuthMode, CatalogError, HeaderMap, Json, PairResponse, State,
    StatusCode, TotpCodeRequest, TotpSetupResponse, Uuid, authentication_attempt_allowed,
    map_catalog_error, map_secret_store_error, record_authentication_failure, require_session,
    reset_authentication_attempts, task, validate_origin,
};
use base64::Engine as _;
use qrcodegen::{QrCode, QrCodeEcc};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

pub const STEP_SECONDS: u64 = 30;
pub const ACCEPTED_PAST_STEPS: u64 = 4;
pub const ACCEPTED_FUTURE_STEPS: u64 = 1;
pub const SETUP_TTL: Duration = Duration::from_mins(10);

pub struct PendingSetup {
    pub secret: Zeroizing<String>,
    pub expires_at: Instant,
}

pub struct SetupMaterial {
    pub secret: Zeroizing<String>,
    pub qr_code_base64: Zeroizing<String>,
}

fn build(secret: impl Into<Secret>) -> Result<Totp, ()> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(0)
        .with_step_duration(STEP_SECONDS)
        .with_secret(secret)
        .with_issuer(Some("SecretBridge"))
        .with_account_name("local-user")
        .build()
        .map_err(|_| ())
}

pub fn generate_setup() -> Result<SetupMaterial, ()> {
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(0)
        .with_step_duration(STEP_SECONDS)
        .with_issuer(Some("SecretBridge"))
        .with_account_name("local-user")
        .build()
        .map_err(|_| ())?;
    let secret = Zeroizing::new(totp.secret().to_base32());
    let provisioning_uri = Zeroizing::new(totp.to_url().map_err(|_| ())?);
    let qr_code =
        QrCode::encode_text(provisioning_uri.as_str(), QrCodeEcc::Medium).map_err(|_| ())?;
    let qr_code_base64 = render_qr_png(&qr_code)?;
    Ok(SetupMaterial {
        secret,
        qr_code_base64,
    })
}

fn render_qr_png(qr_code: &QrCode) -> Result<Zeroizing<String>, ()> {
    const SCALE: u32 = 8;
    const QUIET_ZONE: u32 = 4;
    let modules = u32::try_from(qr_code.size()).map_err(|_| ())?;
    let width = modules
        .checked_add(QUIET_ZONE * 2)
        .and_then(|value| value.checked_mul(SCALE))
        .ok_or(())?;
    let pixel_count = width.checked_mul(width).ok_or(())?;
    let mut pixels = Zeroizing::new(vec![255_u8; usize::try_from(pixel_count).map_err(|_| ())?]);
    for module_y in 0..modules {
        for module_x in 0..modules {
            if !qr_code.get_module(
                i32::try_from(module_x).map_err(|_| ())?,
                i32::try_from(module_y).map_err(|_| ())?,
            ) {
                continue;
            }
            let start_x = (module_x + QUIET_ZONE) * SCALE;
            let start_y = (module_y + QUIET_ZONE) * SCALE;
            for pixel_y in start_y..start_y + SCALE {
                for pixel_x in start_x..start_x + SCALE {
                    let index = usize::try_from(pixel_y * width + pixel_x).map_err(|_| ())?;
                    pixels[index] = 0;
                }
            }
        }
    }
    let mut output = Zeroizing::new(Vec::new());
    {
        let mut encoder = png::Encoder::new(&mut *output, width, width);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| ())?;
        writer.write_image_data(&pixels).map_err(|_| ())?;
    }
    Ok(Zeroizing::new(
        base64::engine::general_purpose::STANDARD.encode(output.as_slice()),
    ))
}

pub fn verify(secret_base32: &str, code: &str, now_seconds: u64) -> Option<u64> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let secret = Secret::try_from_base32(secret_base32).ok()?;
    let totp = build(secret).ok()?;
    let current_step = now_seconds / STEP_SECONDS;
    let mut candidates =
        Vec::with_capacity(usize::try_from(ACCEPTED_PAST_STEPS + ACCEPTED_FUTURE_STEPS + 1).ok()?);
    candidates.push(current_step);
    for distance in 1..=ACCEPTED_PAST_STEPS.max(ACCEPTED_FUTURE_STEPS) {
        if distance <= ACCEPTED_PAST_STEPS {
            candidates.push(current_step.saturating_sub(distance));
        }
        if distance <= ACCEPTED_FUTURE_STEPS {
            candidates.push(current_step.saturating_add(distance));
        }
    }
    let mut matched = None;
    for step in candidates {
        let generated = totp.generate(step.saturating_mul(STEP_SECONDS)).to_string();
        if bool::from(generated.as_bytes().ct_eq(code.as_bytes())) && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

fn valid_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit())
}

impl AppState {
    pub(super) async fn verify_and_consume_totp(
        &self,
        code: String,
        channel: BrowserAuthChannel,
        approval_id: Option<Uuid>,
    ) -> Result<(), ApiError> {
        if !authentication_attempt_allowed(self).await {
            self.catalog
                .record_browser_auth_event(BrowserAuthEventKind::RateLimited, channel, approval_id)
                .map_err(map_catalog_error)?;
            return Err(ApiError::Unauthorized);
        }
        if !valid_code(&code)
            || self
                .catalog
                .browser_auth_mode()
                .map_err(map_catalog_error)?
                != BrowserAuthMode::Totp
        {
            self.catalog
                .record_browser_auth_event(
                    BrowserAuthEventKind::VerificationFailed,
                    channel,
                    approval_id,
                )
                .map_err(map_catalog_error)?;
            return Err(ApiError::Unauthorized);
        }
        let store = self.secret_store.clone();
        let secret = task::spawn_blocking(move || store.get(BROWSER_TOTP_CREDENTIAL_ID))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(map_secret_store_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::Internal)?
            .as_secs();
        let Some(step) = verify(secret.as_str(), &code, now) else {
            record_authentication_failure(self).await;
            self.catalog
                .record_browser_auth_event(
                    BrowserAuthEventKind::VerificationFailed,
                    channel,
                    approval_id,
                )
                .map_err(map_catalog_error)?;
            return Err(ApiError::Unauthorized);
        };
        if let Err(error) = self.catalog.consume_totp_step(step) {
            record_authentication_failure(self).await;
            self.catalog
                .record_browser_auth_event(
                    BrowserAuthEventKind::VerificationFailed,
                    channel,
                    approval_id,
                )
                .map_err(map_catalog_error)?;
            return Err(match error {
                CatalogError::InvalidApprovalTransition => ApiError::Unauthorized,
                other => map_catalog_error(other),
            });
        }
        reset_authentication_attempts(self).await;
        self.catalog
            .record_browser_auth_event(
                BrowserAuthEventKind::VerificationSucceeded,
                channel,
                approval_id,
            )
            .map_err(map_catalog_error)?;
        Ok(())
    }
}

pub(super) async fn pair(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    state
        .verify_and_consume_totp(request.code, BrowserAuthChannel::Browser, None)
        .await?;
    let (session_token, expires_in_seconds) = state.issue_session().await?;
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
        expires_in_seconds,
    }))
}

pub(super) async fn start_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TotpSetupResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let material = generate_setup().map_err(|()| ApiError::Internal)?;
    let response = TotpSetupResponse {
        manual_key: material.secret.to_string(),
        qr_code_data_url: format!("data:image/png;base64,{}", material.qr_code_base64.as_str()),
        expires_in_seconds: SETUP_TTL.as_secs(),
        accepted_past_steps: ACCEPTED_PAST_STEPS,
    };
    state.pin_attempts.lock().await.pending_totp_setup = Some(PendingSetup {
        secret: material.secret,
        expires_at: Instant::now() + SETUP_TTL,
    });
    state
        .catalog
        .record_browser_auth_event(
            BrowserAuthEventKind::EnrollmentStarted,
            BrowserAuthChannel::Settings,
            None,
        )
        .map_err(map_catalog_error)?;
    Ok(Json(response))
}

pub(super) async fn confirm_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    if !authentication_attempt_allowed(&state).await {
        state
            .catalog
            .record_browser_auth_event(
                BrowserAuthEventKind::RateLimited,
                BrowserAuthChannel::Settings,
                None,
            )
            .map_err(map_catalog_error)?;
        return Err(ApiError::Unauthorized);
    }
    if !valid_code(&request.code) {
        state
            .catalog
            .record_browser_auth_event(
                BrowserAuthEventKind::VerificationFailed,
                BrowserAuthChannel::Settings,
                None,
            )
            .map_err(map_catalog_error)?;
        return Err(ApiError::Unauthorized);
    }
    let pending = state
        .pin_attempts
        .lock()
        .await
        .pending_totp_setup
        .take()
        .filter(|pending| pending.expires_at > Instant::now())
        .ok_or(ApiError::BadRequest)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::Internal)?
        .as_secs();
    let Some(step) = verify(pending.secret.as_str(), &request.code, now) else {
        state.pin_attempts.lock().await.pending_totp_setup = Some(pending);
        record_authentication_failure(&state).await;
        state
            .catalog
            .record_browser_auth_event(
                BrowserAuthEventKind::VerificationFailed,
                BrowserAuthChannel::Settings,
                None,
            )
            .map_err(map_catalog_error)?;
        return Err(ApiError::Unauthorized);
    };
    let store = state.secret_store.clone();
    let previous_secret = {
        let store = store.clone();
        task::spawn_blocking(move || store.get(BROWSER_TOTP_CREDENTIAL_ID))
            .await
            .map_err(|_| ApiError::Internal)?
            .ok()
    };
    let secret = pending.secret;
    let store_for_write = store.clone();
    task::spawn_blocking(move || store_for_write.set(BROWSER_TOTP_CREDENTIAL_ID, secret.as_str()))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_secret_store_error)?;
    if let Err(error) = state.catalog.activate_totp(step) {
        let _ = task::spawn_blocking(move || match previous_secret {
            Some(previous) => store.set(BROWSER_TOTP_CREDENTIAL_ID, previous.as_str()),
            None => store.delete(BROWSER_TOTP_CREDENTIAL_ID),
        })
        .await;
        return Err(map_catalog_error(error));
    }
    let store = state.secret_store.clone();
    let _ = task::spawn_blocking(move || store.delete(BROWSER_PIN_CREDENTIAL_ID)).await;
    reset_authentication_attempts(&state).await;
    state
        .catalog
        .record_browser_auth_event(
            BrowserAuthEventKind::EnrollmentSucceeded,
            BrowserAuthChannel::Settings,
            None,
        )
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use base64::Engine as _;

    use super::{ACCEPTED_PAST_STEPS, STEP_SECONDS, build, generate_setup, verify};
    use totp_rs::Secret;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn accepts_delayed_code_and_rejects_outside_grace_window() {
        let secret = Secret::from(RFC_SECRET);
        let encoded = secret.to_base32();
        let totp = build(secret).unwrap();
        let generated_at = 20 * STEP_SECONDS;
        let code = totp.generate(generated_at).to_string();
        let latest_accepted = generated_at + ACCEPTED_PAST_STEPS * STEP_SECONDS;
        assert_eq!(verify(&encoded, &code, latest_accepted), Some(20));
        assert_eq!(
            verify(&encoded, &code, latest_accepted + STEP_SECONDS),
            None
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        let encoded = Secret::from(RFC_SECRET).to_base32();
        assert_eq!(verify(&encoded, "12345", 0), None);
        assert_eq!(verify(&encoded, "12345x", 0), None);
    }

    #[test]
    fn enrollment_qr_is_a_bounded_grayscale_png() {
        let setup = generate_setup().expect("setup material");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(setup.qr_code_base64.as_bytes())
            .expect("base64 QR");
        let decoder = png::Decoder::new(Cursor::new(bytes));
        let reader = decoder.read_info().expect("PNG header");
        let info = reader.info();
        assert_eq!(info.width, info.height);
        assert!((200..=800).contains(&info.width));
        assert_eq!(info.color_type, png::ColorType::Grayscale);
        assert_eq!(info.bit_depth, png::BitDepth::Eight);
    }
}
