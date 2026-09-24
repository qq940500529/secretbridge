// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::{
    ApiError, AppState, BROWSER_TOTP_CREDENTIAL_ID, BrowserAuthChannel, BrowserAuthEventKind,
    BrowserAuthMode, CatalogError, CurrentBrowserAuthProof, HeaderMap, Json, PairResponse,
    SecretStoreError, State, StatusCode, TotpCodeRequest, TotpSetupResponse, Uuid,
    authentication_attempt_allowed, map_catalog_error, map_secret_store_error,
    record_authentication_failure, require_session, reset_authentication_attempts, task,
    validate_origin, verify_current_browser_auth,
};
use crate::secret_store::{SECRET_READ_TIMEOUT, SecretReadError};
use base64::Engine as _;
use qrcodegen::{QrCode, QrCodeEcc};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{OwnedMutexGuard, oneshot},
    time::timeout,
};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

use crate::credential_service::NATIVE_MUTATION_TIMEOUT;

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

fn map_secret_read_error(error: SecretReadError) -> ApiError {
    match error {
        SecretReadError::Store(error) => map_secret_store_error(error),
        SecretReadError::TimedOut | SecretReadError::Cancelled | SecretReadError::Worker => {
            ApiError::SecretStoreUnavailable
        }
    }
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
    pub(super) async fn lock_native_secret_mutation(
        &self,
    ) -> Result<OwnedMutexGuard<()>, ApiError> {
        timeout(
            NATIVE_MUTATION_TIMEOUT,
            self.native_secret_mutations.clone().lock_owned(),
        )
        .await
        .map_err(|_| ApiError::SecretStoreTimedOut)
    }

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
        let _native_guard = self.lock_native_secret_mutation().await?;
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
        let secret = self
            .secret_reads
            .get(
                self.secret_store.clone(),
                BROWSER_TOTP_CREDENTIAL_ID,
                SECRET_READ_TIMEOUT,
                None,
            )
            .await
            .map_err(map_secret_read_error)?;
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
    Json(proof): Json<CurrentBrowserAuthProof>,
) -> Result<Json<TotpSetupResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let previous_mode = state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?;
    if previous_mode != BrowserAuthMode::Pin {
        return Err(ApiError::BadRequest);
    }
    verify_current_browser_auth(&state, previous_mode, proof).await?;
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
    let native_guard = state.lock_native_secret_mutation().await?;
    let mode = state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?;
    if mode != BrowserAuthMode::Pin {
        return Err(ApiError::BadRequest);
    }
    publish_totp_secret(
        &state,
        native_guard,
        pending.secret,
        step,
        NATIVE_MUTATION_TIMEOUT,
    )
    .await?;
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

async fn publish_totp_secret(
    state: &AppState,
    native_guard: OwnedMutexGuard<()>,
    secret: Zeroizing<String>,
    step: u64,
    limit: Duration,
) -> Result<(), ApiError> {
    let store = state.secret_store.clone();
    let catalog = state.catalog.clone();
    let (ready_sender, ready_receiver) = oneshot::channel();
    let (commit_sender, commit_receiver) = mpsc::channel();
    let (finished_sender, finished_receiver) = oneshot::channel();
    task::spawn_blocking(move || {
        let _native_guard = native_guard;
        match store.set(BROWSER_TOTP_CREDENTIAL_ID, secret.as_str()) {
            Ok(()) => {
                if ready_sender.send(Ok(())).is_err() || commit_receiver.recv().is_err() {
                    cleanup_uncommitted_totp(store.as_ref());
                    return;
                }
                let result = catalog.activate_totp(step).map_err(map_catalog_error);
                if result.is_err() {
                    cleanup_uncommitted_totp(store.as_ref());
                }
                let _ = finished_sender.send(result);
            }
            Err(error) => {
                cleanup_uncommitted_totp(store.as_ref());
                let _ = ready_sender.send(Err(error));
            }
        }
    });
    timeout(limit, ready_receiver)
        .await
        .map_err(|_| ApiError::SecretStoreTimedOut)?
        .map_err(|_| ApiError::Internal)?
        .map_err(map_secret_store_error)?;
    commit_sender.send(()).map_err(|_| ApiError::Internal)?;
    finished_receiver.await.map_err(|_| ApiError::Internal)??;
    Ok(())
}

pub(super) async fn disable_totp_secret(
    state: &AppState,
    native_guard: OwnedMutexGuard<()>,
    limit: Duration,
) -> Result<(), ApiError> {
    if state
        .catalog
        .browser_auth_mode()
        .map_err(map_catalog_error)?
        != BrowserAuthMode::Totp
    {
        return Err(ApiError::BadRequest);
    }
    // PIN remains valid independently of TOTP. Disable the seed in SQLite
    // first so a late native deletion cannot leave an active mode without it.
    state.catalog.deactivate_totp().map_err(map_catalog_error)?;
    reset_authentication_attempts(state).await;
    state.pin_attempts.lock().await.pending_totp_setup = None;
    let event_result = state.catalog.record_browser_auth_event(
        BrowserAuthEventKind::Disabled,
        BrowserAuthChannel::Settings,
        None,
    );
    let store = state.secret_store.clone();
    let deletion = match timeout(
        limit,
        task::spawn_blocking(move || {
            let _native_guard = native_guard;
            store.delete(BROWSER_TOTP_CREDENTIAL_ID)
        }),
    )
    .await
    .map_err(|_| ApiError::SecretStoreTimedOut)?
    .map_err(|_| ApiError::Internal)?
    {
        Ok(()) | Err(SecretStoreError::NotFound) => Ok(()),
        Err(error) => Err(map_secret_store_error(error)),
    };
    event_result.map_err(map_catalog_error)?;
    deletion
}

fn cleanup_uncommitted_totp(store: &dyn crate::secret_store::SecretStore) {
    if !matches!(
        store.delete(BROWSER_TOTP_CREDENTIAL_ID),
        Ok(()) | Err(SecretStoreError::NotFound)
    ) {
        tracing::warn!(code = "native_totp_cleanup_failed");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use base64::Engine as _;
    use tokio::sync::Notify;

    use super::{
        ACCEPTED_PAST_STEPS, ApiError, AppState, BROWSER_TOTP_CREDENTIAL_ID, BrowserAuthMode,
        Duration, STEP_SECONDS, SecretStoreError, Uuid, Zeroizing, build, disable_totp_secret,
        generate_setup, publish_totp_secret, verify,
    };
    use crate::secret_store::SecretStore;
    use totp_rs::Secret;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    struct PausedTotpStore {
        write_released: (Mutex<bool>, Condvar),
        delete_released: (Mutex<bool>, Condvar),
        write_started: Notify,
        delete_started: Notify,
        value: Mutex<Option<Zeroizing<String>>>,
        deletions: AtomicUsize,
    }

    impl PausedTotpStore {
        fn new(write_released: bool, delete_released: bool) -> Self {
            Self {
                write_released: (Mutex::new(write_released), Condvar::new()),
                delete_released: (Mutex::new(delete_released), Condvar::new()),
                write_started: Notify::new(),
                delete_started: Notify::new(),
                value: Mutex::new(None),
                deletions: AtomicUsize::new(0),
            }
        }

        fn release(gate: &(Mutex<bool>, Condvar)) {
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
        }
    }

    impl SecretStore for PausedTotpStore {
        fn set(&self, _: Uuid, secret: &str) -> Result<(), SecretStoreError> {
            self.write_started.notify_one();
            let mut released = self.write_released.0.lock().unwrap();
            while !*released {
                let (guard, wait) = self
                    .write_released
                    .1
                    .wait_timeout(released, Duration::from_secs(5))
                    .unwrap();
                released = guard;
                if wait.timed_out() {
                    return Err(SecretStoreError::Unavailable);
                }
            }
            *self.value.lock().unwrap() = Some(Zeroizing::new(secret.to_owned()));
            Ok(())
        }

        fn get(&self, _: Uuid) -> Result<Zeroizing<String>, SecretStoreError> {
            self.value
                .lock()
                .unwrap()
                .clone()
                .ok_or(SecretStoreError::NotFound)
        }

        fn delete(&self, _: Uuid) -> Result<(), SecretStoreError> {
            self.delete_started.notify_one();
            let mut released = self.delete_released.0.lock().unwrap();
            while !*released {
                let (guard, wait) = self
                    .delete_released
                    .1
                    .wait_timeout(released, Duration::from_secs(5))
                    .unwrap();
                released = guard;
                if wait.timed_out() {
                    return Err(SecretStoreError::Unavailable);
                }
            }
            self.deletions.fetch_add(1, Ordering::SeqCst);
            self.value
                .lock()
                .unwrap()
                .take()
                .map(|_| ())
                .ok_or(SecretStoreError::NotFound)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timed_out_enrollment_cleans_late_seed_before_retry() {
        let (mut state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
        state
            .catalog
            .set_browser_auth_mode(BrowserAuthMode::Pin)
            .unwrap();
        let store = Arc::new(PausedTotpStore::new(false, true));
        state.secret_store = store.clone();
        let gate = state.lock_native_secret_mutation().await.unwrap();
        let pending = {
            let state = state.clone();
            tokio::spawn(async move {
                publish_totp_secret(
                    &state,
                    gate,
                    Zeroizing::new("synthetic-first".to_owned()),
                    1,
                    Duration::from_millis(100),
                )
                .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), store.write_started.notified())
            .await
            .unwrap();
        assert!(matches!(
            pending.await.unwrap(),
            Err(ApiError::SecretStoreTimedOut)
        ));
        assert_eq!(
            state.catalog.browser_auth_mode().unwrap(),
            BrowserAuthMode::Pin
        );
        PausedTotpStore::release(&store.write_released);
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.deletions.load(Ordering::SeqCst) != 1
                || store.get(BROWSER_TOTP_CREDENTIAL_ID).is_ok()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            store.get(BROWSER_TOTP_CREDENTIAL_ID),
            Err(SecretStoreError::NotFound)
        ));
        let gate = state.lock_native_secret_mutation().await.unwrap();
        publish_totp_secret(
            &state,
            gate,
            Zeroizing::new("synthetic-retry".to_owned()),
            2,
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(
            state.catalog.browser_auth_mode().unwrap(),
            BrowserAuthMode::Totp
        );
        assert_eq!(
            store.get(BROWSER_TOTP_CREDENTIAL_ID).unwrap().as_str(),
            "synthetic-retry"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timed_out_disable_keeps_pin_mode_and_late_delete_cannot_erase_retry() {
        let (mut state, _) = AppState::new(["http://127.0.0.1:8787".to_owned()]);
        state
            .catalog
            .set_browser_auth_mode(BrowserAuthMode::Pin)
            .unwrap();
        let store = Arc::new(PausedTotpStore::new(true, false));
        state.secret_store = store.clone();
        store
            .set(BROWSER_TOTP_CREDENTIAL_ID, "synthetic-old")
            .unwrap();
        state.catalog.activate_totp(1).unwrap();
        let gate = state.lock_native_secret_mutation().await.unwrap();
        let pending = {
            let state = state.clone();
            tokio::spawn(async move {
                disable_totp_secret(&state, gate, Duration::from_millis(100)).await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), store.delete_started.notified())
            .await
            .unwrap();
        assert!(matches!(
            pending.await.unwrap(),
            Err(ApiError::SecretStoreTimedOut)
        ));
        assert_eq!(
            state.catalog.browser_auth_mode().unwrap(),
            BrowserAuthMode::Pin
        );
        PausedTotpStore::release(&store.delete_released);
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.deletions.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let gate = state.lock_native_secret_mutation().await.unwrap();
        publish_totp_secret(
            &state,
            gate,
            Zeroizing::new("synthetic-new".to_owned()),
            2,
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(
            store.get(BROWSER_TOTP_CREDENTIAL_ID).unwrap().as_str(),
            "synthetic-new"
        );
    }

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
