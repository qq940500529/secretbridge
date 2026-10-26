// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only release discovery. Remote text, URLs and assets are never executed.
use std::{sync::Arc, time::Duration};

use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

const ENDPOINT: &str = "https://api.github.com/repos/qq940500529/secretbridge/releases?per_page=20";
const RELEASES: &str = "https://github.com/qq940500529/secretbridge/releases";
const MAX_BYTES: usize = 1024 * 1024;
const CHECK_INTERVAL: u64 = 6 * 60 * 60 * 1000;
const FAILURE_INTERVAL: u64 = 60 * 60 * 1000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "explicit independent read-only wire policy guarantees, not mutable operation flags"
)]
pub(crate) struct UpdateStatus {
    pub(crate) current_version: String,
    pub(crate) latest_version: Option<String>,
    pub(crate) update_available: bool,
    pub(crate) checked_at_unix_ms: Option<u64>,
    pub(crate) check_state: String,
    pub(crate) release_url: String,
    pub(crate) automatic_install: bool,
    pub(crate) compatibility_guaranteed: bool,
    pub(crate) user_choice_required: bool,
    pub(crate) default_action: String,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            current_version: env!("CARGO_PKG_VERSION").to_owned(),
            latest_version: None,
            update_available: false,
            checked_at_unix_ms: None,
            check_state: "not_checked".to_owned(),
            release_url: RELEASES.to_owned(),
            automatic_install: false,
            compatibility_guaranteed: false,
            user_choice_required: true,
            default_action: "keep_current_version".to_owned(),
        }
    }
}

#[derive(Default)]
struct Cache {
    status: UpdateStatus,
    last_attempt: Option<u64>,
    next_check: u64,
}

#[derive(Clone, Default)]
pub(crate) struct UpdateChecker {
    cache: Arc<RwLock<Cache>>,
    gate: Arc<Mutex<()>>,
}

impl UpdateChecker {
    #[cfg(test)]
    pub(crate) async fn seed_for_test(&self) {
        self.record(Ok(Some("99.0.0".to_owned())), crate::now_unix_ms())
            .await;
        self.cache.write().await.last_attempt = Some(crate::now_unix_ms());
    }
    pub(crate) async fn snapshot(&self) -> UpdateStatus {
        self.cache.read().await.status.clone()
    }

    pub(crate) fn start(&self, cancellation: CancellationToken) {
        let checker = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    _ = checker.refresh(false) => {}
                }
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_hours(1)) => {}
                }
            }
        });
    }

    pub(crate) async fn refresh(&self, manual: bool) -> UpdateStatus {
        let Ok(_guard) = self.gate.try_lock() else {
            return self.snapshot().await;
        };
        let now = crate::now_unix_ms();
        {
            let mut cache = self.cache.write().await;
            if cache
                .last_attempt
                .is_some_and(|last| now.saturating_sub(last) < 60_000)
                || (!manual && now < cache.next_check)
            {
                return cache.status.clone();
            }
            cache.last_attempt = Some(now);
            "checking".clone_into(&mut cache.status.check_state);
        }
        // No tokens, cookies, local identifiers or broker configuration are sent.
        let result = fetch_latest(ENDPOINT).await;
        self.record(result, crate::now_unix_ms()).await
    }

    async fn record(&self, result: Result<Option<String>, ()>, now: u64) -> UpdateStatus {
        let mut cache = self.cache.write().await;
        cache.next_check = now.saturating_add(if result.is_ok() {
            CHECK_INTERVAL
        } else {
            FAILURE_INTERVAL
        });
        if let Ok(latest) = result {
            cache.status.latest_version.clone_from(&latest);
            cache.status.update_available = latest.is_some();
            cache.status.release_url = latest.map_or_else(
                || RELEASES.to_owned(),
                |version| format!("{RELEASES}/tag/v{version}"),
            );
            cache.status.checked_at_unix_ms = Some(now);
            "checked".clone_into(&mut cache.status.check_state);
        } else {
            // Retain the last verified notice, but make stale/unavailable status explicit.
            "unavailable".clone_into(&mut cache.status.check_state);
        }
        cache.status.clone()
    }
}

async fn fetch_latest(endpoint: &str) -> Result<Option<String>, ()> {
    let _ = rustls_tokio_postgres::rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(6))
        .user_agent(concat!(
            "SecretBridge/",
            env!("CARGO_PKG_VERSION"),
            " update-check"
        ))
        .build()
        .map_err(|_| ())?;
    let mut response = client
        .get(endpoint)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size > MAX_BYTES as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    select_latest(&body, env!("CARGO_PKG_VERSION"))
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
}

fn select_latest(body: &[u8], current: &str) -> Result<Option<String>, ()> {
    let releases: Vec<Release> = serde_json::from_slice(body).map_err(|_| ())?;
    let current = Version::parse(current).map_err(|_| ())?;
    Ok(releases
        .into_iter()
        .filter(|release| !release.draft)
        .filter_map(|release| {
            let tag = release.tag_name.strip_prefix('v')?;
            if tag.len() > 80 {
                return None;
            }
            Version::parse(tag).ok()
        })
        .filter(|version| version.cmp_precedence(&current).is_gt())
        .max_by(Version::cmp_precedence)
        .map(|version| version.to_string()))
}

pub(crate) async fn check_web(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<UpdateStatus>, crate::ApiError> {
    crate::validate_origin(&headers, &state)?;
    crate::require_session(&state, &headers).await?;
    Ok(axum::Json(state.updates.refresh(true).await))
}

#[cfg(test)]
mod tests;
