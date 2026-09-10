// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::{collections::HashSet, path::Path, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use secretbridge_core::StatusResponse;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use uuid::Uuid;

const BEARER_PREFIX: &str = "Bearer ";

#[derive(Clone)]
pub struct AppState {
    bootstrap_token: Arc<RwLock<Option<String>>>,
    session_tokens: Arc<RwLock<Vec<String>>>,
    trusted_origins: Arc<HashSet<String>>,
}

impl AppState {
    #[must_use]
    pub fn new(trusted_origins: impl IntoIterator<Item = String>) -> (Self, String) {
        let bootstrap_token = new_token();
        let state = Self {
            bootstrap_token: Arc::new(RwLock::new(Some(bootstrap_token.clone()))),
            session_tokens: Arc::new(RwLock::new(Vec::new())),
            trusted_origins: Arc::new(trusted_origins.into_iter().collect()),
        };
        (state, bootstrap_token)
    }
}

#[derive(Serialize)]
struct PairResponse {
    session_token: String,
    token_type: &'static str,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    mode: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

enum ApiError {
    InvalidOrigin,
    Unauthorized,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidOrigin => (
                StatusCode::FORBIDDEN,
                "invalid_origin",
                "The request origin is not trusted.",
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication failed.",
            ),
        };
        (status, Json(ErrorResponse { code, message })).into_response()
    }
}

pub fn router(state: AppState) -> Router {
    apply_security_headers(api_router(state))
}

pub fn router_with_web(state: AppState, web_root: impl AsRef<Path>) -> Router {
    apply_security_headers(
        api_router(state)
            .fallback_service(ServeDir::new(web_root).append_index_html_on_directories(true)),
    )
}

fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/session/pair", post(pair))
        .route("/api/v1/session", get(session))
        .with_state(state)
}

fn apply_security_headers(router: Router) -> Router {
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
                 script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                 form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let paired = !state.session_tokens.read().await.is_empty();
    Json(StatusResponse::synthetic_only(paired))
}

async fn pair(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, ApiError> {
    validate_origin(&headers, &state)?;
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let mut bootstrap = state.bootstrap_token.write().await;
    let Some(expected) = bootstrap.as_ref() else {
        return Err(ApiError::Unauthorized);
    };
    if !constant_time_equal(presented, expected) {
        return Err(ApiError::Unauthorized);
    }
    bootstrap.take();

    let session_token = new_token();
    state
        .session_tokens
        .write()
        .await
        .push(session_token.clone());
    Ok(Json(PairResponse {
        session_token,
        token_type: "Bearer",
    }))
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let presented = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let tokens = state.session_tokens.read().await;
    if !tokens
        .iter()
        .any(|expected| constant_time_equal(presented, expected))
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(Json(SessionResponse {
        authenticated: true,
        mode: "synthetic_only",
    }))
}

fn validate_origin(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidOrigin)?;
    state
        .trusted_origins
        .contains(origin)
        .then_some(())
        .ok_or(ApiError::InvalidOrigin)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix(BEARER_PREFIX)
        .filter(|token| !token.is_empty())
}

fn constant_time_equal(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header::AUTHORIZATION},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{AppState, apply_security_headers, router};

    const ORIGIN: &str = "http://127.0.0.1:8787";

    fn test_app() -> (axum::Router, String) {
        let (state, bootstrap) = AppState::new([ORIGIN.to_owned()]);
        (router(state), bootstrap)
    }

    #[tokio::test]
    async fn status_is_explicitly_synthetic_only() {
        let (app, _) = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let status: serde_json::Value = serde_json::from_slice(&bytes).expect("status JSON");
        assert_eq!(status["mode"], "synthetic_only");
        assert_eq!(status["real_credentials_enabled"], false);
    }

    #[tokio::test]
    async fn pairing_rejects_missing_origin() {
        let (app, bootstrap) = test_app();
        let response = app
            .oneshot(pair_request(&bootstrap, None))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pairing_rejects_wrong_token() {
        let (app, _) = test_app();
        let response = app
            .oneshot(pair_request("synthetic-wrong-token", Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_token_can_only_be_used_once() {
        let (app, bootstrap) = test_app();
        let first = app
            .clone()
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(first.status(), StatusCode::OK);
        let body = first
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let pair: serde_json::Value = serde_json::from_slice(&body).expect("pair JSON");
        assert_eq!(pair["token_type"], "Bearer");
        assert!(
            pair["session_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );

        let replay = app
            .oneshot(pair_request(&bootstrap, Some(ORIGIN)))
            .await
            .expect("router response");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn security_headers_cover_web_fallbacks() {
        let app = apply_security_headers(axum::Router::new().fallback(|| async { "web" }));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(response.headers().contains_key("content-security-policy"));
    }

    fn pair_request(token: &str, origin: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/session/pair")
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(Body::empty()).expect("valid request")
    }
}
