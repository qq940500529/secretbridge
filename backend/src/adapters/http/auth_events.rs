// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;

use crate::{ApiError, AppState, catalog::BrowserAuthEvent, map_catalog_error, require_session};

#[derive(Serialize)]
pub(super) struct BrowserAuthEventListResponse {
    items: Vec<BrowserAuthEvent>,
    retention_truncated: bool,
}

pub(super) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BrowserAuthEventListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let items = state
        .catalog
        .list_browser_auth_events()
        .map_err(map_catalog_error)?;
    let retention_truncated = items.last().is_some_and(|event| event.id > 1);
    Ok(Json(BrowserAuthEventListResponse {
        items,
        retention_truncated,
    }))
}
