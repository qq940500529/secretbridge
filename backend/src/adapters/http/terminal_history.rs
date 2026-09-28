// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{
    ApiError, AppState, AxumPath, HeaderMap, Json, Router, State, StatusCode, map_catalog_error,
    require_session, task, validate_origin,
};
use axum::extract::Query;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    terminal_id: Option<Uuid>,
    #[serde(default)]
    after: i64,
}
#[derive(Serialize)]
struct Page {
    items: Vec<crate::catalog::TerminalHistoryEntry>,
    next_cursor: i64,
    retention_limit: usize,
}
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/terminal-history", axum::routing::get(list))
        .route(
            "/api/v1/terminal-history/{id}",
            axum::routing::delete(clear),
        )
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Page>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items =
        task::spawn_blocking(move || catalog.terminal_history(filter.terminal_id, filter.after))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(map_catalog_error)?;
    let next_cursor = items.last().map_or(filter.after, |item| item.cursor);
    Ok(Json(Page {
        items,
        next_cursor,
        retention_limit: 10000,
    }))
}
async fn clear(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.clear_terminal_history(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
}
