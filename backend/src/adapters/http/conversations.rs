// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, AxumPath, HeaderMap, Json, Router, Serialize, State, get,
    map_catalog_error, require_session, task, validate_origin,
};
use crate::catalog::{AiConversation, SetAiConversationPolicy};
use uuid::Uuid;

#[derive(Serialize)]
struct ConversationList {
    items: Vec<AiConversation>,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ai-conversations", get(list))
        .route("/api/v1/ai-conversations/{id}", get(get_one))
        .route(
            "/api/v1/ai-conversations/{id}/policy",
            axum::routing::put(set_policy),
        )
}

async fn get_one(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<AiConversation>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let item = task::spawn_blocking(move || catalog.get_ai_conversation(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(item))
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ConversationList>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_ai_conversations())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(ConversationList { items }))
}

async fn set_policy(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<SetAiConversationPolicy>,
) -> Result<Json<AiConversation>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let conversation =
        task::spawn_blocking(move || catalog.set_ai_conversation_policy(id, &request))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(map_catalog_error)?;
    let _ = state.changes.send(());
    Ok(Json(conversation))
}
