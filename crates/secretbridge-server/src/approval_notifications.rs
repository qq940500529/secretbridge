// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, HeaderMap, Json, Router, Serialize, State, get, map_catalog_error,
    require_session, task, validate_origin,
};
use crate::catalog::{Approval, ApprovalNotificationChannel};
use serde::Deserialize;

#[derive(Serialize)]
struct NotificationSettings {
    channel: ApprovalNotificationChannel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateNotificationSettings {
    channel: ApprovalNotificationChannel,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/notification-settings", get(read).put(update))
}

async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NotificationSettings>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let channel = task::spawn_blocking(move || catalog.approval_notification_channel())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(NotificationSettings { channel }))
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateNotificationSettings>,
) -> Result<Json<NotificationSettings>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.set_approval_notification_channel(request.channel))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    let _ = state.changes.send(());
    Ok(Json(NotificationSettings {
        channel: request.channel,
    }))
}

pub(super) fn notify_pending_approval(state: &AppState, approval: &Approval) {
    if approval.state != crate::catalog::ApprovalState::Pending {
        return;
    }
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || {
        if catalog.approval_notification_channel().ok() != Some(ApprovalNotificationChannel::System)
        {
            return;
        }
        // No target, command, credential or account data enters the OS notification center.
        let _ = notify_rust::Notification::new()
            .summary("SecretBridge")
            .body("An approval request is pending in the local console.")
            .show();
    });
}
