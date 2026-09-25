// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    catalog::{Approval, ApprovalNotificationChannel, ApprovalState},
};

pub(crate) fn notify_pending_approval(state: &AppState, approval: &Approval) {
    if approval.state != ApprovalState::Pending {
        return;
    }
    let catalog = state.catalog.clone();
    tokio::task::spawn_blocking(move || {
        if catalog.approval_notification_channel().ok() != Some(ApprovalNotificationChannel::System)
        {
            return;
        }
        // Do not include target, command, credential or account details in OS notifications.
        let _ = notify_rust::Notification::new()
            .summary("SecretBridge")
            .body("An approval request is pending in the local console.")
            .show();
    });
}
