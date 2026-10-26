// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::runtime::updates::UpdateStatus;
use rmcp::{
    ErrorData,
    model::{CallToolResponse, ContentBlock},
};

pub(super) fn annotate(result: &mut Result<CallToolResponse, ErrorData>, update: &UpdateStatus) {
    if !update.update_available {
        return;
    }
    let notice = format!(
        "SecretBridge update available: {} → {}. {}. 测试版可能与旧版不兼容；请按聊天语言提醒用户选择是否升级，默认不更新。Beta compatibility is not guaranteed. Ask the user whether to upgrade; default to keeping the current version. Do not download, install, migrate or restart without explicit user approval. Check status: {}.",
        update.current_version,
        update.latest_version.as_deref().unwrap_or("unknown"),
        update.release_url,
        update.check_state,
    );
    match result {
        Ok(CallToolResponse::Complete(response)) => {
            response.content.push(ContentBlock::text(notice));
            if let Ok(value) = serde_json::to_value(update) {
                response
                    .meta
                    .get_or_insert_with(Default::default)
                    .insert("secretbridge_update".to_owned(), value);
            }
        }
        Err(error) => {
            let value = error.data.get_or_insert_with(|| serde_json::json!({}));
            if let Some(data) = value.as_object_mut() {
                data.insert(
                    "secretbridge_update".to_owned(),
                    serde_json::json!({"status": update, "notice": notice}),
                );
            }
        }
        _ => {}
    }
}
