// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rmcp::ErrorData;

use super::{AppState, OP_HEALTH};

pub(super) fn ensure_bridge_ready(state: &AppState, operation: &str) -> Result<(), ErrorData> {
    if state.runtime_control.is_some()
        && operation != OP_HEALTH
        && !state.catalog.diagnostic_vault_ready().unwrap_or(false)
    {
        let console_url = state
            .runtime_control
            .as_ref()
            .map(|control| &control.origin);
        return Err(ErrorData::invalid_params(
            "initialization_required",
            Some(serde_json::json!({ "console_url": console_url })),
        ));
    }
    if state
        .runtime_control
        .as_ref()
        .is_some_and(|control| control.stopping.is_cancelled())
    {
        return Err(ErrorData::internal_error("broker_stopping", None));
    }
    Ok(())
}
