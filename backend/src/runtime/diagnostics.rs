// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::AppState;

impl AppState {
    /// Records a fixed, safe category when the local bridge cannot bind during startup.
    pub fn record_bridge_startup_failure(&self) {
        let _ = self
            .catalog
            .record_diagnostic_failure("bridge_startup_failed");
        if self.catalog.diagnostic_vault_ready().unwrap_or(false) {
            let _ = self.catalog.record_encrypted_diagnostic(
                "event",
                serde_json::json!({ "source": "bridge", "code": "bridge_startup_failed" }),
            );
        }
    }
}
