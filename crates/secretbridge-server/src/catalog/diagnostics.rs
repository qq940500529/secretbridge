// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::params;
use serde::Serialize;

use super::{Catalog, CatalogError, now_unix_ms_i64};

#[derive(Debug, Serialize)]
pub struct DiagnosticFailure {
    pub code: &'static str,
    pub stage: &'static str,
    pub recovery_actions: &'static [&'static str],
    pub occurrences: u64,
    pub first_at_unix_ms: u64,
    pub last_at_unix_ms: u64,
}

const DIAGNOSTIC_FAILURE_CODES: &[(&str, &str)] = &[
    ("command_arguments_too_large", "mcp_validation"),
    ("command_argument_too_large", "mcp_validation"),
    ("command_stdin_too_large", "mcp_validation"),
    ("command_stdin_invalid", "mcp_validation"),
    ("command_stdin_conflict", "mcp_validation"),
    ("unknown_credential_placeholder", "mcp_validation"),
    ("legacy_credential_placeholder", "mcp_validation"),
    ("invalid_request", "mcp_validation"),
    ("verification_failed", "authorization"),
    ("approval_not_usable", "authorization"),
    ("policy_denied", "authorization"),
    ("credential_reference_not_found", "credential_resolution"),
    ("terminal_busy", "terminal_lease"),
    ("terminal_input_required", "terminal_lease"),
    ("terminal_attach_required", "terminal_lease"),
    ("terminal_context_unknown", "terminal_lease"),
    ("secure_terminal_not_running", "terminal_lease"),
    ("terminal_closed", "terminal_lease"),
    ("terminal_spawn_failed", "command_start"),
    ("secretbridge_operation_failed", "bridge_dispatch"),
    ("bridge_startup_failed", "bridge_startup"),
];

fn diagnostic_recovery_actions(code: &str) -> &'static [&'static str] {
    match code {
        "command_arguments_too_large"
        | "command_argument_too_large"
        | "command_stdin_too_large" => &[
            "split_the_operation",
            "use_bounded_stdin_or_structured_connector",
        ],
        "command_stdin_invalid" | "command_stdin_conflict" => {
            &["remove_invalid_stdin_content_or_conflicting_slot"]
        }
        "legacy_credential_placeholder" | "unknown_credential_placeholder" => {
            &["review_explicit_secret_slot_syntax"]
        }
        "terminal_busy" => &["wait_for_active_run", "inspect_terminal_state"],
        "terminal_input_required" | "terminal_attach_required" => {
            &["attach_terminal_and_request_input"]
        }
        "terminal_context_unknown" | "terminal_closed" | "secure_terminal_not_running" => {
            &["create_new_terminal", "request_new_approval_if_needed"]
        }
        "verification_failed" | "approval_not_usable" | "policy_denied" => &[
            "review_current_approval_state",
            "request_new_approval_if_needed",
        ],
        "credential_reference_not_found" => &["refresh_catalog", "ask_human_to_reenter_credential"],
        "terminal_spawn_failed" => &["check_shell_and_program_availability"],
        "bridge_startup_failed" | "secretbridge_operation_failed" => {
            &["check_local_broker_health", "review_private_data_directory"]
        }
        _ => &["check_request_and_retry_if_safe"],
    }
}

fn diagnostic_failure_class(code: &str) -> Option<(&'static str, &'static str)> {
    DIAGNOSTIC_FAILURE_CODES
        .iter()
        .copied()
        .find(|(candidate, _)| *candidate == code)
}

impl Catalog {
    pub fn record_diagnostic_failure(&self, code: &str) -> Result<(), CatalogError> {
        if diagnostic_failure_class(code).is_none() {
            return Ok(());
        }
        let now = now_unix_ms_i64()?;
        self.lock()
            .execute(
                "INSERT INTO diagnostic_failures
                    (code, occurrences, first_at_unix_ms, last_at_unix_ms)
                 VALUES (?1, 1, ?2, ?2)
                 ON CONFLICT(code) DO UPDATE SET
                    occurrences = CASE
                        WHEN occurrences < 9223372036854775807 THEN occurrences + 1
                        ELSE occurrences
                    END,
                    last_at_unix_ms = MAX(last_at_unix_ms, excluded.last_at_unix_ms)",
                params![code, now],
            )
            .map_err(|_| CatalogError::Storage)?;
        Ok(())
    }

    pub fn list_diagnostic_failures(&self) -> Result<Vec<DiagnosticFailure>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare(
                "SELECT code, occurrences, first_at_unix_ms, last_at_unix_ms
                   FROM diagnostic_failures ORDER BY code",
            )
            .map_err(|_| CatalogError::Storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|_| CatalogError::Storage)?;
        rows.map(|row| {
            let (code, occurrences, first, last) = row.map_err(|_| CatalogError::Storage)?;
            let (code, stage) = diagnostic_failure_class(&code).ok_or(CatalogError::Storage)?;
            Ok(DiagnosticFailure {
                code,
                stage,
                recovery_actions: diagnostic_recovery_actions(code),
                occurrences: u64::try_from(occurrences).map_err(|_| CatalogError::Storage)?,
                first_at_unix_ms: u64::try_from(first).map_err(|_| CatalogError::Storage)?,
                last_at_unix_ms: u64::try_from(last).map_err(|_| CatalogError::Storage)?,
            })
        })
        .collect()
    }
}
