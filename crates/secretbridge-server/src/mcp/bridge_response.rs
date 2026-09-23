// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use rmcp::ErrorData;

use super::{BRIDGE_CONNECTION_SCHEMA, BridgeResponse, errors::recovery_actions};

pub(super) fn safe_bridge_error_code(code: &str) -> String {
    match code {
        "not_found"
        | "approval_consumed"
        | "approval_not_usable"
        | "approval_not_pending"
        | "capacity_exceeded"
        | "credential_reference_not_found"
        | "invalid_request"
        | "initialization_required"
        | "invalid_approval_transition"
        | "invalid_run_transition"
        | "idempotency_conflict"
        | "policy_denied"
        | "resource_in_use"
        | "version_conflict"
        | "verification_failed"
        | "terminal_attach_required"
        | "terminal_input_required"
        | "terminal_busy"
        | "terminal_context_unknown"
        | "secure_terminal_not_usable"
        | "secure_terminal_not_running"
        | "ssh_connection_required"
        | "ssh_connection_address_required"
        | "ssh_connection_username_required"
        | "ssh_connection_credential_required"
        | "ssh_password_credential_required"
        | "ssh_credential_target_mismatch"
        | "telnet_not_explicitly_allowed"
        | "terminal_closed"
        | "terminal_spawn_failed"
        | "terminal_unsupported_shell"
        | "runtime_control_unavailable"
        | "browser_open_failed"
        | "broker_stopping"
        | "command_arguments_too_large"
        | "command_argument_too_large"
        | "command_stdin_too_large"
        | "command_stdin_invalid"
        | "command_stdin_conflict"
        | "legacy_credential_placeholder"
        | "unknown_credential_placeholder" => code.to_owned(),
        _ => "secretbridge_operation_failed".to_owned(),
    }
}

impl BridgeResponse {
    pub(super) fn success(payload: serde_json::Value) -> Self {
        Self {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            ok: true,
            payload: Some(payload),
            error: None,
            error_data: None,
        }
    }

    pub(super) fn error(code: &str) -> Self {
        Self {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            ok: false,
            payload: None,
            error: Some(code.to_owned()),
            error_data: None,
        }
    }

    pub(super) fn from_error(error: ErrorData) -> Self {
        let code = safe_bridge_error_code(error.message.as_ref());
        let error_data = if matches!(
            code.as_str(),
            "command_arguments_too_large"
                | "command_argument_too_large"
                | "command_stdin_too_large"
                | "command_stdin_invalid"
                | "command_stdin_conflict"
                | "legacy_credential_placeholder"
                | "unknown_credential_placeholder"
        ) {
            error.data.and_then(|value| {
                let field = value.get("field")?.as_str()?;
                if field != "arguments"
                    && field != "stdin_content"
                    && !(field.starts_with("arguments[")
                        && field.ends_with(']')
                        && field.len() <= 32
                        && field[10..field.len() - 1].bytes().all(|byte| byte.is_ascii_digit()))
                {
                    return None;
                }
                Some(if code == "legacy_credential_placeholder" {
                    serde_json::json!({
                        "field": field,
                        "next_actions": ["use_explicit_secret_placeholder"]
                    })
                } else if code == "unknown_credential_placeholder" {
                    serde_json::json!({
                        "field": field,
                        "next_actions": ["declare_matching_credential_slot", "use_literal_double_braces_without_secret_prefix"]
                    })
                } else if code == "command_stdin_invalid" {
                    serde_json::json!({
                        "field": field,
                        "next_actions": ["remove_secret_placeholder_or_nul"]
                    })
                } else if code == "command_stdin_conflict" {
                    serde_json::json!({
                        "field": field,
                        "next_actions": ["choose_either_stdin_content_or_stdin_credential"]
                    })
                } else {
                    serde_json::json!({
                        "field": field,
                        "actual_bytes": value.get("actual_bytes")?.as_u64()?,
                        "limit_bytes": value.get("limit_bytes")?.as_u64()?,
                        "next_actions": ["split_the_operation", "use_a_structured_connector"]
                    })
                })
            })
        } else if code == "initialization_required" {
            error.data.and_then(|value| {
                let console_url = value.get("console_url")?.as_str()?;
                Some(serde_json::json!({
                    "console_url": console_url,
                    "next_actions": ["open_local_management_page", "set_required_pin", "optionally_bind_authenticator", "retry_after_initialization"]
                }))
            })
        } else {
            recovery_actions(&code).map(|actions| serde_json::json!({ "next_actions": actions }))
        };
        Self {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            ok: false,
            payload: None,
            error: Some(code),
            error_data,
        }
    }
}
