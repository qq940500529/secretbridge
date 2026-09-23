// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::catalog::CatalogError;
use rmcp::ErrorData;
use uuid::Uuid;

pub(super) fn recovery_actions(code: &str) -> Option<&'static [&'static str]> {
    match code {
        "approval_consumed"
        | "approval_not_usable"
        | "approval_not_pending"
        | "invalid_approval_transition"
        | "version_conflict" => Some(&[
            "get_current_approval_state",
            "request_new_approval_if_still_intended",
        ]),
        "idempotency_conflict" => Some(&["check_existing_run", "use_new_key_for_new_intent"]),
        "terminal_busy" => Some(&["read_current_run_and_terminal_state", "wait_for_run"]),
        "terminal_context_unknown" | "terminal_closed" | "secure_terminal_not_running" => Some(&[
            "create_new_terminal",
            "request_new_approval_if_still_intended",
        ]),
        "terminal_attach_required" | "terminal_input_required" => {
            Some(&["attach_terminal_and_request_input"])
        }
        "ssh_connection_required"
        | "ssh_connection_address_required"
        | "ssh_connection_username_required"
        | "ssh_connection_credential_required"
        | "ssh_password_credential_required"
        | "ssh_credential_target_mismatch" => {
            Some(&["ask_human_to_correct_connection_metadata", "retry_request"])
        }
        "telnet_not_explicitly_allowed" => Some(&["ask_human_to_review_insecure_protocol_risk"]),
        "credential_reference_not_found" => {
            Some(&["refresh_catalog", "select_valid_credential_reference"])
        }
        "verification_failed" => Some(&[
            "ask_human_to_review_pending_approval",
            "use_current_code_only_if_voluntarily_supplied",
        ]),
        "broker_stopping" | "runtime_control_unavailable" => {
            Some(&["wait_for_local_broker", "retry_after_health_check"])
        }
        _ => None,
    }
}

pub(super) fn recoverable_error(code: &str) -> ErrorData {
    ErrorData::invalid_params(
        code.to_owned(),
        recovery_actions(code).map(|actions| serde_json::json!({ "next_actions": actions })),
    )
}

pub(super) fn reject_legacy_placeholder(
    argument: &str,
    index: usize,
    slots: &[super::DynamicCredentialSlot],
) -> Result<(), ErrorData> {
    if slots
        .iter()
        .any(|slot| argument == format!("{{{{{}}}}}", slot.name))
    {
        return Err(ErrorData::invalid_params(
            "legacy_credential_placeholder",
            Some(serde_json::json!({
                "field": format!("arguments[{index}]"),
                "next_actions": ["use_explicit_secret_placeholder"]
            })),
        ));
    }
    Ok(())
}

pub(super) fn remote_error(code: &str, data: Option<serde_json::Value>) -> ErrorData {
    match code {
        "not_found" => ErrorData::resource_not_found("not_found", None),
        "approval_consumed"
        | "approval_not_usable"
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
        | "command_arguments_too_large"
        | "command_argument_too_large"
        | "legacy_credential_placeholder"
        | "unknown_credential_placeholder"
        | "verification_failed"
        | "terminal_attach_required"
        | "terminal_input_required"
        | "terminal_busy"
        | "terminal_context_unknown"
        | "terminal_closed"
        | "terminal_spawn_failed"
        | "terminal_unsupported_shell"
        | "secure_terminal_not_usable"
        | "ssh_connection_required"
        | "ssh_connection_address_required"
        | "ssh_connection_username_required"
        | "ssh_connection_credential_required"
        | "ssh_password_credential_required"
        | "ssh_credential_target_mismatch"
        | "telnet_not_explicitly_allowed"
        | "secure_terminal_not_running"
        | "browser_open_failed"
        | "approval_not_pending"
        | "broker_stopping" => ErrorData::invalid_params(
            code.to_owned(),
            if matches!(
                code,
                "command_arguments_too_large"
                    | "command_argument_too_large"
                    | "legacy_credential_placeholder"
                    | "unknown_credential_placeholder"
                    | "initialization_required"
            ) {
                data
            } else {
                recovery_actions(code).map(|actions| serde_json::json!({ "next_actions": actions }))
            },
        ),
        "runtime_control_unavailable" => ErrorData::internal_error(code.to_owned(), None),
        "bridge_unauthorized" => {
            ErrorData::internal_error("secretbridge_bridge_authentication_failed", None)
        }
        _ => ErrorData::internal_error("secretbridge_bridge_unavailable", None),
    }
}

pub(super) fn parse_uuid(value: &str) -> Result<Uuid, ErrorData> {
    Uuid::parse_str(value).map_err(|_| ErrorData::invalid_params("invalid_identifier", None))
}

pub(super) fn catalog_error(error: CatalogError) -> ErrorData {
    let code = match error {
        CatalogError::ApprovalConsumed => "approval_consumed",
        CatalogError::ApprovalNotUsable => "approval_not_usable",
        CatalogError::Capacity => "capacity_exceeded",
        CatalogError::CredentialReferenceNotFound => "credential_reference_not_found",
        CatalogError::Invalid => "invalid_request",
        CatalogError::InvalidApprovalTransition => "invalid_approval_transition",
        CatalogError::InvalidRunTransition => "invalid_run_transition",
        CatalogError::IdempotencyConflict => "idempotency_conflict",
        CatalogError::NotFound => return ErrorData::resource_not_found("not_found", None),
        CatalogError::PolicyDenied => "policy_denied",
        CatalogError::ResourceInUse => "resource_in_use",
        CatalogError::Storage => {
            return ErrorData::internal_error("secretbridge_operation_failed", None);
        }
        CatalogError::VersionConflict => "version_conflict",
    };
    recoverable_error(code)
}
