// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::catalog::CatalogError;
use rmcp::ErrorData;
use uuid::Uuid;

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
        | "secure_terminal_not_running"
        | "browser_open_failed"
        | "broker_stopping" => ErrorData::invalid_params(
            code.to_owned(),
            if matches!(
                code,
                "command_arguments_too_large"
                    | "command_argument_too_large"
                    | "legacy_credential_placeholder"
                    | "unknown_credential_placeholder"
            ) {
                data
            } else {
                None
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
    ErrorData::invalid_params(code, None)
}
