// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ActionTemplate, Approval, ApprovalOperation, ApprovalResultScope, CatalogError, Connection,
    CredentialKind, CredentialReference, MAX_IDEMPOTENCY_KEY_CHARS, OptionalExtension,
    POSTGRES_POLICY_VERSION, PolicyDecision, PolicyEvaluation, PolicyReasonCode, PolicyRequirement,
    PostgresTargetConfig, RunState, SYNTHETIC_POLICY_VERSION, SafeEventKind, SecretState,
    SyntheticRun, SystemTime, Target, TargetKind, UNIX_EPOCH, Uuid, action_template_by_id,
    credential_from_row, params, target_from_row,
};

pub(crate) fn validate_command(
    connection: &Connection,
    operation: ApprovalOperation,
    config: Option<&crate::command::CommandConfig>,
) -> Result<(), CatalogError> {
    if (operation == ApprovalOperation::CommandExecution) != config.is_some() {
        return Err(CatalogError::Invalid);
    }
    if let Some(config) = config {
        config.validate()?;
        for slot in &config.slots {
            if credential_by_id(connection, slot.credential_id)?.is_none() {
                return Err(CatalogError::CredentialReferenceNotFound);
            }
        }
    }
    Ok(())
}

pub(crate) fn save_command_slots(
    connection: &Connection,
    id: Uuid,
    config: Option<&crate::command::CommandConfig>,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "DELETE FROM command_slots WHERE template_id=?1",
            [id.to_string()],
        )
        .map_err(|_| CatalogError::Storage)?;
    if let Some(config) = config {
        for slot in &config.slots {
            connection
                .execute(
                    "INSERT OR IGNORE INTO command_slots(template_id,credential_id) VALUES (?1,?2)",
                    params![id.to_string(), slot.credential_id.to_string()],
                )
                .map_err(|_| CatalogError::Storage)?;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "operation-specific policy rules are reviewed together"
)]
pub(crate) fn policy_evaluation(
    connection: &Connection,
    template: &ActionTemplate,
    target: &Target,
) -> Result<PolicyEvaluation, CatalogError> {
    let postgres = template.operation == ApprovalOperation::PostgresConnectionCheck;
    let command = template.operation == ApprovalOperation::CommandExecution;
    let mut reasons = Vec::new();
    if (template.result_scope == ApprovalResultScope::SanitizedOutput) != command {
        reasons.push(PolicyReasonCode::ResultScopeUnsupported);
    }
    if !template.enabled {
        reasons.push(PolicyReasonCode::TemplateDisabled);
    }
    if command {
        if let Some(config) = &template.command {
            if config.validate().is_err() {
                reasons.push(PolicyReasonCode::TargetIncompatible);
            }
            if config
                .telnet
                .as_ref()
                .is_some_and(|telnet| !telnet.matches_target(config, target))
            {
                reasons.push(PolicyReasonCode::TargetIncompatible);
            }
            for slot in &config.slots {
                match credential_by_id(connection, slot.credential_id)? {
                    None => reasons.push(PolicyReasonCode::CredentialMissing),
                    Some(credential) if credential.secret_state != SecretState::Available => {
                        reasons.push(PolicyReasonCode::CredentialNotConfigured);
                    }
                    Some(_) => {}
                }
            }
        } else {
            reasons.push(PolicyReasonCode::TargetIncompatible);
        }
        if reasons.is_empty() {
            reasons.push(PolicyReasonCode::FixedCommandTemplate);
        }
    } else if postgres {
        if target.kind != TargetKind::Database {
            reasons.push(PolicyReasonCode::TargetIncompatible);
        }
        if target.postgres.is_none() {
            reasons.push(PolicyReasonCode::PostgresConfigurationMissing);
        }
        if template.result_scope != ApprovalResultScope::StatusOnly {
            reasons.push(PolicyReasonCode::ResultScopeUnsupported);
        }
        let credential = target
            .credential_reference_id
            .map(|id| credential_by_id(connection, id))
            .transpose()?
            .flatten();
        match credential {
            None => reasons.push(PolicyReasonCode::CredentialMissing),
            Some(credential) => {
                if credential.kind != CredentialKind::Password {
                    reasons.push(PolicyReasonCode::CredentialKindUnsupported);
                }
                if credential.secret_state != SecretState::Available {
                    reasons.push(PolicyReasonCode::CredentialNotConfigured);
                }
            }
        }
        if reasons.is_empty() {
            reasons.push(PolicyReasonCode::FixedPostgresConnectionCheck);
        }
    } else if reasons.is_empty() {
        reasons.push(PolicyReasonCode::FixedSyntheticScope);
    }
    let eligible = reasons.iter().all(|reason| {
        matches!(
            reason,
            PolicyReasonCode::FixedSyntheticScope
                | PolicyReasonCode::FixedPostgresConnectionCheck
                | PolicyReasonCode::FixedCommandTemplate
        )
    });
    Ok(PolicyEvaluation {
        policy_version: if command {
            "credential-command-policy-v1"
        } else if postgres {
            POSTGRES_POLICY_VERSION
        } else {
            SYNTHETIC_POLICY_VERSION
        },
        decision: if eligible {
            PolicyDecision::EligibleForApproval
        } else {
            PolicyDecision::Denied
        },
        reason_codes: reasons,
        requirements: if command {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::ValidatedParameters,
                PolicyRequirement::ScopedAuthorization,
                PolicyRequirement::TransitionRevalidation,
                PolicyRequirement::RedactedOutput,
            ]
        } else if postgres {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::NoParameters,
                PolicyRequirement::ScopedAuthorization,
                PolicyRequirement::TransitionRevalidation,
                PolicyRequirement::TlsVerifyFull,
                PolicyRequirement::ReadOnlyTransaction,
                PolicyRequirement::StructuredStatusOnly,
            ]
        } else {
            vec![
                PolicyRequirement::ExplicitApproval,
                PolicyRequirement::NoParameters,
                PolicyRequirement::ScopedAuthorization,
                PolicyRequirement::SyntheticOnly,
                PolicyRequirement::TransitionRevalidation,
            ]
        },
        action_template_id: template.id,
        action_template_version: template.version,
        target_id: target.id,
        target_version: target.version,
        target_environment: target.environment,
        operation: template.operation,
        result_scope: template.result_scope,
        timeout_seconds: template.timeout_seconds,
        execution_mode: if command {
            "credential_command"
        } else if postgres {
            "controlled_postgres"
        } else {
            "synthetic_simulation"
        },
    })
}

pub(crate) fn ensure_approval_policy(
    connection: &Connection,
    approval: &Approval,
) -> Result<(), CatalogError> {
    let template_id = approval
        .action_template_id
        .ok_or(CatalogError::PolicyDenied)?;
    let template_version = approval
        .action_template_version
        .ok_or(CatalogError::PolicyDenied)?;
    let template =
        action_template_by_id(connection, template_id)?.ok_or(CatalogError::PolicyDenied)?;
    let target = target_by_id(connection, approval.target_id)?.ok_or(CatalogError::PolicyDenied)?;
    if !template.enabled
        || template.version != template_version
        || template.target_id != approval.target_id
        || template.operation != approval.operation
        || template.result_scope != approval.result_scope
        || target.version != approval.target_version
    {
        return Err(CatalogError::PolicyDenied);
    }
    if policy_evaluation(connection, &template, &target)?.decision
        != PolicyDecision::EligibleForApproval
    {
        return Err(CatalogError::PolicyDenied);
    }
    Ok(())
}

pub(crate) fn credential_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<CredentialReference>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, purpose, address, username, secret_configured,
                    secret_updated_at_unix_ms, created_at_unix_ms,
                    updated_at_unix_ms, version
               FROM credential_references WHERE id = ?1",
            [id.to_string()],
            credential_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(crate) fn target_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<Target>, CatalogError> {
    connection
        .query_row(
            "SELECT id, name, kind, environment, description, address, username,
                    allow_insecure_protocol, credential_reference_id, postgres_host, postgres_port,
                    postgres_database, postgres_username, postgres_tls_mode,
                    created_at_unix_ms, updated_at_unix_ms, version
               FROM targets WHERE id = ?1",
            [id.to_string()],
            target_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(crate) fn synthetic_run_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                    result_scope, state, result_status, created_at_unix_ms,
                    updated_at_unix_ms, started_at_unix_ms,
                    finished_at_unix_ms, version
               FROM synthetic_runs WHERE id = ?1",
            [id.to_string()],
            synthetic_run_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(crate) fn synthetic_run_by_idempotency_key_hash(
    connection: &Connection,
    key: &str,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                    result_scope, state, result_status, created_at_unix_ms,
                    updated_at_unix_ms, started_at_unix_ms,
                    finished_at_unix_ms, version
               FROM synthetic_runs WHERE idempotency_key_hash = ?1",
            [key],
            synthetic_run_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(crate) fn synthetic_run_by_approval(
    connection: &Connection,
    approval_id: Uuid,
) -> Result<Option<SyntheticRun>, CatalogError> {
    connection
        .query_row(
            "SELECT id, approval_id, action_template_id, target_id, target_version, operation,
                    result_scope, state, result_status, created_at_unix_ms,
                    updated_at_unix_ms, started_at_unix_ms,
                    finished_at_unix_ms, version
               FROM synthetic_runs WHERE approval_id = ?1",
            [approval_id.to_string()],
            synthetic_run_from_row,
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

pub(crate) fn synthetic_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyntheticRun> {
    Ok(SyntheticRun {
        id: uuid_from_row(row, 0)?,
        approval_id: uuid_from_row(row, 1)?,
        action_template_id: uuid_from_row(row, 2)?,
        target_id: uuid_from_row(row, 3)?,
        target_version: u64_from_row(row, 4)?,
        operation: ApprovalOperation::from_storage(&row.get::<_, String>(5)?)?,
        result_scope: ApprovalResultScope::from_storage(&row.get::<_, String>(6)?)?,
        state: RunState::from_storage(&row.get::<_, String>(7)?)?,
        result_status: row.get(8)?,
        created_at_unix_ms: u64_from_row(row, 9)?,
        updated_at_unix_ms: u64_from_row(row, 10)?,
        started_at_unix_ms: optional_u64_from_row(row, 11)?,
        finished_at_unix_ms: optional_u64_from_row(row, 12)?,
        version: u64_from_row(row, 13)?,
    })
}

pub(crate) fn insert_safe_event(
    connection: &Connection,
    run_id: Uuid,
    sequence: u64,
    kind: SafeEventKind,
    state: RunState,
    message: &str,
    created_at: i64,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT INTO safe_events
                (run_id, sequence, kind, state, message, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run_id.to_string(),
                i64::try_from(sequence).map_err(|_| CatalogError::Storage)?,
                kind.as_storage(),
                state.as_storage(),
                message,
                created_at
            ],
        )
        .map(|_| ())
        .map_err(|_| CatalogError::Storage)
}

pub(crate) fn uuid_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&row.get::<_, String>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(crate) fn u64_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    row.get::<_, i64>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(crate) fn optional_u64_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}

pub(crate) fn ensure_capacity(
    connection: &Connection,
    table: &str,
    maximum: i64,
) -> Result<(), CatalogError> {
    let statement = match table {
        "credential_references" => "SELECT COUNT(*) FROM credential_references",
        "targets" => "SELECT COUNT(*) FROM targets",
        "approvals" => {
            "SELECT COUNT(*) FROM approvals
            WHERE state = 'pending'
               OR (state = 'approved' AND (
                    authorization_mode = '\"time_window\"'
                    OR NOT EXISTS (
                        SELECT 1 FROM synthetic_runs WHERE synthetic_runs.approval_id = approvals.id
                    )
               ))"
        }
        "action_templates" => "SELECT COUNT(*) FROM action_templates",
        "synthetic_runs" => {
            "SELECT COUNT(*) FROM synthetic_runs WHERE state IN ('queued', 'running')"
        }
        "configuration_imports" => "SELECT COUNT(*) FROM configuration_imports",
        _ => return Err(CatalogError::Storage),
    };
    let count = connection
        .query_row(statement, [], |row| row.get::<_, i64>(0))
        .map_err(|_| CatalogError::Storage)?;
    (count < maximum)
        .then_some(())
        .ok_or(CatalogError::Capacity)
}

pub(crate) fn ensure_credential_reference_unlinked(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogError> {
    let references = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM targets WHERE credential_reference_id = ?1) +
                    (SELECT COUNT(*) FROM command_slots WHERE credential_id = ?1)",
            [id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| CatalogError::Storage)?;
    (references == 0)
        .then_some(())
        .ok_or(CatalogError::ResourceInUse)
}

pub(crate) fn normalize_idempotency_key(value: &str) -> Result<String, CatalogError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
    {
        return Err(CatalogError::Invalid);
    }
    Ok(value.to_owned())
}

pub(crate) fn normalize_postgres_config(
    kind: TargetKind,
    config: Option<&PostgresTargetConfig>,
) -> Result<Option<PostgresTargetConfig>, CatalogError> {
    let Some(config) = config else {
        return Ok(None);
    };
    if kind != TargetKind::Database {
        return Err(CatalogError::Invalid);
    }
    let host = config.host.trim();
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.chars().any(char::is_whitespace)
        || host.contains(['/', '\\', '@'])
        || host.contains("://")
        || !host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-:_[]".contains(character))
    {
        return Err(CatalogError::Invalid);
    }
    if config.port == 0 {
        return Err(CatalogError::Invalid);
    }
    Ok(Some(PostgresTargetConfig {
        host: host.to_ascii_lowercase(),
        port: config.port,
        database: normalize_required(&config.database, 63)?,
        username: normalize_required(&config.username, 63)?,
        tls_mode: config.tls_mode,
    }))
}

pub(crate) fn ensure_target_exists(connection: &Connection, id: Uuid) -> Result<(), CatalogError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM targets WHERE id = ?1",
            [id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| CatalogError::Storage)?
        .is_some();
    exists.then_some(()).ok_or(CatalogError::NotFound)
}

pub(crate) fn ensure_credential_exists(
    connection: &Connection,
    id: Option<Uuid>,
) -> Result<(), CatalogError> {
    let Some(id) = id else {
        return Ok(());
    };
    let exists = connection
        .query_row(
            "SELECT 1 FROM credential_references WHERE id = ?1",
            [id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| CatalogError::Storage)?
        .is_some();
    exists
        .then_some(())
        .ok_or(CatalogError::CredentialReferenceNotFound)
}

pub(crate) fn normalize_required(value: &str, maximum: usize) -> Result<String, CatalogError> {
    let value = value.trim();
    let count = value.chars().count();
    if count == 0 || count > maximum || value.chars().any(char::is_control) {
        return Err(CatalogError::Invalid);
    }
    Ok(value.to_owned())
}

pub(crate) fn normalize_optional(
    value: Option<&str>,
    maximum: usize,
) -> Result<Option<String>, CatalogError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    normalize_required(value, maximum).map(Some)
}

pub(crate) fn now_unix_ms_i64() -> Result<i64, CatalogError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .map_err(|_| CatalogError::Storage)
}
