// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ActionTemplate, AppState, Approval, ApprovalOperation, ApprovalResultScope, ApprovalState,
    Deserialize, JsonSchema, PolicyDecision, PolicyEvaluation, PolicyReasonCode, PolicyRequirement,
    RunState, SafeEvent, SafeEventKind, Serialize, SyntheticRun,
};

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentifierParams {
    #[schemars(description = "SecretBridge UUID returned by another tool")]
    pub(super) id: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestApprovalParams {
    #[serde(default)]
    #[schemars(
        description = "Ordinary non-secret parameter values. Defaults are resolved and frozen in the approval."
    )]
    pub(super) parameters: crate::parameters::ParameterValues,
    #[serde(default)]
    #[schemars(
        description = "every_run/once consume one run; time_window allows repeated runs of exactly the same confirmed parameters until expiry"
    )]
    pub(super) authorization_mode: crate::parameters::AuthorizationMode,
    #[schemars(description = "Action-template UUID")]
    pub(super) action_template_id: String,
    #[serde(default)]
    #[schemars(
        description = "AI conversation UUID from secretbridge_begin_conversation; reuse it for every task in the same chat"
    )]
    pub(super) conversation_id: Option<String>,
    #[schemars(description = "Approval lifetime in seconds, from 60 through 3600")]
    pub(super) expires_in_seconds: u64,
    #[serde(default)]
    #[schemars(
        description = "Non-secret reason in the current conversation language, up to 240 characters"
    )]
    pub(super) reason: Option<String>,
    #[serde(default)]
    pub(super) language: ConversationLanguage,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConversationLanguage {
    #[default]
    En,
    Zh,
}

impl ConversationLanguage {
    pub(super) fn default_reason(self, kind: &str) -> String {
        match (self, kind) {
            (Self::Zh, "command") => "通过 MCP 申请一次性命令".to_owned(),
            (Self::Zh, _) => "通过 MCP 申请受控操作".to_owned(),
            (Self::En, "command") => "One-time command requested through MCP".to_owned(),
            (Self::En, _) => "Requested through MCP".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmApprovalParams {
    #[schemars(description = "Pending approval UUID returned by SecretBridge")]
    pub(super) approval_id: String,
    #[schemars(description = "Current optimistic version returned with that pending approval")]
    pub(super) expected_version: u64,
    #[schemars(
        description = "Six-digit one-time authenticator code supplied by the user for this approval"
    )]
    pub(super) verification_code: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestCommandParams {
    #[schemars(description = "Short human-readable label for this one-time command draft")]
    pub(super) name: String,
    #[schemars(description = "Connection UUID returned by secretbridge_list_catalog")]
    pub(super) connection_id: String,
    #[serde(default)]
    #[schemars(description = "AI conversation UUID from secretbridge_begin_conversation")]
    pub(super) conversation_id: Option<String>,
    #[schemars(
        description = "Running secure-terminal UUID returned by secretbridge_terminal_list"
    )]
    pub(super) terminal_id: String,
    #[schemars(description = "Absolute executable path; never a shell command string")]
    pub(super) program: String,
    #[schemars(description = "Existing absolute working directory")]
    pub(super) working_directory: String,
    #[schemars(
        description = "Exact argv items; argument/file credential slots require one complete {{secret:slot_name}} item. Other double-brace text such as {{.Names}} is literal"
    )]
    pub(super) arguments: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional non-secret script or data sent to program stdin, up to 32768 UTF-8 bytes; cannot be combined with a stdin credential slot"
    )]
    pub(super) stdin_content: Option<String>,
    #[serde(default)]
    #[schemars(description = "Opaque credential bindings and injection modes; no secret values")]
    pub(super) credential_slots: Vec<DynamicCredentialSlot>,
    #[serde(default)]
    pub(super) authorization_mode: crate::parameters::AuthorizationMode,
    #[schemars(description = "Pending approval lifetime in seconds, from 60 through 3600")]
    pub(super) expires_in_seconds: u64,
    #[schemars(description = "Maximum command runtime in seconds, from 1 through 300")]
    pub(super) timeout_seconds: u64,
    #[serde(default)]
    #[schemars(
        description = "Non-secret reason in the current conversation language, up to 240 characters"
    )]
    pub(super) reason: Option<String>,
    #[serde(default)]
    pub(super) language: ConversationLanguage,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestSshParams {
    #[schemars(description = "Saved SSH connection UUID from secretbridge_list_catalog")]
    pub(super) connection_id: String,
    #[serde(default)]
    #[schemars(description = "AI conversation UUID from secretbridge_begin_conversation")]
    pub(super) conversation_id: Option<String>,
    #[schemars(description = "Short human-readable label for this one-time operation")]
    pub(super) name: String,
    #[schemars(
        description = "User-confirmed SHA256 host-key fingerprint; never accept an unknown host automatically"
    )]
    pub(super) host_key_sha256: String,
    #[serde(default = "default_ssh_port")]
    pub(super) port: u16,
    #[schemars(description = "Absolute remote executable path, not a shell command string")]
    pub(super) remote_program: String,
    #[serde(default)]
    #[schemars(description = "Optional absolute remote working directory; no shell expressions")]
    pub(super) working_directory: Option<String>,
    #[schemars(description = "Remote argv items; sent as individually quoted POSIX words")]
    pub(super) arguments: Vec<String>,
    #[schemars(description = "Pending approval lifetime in seconds, 60 through 3600")]
    pub(super) expires_in_seconds: u64,
    #[schemars(description = "Maximum remote runtime in seconds, 1 through 300")]
    pub(super) timeout_seconds: u64,
    #[serde(default)]
    pub(super) reason: Option<String>,
    #[serde(default)]
    pub(super) language: ConversationLanguage,
}

const fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DynamicCredentialSlot {
    pub(super) name: String,
    #[schemars(description = "Credential UUID returned by secretbridge_list_catalog")]
    pub(super) credential_id: String,
    pub(super) injection: DynamicInjection,
    #[serde(default)]
    pub(super) environment_variable: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DynamicInjection {
    Stdin,
    Environment,
    Argument,
    File,
}

impl From<DynamicInjection> for crate::command::Injection {
    fn from(value: DynamicInjection) -> Self {
        match value {
            DynamicInjection::Stdin => Self::Stdin,
            DynamicInjection::Environment => Self::Environment,
            DynamicInjection::Argument => Self::Argument,
            DynamicInjection::File => Self::File,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRunParams {
    #[schemars(description = "Approved usable approval UUID")]
    pub(super) approval_id: String,
    #[schemars(description = "Caller-generated idempotency key, 1 through 96 safe characters")]
    pub(super) idempotency_key: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CancelRunParams {
    #[schemars(description = "Queued or running run UUID")]
    pub(super) run_id: String,
    #[schemars(description = "Current run version returned by get_run")]
    pub(super) expected_version: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct CatalogSummary {
    pub(super) credentials: Vec<CredentialSummary>,
    pub(super) connections: Vec<ConnectionSummary>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct CredentialSummary {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) address: Option<String>,
    pub(super) username: Option<String>,
    pub(super) configured: bool,
    pub(super) version: u64,
}

impl From<crate::catalog::CredentialReference> for CredentialSummary {
    fn from(value: crate::catalog::CredentialReference) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            kind: match value.kind {
                crate::catalog::CredentialKind::Password => "password",
                crate::catalog::CredentialKind::ApiToken => "api_token",
                crate::catalog::CredentialKind::SshKey => "ssh_key",
            }
            .to_owned(),
            address: value.address,
            username: value.username,
            configured: value.secret_state == crate::catalog::SecretState::Available,
            version: value.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct ConnectionSummary {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) environment: String,
    pub(super) address: Option<String>,
    pub(super) username: Option<String>,
    pub(super) credential_id: Option<String>,
    pub(super) insecure_protocol_explicitly_allowed: bool,
    pub(super) version: u64,
}

impl From<crate::catalog::Target> for ConnectionSummary {
    fn from(value: crate::catalog::Target) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            kind: match value.kind {
                crate::catalog::TargetKind::Database => "database",
                crate::catalog::TargetKind::HttpService => "http_service",
                crate::catalog::TargetKind::SshHost => "ssh_host",
                crate::catalog::TargetKind::TelnetHost => "telnet_host",
            }
            .to_owned(),
            environment: match value.environment {
                crate::catalog::TargetEnvironment::Development => "development",
                crate::catalog::TargetEnvironment::Test => "test",
                crate::catalog::TargetEnvironment::Production => "production",
            }
            .to_owned(),
            address: value.address,
            username: value.username,
            credential_id: value.credential_reference_id.map(|id| id.to_string()),
            insecure_protocol_explicitly_allowed: value.allow_insecure_protocol,
            version: value.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct TemplateList {
    pub(super) items: Vec<TemplateSummary>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct TemplateSummary {
    pub(super) execution_kind: String,
    pub(super) parameters: Vec<crate::parameters::ParameterDefinition>,
    pub(super) credential_slots: Vec<SlotSummary>,
    pub(super) id: String,
    pub(super) name: String,
    pub(super) operation: ApprovalOperation,
    pub(super) result_scope: ApprovalResultScope,
    pub(super) timeout_seconds: u64,
    pub(super) enabled: bool,
    pub(super) version: u64,
}

impl From<ActionTemplate> for TemplateSummary {
    fn from(template: ActionTemplate) -> Self {
        Self {
            execution_kind: if template
                .command
                .as_ref()
                .is_some_and(|c| c.database.is_some())
            {
                "database"
            } else if template
                .command
                .as_ref()
                .is_some_and(|c| c.ssh.as_ref().is_some_and(|s| s.transfer.is_some()))
            {
                "sftp"
            } else if template.command.as_ref().is_some_and(|c| c.git.is_some()) {
                "git"
            } else if template.command.as_ref().is_some_and(|c| c.ssh.is_some()) {
                "ssh"
            } else if template
                .command
                .as_ref()
                .is_some_and(|c| c.telnet.is_some())
            {
                "telnet"
            } else if template.command.as_ref().is_some_and(|c| c.http.is_some()) {
                "http"
            } else if template.command.is_some() {
                "program"
            } else {
                "builtin"
            }
            .into(),
            parameters: template
                .command
                .as_ref()
                .map_or_else(Vec::new, |c| c.parameters.clone()),
            credential_slots: template.command.as_ref().map_or_else(Vec::new, |config| {
                config
                    .slots
                    .iter()
                    .map(|s| SlotSummary {
                        name: s.name.clone(),
                        injection: format!("{:?}", s.injection).to_lowercase(),
                    })
                    .collect()
            }),
            id: template.id.to_string(),
            name: template.name,
            operation: template.operation,
            result_scope: template.result_scope,
            timeout_seconds: template.timeout_seconds,
            enabled: template.enabled,
            version: template.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct SlotSummary {
    pub(super) name: String,
    pub(super) injection: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct PolicySummary {
    pub(super) policy_version: String,
    pub(super) decision: PolicyDecision,
    pub(super) reason_codes: Vec<PolicyReasonCode>,
    pub(super) requirements: Vec<PolicyRequirement>,
    pub(super) action_template_id: String,
    pub(super) action_template_version: u64,
    pub(super) target_version: u64,
    pub(super) operation: ApprovalOperation,
    pub(super) result_scope: ApprovalResultScope,
    pub(super) timeout_seconds: u64,
    pub(super) execution_mode: String,
}

impl From<PolicyEvaluation> for PolicySummary {
    fn from(evaluation: PolicyEvaluation) -> Self {
        Self {
            policy_version: evaluation.policy_version.to_owned(),
            decision: evaluation.decision,
            reason_codes: evaluation.reason_codes,
            requirements: evaluation.requirements,
            action_template_id: evaluation.action_template_id.to_string(),
            action_template_version: evaluation.action_template_version,
            target_version: evaluation.target_version,
            operation: evaluation.operation,
            result_scope: evaluation.result_scope,
            timeout_seconds: evaluation.timeout_seconds,
            execution_mode: evaluation.execution_mode.to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct ApprovalSummary {
    pub(super) parameters: crate::parameters::ParameterValues,
    pub(super) authorization_mode: crate::parameters::AuthorizationMode,
    pub(super) id: String,
    pub(super) conversation_id: Option<String>,
    pub(super) preauthorized: bool,
    pub(super) action_template_id: Option<String>,
    pub(super) action_template_version: Option<u64>,
    pub(super) target_id: String,
    pub(super) reason: Option<String>,
    pub(super) operation: ApprovalOperation,
    pub(super) result_scope: ApprovalResultScope,
    pub(super) state: ApprovalState,
    pub(super) expires_at_unix_ms: u64,
    pub(super) version: u64,
    pub(super) console_url: Option<String>,
    pub(super) next_actions: Vec<String>,
}

impl From<Approval> for ApprovalSummary {
    fn from(approval: Approval) -> Self {
        Self {
            parameters: approval.parameters,
            authorization_mode: approval.authorization_mode,
            id: approval.id.to_string(),
            conversation_id: approval.conversation_id.map(|id| id.to_string()),
            preauthorized: approval.preauthorized,
            action_template_id: approval.action_template_id.map(|id| id.to_string()),
            action_template_version: approval.action_template_version,
            target_id: approval.target_id.to_string(),
            reason: approval.reason,
            operation: approval.operation,
            result_scope: approval.result_scope,
            state: approval.state,
            expires_at_unix_ms: approval.expires_at_unix_ms,
            version: approval.version,
            console_url: None,
            next_actions: Vec::new(),
        }
    }
}

impl ApprovalSummary {
    pub(super) fn with_human_action(mut self, state: &AppState) -> Self {
        if self.state == ApprovalState::Pending {
            self.console_url = state
                .runtime_control
                .as_ref()
                .map(|control| control.origin.clone());
            self.next_actions = vec![
                "show_pending_approval_details_to_user".to_owned(),
                "user_approves_in_local_web_console".to_owned(),
                "or_if_totp_configured_submit_current_code_with_secretbridge_confirm_approval"
                    .to_owned(),
            ];
        } else if self.preauthorized {
            self.next_actions = vec![
                "disclose_conversation_preapproval_and_risk_to_user".to_owned(),
                "create_run_if_still_intended".to_owned(),
            ];
        }
        self
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct CreateRunSummary {
    pub(super) run: RunSummary,
    pub(super) replayed: bool,
    pub(super) execution_mode: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct RunSummary {
    pub(super) id: String,
    pub(super) approval_id: String,
    pub(super) action_template_id: String,
    pub(super) operation: ApprovalOperation,
    pub(super) result_scope: ApprovalResultScope,
    pub(super) state: RunState,
    pub(super) result_status: Option<String>,
    pub(super) created_at_unix_ms: u64,
    pub(super) updated_at_unix_ms: u64,
    pub(super) started_at_unix_ms: Option<u64>,
    pub(super) finished_at_unix_ms: Option<u64>,
    pub(super) version: u64,
}

impl From<SyntheticRun> for RunSummary {
    fn from(run: SyntheticRun) -> Self {
        Self {
            id: run.id.to_string(),
            approval_id: run.approval_id.to_string(),
            action_template_id: run.action_template_id.to_string(),
            operation: run.operation,
            result_scope: run.result_scope,
            state: run.state,
            result_status: run.result_status,
            created_at_unix_ms: run.created_at_unix_ms,
            updated_at_unix_ms: run.updated_at_unix_ms,
            started_at_unix_ms: run.started_at_unix_ms,
            finished_at_unix_ms: run.finished_at_unix_ms,
            version: run.version,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct EventList {
    pub(super) payload_policy: String,
    pub(super) items: Vec<EventSummary>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub(super) struct EventSummary {
    pub(super) sequence: u64,
    pub(super) kind: SafeEventKind,
    pub(super) state: RunState,
    pub(super) message: String,
    pub(super) created_at_unix_ms: u64,
}

impl From<SafeEvent> for EventSummary {
    fn from(event: SafeEvent) -> Self {
        Self {
            sequence: event.sequence,
            kind: event.kind,
            state: event.state,
            message: event.message,
            created_at_unix_ms: event.created_at_unix_ms,
        }
    }
}
