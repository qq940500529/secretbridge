// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::domain::{
    parameters::{AuthorizationMode, ParameterValues},
    targets::TargetEnvironment,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOperation {
    InspectMetadata,
    SyntheticHealthCheck,
    PostgresConnectionCheck,
    CommandExecution,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResultScope {
    StatusOnly,
    MetadataSummary,
    SanitizedOutput,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    EligibleForApproval,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasonCode {
    FixedSyntheticScope,
    FixedPostgresConnectionCheck,
    FixedCommandTemplate,
    TemplateDisabled,
    TargetIncompatible,
    PostgresConfigurationMissing,
    CredentialMissing,
    CredentialNotConfigured,
    CredentialKindUnsupported,
    ResultScopeUnsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRequirement {
    ValidatedParameters,
    ScopedAuthorization,
    ExplicitApproval,
    NoParameters,
    SingleUse,
    SyntheticOnly,
    TransitionRevalidation,
    TlsVerifyFull,
    ReadOnlyTransaction,
    StructuredStatusOnly,
    RedactedOutput,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyEvaluation {
    pub policy_version: &'static str,
    pub decision: PolicyDecision,
    pub reason_codes: Vec<PolicyReasonCode>,
    pub requirements: Vec<PolicyRequirement>,
    pub action_template_id: Uuid,
    pub action_template_version: u64,
    pub target_id: Uuid,
    pub target_version: u64,
    pub target_environment: TargetEnvironment,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub timeout_seconds: u64,
    pub execution_mode: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Approval {
    pub authorization_mode: AuthorizationMode,
    pub parameters: ParameterValues,
    pub id: Uuid,
    pub conversation_id: Option<Uuid>,
    pub preauthorized: bool,
    pub action_template_id: Option<Uuid>,
    pub action_template_version: Option<u64>,
    pub target_id: Uuid,
    pub target_version: u64,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub reason: Option<String>,
    pub state: ApprovalState,
    pub decision_note: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApproval {
    #[serde(default)]
    pub(crate) authorization_mode: AuthorizationMode,
    #[serde(default)]
    pub(crate) parameters: ParameterValues,
    pub(crate) action_template_id: Uuid,
    #[serde(default)]
    pub(crate) conversation_id: Option<Uuid>,
    pub(crate) reason: Option<String>,
    pub(crate) expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideApproval {
    pub(crate) expected_version: u64,
    pub(crate) note: Option<String>,
}
