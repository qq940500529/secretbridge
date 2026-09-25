// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::domain::approvals::{ApprovalOperation, ApprovalResultScope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Succeeded,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyntheticRun {
    pub id: Uuid,
    pub approval_id: Uuid,
    pub action_template_id: Uuid,
    pub target_id: Uuid,
    pub target_version: u64,
    pub operation: ApprovalOperation,
    pub result_scope: ApprovalResultScope,
    pub state: RunState,
    pub result_status: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub finished_at_unix_ms: Option<u64>,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSyntheticRun {
    pub(crate) approval_id: Uuid,
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelSyntheticRun {
    pub(crate) expected_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeEventKind {
    AuthorizationRevoked,
    Requested,
    Started,
    Succeeded,
    Cancelled,
    Interrupted,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct SafeEvent {
    pub id: u64,
    pub run_id: Uuid,
    pub sequence: u64,
    pub kind: SafeEventKind,
    pub state: RunState,
    pub message: String,
    pub created_at_unix_ms: u64,
    pub terminal_id: Option<Uuid>,
}
