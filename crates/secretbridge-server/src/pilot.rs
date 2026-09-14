// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PILOT_PROFILE_VERSION: &str = "postgres-pilot-v1";
pub const MIN_PILOT_TTL_SECONDS: u64 = 3_600;
pub const MAX_PILOT_TTL_SECONDS: u64 = 604_800;

pub const PILOT_SCENARIOS: [(&str, &str); 11] = [
    (
        "connection_success",
        "Authorized fixed connection check succeeds",
    ),
    (
        "authentication_rejected",
        "Invalid or revoked credentials fail with a fixed safe result",
    ),
    (
        "connection_timeout",
        "A connection timeout is bounded and observable",
    ),
    (
        "dns_failure",
        "DNS failure does not expose resolver details",
    ),
    (
        "tls_untrusted_certificate",
        "An untrusted certificate is rejected without raw error disclosure",
    ),
    (
        "tls_hostname_mismatch",
        "A certificate hostname mismatch is rejected",
    ),
    (
        "network_unreachable",
        "Network interruption produces a bounded fixed result",
    ),
    (
        "credential_rotation",
        "Credential rotation invalidates stale authorization",
    ),
    (
        "approval_revocation",
        "Approval revocation stops queued or active work",
    ),
    (
        "service_restart_unknown_result",
        "Service restart preserves an explicit unknown or interrupted result",
    ),
    (
        "credential_revoked_on_close",
        "The temporary pilot credential is removed before closure",
    ),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotCampaignState {
    Registered,
    Active,
    Closing,
    Closed,
    Revoked,
    Expired,
}

impl PilotCampaignState {
    pub(crate) const fn as_storage(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "registered" => Ok(Self::Registered),
            "active" => Ok(Self::Active),
            "closing" => Ok(Self::Closing),
            "closed" => Ok(Self::Closed),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotScenarioResult {
    NotRun,
    Passed,
    Failed,
    NotApplicable,
}

impl PilotScenarioResult {
    pub(crate) const fn as_storage(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::NotApplicable => "not_applicable",
        }
    }

    pub(crate) fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "not_run" => Ok(Self::NotRun),
            "passed" => Ok(Self::Passed),
            "failed" => Ok(Self::Failed),
            "not_applicable" => Ok(Self::NotApplicable),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PilotScenarioEvidence {
    pub code: String,
    pub ordinal: u64,
    pub result: PilotScenarioResult,
    pub expected_behavior: String,
    pub evidence_reference: Option<String>,
    pub reviewer_reference: Option<String>,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PilotCampaign {
    pub id: Uuid,
    pub profile_version: String,
    pub name: String,
    pub state: PilotCampaignState,
    pub target_id: Uuid,
    pub target_version: u64,
    pub action_template_id: Uuid,
    pub action_template_version: u64,
    pub readiness_snapshot_id: Uuid,
    pub platform_snapshot_id: Uuid,
    pub authorization_reference: String,
    pub least_privilege_reference: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub version: u64,
    pub scenarios: Vec<PilotScenarioEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePilotCampaign {
    pub(crate) name: String,
    pub(crate) action_template_id: Uuid,
    pub(crate) readiness_snapshot_id: Uuid,
    pub(crate) platform_snapshot_id: Uuid,
    pub(crate) authorization_reference: String,
    pub(crate) least_privilege_reference: String,
    pub(crate) expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionPilotCampaign {
    pub(crate) expected_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePilotScenario {
    pub(crate) result: PilotScenarioResult,
    pub(crate) evidence_reference: Option<String>,
    pub(crate) reviewer_reference: Option<String>,
    pub(crate) expected_version: u64,
}
