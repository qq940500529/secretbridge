// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    ApiToken,
    SshKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    NotConfigured,
    Available,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialReference {
    pub id: Uuid,
    pub name: String,
    pub kind: CredentialKind,
    pub purpose: Option<String>,
    pub address: Option<String>,
    pub username: Option<String>,
    pub secret_state: SecretState,
    pub secret_updated_at_unix_ms: Option<u64>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredentialReference {
    pub(crate) name: String,
    pub(crate) kind: CredentialKind,
    pub(crate) purpose: Option<String>,
    #[serde(default)]
    pub(crate) address: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCredentialReference {
    pub(crate) name: String,
    pub(crate) kind: CredentialKind,
    pub(crate) purpose: Option<String>,
    #[serde(default)]
    pub(crate) address: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
    pub(crate) expected_version: u64,
}
