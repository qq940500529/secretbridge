// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresTlsMode {
    VerifyFull,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresTargetConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub tls_mode: PostgresTlsMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Database,
    HttpService,
    SshHost,
    TelnetHost,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetEnvironment {
    Development,
    Test,
    Production,
}

#[derive(Clone, Debug, Serialize)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub kind: TargetKind,
    pub environment: TargetEnvironment,
    pub description: Option<String>,
    pub address: Option<String>,
    pub username: Option<String>,
    pub allow_insecure_protocol: bool,
    pub credential_reference_id: Option<Uuid>,
    pub postgres: Option<PostgresTargetConfig>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTarget {
    pub(crate) name: String,
    pub(crate) kind: TargetKind,
    pub(crate) environment: TargetEnvironment,
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) address: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) allow_insecure_protocol: bool,
    pub(crate) credential_reference_id: Option<Uuid>,
    pub(crate) postgres: Option<PostgresTargetConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTarget {
    pub(crate) name: String,
    pub(crate) kind: TargetKind,
    pub(crate) environment: TargetEnvironment,
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) address: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) allow_insecure_protocol: bool,
    pub(crate) credential_reference_id: Option<Uuid>,
    pub(crate) postgres: Option<PostgresTargetConfig>,
    pub(crate) expected_version: u64,
}
