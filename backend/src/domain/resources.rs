// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    catalog::{CredentialKind, SecretState, Target, TargetEnvironment, TargetKind},
    command::{CommandConfig, CredentialSlot, Injection},
    database_task::{DatabaseConfig, DatabaseEngine, DatabaseTls},
    ssh_task::{Authentication, SshConfig},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One catalog aggregate. Authentication is a write-only component, not another user record.
#[derive(Clone, Debug, Serialize)]
pub struct Resource {
    #[serde(flatten, serialize_with = "serialize_identity")]
    pub target: Target,
    pub authentication: ResourceAuthentication,
    pub labels: Vec<String>,
    pub connection: ConnectionOptions,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResourceAuthentication {
    pub kind: CredentialKind,
    pub secret_state: SecretState,
    pub secret_version: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionOptions {
    #[default]
    None,
    Database {
        engine: DatabaseEngine,
        port: u16,
        database: String,
        tls_mode: DatabaseTls,
        ca_certificate: Option<String>,
    },
    Ssh {
        port: u16,
        host_key_sha256: String,
    },
    Http {
        authentication: HttpAuthentication,
        #[serde(default)]
        header_name: Option<String>,
    },
    Telnet {
        allow_plaintext: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuthentication {
    None,
    Bearer,
    Basic,
    ApiKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    pub name: String,
    pub kind: TargetKind,
    pub environment: TargetEnvironment,
    pub description: Option<String>,
    pub address: Option<String>,
    pub username: Option<String>,
    pub authentication_kind: CredentialKind,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub connection: ConnectionOptions,
    #[serde(default)]
    pub expected_version: Option<u64>,
}

impl Resource {
    /// Incomplete metadata can be saved, but is never guessed during execution.
    pub fn missing_connection_fields(&self) -> Vec<&'static str> {
        let mut missing = vec![];
        if !matches!(
            self.connection,
            ConnectionOptions::None | ConnectionOptions::Telnet { .. }
        ) && self.target.address.as_deref().is_none_or(str::is_empty)
        {
            missing.push("address");
        }
        match &self.connection {
            ConnectionOptions::Database { database, .. } => {
                if database.is_empty() {
                    missing.push("database");
                }
                if self.target.username.as_deref().is_none_or(str::is_empty) {
                    missing.push("username");
                }
            }
            ConnectionOptions::Ssh {
                host_key_sha256, ..
            } => {
                if host_key_sha256.is_empty() {
                    missing.push("host_key_sha256");
                }
                if self.target.username.as_deref().is_none_or(str::is_empty) {
                    missing.push("username");
                }
            }
            ConnectionOptions::Http {
                authentication: HttpAuthentication::Basic,
                ..
            } if self.target.username.as_deref().is_none_or(str::is_empty) => {
                missing.push("username");
            }
            ConnectionOptions::Http {
                authentication: HttpAuthentication::ApiKey,
                header_name,
            } if header_name.as_deref().is_none_or(str::is_empty) => missing.push("header_name"),
            _ => (),
        }
        missing
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionTestResult {
    pub resource_id: Uuid,
    pub success: bool,
    pub missing_fields: Vec<&'static str>,
    pub code: &'static str,
    pub duration_ms: u64,
    pub tested_at_unix_ms: u64,
}

fn serialize_identity<S: serde::Serializer>(
    target: &Target,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut value = serde_json::to_value(target).map_err(serde::ser::Error::custom)?;
    if let Some(object) = value.as_object_mut() {
        for key in [
            "credential_reference_id",
            "postgres",
            "allow_insecure_protocol",
        ] {
            object.remove(key);
        }
    }
    value.serialize(serializer)
}

fn protocol_command(id: Uuid) -> CommandConfig {
    CommandConfig {
        terminal_id: None,
        database: None,
        http: None,
        ssh: None,
        telnet: None,
        git: None,
        parameters: vec![],
        program: String::new(),
        working_directory: String::new(),
        arguments: vec![],
        stdin_content: None,
        slots: vec![CredentialSlot {
            name: "authentication".into(),
            credential_id: id,
            injection: Injection::Protocol,
            environment_variable: None,
        }],
    }
}

pub(crate) fn database_command(database: DatabaseConfig, id: Uuid) -> CommandConfig {
    CommandConfig {
        database: Some(database),
        ..protocol_command(id)
    }
}
pub(crate) fn ssh_command(
    host: &str,
    username: &str,
    port: u16,
    host_key: &str,
    kind: CredentialKind,
    id: Uuid,
) -> CommandConfig {
    let authentication = if kind == CredentialKind::SshKey {
        Authentication::PrivateKey {
            slot: "authentication".into(),
            passphrase_slot: None,
        }
    } else {
        Authentication::Password {
            slot: "authentication".into(),
        }
    };
    CommandConfig {
        ssh: Some(SshConfig {
            host: host.into(),
            port,
            username: username.into(),
            host_key_sha256: host_key.into(),
            authentication,
            remote_program: "/bin/true".into(),
            working_directory: None,
            arguments: vec![],
            transfer: None,
        }),
        ..protocol_command(id)
    }
}
