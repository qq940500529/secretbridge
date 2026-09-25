// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    catalog::CatalogError,
    command::{CommandConfig, CredentialSlot, Injection},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Command};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "git_tests.rs"]
pub(crate) mod integration_tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitConfig {
    pub operation: Operation,
    pub remote_url: String,
    pub branch: String,
    pub username: String,
    pub token_slot: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Inspect,
    Fetch,
    Push,
}

impl GitConfig {
    pub fn validate(&self, config: &CommandConfig) -> Result<(), CatalogError> {
        let url = reqwest::Url::parse(&self.remote_url).map_err(|_| CatalogError::Invalid)?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.remote_url.len() > 2048
            || self.remote_url.chars().any(char::is_control)
            || self.username.is_empty()
            || self.username.len() > 128
            || self.username.contains(':')
            || self.username.chars().any(char::is_control)
            || !valid_branch(&self.branch)
            || !Path::new(&config.program).is_absolute()
            || !Path::new(&config.program).is_file()
            || !Path::new(&config.working_directory).is_absolute()
            || !Path::new(&config.working_directory).is_dir()
            || !config.arguments.is_empty()
            || !config.parameters.is_empty()
            || config.slots.len() != 1
            || config.slots[0].name != self.token_slot
            || config.slots[0].injection != Injection::Protocol
            || config.slots[0].environment_variable.is_some()
        {
            return Err(CatalogError::Invalid);
        }
        Ok(())
    }

    /// Build the fixed argv and an environment-only auth header, never an authenticated URL.
    pub fn prepare(
        &self,
        config: &CommandConfig,
        secrets: &[Zeroizing<String>],
    ) -> Result<(CommandConfig, Vec<Zeroizing<String>>), CatalogError> {
        self.validate(config)?;
        let token = secrets
            .first()
            .filter(|s| !s.is_empty())
            .ok_or(CatalogError::Invalid)?;
        let raw = Zeroizing::new(format!("{}:{}", self.username, token.as_str()));
        let encoded = Zeroizing::new(STANDARD.encode(raw.as_bytes()));
        let header = Zeroizing::new(format!("Authorization: Basic {}", encoded.as_str()));
        let mut arguments = vec!["--no-pager".into()];
        for setting in [
            "credential.helper=",
            "credential.interactive=false",
            "http.extraHeader=",
            "http.sslVerify=true",
            "http.followRedirects=false",
            "core.hooksPath=",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "fetch.recurseSubmodules=false",
            "fetch.writeCommitGraph=false",
            "maintenance.auto=false",
            "gc.auto=0",
        ] {
            arguments.extend(["-c".into(), setting.into()]);
        }
        arguments.extend([
            "-c".into(),
            format!(
                "protocol.http.allow={}",
                if self.remote_url.starts_with("http://") {
                    "always"
                } else {
                    "never"
                }
            ),
        ]);
        arguments.extend([
            "-c".into(),
            format!("credential.{}.helper=", self.remote_url),
        ]);
        arguments.push(format!(
            "--config-env=http.{}.extraHeader=SECRETBRIDGE_GIT_AUTH",
            self.remote_url
        ));
        // URL-specific settings take precedence over generic defaults in repository configuration.
        arguments.extend([
            "-c".into(),
            format!("http.{}.followRedirects=false", self.remote_url),
            "-c".into(),
            format!("http.{}.sslVerify=true", self.remote_url),
        ]);
        let reference = format!("refs/heads/{}", self.branch);
        match self.operation {
            Operation::Inspect => arguments.extend([
                "ls-remote".into(),
                "--heads".into(),
                "--".into(),
                self.remote_url.clone(),
                reference,
            ]),
            Operation::Fetch => arguments.extend([
                "fetch".into(),
                "--no-tags".into(),
                "--no-recurse-submodules".into(),
                "--".into(),
                self.remote_url.clone(),
                format!("{reference}:refs/remotes/secretbridge/{}", self.branch),
            ]),
            Operation::Push => arguments.extend([
                "push".into(),
                "--no-verify".into(),
                "--no-recurse-submodules".into(),
                "--".into(),
                self.remote_url.clone(),
                format!("{reference}:{reference}"),
            ]),
        }
        let mut prepared = config.clone();
        prepared.git = None;
        prepared.arguments = arguments;
        prepared.slots = vec![CredentialSlot {
            name: self.token_slot.clone(),
            credential_id: config.slots[0].credential_id,
            injection: Injection::Environment,
            environment_variable: Some("SECRETBRIDGE_GIT_AUTH".into()),
        }];
        // Filter every known authentication representation, including child-process diagnostic output.
        Ok((prepared, vec![header, token.clone(), raw, encoded]))
    }
}

#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "Git refname rules are case-sensitive, not filesystem extension checks"
)]
fn valid_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 128
        && !branch.starts_with('-')
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.ends_with('.')
        && branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        && branch
            .split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
}

pub fn configure_environment(command: &mut Command) {
    // Git diagnostics can include headers; inherited Git flags must not enable trace or override TLS.
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
            || name == "SSLKEYLOGFILE"
        {
            command.env_remove(name);
        }
    }
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn branches_are_fixed_non_option_ref_names() {
        for value in ["main", "feature/task-1", "release/1.0"] {
            assert!(valid_branch(value));
        }
        for value in [
            "", "-f", "x..y", "x.lock", "a//b", "a/", ".x", "x@{0}", "a;id", "a b",
        ] {
            assert!(!valid_branch(value));
        }
    }
}
