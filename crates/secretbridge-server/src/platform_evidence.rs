// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{fs, path::PathBuf};

use serde::Serialize;
use uuid::Uuid;

pub const PLATFORM_BOUNDARY_PROFILE_VERSION: &str = "platform-boundary-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformBoundaryStatus {
    Verified,
    Attention,
    Blocked,
}

impl PlatformBoundaryStatus {
    pub(crate) const fn as_storage(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Attention => "attention",
            Self::Blocked => "blocked",
        }
    }

    pub(crate) fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "verified" => Ok(Self::Verified),
            "attention" => Ok(Self::Attention),
            "blocked" => Ok(Self::Blocked),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformCheckStatus {
    Passed,
    Warning,
    Failed,
    NotApplicable,
}

impl PlatformCheckStatus {
    pub(crate) const fn as_storage(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warning => "warning",
            Self::Failed => "failed",
            Self::NotApplicable => "not_applicable",
        }
    }

    pub(crate) fn from_storage(value: &str) -> rusqlite::Result<Self> {
        match value {
            "passed" => Ok(Self::Passed),
            "warning" => Ok(Self::Warning),
            "failed" => Ok(Self::Failed),
            "not_applicable" => Ok(Self::NotApplicable),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PlatformBoundaryCheck {
    pub code: String,
    pub category: String,
    pub status: PlatformCheckStatus,
    pub summary: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlatformBoundarySnapshot {
    pub id: Uuid,
    pub profile_version: String,
    pub status: PlatformBoundaryStatus,
    pub application_version: String,
    pub platform: String,
    pub runtime_context: String,
    pub identity_boundary: String,
    pub created_at_unix_ms: u64,
    pub evidence_digest_sha256: String,
    pub digest_verified: bool,
    pub checks: Vec<PlatformBoundaryCheck>,
}

#[derive(Serialize)]
pub(crate) struct PlatformBoundaryEvidence<'a> {
    pub id: Uuid,
    pub profile_version: &'a str,
    pub status: PlatformBoundaryStatus,
    pub application_version: &'a str,
    pub platform: &'a str,
    pub runtime_context: &'a str,
    pub identity_boundary: &'a str,
    pub created_at_unix_ms: u64,
    pub checks: &'a [PlatformBoundaryCheck],
}

#[derive(Clone)]
pub(crate) struct PlatformEvidenceProbe {
    data_directory: Option<PathBuf>,
    native_credential_store: bool,
}

impl PlatformEvidenceProbe {
    pub(crate) fn ephemeral() -> Self {
        Self {
            data_directory: None,
            native_credential_store: false,
        }
    }

    pub(crate) fn persistent(data_directory: PathBuf) -> Self {
        Self {
            data_directory: Some(data_directory),
            native_credential_store: true,
        }
    }

    pub(crate) fn collect(&self) -> Vec<PlatformBoundaryCheck> {
        let mut checks = Vec::new();
        self.collect_runtime_checks(&mut checks);
        collect_transport_checks(&mut checks);
        checks.push(check(
            "native_credential_store",
            "credential_store",
            if self.native_credential_store {
                PlatformCheckStatus::Passed
            } else {
                PlatformCheckStatus::Warning
            },
            "The persistent runtime selects the operating-system credential store",
            if self.native_credential_store {
                "Native credential-store backend selected; no secret was read by this probe"
            } else {
                "Ephemeral test runtime uses an in-memory credential store"
            },
        ));
        checks.push(check(
            "installed_service_identity",
            "installation",
            PlatformCheckStatus::Warning,
            "Installed service identity must be proven outside the running process",
            "No independently signed fresh-install evidence is attached to this self-check",
        ));
        checks.push(check(
            "hostile_subject_denial",
            "external_evidence",
            PlatformCheckStatus::Warning,
            "Unauthorized operating-system subjects must be denied in an installed test",
            "Same-user, non-owner and connection-document replacement tests require external evidence",
        ));
        checks
    }

    fn collect_runtime_checks(&self, checks: &mut Vec<PlatformBoundaryCheck>) {
        let Some(directory) = self.data_directory.as_deref() else {
            checks.push(check(
                "persistent_runtime_directory",
                "runtime_directory",
                PlatformCheckStatus::Warning,
                "A persistent runtime directory is available for permission inspection",
                "In-memory test state has no installed runtime directory",
            ));
            return;
        };
        let directory_metadata = fs::symlink_metadata(directory);
        checks.push(check(
            "runtime_directory_type",
            "runtime_directory",
            match &directory_metadata {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    PlatformCheckStatus::Passed
                }
                _ => PlatformCheckStatus::Failed,
            },
            "The runtime directory exists as a real directory rather than a symbolic link",
            match &directory_metadata {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    "Runtime directory type and link policy passed"
                }
                _ => "Runtime directory is missing, invalid or linked",
            },
        ));

        collect_directory_permission_check(directory_metadata.as_ref().ok(), checks);
        let connection_metadata = fs::symlink_metadata(directory.join("mcp-bridge.json"));
        checks.push(check(
            "connection_document_type",
            "runtime_directory",
            match &connection_metadata {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    PlatformCheckStatus::Passed
                }
                _ => PlatformCheckStatus::Failed,
            },
            "The bridge connection document is a regular file and not a symbolic link",
            match &connection_metadata {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    "Connection-document type and link policy passed"
                }
                _ => "Connection document is missing, invalid or linked",
            },
        ));
        collect_endpoint_permission_check(directory, connection_metadata.as_ref().ok(), checks);
    }
}

fn check(
    code: &str,
    category: &str,
    status: PlatformCheckStatus,
    summary: &str,
    evidence: &str,
) -> PlatformBoundaryCheck {
    PlatformBoundaryCheck {
        code: code.to_owned(),
        category: category.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence: evidence.to_owned(),
    }
}

#[cfg(unix)]
fn collect_directory_permission_check(
    metadata: Option<&fs::Metadata>,
    checks: &mut Vec<PlatformBoundaryCheck>,
) {
    let private = metadata.is_some_and(posix_permissions_private);
    checks.push(check(
        "runtime_directory_permissions",
        "runtime_directory",
        if private {
            PlatformCheckStatus::Passed
        } else {
            PlatformCheckStatus::Failed
        },
        "The runtime directory grants no group or other permission bits",
        if private {
            "POSIX permission mask excludes group and other access"
        } else {
            "POSIX permission mask is missing or exposes group/other access"
        },
    ));
}

#[cfg(windows)]
fn collect_directory_permission_check(
    metadata: Option<&fs::Metadata>,
    checks: &mut Vec<PlatformBoundaryCheck>,
) {
    checks.push(check(
        "runtime_directory_acl",
        "runtime_directory",
        if metadata.is_some() {
            PlatformCheckStatus::Warning
        } else {
            PlatformCheckStatus::Failed
        },
        "The runtime directory DACL limits access to the intended service identity",
        if metadata.is_some() {
            "Directory exists, but this build does not inspect or normalize its Windows DACL"
        } else {
            "Runtime directory metadata is unavailable"
        },
    ));
}

#[cfg(not(any(unix, windows)))]
fn collect_directory_permission_check(
    metadata: Option<&fs::Metadata>,
    checks: &mut Vec<PlatformBoundaryCheck>,
) {
    checks.push(check(
        "runtime_directory_permissions",
        "runtime_directory",
        if metadata.is_some() {
            PlatformCheckStatus::Warning
        } else {
            PlatformCheckStatus::Failed
        },
        "The runtime directory is restricted to the intended identity",
        "This platform has no built-in permission verifier",
    ));
}

#[cfg(unix)]
fn collect_endpoint_permission_check(
    directory: &std::path::Path,
    connection_metadata: Option<&fs::Metadata>,
    checks: &mut Vec<PlatformBoundaryCheck>,
) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let connection_private = connection_metadata.is_some_and(posix_permissions_private);
    checks.push(check(
        "connection_document_permissions",
        "ipc_transport",
        if connection_private {
            PlatformCheckStatus::Passed
        } else {
            PlatformCheckStatus::Failed
        },
        "The connection document grants no group or other permission bits",
        if connection_private {
            "Connection-document POSIX permission mask is private"
        } else {
            "Connection-document permission mask is missing or not private"
        },
    ));
    let socket_metadata = fs::symlink_metadata(directory.join("mcp-bridge.sock"));
    let socket_private = socket_metadata
        .as_ref()
        .is_ok_and(|value| value.file_type().is_socket() && posix_permissions_private(value));
    checks.push(check(
        "ipc_endpoint_permissions",
        "ipc_transport",
        if socket_private {
            PlatformCheckStatus::Passed
        } else {
            PlatformCheckStatus::Failed
        },
        "The Unix-domain socket is a private socket node",
        if socket_private {
            "Socket type and POSIX permission mask passed"
        } else {
            "Socket is missing, invalid or not private"
        },
    ));
    let directory_owner = fs::metadata(directory).ok().map(|value| value.uid());
    let owner_consistent = directory_owner.is_some_and(|owner| {
        connection_metadata.is_some_and(|value| value.uid() == owner)
            && socket_metadata
                .as_ref()
                .is_ok_and(|value| value.uid() == owner)
    });
    checks.push(check(
        "ipc_owner_consistency",
        "ipc_transport",
        if owner_consistent {
            PlatformCheckStatus::Passed
        } else {
            PlatformCheckStatus::Failed
        },
        "The runtime directory, connection document and socket have the same owner",
        if owner_consistent {
            "Owner identifiers matched without disclosing their value"
        } else {
            "Owner metadata is missing or inconsistent"
        },
    ));
}

#[cfg(unix)]
#[allow(
    clippy::verbose_bit_mask,
    reason = "the evidence check intentionally names the POSIX group/other permission mask"
)]
fn posix_permissions_private(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(windows)]
fn collect_endpoint_permission_check(
    _directory: &std::path::Path,
    connection_metadata: Option<&fs::Metadata>,
    checks: &mut Vec<PlatformBoundaryCheck>,
) {
    checks.push(check(
        "connection_document_acl",
        "ipc_transport",
        if connection_metadata.is_some() {
            PlatformCheckStatus::Warning
        } else {
            PlatformCheckStatus::Failed
        },
        "The connection document DACL limits access to the intended service identity",
        if connection_metadata.is_some() {
            "File exists, but this build does not inspect or normalize its Windows DACL"
        } else {
            "Connection-document metadata is unavailable"
        },
    ));
    checks.push(check(
        "named_pipe_explicit_dacl",
        "ipc_transport",
        PlatformCheckStatus::Warning,
        "The named pipe has an explicit service-identity DACL",
        "Remote clients are rejected, but an explicit named-pipe DACL is not yet applied",
    ));
}

#[cfg(not(any(unix, windows)))]
fn collect_endpoint_permission_check(
    _directory: &std::path::Path,
    _connection_metadata: Option<&fs::Metadata>,
    checks: &mut Vec<PlatformBoundaryCheck>,
) {
    checks.push(check(
        "ipc_endpoint_permissions",
        "ipc_transport",
        PlatformCheckStatus::Warning,
        "The local IPC endpoint is restricted to the intended identity",
        "This platform has no built-in endpoint permission verifier",
    ));
}

#[cfg(unix)]
fn collect_transport_checks(checks: &mut Vec<PlatformBoundaryCheck>) {
    checks.push(check(
        "local_transport_scope",
        "ipc_transport",
        PlatformCheckStatus::Passed,
        "The bridge uses a local Unix-domain socket",
        "No TCP listener is used by the native bridge",
    ));
    checks.push(check(
        "peer_identity_enforcement",
        "ipc_transport",
        PlatformCheckStatus::Passed,
        "Every accepted bridge peer is checked against the runtime-directory owner",
        "Unix peer credentials are checked before protocol handling",
    ));
}

#[cfg(windows)]
fn collect_transport_checks(checks: &mut Vec<PlatformBoundaryCheck>) {
    checks.push(check(
        "remote_pipe_clients_rejected",
        "ipc_transport",
        PlatformCheckStatus::Passed,
        "The named-pipe listener rejects remote clients",
        "Named-pipe server is configured with reject_remote_clients",
    ));
    checks.push(check(
        "first_pipe_instance",
        "ipc_transport",
        PlatformCheckStatus::Passed,
        "The broker requires the first named-pipe server instance",
        "Named-pipe server is configured with first_pipe_instance",
    ));
    checks.push(check(
        "peer_identity_enforcement",
        "ipc_transport",
        PlatformCheckStatus::Warning,
        "Every accepted bridge peer is checked against the intended Windows identity",
        "This build authenticates the runtime token but does not inspect the pipe-client token",
    ));
}

#[cfg(not(any(unix, windows)))]
fn collect_transport_checks(checks: &mut Vec<PlatformBoundaryCheck>) {
    checks.push(check(
        "local_transport_scope",
        "ipc_transport",
        PlatformCheckStatus::Warning,
        "The bridge transport is restricted to the local operating system",
        "No platform-specific transport evidence is available",
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_probe_never_claims_identity_verification() {
        let checks = PlatformEvidenceProbe::ephemeral().collect();
        assert!(checks.iter().any(|check| {
            check.code == "persistent_runtime_directory"
                && check.status == PlatformCheckStatus::Warning
        }));
        assert!(checks.iter().any(|check| {
            check.code == "hostile_subject_denial" && check.status == PlatformCheckStatus::Warning
        }));
        let serialized = serde_json::to_string(&checks).expect("checks should serialize");
        for forbidden in [
            "synthetic-secret-value",
            "synthetic-user-name",
            "synthetic-host-name",
            "synthetic-pipe-name",
            "synthetic-file-path",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}
