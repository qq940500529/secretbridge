// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState, catalog::CatalogError, command::CommandConfig, redaction::Redactor,
    ssh_task::SshConfig,
};
use russh_sftp::{
    client::{RawSftpSession, error::Error},
    protocol::{FileAttributes, OpenFlags, Packet, StatusCode},
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const POSIX_RENAME: &str = "posix-rename@openssh.com";

#[cfg(test)]
#[path = "sftp_tests.rs"]
pub(crate) mod tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferConfig {
    pub direction: Direction,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default)]
    pub overwrite: bool,
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upload,
    Download,
}

impl TransferConfig {
    pub fn validate(&self) -> Result<(), CatalogError> {
        let local = Path::new(&self.local_path);
        if !local.is_absolute()
            || local.file_name().is_none()
            || self.local_path.len() > 4096
            || self.local_path.contains(['\0', '\r', '\n'])
            || !local.parent().is_some_and(Path::is_dir)
            || !self.remote_path.starts_with('/')
            || self.remote_path.ends_with('/')
            || self.remote_path.len() > 4096
            || self.remote_path.contains(['\0', '\r', '\n'])
            || self.remote_path.split('/').any(|p| matches!(p, "." | ".."))
            || !(1..=1_073_741_824).contains(&self.max_bytes)
        {
            return Err(CatalogError::Invalid);
        }
        if self.direction == Direction::Upload
            && !std::fs::symlink_metadata(local).is_ok_and(|m| m.is_file())
        {
            return Err(CatalogError::Invalid);
        }
        Ok(())
    }
}

#[derive(Default)]
struct PartialFile {
    local: Option<PathBuf>,
    remote: Option<String>,
    handle: Option<String>,
}
impl Drop for PartialFile {
    fn drop(&mut self) {
        if let Some(path) = &self.local {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn remote_exists(sftp: &RawSftpSession, path: &str) -> Result<bool, &'static str> {
    match sftp.lstat(path).await {
        Ok(attrs) if attrs.attrs.file_type().is_file() => Ok(true),
        Ok(_) => Err("not_regular_file"),
        Err(Error::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(false),
        Err(_) => Err("remote_stat_failed"),
    }
}

fn local_exists(path: &Path) -> Result<bool, &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err("not_regular_file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("local_stat_failed"),
    }
}

fn rename_payload(from: &str, to: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for path in [from, to] {
        bytes.extend_from_slice(
            &u32::try_from(path.len())
                .expect("bounded path")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(path.as_bytes());
    }
    bytes
}

#[allow(
    clippy::too_many_lines,
    reason = "single-file transfer holds temporary handles until atomic commit"
)]
async fn transfer(
    sftp: &RawSftpSession,
    config: &TransferConfig,
    partial: &mut PartialFile,
    posix: bool,
) -> Result<u64, &'static str> {
    let local = Path::new(&config.local_path);
    let uploading = config.direction == Direction::Upload;
    let exists = if uploading {
        remote_exists(sftp, &config.remote_path).await?
    } else {
        local_exists(local)?
    };
    if exists && !config.overwrite {
        return Err("destination_exists");
    }
    // Never remove the old destination to simulate replacement: a failed transfer must preserve it.
    if uploading && config.overwrite && !posix {
        return Err("atomic_overwrite_unsupported");
    }
    let temporary = format!(".secretbridge-{}.part", Uuid::new_v4());
    let mut file = if uploading {
        let metadata = std::fs::symlink_metadata(local).map_err(|_| "local_open_failed")?;
        if !metadata.is_file() {
            return Err("not_regular_file");
        }
        if metadata.len() > config.max_bytes {
            return Err("size_limit");
        }
        let remote = format!(
            "{}/{}",
            config
                .remote_path
                .rsplit_once('/')
                .expect("absolute path")
                .0,
            temporary
        );
        partial.remote = Some(remote.clone());
        let handle = sftp
            .open(
                remote,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                FileAttributes {
                    permissions: Some(0o600),
                    ..FileAttributes::default()
                },
            )
            .await
            .map_err(|_| "remote_open_failed")?;
        partial.handle = Some(handle.handle);
        tokio::fs::File::open(local)
            .await
            .map_err(|_| "local_open_failed")?
    } else {
        if !remote_exists(sftp, &config.remote_path).await? {
            return Err("source_missing");
        }
        let handle = sftp
            .open(
                &config.remote_path,
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .map_err(|_| "remote_open_failed")?;
        partial.handle = Some(handle.handle);
        let attrs = sftp
            .fstat(partial.handle.as_ref().expect("opened"))
            .await
            .map_err(|_| "remote_stat_failed")?;
        if !attrs.attrs.file_type().is_file() {
            return Err("not_regular_file");
        }
        if attrs.attrs.size.is_some_and(|n| n > config.max_bytes) {
            return Err("size_limit");
        }
        let path = local.parent().expect("validated parent").join(temporary);
        // Track only after exclusive creation succeeds; never remove somebody else's existing file.
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path).await.map_err(|_| "local_open_failed")?;
        partial.local = Some(path);
        file
    };
    let handle = partial.handle.as_ref().expect("opened").clone();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 32768];
    loop {
        let count = if uploading {
            let count = file
                .read(&mut buffer)
                .await
                .map_err(|_| "local_read_failed")?;
            if count == 0 {
                break;
            }
            if bytes + u64::try_from(count).expect("bounded buffer") > config.max_bytes {
                return Err("size_limit");
            }
            sftp.write(&handle, bytes, buffer[..count].to_vec())
                .await
                .map_err(|_| "remote_write_failed")?;
            count
        } else {
            let data = match sftp.read(&handle, bytes, 32768).await {
                Ok(data) => data.data,
                Err(Error::Status(status)) if status.status_code == StatusCode::Eof => break,
                Err(_) => return Err("remote_read_failed"),
            };
            if data.is_empty() || data.len() > 32768 {
                return Err("invalid_remote_data");
            }
            if bytes + u64::try_from(data.len()).expect("bounded packet") > config.max_bytes {
                return Err("size_limit");
            }
            file.write_all(&data)
                .await
                .map_err(|_| "local_write_failed")?;
            data.len()
        };
        bytes += u64::try_from(count).expect("bounded buffer");
    }
    if !uploading {
        file.sync_all().await.map_err(|_| "local_write_failed")?;
    }
    drop(file);
    sftp.close(&handle)
        .await
        .map_err(|_| "remote_close_failed")?;
    partial.handle = None;
    if uploading {
        let from = partial.remote.as_ref().expect("temporary remote");
        if config.overwrite {
            let result = sftp
                .extended(POSIX_RENAME, rename_payload(from, &config.remote_path))
                .await
                .map_err(|_| "commit_failed")?;
            if !matches!(result, Packet::Status(s) if s.status_code == StatusCode::Ok) {
                return Err("commit_failed");
            }
        } else {
            sftp.rename(from, &config.remote_path)
                .await
                .map_err(|_| "commit_failed")?;
        }
        partial.remote = None;
    } else {
        let from = partial.local.as_ref().expect("temporary local");
        if config.overwrite {
            local_exists(local)?;
            std::fs::rename(from, local).map_err(|_| "commit_failed")?;
        } else {
            std::fs::hard_link(from, local).map_err(|_| "commit_failed")?;
            std::fs::remove_file(from).map_err(|_| "cleanup_failed")?;
        }
        partial.local = None;
    }
    Ok(bytes)
}

#[allow(
    clippy::too_many_arguments,
    reason = "uses the common credential execution context"
)]
pub async fn drive(
    state: &AppState,
    id: Uuid,
    ssh: &SshConfig,
    command: &CommandConfig,
    config: &TransferConfig,
    secrets: &[Zeroizing<String>],
    cancel: &CancellationToken,
    limit: Duration,
) {
    let deadline = tokio::time::Instant::now() + limit;
    let connected = tokio::select! {
        biased;
        () = cancel.cancelled() => Err("cancelled"),
        result = tokio::time::timeout_at(deadline, async {
            let (session, guard) = crate::ssh_task::connect(ssh, command, secrets).await?;
            let channel = session.channel_open_session().await.map_err(|_| "channel_failed")?;
            channel.request_subsystem(true, "sftp").await.map_err(|_| "subsystem_failed")?;
            let sftp = RawSftpSession::new(channel.into_stream());
            let version = sftp.init().await.map_err(|_| "subsystem_failed")?;
            let posix = version.extensions.get(POSIX_RENAME).is_some_and(|v| v == "1");
            Ok((sftp, session, guard, posix))
        }) => result.unwrap_or(Err("timed_out")),
    };
    let mut cleanup_ok = true;
    let result = match connected {
        Ok((sftp, _session, _guard, posix)) => {
            let mut partial = PartialFile::default();
            let result = tokio::select! {
                biased;
                () = cancel.cancelled() => Err("cancelled"),
                result = tokio::time::timeout_at(deadline, transfer(&sftp, config, &mut partial, posix)) => result.unwrap_or(Err("timed_out")),
            };
            // Keep the authenticated transport alive for bounded cleanup after dropping the operation.
            cleanup_ok = tokio::time::timeout(Duration::from_secs(2), async {
                let mut ok = true;
                if let Some(handle) = &partial.handle {
                    ok &= sftp.close(handle).await.is_ok();
                }
                if let Some(path) = &partial.remote {
                    ok &= match sftp.remove(path).await {
                        Ok(_) => true,
                        Err(Error::Status(s)) => s.status_code == StatusCode::NoSuchFile,
                        Err(_) => false,
                    };
                }
                if let Some(path) = &partial.local {
                    ok &= std::fs::remove_file(path).is_ok();
                    if ok {
                        partial.local = None;
                    }
                }
                ok
            })
            .await
            .unwrap_or(false);
            result
        }
        Err(error) => Err(error),
    };
    let (status, exit, summary) = match result {
        Ok(bytes) if cleanup_ok => (
            "command_ok",
            Some(0),
            serde_json::json!({"kind":"sftp", "direction":config.direction, "bytes_transferred":bytes, "cleanup_ok":true}),
        ),
        result => {
            let error = result.err().unwrap_or("cleanup_failed");
            let status = match error {
                "cancelled" => "cancelled",
                "timed_out" => "timed_out",
                _ => "command_failed",
            };
            (
                status,
                None,
                serde_json::json!({"kind":"sftp", "error_code":error, "cleanup_ok":cleanup_ok}),
            )
        }
    };
    let mut redactor = Redactor::new(secrets);
    let filtered = redactor.feed(summary.to_string().as_bytes(), true);
    let saved = state.catalog.append_output(
        id,
        if exit == Some(0) { "stdout" } else { "stderr" },
        &String::from_utf8_lossy(&filtered),
    );
    let _ = state.catalog.complete_command_run(
        id,
        if saved.is_ok() {
            status
        } else {
            "command_failed"
        },
        exit,
    );
    let _ = state.changes.send(());
}
