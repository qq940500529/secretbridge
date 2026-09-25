// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    application::redaction::{Redactor, Utf8Decoder},
    catalog::CatalogError,
    command::{CommandConfig, Injection},
    parameters::ParameterValues,
};
use russh::{
    ChannelMsg, client,
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, ssh_key::Fingerprint},
};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_sha256: String,
    pub authentication: Authentication,
    pub remote_program: String,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub arguments: Vec<Argument>,
    #[serde(default)]
    pub transfer: Option<crate::sftp_task::TransferConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authentication {
    Password {
        slot: String,
    },
    PrivateKey {
        slot: String,
        passphrase_slot: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Argument {
    Literal { value: String },
    Parameter { name: String },
}

impl SshConfig {
    pub fn validate(&self, config: &CommandConfig) -> Result<(), CatalogError> {
        let fingerprint = self
            .host_key_sha256
            .parse::<Fingerprint>()
            .map_err(|_| CatalogError::Invalid)?;
        if fingerprint.algorithm() != HashAlg::Sha256
            || self.host.is_empty()
            || self.host.len() > 253
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
            || self.port == 0
            || self.username.is_empty()
            || self.username.len() > 128
            || self
                .username
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || (self.transfer.is_none() && !self.remote_program.starts_with('/'))
            || self.remote_program.len() > 1024
            || self.remote_program.contains('\0')
            || self.working_directory.as_ref().is_some_and(|directory| {
                !directory.starts_with('/')
                    || directory.len() > 1024
                    || directory.chars().any(char::is_control)
            })
            || self.arguments.len() > 32
            || !config.program.is_empty()
            || !config.working_directory.is_empty()
            || !config.arguments.is_empty()
        {
            return Err(CatalogError::Invalid);
        }
        if let Some(transfer) = &self.transfer {
            if !self.remote_program.is_empty()
                || !self.arguments.is_empty()
                || !config.parameters.is_empty()
            {
                return Err(CatalogError::Invalid);
            }
            transfer.validate()?;
        }
        let slots: Vec<&str> = match &self.authentication {
            Authentication::Password { slot } => vec![slot],
            Authentication::PrivateKey {
                slot,
                passphrase_slot,
            } => {
                let mut names = vec![slot.as_str()];
                if let Some(passphrase) = passphrase_slot {
                    names.push(passphrase);
                }
                names
            }
        };
        if slots.len() != config.slots.len()
            || slots.len() == 2 && slots[0] == slots[1]
            || slots.iter().any(|name| {
                config
                    .slots
                    .iter()
                    .filter(|s| &s.name.as_str() == name)
                    .count()
                    != 1
            })
            || config.slots.iter().any(|s| {
                !crate::parameters::identifier(&s.name)
                    || s.injection != Injection::Protocol
                    || s.environment_variable.is_some()
                    || !slots.contains(&s.name.as_str())
            })
        {
            return Err(CatalogError::Invalid);
        }
        for argument in &self.arguments {
            match argument {
                Argument::Literal { value } if value.len() <= 8192 && !value.contains('\0') => {}
                Argument::Parameter { name }
                    if config.parameters.iter().any(|p| &p.name == name) => {}
                _ => return Err(CatalogError::Invalid),
            }
        }
        Ok(())
    }
    fn command(&self, parameters: &ParameterValues) -> Result<String, &'static str> {
        let mut pieces = vec![quote(&self.remote_program)];
        for argument in &self.arguments {
            let value = match argument {
                Argument::Literal { value } => value.clone(),
                Argument::Parameter { name } => {
                    crate::parameters::argument(parameters.get(name).ok_or("invalid_input")?)
                }
            };
            pieces.push(quote(&value));
        }
        let command = pieces.join(" ");
        Ok(match &self.working_directory {
            Some(directory) => format!("cd {} && exec {command}", quote(directory)),
            None => command,
        })
    }
}

// SSH exec sends one string, not argv. Each POSIX-shell word is quoted independently.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(crate) struct HostVerifier {
    expected: String,
    rejected: Arc<AtomicBool>,
}
impl client::Handler for HostVerifier {
    type Error = russh::Error;
    fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let trusted = key.certificate().is_none()
            && key.public_key().fingerprint(HashAlg::Sha256).to_string() == self.expected;
        self.rejected.store(!trusted, Ordering::SeqCst);
        std::future::ready(Ok(trusted))
    }
}

// Dropping a russh Handle alone does not abort its spawned transport task.
// A cancellation-aware stream wakes pending reads/writes and closes the socket.
struct Transport {
    stream: TcpStream,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}
impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
pub(crate) struct TransportGuard(CancellationToken);
impl Drop for TransportGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct Output {
    redactor: Redactor,
    decoder: Utf8Decoder,
}
impl Output {
    fn append(
        &mut self,
        state: &AppState,
        id: Uuid,
        stream: &str,
        bytes: &[u8],
        final_chunk: bool,
    ) -> Result<(), &'static str> {
        let filtered = self.redactor.feed(bytes, final_chunk);
        let text = self.decoder.feed(&filtered, final_chunk);
        state
            .catalog
            .append_output(id, stream, &text)
            .map_err(|_| "output_storage_failed")?;
        let _ = state.changes.send(());
        Ok(())
    }
}

fn secret<'a>(
    name: &str,
    config: &CommandConfig,
    secrets: &'a [Zeroizing<String>],
) -> Result<&'a str, &'static str> {
    config
        .slots
        .iter()
        .position(|s| s.name == name)
        .and_then(|i| secrets.get(i))
        .map(|s| s.as_str())
        .ok_or("invalid_input")
}

pub(crate) async fn connect(
    ssh: &SshConfig,
    config: &CommandConfig,
    secrets: &[Zeroizing<String>],
) -> Result<(client::Handle<HostVerifier>, TransportGuard), &'static str> {
    let transport_stop = CancellationToken::new();
    let guard = TransportGuard(transport_stop.clone());
    let stream = TcpStream::connect((ssh.host.as_str(), ssh.port))
        .await
        .map_err(|_| "connection_failed")?;
    let rejected = Arc::new(AtomicBool::new(false));
    let mut session = client::connect_stream(
        Arc::new(client::Config::default()),
        Transport {
            stream,
            cancelled: Box::pin(transport_stop.cancelled_owned()),
        },
        HostVerifier {
            expected: ssh.host_key_sha256.clone(),
            rejected: rejected.clone(),
        },
    )
    .await
    .map_err(|_| {
        if rejected.load(Ordering::SeqCst) {
            "host_key_rejected"
        } else {
            "connection_failed"
        }
    })?;
    let authentication = match &ssh.authentication {
        Authentication::Password { slot } => {
            session
                .authenticate_password(&ssh.username, secret(slot, config, secrets)?)
                .await
        }
        Authentication::PrivateKey {
            slot,
            passphrase_slot,
        } => {
            let encoded = Zeroizing::new(secret(slot, config, secrets)?.to_owned());
            let passphrase = passphrase_slot
                .as_ref()
                .map(|name| secret(name, config, secrets).map(|s| Zeroizing::new(s.to_owned())))
                .transpose()?;
            let key = tokio::task::spawn_blocking(move || {
                russh::keys::decode_secret_key(&encoded, passphrase.as_ref().map(|s| s.as_str()))
            })
            .await
            .map_err(|_| "invalid_private_key")?
            .map_err(|_| "invalid_private_key")?;
            session
                .authenticate_publickey(
                    &ssh.username,
                    PrivateKeyWithHashAlg::new(Arc::new(key), None),
                )
                .await
        }
    }
    .map_err(|_| "authentication_failed")?;
    if !authentication.success() {
        return Err("authentication_failed");
    }
    Ok((session, guard))
}

#[allow(
    clippy::too_many_arguments,
    reason = "uses the existing credential execution context"
)]
async fn execute(
    state: &AppState,
    id: Uuid,
    ssh: &SshConfig,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
    stdout: &mut Output,
    stderr: &mut Output,
) -> Result<i32, &'static str> {
    let (session, _guard) = connect(ssh, config, secrets).await?;
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|_| "channel_failed")?;
    channel
        .exec(true, ssh.command(parameters)?)
        .await
        .map_err(|_| "command_rejected")?;
    channel.eof().await.map_err(|_| "channel_failed")?;
    let mut exit = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.append(state, id, "stdout", &data, false)?,
            ChannelMsg::ExtendedData { ext: 1, data } => {
                stderr.append(state, id, "stderr", &data, false)?;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                exit = Some(i32::try_from(exit_status).map_err(|_| "invalid_exit_status")?);
            }
            ChannelMsg::ExitSignal { .. } => return Err("remote_signal"),
            ChannelMsg::Failure => return Err("command_rejected"),
            _ => {}
        }
    }
    // The guard closes the transport even if a disconnect reply never arrives.
    exit.ok_or("exit_status_missing")
}

#[allow(
    clippy::too_many_arguments,
    reason = "shares the existing credential execution context"
)]
pub async fn drive(
    state: &AppState,
    id: Uuid,
    ssh: &SshConfig,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
    cancellation: &CancellationToken,
    limit: Duration,
) {
    if let Some(transfer) = &ssh.transfer {
        crate::sftp_task::drive(
            state,
            id,
            ssh,
            config,
            transfer,
            secrets,
            cancellation,
            limit,
        )
        .await;
        return;
    }
    let mut stdout = Output {
        redactor: Redactor::new(secrets),
        decoder: Utf8Decoder::default(),
    };
    let mut stderr = Output {
        redactor: Redactor::new(secrets),
        decoder: Utf8Decoder::default(),
    };
    let (status, exit, error) = tokio::select! {
        biased;
        () = cancellation.cancelled() => ("cancelled", None, Some("cancelled")),
        result = tokio::time::timeout(limit, execute(state, id, ssh, config, parameters, secrets, &mut stdout, &mut stderr)) => match result {
            Ok(Ok(code)) => (if code == 0 { "command_ok" } else { "command_failed" }, Some(code), None),
            Ok(Err(code)) => ("command_failed", None, Some(code)),
            Err(_) => ("timed_out", None, Some("timed_out")),
        }
    };
    let stdout_final = stdout.append(state, id, "stdout", &[], true);
    let stderr_final = stderr.append(state, id, "stderr", &[], true);
    let status = if stdout_final.is_err() || stderr_final.is_err() {
        "command_failed"
    } else {
        status
    };
    if let Some(code) = error {
        let text = serde_json::json!({"kind":"ssh", "error_code":code}).to_string();
        let mut redactor = Redactor::new(secrets);
        let filtered = redactor.feed(text.as_bytes(), true);
        let _ = state
            .catalog
            .append_output(id, "stderr", &String::from_utf8_lossy(&filtered));
    }
    let _ = state.catalog.complete_command_run(id, status, exit);
    let _ = state.changes.send(());
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
pub(crate) mod tests;
