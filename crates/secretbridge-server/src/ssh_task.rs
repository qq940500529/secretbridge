// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    catalog::CatalogError,
    command::{CommandConfig, Injection},
    parameters::ParameterValues,
    redaction::{Redactor, Utf8Decoder},
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
    pub arguments: Vec<Argument>,
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
            || !self.remote_program.starts_with('/')
            || self.remote_program.len() > 1024
            || self.remote_program.contains('\0')
            || self.arguments.len() > 32
            || !config.program.is_empty()
            || !config.working_directory.is_empty()
            || !config.arguments.is_empty()
        {
            return Err(CatalogError::Invalid);
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
                !crate::command::identifier(&s.name)
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
        Ok(pieces.join(" "))
    }
}

// SSH exec sends one string, not argv. Each POSIX-shell word is quoted independently.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct HostVerifier {
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
struct TransportGuard(CancellationToken);
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
    let transport_stop = CancellationToken::new();
    let _guard = TransportGuard(transport_stop.clone());
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
pub(crate) mod tests {
    use super::*;
    use crate::catalog::{CreateSyntheticRun, DecideApproval, RunState};
    use russh::{
        Channel, ChannelId,
        keys::{Algorithm, PrivateKey, PublicKey},
        server,
    };
    use serde_json::{Value, json};
    use std::sync::{Mutex, atomic::AtomicUsize};

    pub(crate) const SECRET: &str = "Synthetic-ssh-password_A&z";
    const PASSPHRASE: &str = "Synthetic-key-passphrase_A&z";
    pub(crate) struct Fixture {
        pub port: u16,
        pub fingerprint: String,
        key: PrivateKey,
        pub auth_hits: Arc<AtomicUsize>,
        pub commands: Arc<Mutex<Vec<String>>>,
        disconnected: Arc<AtomicUsize>,
        listener: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.listener.abort();
        }
    }
    struct Server {
        key: Arc<PublicKey>,
        auth_hits: Arc<AtomicUsize>,
        commands: Arc<Mutex<Vec<String>>>,
        disconnected: Arc<AtomicUsize>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.disconnected.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl server::Handler for Server {
        type Error = russh::Error;
        fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> impl Future<Output = Result<server::Auth, Self::Error>> + Send {
            self.auth_hits.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(if user == "operator" && password == SECRET {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            }))
        }
        fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> impl Future<Output = Result<server::Auth, Self::Error>> + Send {
            self.auth_hits.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(if user == "operator" && key == self.key.as_ref() {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            }))
        }
        async fn channel_open_session(
            &mut self,
            _channel: Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "protocol fixture queues synchronous channel events in the asynchronous handler contract"
        )]
        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            let command = String::from_utf8(data.to_vec()).unwrap();
            self.commands.lock().unwrap().push(command.clone());
            if command.contains("/reject'") {
                session.channel_failure(channel)?;
                session.close(channel)?;
                return Ok(());
            }
            session.channel_success(channel)?;
            if command.contains("/wait'") {
                session.data(channel, b"running\n".to_vec())?;
                return Ok(());
            }
            let midpoint = SECRET.len() / 2;
            session.data(channel, SECRET.as_bytes()[..midpoint].to_vec())?;
            session.data(channel, SECRET.as_bytes()[midpoint..].to_vec())?;
            // Exercise UTF-8 split across SSH packets independently of secret fragments.
            let chinese = "中文完成\n".as_bytes();
            session.data(channel, chinese[..1].to_vec())?;
            session.data(channel, chinese[1..].to_vec())?;
            session.extended_data(channel, 1, format!("{SECRET}\n{PASSPHRASE}\n").into_bytes())?;
            if !command.contains("/missing-exit'") {
                session.exit_status_request(
                    channel,
                    if command.contains("/fail'") { 17 } else { 0 },
                )?;
            }
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }
    pub(crate) async fn server() -> Fixture {
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let public_key = Arc::new(key.public_key().clone());
        let auth_hits = Arc::new(AtomicUsize::new(0));
        let commands = Arc::new(Mutex::new(Vec::new()));
        let disconnected = Arc::new(AtomicUsize::new(0));
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let config = Arc::new(server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..server::Config::default()
        });
        let hits = auth_hits.clone();
        let executed = commands.clone();
        let closed = disconnected.clone();
        let listener = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = socket.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let handler = Server { key: public_key.clone(), auth_hits: hits.clone(), commands: executed.clone(), disconnected: closed.clone() };
                        let config = config.clone();
                        sessions.spawn(async move {
                            if let Ok(session) = server::run_stream(config, stream, handler).await { let _ = session.await; }
                        });
                    }
                    _ = sessions.join_next(), if !sessions.is_empty() => {},
                }
            }
        });
        Fixture {
            port,
            fingerprint,
            key,
            auth_hits,
            commands,
            disconnected,
            listener,
        }
    }
    fn config(fixture: &Fixture, credential: Uuid) -> CommandConfig {
        serde_json::from_value(json!({"program":"","working_directory":"","arguments":[],
            "slots":[{"name":"password","credential_id":credential,"injection":"protocol","environment_variable":null}],
            "parameters":[{"name":"message","label":"消息","kind":"string","required":true,"default":"a'; $(printf BAD); {{password}}"}],
            "ssh":{"host":"127.0.0.1","port":fixture.port,"username":"operator","host_key_sha256":fixture.fingerprint,"authentication":{"kind":"password","slot":"password"},"remote_program":"/usr/bin/printf","arguments":[{"kind":"literal","value":"%s"},{"kind":"parameter","name":"message"}]}})).unwrap()
    }
    pub(crate) fn configure(state: &AppState, fixture: &Fixture, timeout: u64) -> Uuid {
        let credential = state
            .catalog
            .create_credential_reference(
                &serde_json::from_value(json!({"name":"SSH fixture","kind":"password"})).unwrap(),
            )
            .unwrap();
        state.secret_store.set(credential.id, SECRET).unwrap();
        state
            .catalog
            .set_credential_secret_state(credential.id, credential.version, true)
            .unwrap();
        let target = state
            .catalog
            .create_target(
                &serde_json::from_value(
                    json!({"name":"SSH fixture","kind":"ssh_host","environment":"test"}),
                )
                .unwrap(),
            )
            .unwrap();
        state.catalog.create_action_template(&serde_json::from_value(json!({"name":"SSH fixture","target_id":target.id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"command":config(fixture, credential.id)})).unwrap()).unwrap().id
    }
    fn update(state: &AppState, change: impl FnOnce(&mut CommandConfig)) {
        let template = state.catalog.list_action_templates().unwrap().remove(0);
        let mut config = template.command.unwrap();
        change(&mut config);
        state.catalog.update_action_template(template.id, &serde_json::from_value(json!({"name":template.name,"target_id":template.target_id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":template.timeout_seconds,"expected_version":template.version,"enabled":true,"command":config})).unwrap()).unwrap();
    }
    fn approve(state: &AppState, template: Uuid) -> Uuid {
        let approval = state.catalog.create_approval(&serde_json::from_value(json!({"action_template_id":template,"expires_in_seconds":60,"authorization_mode":"time_window"})).unwrap()).unwrap();
        state
            .catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: None,
                },
            )
            .unwrap();
        approval.id
    }
    pub(crate) async fn wait(state: &AppState, id: Uuid) -> crate::command::OutputPage {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let page = state.catalog.output(id, 0).unwrap();
                if !matches!(page.state, RunState::Queued | RunState::Running) {
                    return page;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    fn text(page: &crate::command::OutputPage) -> String {
        page.items.iter().map(|c| c.text.as_str()).collect()
    }
    #[tokio::test]
    async fn real_ssh_password_uses_frozen_quoted_arguments_filters_streams_and_replays() {
        let fixture = server().await;
        let (state, _) = AppState::new([]);
        let template = configure(&state, &fixture, 10);
        let approval = approve(&state, template);
        let key = Uuid::new_v4().to_string();
        let request = || CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: key.clone(),
        };
        let run = crate::create_run_for_state(&state, request())
            .await
            .unwrap();
        let page = wait(&state, run.run.id).await;
        assert_eq!(page.state, RunState::Succeeded);
        assert_eq!(page.exit_code, Some(0));
        let output = text(&page);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains(SECRET));
        assert!(output.contains("中文完成"));
        assert!(page.items.iter().any(|c| c.stream == "stderr"));
        let command = fixture.commands.lock().unwrap()[0].clone();
        assert_eq!(
            command,
            "'/usr/bin/printf' '%s' 'a'\\''; $(printf BAD); {{password}}'"
        );
        assert!(
            crate::create_run_for_state(&state, request())
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(fixture.auth_hits.load(Ordering::SeqCst), 1);
        let second = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(wait(&state, second.run.id).await.state, RunState::Succeeded);
        assert_eq!(fixture.commands.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn untrusted_host_is_rejected_before_password_authentication() {
        let fixture = server().await;
        let (state, _) = AppState::new([]);
        let template = configure(&state, &fixture, 10);
        let wrong = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        update(&state, |c| c.ssh.as_mut().unwrap().host_key_sha256 = wrong);
        let run = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approve(&state, template),
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .unwrap();
        let page = wait(&state, run.run.id).await;
        assert_eq!(page.state, RunState::Failed);
        assert!(text(&page).contains("host_key_rejected"));
        assert_eq!(fixture.auth_hits.load(Ordering::SeqCst), 0);
        assert!(fixture.commands.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn real_ssh_authenticates_unencrypted_and_encrypted_private_keys_without_files() {
        use crate::command::tests::{web_request, web_request_method};
        use axum::http::StatusCode;
        let fixture = server().await;
        for encrypted in [false, true] {
            let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
            let template = configure(&state, &fixture, 15);
            let (token, _) = state.issue_session().await;
            let (status, credential) = web_request(
                &state,
                &token,
                "/api/v1/credential-references",
                json!({"name":"SSH key via Web","kind":"ssh_key"}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let credential_id = Uuid::parse_str(credential["id"].as_str().unwrap()).unwrap();
            let private_key = if encrypted {
                fixture.key.encrypt(&mut rand::rng(), PASSPHRASE).unwrap()
            } else {
                fixture.key.clone()
            };
            let encoded = private_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap();
            let (status, saved) = web_request_method(
                &state,
                &token,
                "PUT",
                &format!("/api/v1/credential-references/{credential_id}/secret"),
                json!({"secret":encoded.as_str(),"expected_version":credential["version"]}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(saved["secret_state"], "available");
            assert!(!saved.to_string().contains(encoded.as_str()));
            assert!(saved.get("secret").is_none());
            let passphrase = if encrypted {
                let c = state
                    .catalog
                    .create_credential_reference(
                        &serde_json::from_value(json!({"name":"SSH passphrase","kind":"password"}))
                            .unwrap(),
                    )
                    .unwrap();
                state.secret_store.set(c.id, PASSPHRASE).unwrap();
                state
                    .catalog
                    .set_credential_secret_state(c.id, c.version, true)
                    .unwrap();
                Some(c.id)
            } else {
                None
            };
            update(&state, |c| {
                c.slots[0].credential_id = credential_id;
                c.ssh.as_mut().unwrap().authentication = Authentication::PrivateKey {
                    slot: "password".into(),
                    passphrase_slot: passphrase.map(|_| "passphrase".into()),
                };
                if let Some(id) = passphrase {
                    c.slots.push(crate::command::CredentialSlot {
                        name: "passphrase".into(),
                        credential_id: id,
                        injection: Injection::Protocol,
                        environment_variable: None,
                    });
                }
            });
            let run = crate::create_run_for_state(
                &state,
                CreateSyntheticRun {
                    approval_id: approve(&state, template),
                    idempotency_key: Uuid::new_v4().to_string(),
                },
            )
            .await
            .unwrap();
            let page = wait(&state, run.run.id).await;
            assert_eq!(page.state, RunState::Succeeded);
            assert_eq!(page.exit_code, Some(0));
            assert!(!text(&page).contains(encoded.as_str()));
            if encrypted {
                assert!(!text(&page).contains(PASSPHRASE));
            }
            assert!(
                !serde_json::to_string(&state.catalog.list_action_templates().unwrap())
                    .unwrap()
                    .contains(encoded.as_str())
            );
        }
    }
    #[tokio::test]
    async fn remote_failures_have_fixed_codes_and_real_exit_status() {
        let fixture = server().await;
        for (program, expected, exit) in [
            ("/fail", "", Some(17)),
            ("/reject", "command_rejected", None),
            ("/missing-exit", "exit_status_missing", None),
            ("/usr/bin/printf", "authentication_failed", None),
        ] {
            let (state, _) = AppState::new([]);
            let template = configure(&state, &fixture, 10);
            update(&state, |c| {
                c.ssh.as_mut().unwrap().remote_program = program.into();
            });
            if expected == "authentication_failed" {
                let c = state
                    .catalog
                    .list_credential_references()
                    .unwrap()
                    .remove(0);
                state
                    .secret_store
                    .set(c.id, "wrong-synthetic-password")
                    .unwrap();
            }
            let run = crate::create_run_for_state(
                &state,
                CreateSyntheticRun {
                    approval_id: approve(&state, template),
                    idempotency_key: Uuid::new_v4().to_string(),
                },
            )
            .await
            .unwrap();
            let page = wait(&state, run.run.id).await;
            assert_eq!(page.state, RunState::Failed);
            assert_eq!(page.exit_code, exit);
            assert!(text(&page).contains(expected));
        }
    }
    #[tokio::test]
    async fn timeout_and_cancel_close_the_actual_ssh_transport() {
        let fixture = server().await;
        for cancel in [false, true] {
            let before = fixture.disconnected.load(Ordering::SeqCst);
            let (state, _) = AppState::new([]);
            let template = configure(&state, &fixture, 3);
            update(&state, |c| {
                c.ssh.as_mut().unwrap().remote_program = "/wait".into();
            });
            let run = state
                .catalog
                .create_synthetic_run(&CreateSyntheticRun {
                    approval_id: approve(&state, template),
                    idempotency_key: Uuid::new_v4().to_string(),
                })
                .unwrap();
            state.catalog.start_run(run.run.id).unwrap();
            let cancellation = CancellationToken::new();
            let future = crate::command::drive(&state, run.run.id, &cancellation);
            tokio::pin!(future);
            if cancel {
                tokio::select! { () = &mut future => panic!("must be in flight"), () = async { loop { if !state.catalog.output(run.run.id, 0).unwrap().items.is_empty() { break; } tokio::time::sleep(Duration::from_millis(10)).await; } } => cancellation.cancel() }
            }
            future.await;
            let page = state.catalog.output(run.run.id, 0).unwrap();
            assert_eq!(
                page.state,
                if cancel {
                    RunState::Cancelled
                } else {
                    RunState::Failed
                }
            );
            assert!(text(&page).contains(if cancel { "cancelled" } else { "timed_out" }));
            tokio::time::timeout(Duration::from_secs(5), async {
                while fixture.disconnected.load(Ordering::SeqCst) <= before {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }
    #[tokio::test]
    async fn web_creates_config_approves_executes_and_reads_filtered_ssh_output() {
        use crate::command::tests::web_request;
        use axum::http::StatusCode;
        let fixture = server().await;
        let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
        configure(&state, &fixture, 10);
        let template = state.catalog.list_action_templates().unwrap().remove(0);
        let (token, _) = state.issue_session().await;
        let (status, created) = web_request(&state, &token, "/api/v1/action-templates", json!({"name":"SSH via Web","target_id":template.target_id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":10,"command":template.command})).await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, approval) = web_request(
            &state,
            &token,
            "/api/v1/approvals",
            json!({"action_template_id":created["id"],"expires_in_seconds":60}),
        )
        .await;
        let (status, _) = web_request(
            &state,
            &token,
            &format!(
                "/api/v1/approvals/{}/approve",
                approval["id"].as_str().unwrap()
            ),
            json!({"expected_version":approval["version"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, run) = web_request(
            &state,
            &token,
            "/api/v1/runs",
            json!({"approval_id":approval["id"],"idempotency_key":Uuid::new_v4().to_string()}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = Uuid::parse_str(run["run"]["id"].as_str().unwrap()).unwrap();
        assert_eq!(wait(&state, id).await.state, RunState::Succeeded);
        let (status, page) = web_request(
            &state,
            &token,
            &format!("/api/v1/runs/{id}/output"),
            json!({"cursor":0,"wait_ms":0}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["exit_code"], 0);
        assert!(page.to_string().contains("[REDACTED]"));
        assert!(!page.to_string().contains(SECRET));
    }
    #[tokio::test]
    async fn ssh_config_and_frozen_parameters_survive_database_reopen() {
        let fixture = server().await;
        let path = std::env::temp_dir().join(format!("sb-ssh-{}.sqlite3", Uuid::new_v4()));
        let (mut state, _) = AppState::new([]);
        state.catalog = crate::catalog::Catalog::open(&path).unwrap();
        let template = configure(&state, &fixture, 10);
        let approval = approve(&state, template);
        drop(state);
        let catalog = crate::catalog::Catalog::open(&path).unwrap();
        let command = catalog
            .list_action_templates()
            .unwrap()
            .remove(0)
            .command
            .unwrap();
        assert!(command.validate().is_ok());
        assert_eq!(command.ssh.unwrap().host_key_sha256, fixture.fingerprint);
        assert_eq!(
            catalog.get_approval(approval).unwrap().parameters["message"],
            "a'; $(printf BAD); {{password}}"
        );
        assert!(
            !std::fs::read(&path)
                .unwrap()
                .windows(SECRET.len())
                .any(|b| b == SECRET.as_bytes())
        );
        drop(catalog);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn rejects_conflicting_modes_invalid_slots_fingerprints_and_parameters() {
        let fixture = server().await;
        let original = config(&fixture, Uuid::new_v4());
        assert!(original.validate().is_ok());
        let mut c = original.clone();
        c.http = Some(
            crate::http_task::tests::config("https://example.com", Uuid::new_v4())
                .http
                .unwrap(),
        );
        assert!(c.validate().is_err());
        for field in ["host", "host_key_sha256", "username", "remote_program"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value["ssh"][field] = Value::String(String::new());
            assert!(
                serde_json::from_value::<CommandConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut c = original.clone();
        c.slots[0].injection = Injection::Argument;
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.ssh.as_mut().unwrap().arguments.push(Argument::Parameter {
            name: "missing".into(),
        });
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.slots.push(c.slots[0].clone());
        c.ssh.as_mut().unwrap().authentication = Authentication::PrivateKey {
            slot: "password".into(),
            passphrase_slot: Some("passphrase".into()),
        };
        assert!(c.validate().is_err());
        let mut value = serde_json::to_value(&original).unwrap();
        value["ssh"]["unknown"] = json!(true);
        assert!(serde_json::from_value::<CommandConfig>(value).is_err());
    }
    #[test]
    fn posix_quoting_preserves_values_without_recursive_expansion() {
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a'b"), "'a'\\''b'");
        #[cfg(unix)]
        {
            let value = "a'; $(printf BAD); {{password}}\n中文";
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &format!("printf %s {}", quote(value))])
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(String::from_utf8(output.stdout).unwrap(), value);
        }
    }
}
