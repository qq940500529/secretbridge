// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deliberately constrained Telnet support for legacy devices.
//!
//! Telnet provides no transport confidentiality or server authentication. A
//! target must therefore opt in separately, and the connector accepts only a
//! fixed host, login dialogue and bounded line script frozen into approval.

use crate::{
    AppState,
    application::redaction::{Redactor, Utf8Decoder},
    catalog::CatalogError,
    command::{CommandConfig, Injection},
    parameters::ParameterValues,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const MAX_COMMANDS: usize = 32;
const MAX_LINE_BYTES: usize = 2_048;
const MAX_PROMPT_BYTES: usize = 128;
const MAX_OUTPUT_BYTES: u32 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelnetConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password_slot: String,
    pub login_prompt: String,
    pub password_prompt: String,
    pub command_prompt: String,
    #[serde(default)]
    pub authentication_failure_prompt: Option<String>,
    pub commands: Vec<String>,
    #[serde(default = "default_logout")]
    pub logout_command: String,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: u32,
}

fn default_logout() -> String {
    "exit".into()
}

const fn default_output_limit() -> u32 {
    64 * 1024
}

impl TelnetConfig {
    pub fn validate(&self, config: &CommandConfig) -> Result<(), CatalogError> {
        if self.host.is_empty()
            || self.host.len() > 253
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
            || self.port == 0
            || self.username.is_empty()
            || self.username.len() > 128
            || invalid_line(&self.username, 128)
            || !crate::parameters::identifier(&self.password_slot)
            || invalid_prompt(&self.login_prompt)
            || invalid_prompt(&self.password_prompt)
            || invalid_prompt(&self.command_prompt)
            || self
                .authentication_failure_prompt
                .as_ref()
                .is_some_and(|value| invalid_prompt(value))
            || self.commands.is_empty()
            || self.commands.len() > MAX_COMMANDS
            || self
                .commands
                .iter()
                .any(|line| invalid_line(line, MAX_LINE_BYTES))
            || invalid_line(&self.logout_command, 128)
            || !(1_024..=MAX_OUTPUT_BYTES).contains(&self.max_output_bytes)
            || !config.program.is_empty()
            || !config.working_directory.is_empty()
            || !config.arguments.is_empty()
            || !config.parameters.is_empty()
            || config.slots.len() != 1
        {
            return Err(CatalogError::Invalid);
        }
        let slot = &config.slots[0];
        if slot.name != self.password_slot
            || slot.injection != Injection::Protocol
            || slot.environment_variable.is_some()
        {
            return Err(CatalogError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn matches_target(
        &self,
        config: &CommandConfig,
        target: &crate::catalog::Target,
    ) -> bool {
        let credential = config
            .slots
            .iter()
            .find(|slot| slot.name == self.password_slot)
            .map(|slot| slot.credential_id);
        target.kind == crate::catalog::TargetKind::TelnetHost
            && target.allow_insecure_protocol
            && target
                .address
                .as_deref()
                .is_some_and(|address| address.eq_ignore_ascii_case(&self.host))
            && target.username.as_deref() == Some(self.username.as_str())
            && target.credential_reference_id == credential
    }
}

fn invalid_prompt(value: &str) -> bool {
    value.is_empty()
        || value.len() > MAX_PROMPT_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
}

fn invalid_line(value: &str, maximum: usize) -> bool {
    value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\r' | '\n'))
}

fn password<'a>(
    telnet: &TelnetConfig,
    config: &CommandConfig,
    secrets: &'a [Zeroizing<String>],
) -> Result<&'a str, &'static str> {
    config
        .slots
        .iter()
        .position(|slot| slot.name == telnet.password_slot)
        .and_then(|index| secrets.get(index))
        .map(AsRef::as_ref)
        .ok_or("invalid_input")
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
        bytes: &[u8],
        final_chunk: bool,
    ) -> Result<(), &'static str> {
        let filtered = self.redactor.feed(bytes, final_chunk);
        let text = self.decoder.feed(&filtered, final_chunk);
        state
            .catalog
            .append_output(id, "stdout", &text)
            .map_err(|_| "output_storage_failed")?;
        let _ = state.changes.send(());
        Ok(())
    }
}

#[derive(Default)]
enum ParseState {
    #[default]
    Data,
    Iac,
    Negotiation(u8),
    Subnegotiation,
    SubnegotiationIac,
}

#[derive(Default)]
struct TelnetParser {
    state: ParseState,
}

impl TelnetParser {
    fn decode(&mut self, bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut application = Vec::with_capacity(bytes.len());
        let mut replies = Vec::new();
        for &byte in bytes {
            match self.state {
                ParseState::Data if byte == IAC => self.state = ParseState::Iac,
                ParseState::Data => application.push(byte),
                ParseState::Iac if byte == IAC => {
                    application.push(IAC);
                    self.state = ParseState::Data;
                }
                ParseState::Iac if matches!(byte, DO | DONT | WILL | WONT) => {
                    self.state = ParseState::Negotiation(byte);
                }
                ParseState::Iac if byte == SB => self.state = ParseState::Subnegotiation,
                ParseState::Iac => self.state = ParseState::Data,
                ParseState::Negotiation(command) => {
                    replies.extend_from_slice(&[
                        IAC,
                        if matches!(command, DO | DONT) {
                            WONT
                        } else {
                            DONT
                        },
                        byte,
                    ]);
                    self.state = ParseState::Data;
                }
                ParseState::Subnegotiation if byte == IAC => {
                    self.state = ParseState::SubnegotiationIac;
                }
                ParseState::SubnegotiationIac if byte == SE => self.state = ParseState::Data,
                ParseState::SubnegotiationIac if byte != IAC => {
                    self.state = ParseState::Subnegotiation;
                }
                ParseState::Subnegotiation | ParseState::SubnegotiationIac => {}
            }
        }
        (application, replies)
    }
}

struct Session<'a> {
    stream: TcpStream,
    parser: TelnetParser,
    state: &'a AppState,
    run_id: Uuid,
    output: Output,
    output_bytes: usize,
    output_limit: usize,
}

impl Session<'_> {
    async fn send_line(&mut self, line: &str) -> Result<(), &'static str> {
        self.stream
            .write_all(line.as_bytes())
            .await
            .map_err(|_| "connection_closed")?;
        self.stream
            .write_all(b"\r\n")
            .await
            .map_err(|_| "connection_closed")
    }

    async fn read_until(
        &mut self,
        prompt: &str,
        failure_prompt: Option<&str>,
        closed_code: &'static str,
    ) -> Result<(), &'static str> {
        let prompt = prompt.as_bytes();
        let failure = failure_prompt.map(str::as_bytes);
        let keep = prompt
            .len()
            .max(failure.map_or(0, <[u8]>::len))
            .saturating_sub(1);
        let mut window = Vec::new();
        let mut bytes = [0_u8; 4096];
        loop {
            let count = self
                .stream
                .read(&mut bytes)
                .await
                .map_err(|_| "connection_failed")?;
            if count == 0 {
                return Err(closed_code);
            }
            let (application, reply) = self.parser.decode(&bytes[..count]);
            if !reply.is_empty() {
                self.stream
                    .write_all(&reply)
                    .await
                    .map_err(|_| "connection_failed")?;
            }
            self.output_bytes = self
                .output_bytes
                .checked_add(application.len())
                .ok_or("output_limit_exceeded")?;
            if self.output_bytes > self.output_limit {
                return Err("output_limit_exceeded");
            }
            self.output
                .append(self.state, self.run_id, &application, false)?;
            window.extend_from_slice(&application);
            if failure.is_some_and(|needle| contains(&window, needle)) {
                return Err("authentication_failed");
            }
            if contains(&window, prompt) {
                return Ok(());
            }
            if window.len() > keep {
                window.drain(..window.len() - keep);
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

async fn execute(
    state: &AppState,
    id: Uuid,
    telnet: &TelnetConfig,
    config: &CommandConfig,
    secrets: &[Zeroizing<String>],
    output: &mut Option<Output>,
) -> Result<i32, &'static str> {
    let stream = TcpStream::connect((telnet.host.as_str(), telnet.port))
        .await
        .map_err(|_| "connection_failed")?;
    let mut session = Session {
        stream,
        parser: TelnetParser::default(),
        state,
        run_id: id,
        output: output.take().ok_or("output_storage_failed")?,
        output_bytes: 0,
        output_limit: telnet.max_output_bytes as usize,
    };
    let result = async {
        session
            .read_until(&telnet.login_prompt, None, "connection_closed")
            .await?;
        session.send_line(&telnet.username).await?;
        session
            .read_until(&telnet.password_prompt, None, "authentication_failed")
            .await?;
        let password = password(telnet, config, secrets)?;
        if invalid_line(password, 8 * 1024) {
            return Err("invalid_input");
        }
        session.send_line(password).await?;
        session
            .read_until(
                &telnet.command_prompt,
                telnet.authentication_failure_prompt.as_deref(),
                "authentication_failed",
            )
            .await?;
        for command in &telnet.commands {
            session.send_line(command).await?;
            session
                .read_until(&telnet.command_prompt, None, "connection_closed")
                .await?;
        }
        session.send_line(&telnet.logout_command).await?;
        let _ = session.stream.shutdown().await;
        Ok(0)
    }
    .await;
    *output = Some(session.output);
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "shares the existing controlled execution context"
)]
pub async fn drive(
    state: &AppState,
    id: Uuid,
    telnet: &TelnetConfig,
    config: &CommandConfig,
    _parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
    cancellation: &CancellationToken,
    limit: Duration,
) {
    let mut output = Some(Output {
        redactor: Redactor::new(secrets),
        decoder: Utf8Decoder::default(),
    });
    let (status, exit, error) = tokio::select! {
        biased;
        () = cancellation.cancelled() => ("cancelled", None, Some("cancelled")),
        result = tokio::time::timeout(limit, execute(state, id, telnet, config, secrets, &mut output)) => match result {
            Ok(Ok(code)) => ("command_ok", Some(code), None),
            Ok(Err(code)) => ("command_failed", None, Some(code)),
            Err(_) => ("timed_out", None, Some("timed_out")),
        }
    };
    let output = output.get_or_insert_with(|| Output {
        redactor: Redactor::new(secrets),
        decoder: Utf8Decoder::default(),
    });
    let final_result = output.append(state, id, &[], true);
    let status = if final_result.is_err() {
        "command_failed"
    } else {
        status
    };
    if let Some(code) = error {
        let text = serde_json::json!({"kind":"telnet", "error_code":code}).to_string();
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
#[path = "telnet_tests.rs"]
mod tests;
