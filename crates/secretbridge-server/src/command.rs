// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    catalog::{Catalog, CatalogError, RunState},
    redaction::{Redactor, Utf8Decoder},
    secret_store::{SECRET_READ_TIMEOUT, SecretReadError},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt::Write as _,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandConfig {
    #[serde(default)]
    pub terminal_id: Option<Uuid>,
    #[serde(default)]
    pub database: Option<crate::database_task::DatabaseConfig>,
    #[serde(default)]
    pub http: Option<crate::http_task::HttpConfig>,
    #[serde(default)]
    pub ssh: Option<crate::ssh_task::SshConfig>,
    #[serde(default)]
    pub telnet: Option<crate::telnet_task::TelnetConfig>,
    #[serde(default)]
    pub git: Option<crate::git_task::GitConfig>,
    #[serde(default)]
    pub parameters: Vec<crate::parameters::ParameterDefinition>,
    pub program: String,
    pub working_directory: String,
    pub arguments: Vec<String>,
    #[serde(default)]
    pub stdin_content: Option<String>,
    pub slots: Vec<CredentialSlot>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSlot {
    pub name: String,
    pub credential_id: Uuid,
    pub injection: Injection,
    pub environment_variable: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Injection {
    Stdin,
    Environment,
    Argument,
    File,
    Protocol,
}

pub const MAX_ARGUMENT_BYTES: usize = 8192;
pub const MAX_ARGUMENTS_BYTES: usize = 12_000;
pub const MAX_STDIN_CONTENT_BYTES: usize = 32 * 1024;
const MAX_RUN_OUTPUT_CHUNKS: i64 = 2048;

fn credential_placeholder(name: &str) -> String {
    format!("{{{{secret:{name}}}}}")
}

fn is_credential_placeholder(argument: &str, name: &str) -> bool {
    argument == credential_placeholder(name)
}

impl CommandConfig {
    #[allow(
        clippy::too_many_lines,
        reason = "all command and placeholder safety checks remain together"
    )]
    pub fn validate(&self) -> Result<(), CatalogError> {
        crate::parameters::validate(&self.parameters)?;
        if self.stdin_content.as_ref().is_some_and(|content| {
            content.len() > MAX_STDIN_CONTENT_BYTES
                || content.contains('\0')
                || content.contains("{{secret:")
        }) || (self.stdin_content.is_some()
            && (self.database.is_some()
                || self.http.is_some()
                || self.ssh.is_some()
                || self.telnet.is_some()
                || self.git.is_some()))
        {
            return Err(CatalogError::Invalid);
        }
        if usize::from(self.http.is_some())
            + usize::from(self.ssh.is_some())
            + usize::from(self.telnet.is_some())
            + usize::from(self.git.is_some())
            + usize::from(self.database.is_some())
            > 1
        {
            return Err(CatalogError::Invalid);
        }
        if self.terminal_id.is_some()
            && (self.http.is_some()
                || self.ssh.is_some()
                || self.telnet.is_some()
                || self.git.is_some()
                || self.database.is_some())
        {
            return Err(CatalogError::Invalid);
        }
        if let Some(database) = &self.database {
            return database.validate(self);
        }
        if let Some(git) = &self.git {
            return git.validate(self);
        }
        if let Some(ssh) = &self.ssh {
            return ssh.validate(self);
        }
        if let Some(telnet) = &self.telnet {
            return telnet.validate(self);
        }
        if let Some(http) = &self.http {
            return http.validate(self);
        }
        if !Path::new(&self.program).is_absolute()
            || !Path::new(&self.program).is_file()
            || !Path::new(&self.working_directory).is_absolute()
            || !Path::new(&self.working_directory).is_dir()
            || self.program.len() > 1024
            || self.working_directory.len() > 1024
            || self.arguments.len() > 32
            || self.arguments.iter().map(String::len).sum::<usize>() > MAX_ARGUMENTS_BYTES
            || self
                .arguments
                .iter()
                .any(|a| a.len() > MAX_ARGUMENT_BYTES || a.contains('\0'))
            || self.slots.len() > 8
        {
            return Err(CatalogError::Invalid);
        }
        let mut names = HashSet::new();
        let mut variables = HashSet::new();
        let mut stdin = false;
        for slot in &self.slots {
            if !identifier(&slot.name) || !names.insert(&slot.name) {
                return Err(CatalogError::Invalid);
            }
            match slot.injection {
                Injection::Protocol => return Err(CatalogError::Invalid),
                Injection::Stdin => {
                    if stdin {
                        return Err(CatalogError::Invalid);
                    }
                    stdin = true;
                }
                Injection::Environment => {
                    let Some(variable) = &slot.environment_variable else {
                        return Err(CatalogError::Invalid);
                    };
                    if !identifier(variable) || !variables.insert(variable.to_ascii_uppercase()) {
                        return Err(CatalogError::Invalid);
                    }
                }
                Injection::Argument | Injection::File => {
                    if !self
                        .arguments
                        .iter()
                        .any(|argument| is_credential_placeholder(argument, &slot.name))
                    {
                        return Err(CatalogError::Invalid);
                    }
                }
            }
            if slot.injection != Injection::Environment && slot.environment_variable.is_some() {
                return Err(CatalogError::Invalid);
            }
        }
        if stdin && self.stdin_content.is_some() {
            return Err(CatalogError::Invalid);
        }
        for argument in &self.arguments {
            if (argument.contains("{{secret:") || argument.contains("{{param:"))
                && !self.slots.iter().any(|s| {
                    matches!(s.injection, Injection::Argument | Injection::File)
                        && is_credential_placeholder(argument, &s.name)
                })
                && !self
                    .parameters
                    .iter()
                    .any(|p| *argument == format!("{{{{param:{}}}}}", p.name))
            {
                return Err(CatalogError::Invalid);
            }
        }
        Ok(())
    }
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit()))
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputRequest {
    pub id: String,
    pub cursor: u64,
    #[serde(default)]
    pub wait_ms: u64,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct OutputPage {
    pub items: Vec<OutputChunk>,
    pub next_cursor: u64,
    pub oldest_cursor: u64,
    pub truncated: bool,
    pub has_more: bool,
    pub exit_code: Option<i32>,
    pub state: RunState,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct OutputChunk {
    pub sequence: u64,
    pub stream: String,
    pub text: String,
    pub created_at_unix_ms: u64,
}

impl Catalog {
    pub fn append_output(&self, id: Uuid, stream: &str, text: &str) -> Result<(), CatalogError> {
        if text.is_empty() {
            return Ok(());
        }
        let safe_text: String = text
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
            .collect();
        if safe_text.is_empty() {
            return Ok(());
        }
        let connection = self.lock();
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        let mut remaining = safe_text.as_str();
        while !remaining.is_empty() {
            let end = remaining.floor_char_boundary(4096);
            let (chunk, tail) = remaining.split_at(end);
            transaction.execute("INSERT INTO run_output(run_id, sequence, stream, text, created_at_unix_ms) SELECT ?1, COALESCE(MAX(sequence),0)+1, ?2, ?3, ?4 FROM run_output WHERE run_id=?1", rusqlite::params![id.to_string(),stream,chunk,i64::try_from(crate::now_unix_ms()).map_err(|_| CatalogError::Storage)?]).map_err(|_| CatalogError::Storage)?;
            remaining = tail;
        }
        // A bounded 8 MiB history survives terminal closure and service restart.
        transaction.execute("DELETE FROM run_output WHERE run_id=?1 AND sequence <= (SELECT COALESCE(MAX(sequence),0)-?2 FROM run_output WHERE run_id=?1)", rusqlite::params![id.to_string(), MAX_RUN_OUTPUT_CHUNKS]).map_err(|_| CatalogError::Storage)?;
        transaction.commit().map_err(|_| CatalogError::Storage)?;
        Ok(())
    }

    pub fn output(&self, id: Uuid, cursor: u64) -> Result<OutputPage, CatalogError> {
        let run = self.get_synthetic_run(id)?;
        let connection = self.lock();
        let (oldest, last) = connection.query_row("SELECT COALESCE(MIN(sequence),1),COALESCE(MAX(sequence),0) FROM run_output WHERE run_id=?1", [id.to_string()], |r| Ok((r.get::<_,u32>(0)?,r.get::<_,u32>(1)?))).map_err(|_| CatalogError::Storage)?;
        let oldest = u64::from(oldest);
        let last = u64::from(last);
        if cursor > last {
            return Err(CatalogError::Invalid);
        }
        let mut statement = connection.prepare("SELECT sequence,stream,text,created_at_unix_ms FROM run_output WHERE run_id=?1 AND sequence>?2 ORDER BY sequence LIMIT 16").map_err(|_| CatalogError::Storage)?;
        let items = statement
            .query_map(
                rusqlite::params![
                    id.to_string(),
                    i64::try_from(cursor).map_err(|_| CatalogError::Invalid)?
                ],
                |r| {
                    Ok(OutputChunk {
                        sequence: u64::from(r.get::<_, u32>(0)?),
                        stream: r.get(1)?,
                        text: r.get(2)?,
                        created_at_unix_ms: u64::try_from(r.get::<_, i64>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)?;
        let next_cursor = items.last().map_or(cursor, |c| c.sequence);
        let exit_code = connection
            .query_row(
                "SELECT exit_code FROM synthetic_runs WHERE id=?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .map_err(|_| CatalogError::Storage)?;
        Ok(OutputPage {
            items,
            next_cursor,
            oldest_cursor: oldest,
            truncated: cursor.saturating_add(1) < oldest,
            has_more: next_cursor < last,
            exit_code,
            state: run.state,
        })
    }

    pub fn clear_output(&self, id: Uuid) -> Result<(), CatalogError> {
        let run = self.get_synthetic_run(id)?;
        if matches!(run.state, RunState::Queued | RunState::Running) {
            return Err(CatalogError::ResourceInUse);
        }
        self.lock()
            .execute("DELETE FROM run_output WHERE run_id = ?1", [id.to_string()])
            .map_err(|_| CatalogError::Storage)?;
        Ok(())
    }
}

pub async fn read_output(
    state: &AppState,
    request: OutputRequest,
) -> Result<OutputPage, CatalogError> {
    if request.wait_ms > 5000 {
        return Err(CatalogError::Invalid);
    }
    let id = Uuid::parse_str(&request.id).map_err(|_| CatalogError::Invalid)?;
    let mut changes = state.changes.subscribe();
    let catalog = state.catalog.clone();
    let mut result = tokio::task::spawn_blocking(move || catalog.output(id, request.cursor))
        .await
        .map_err(|_| CatalogError::Storage)??;
    if result.items.is_empty()
        && matches!(result.state, RunState::Queued | RunState::Running)
        && request.wait_ms > 0
    {
        let _ = tokio::time::timeout(Duration::from_millis(request.wait_ms), changes.recv()).await;
        let catalog = state.catalog.clone();
        result = tokio::task::spawn_blocking(move || catalog.output(id, request.cursor))
            .await
            .map_err(|_| CatalogError::Storage)??;
    }
    Ok(result)
}

pub async fn drive(state: &AppState, id: Uuid, cancellation: &CancellationToken) {
    let _permit = tokio::select! {
        result = state.command_capacity.acquire() => { let Ok(permit)=result else { return; }; permit },
        () = cancellation.cancelled() => { super::invalidate_synthetic_run(state.catalog.clone(),id).await; return; }
    };
    let _configuration = state.configuration_gate.read().await;
    let catalog = state.catalog.clone();
    let context = tokio::task::spawn_blocking(move || catalog.run_execution_context(id)).await;
    let Ok(Ok(context)) = context else {
        super::invalidate_synthetic_run(state.catalog.clone(), id).await;
        return;
    };
    let Some(config) = context.template.command else {
        return;
    };
    let parameters = context.approval.parameters;
    let remaining = context
        .approval
        .expires_at_unix_ms
        .saturating_sub(super::now_unix_ms());
    let limit =
        Duration::from_secs(context.template.timeout_seconds).min(Duration::from_millis(remaining));
    let started = Instant::now();
    let Some(secrets) = load_command_secrets(state, id, &config, cancellation, limit).await else {
        return;
    };
    let limit = limit.saturating_sub(started.elapsed());
    if limit.is_zero() {
        let _ = state.catalog.complete_command_run(id, "timed_out", None);
        return;
    }
    if drive_protocol(&ProtocolExecution {
        state,
        id,
        config: &config,
        parameters: &parameters,
        secrets: &secrets,
        cancellation,
        limit,
    })
    .await
    {
        return;
    }
    if drive_in_terminal(
        state,
        id,
        &config,
        &secrets,
        cancellation,
        limit,
        &parameters,
    )
    .await
    {
        return;
    }
    let state = state.clone();
    let cancellation = cancellation.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let (status, exit) = execute(
            &state,
            id,
            &config,
            &secrets,
            &cancellation,
            limit,
            &parameters,
        );
        let _ = state.catalog.complete_command_run(id, status, exit);
        let _ = state.changes.send(());
    })
    .await;
}

struct ProtocolExecution<'a> {
    state: &'a AppState,
    id: Uuid,
    config: &'a CommandConfig,
    parameters: &'a crate::parameters::ParameterValues,
    secrets: &'a [Zeroizing<String>],
    cancellation: &'a CancellationToken,
    limit: Duration,
}

async fn drive_protocol(execution: &ProtocolExecution<'_>) -> bool {
    let ProtocolExecution {
        state,
        id,
        config,
        parameters,
        secrets,
        cancellation,
        limit,
    } = execution;
    if let Some(database) = &config.database {
        crate::database_task::drive(
            state,
            *id,
            database,
            config,
            parameters,
            secrets,
            cancellation,
            *limit,
        )
        .await;
    } else if let Some(ssh) = &config.ssh {
        crate::ssh_task::drive(
            state,
            *id,
            ssh,
            config,
            parameters,
            secrets,
            cancellation,
            *limit,
        )
        .await;
    } else if let Some(telnet) = &config.telnet {
        crate::telnet_task::drive(
            state,
            *id,
            telnet,
            config,
            parameters,
            secrets,
            cancellation,
            *limit,
        )
        .await;
    } else if let Some(http) = &config.http {
        crate::http_task::drive(
            state,
            *id,
            http,
            config,
            parameters,
            secrets,
            cancellation,
            *limit,
        )
        .await;
    } else {
        return false;
    }
    true
}

async fn load_command_secrets(
    state: &AppState,
    run_id: Uuid,
    config: &CommandConfig,
    cancellation: &CancellationToken,
    limit: Duration,
) -> Option<Vec<Zeroizing<String>>> {
    let started = Instant::now();
    let mut secrets = Vec::new();
    for slot in &config.slots {
        let read_limit = limit
            .saturating_sub(started.elapsed())
            .min(SECRET_READ_TIMEOUT);
        let secret = state
            .secret_reads
            .get(
                state.secret_store.clone(),
                slot.credential_id,
                read_limit,
                Some(cancellation),
            )
            .await;
        let secret = match secret {
            Ok(secret) => secret,
            Err(error) => {
                let status = match error {
                    SecretReadError::Cancelled => "cancelled",
                    SecretReadError::TimedOut => "timed_out",
                    SecretReadError::Store(_) | SecretReadError::Worker => "credential_unavailable",
                };
                let _ = state.catalog.complete_command_run(run_id, status, None);
                return None;
            }
        };
        if secret.is_empty() {
            let _ = state
                .catalog
                .complete_command_run(run_id, "credential_unavailable", None);
            return None;
        }
        secrets.push(secret);
    }
    Some(secrets)
}

async fn drive_in_terminal(
    state: &AppState,
    run_id: Uuid,
    config: &CommandConfig,
    secrets: &[Zeroizing<String>],
    cancellation: &CancellationToken,
    limit: Duration,
    parameters: &crate::parameters::ParameterValues,
) -> bool {
    let Some(terminal_id) = config.terminal_id else {
        return false;
    };
    let (status, exit) = execute_in_terminal(TerminalExecution {
        state,
        run_id,
        terminal_id,
        config,
        secrets,
        cancellation,
        limit,
        parameters,
    })
    .await;
    let _ = state.catalog.complete_command_run(run_id, status, exit);
    let _ = state.changes.send(());
    true
}

struct TerminalExecution<'a> {
    state: &'a AppState,
    run_id: Uuid,
    terminal_id: Uuid,
    config: &'a CommandConfig,
    secrets: &'a [Zeroizing<String>],
    cancellation: &'a CancellationToken,
    limit: Duration,
    parameters: &'a crate::parameters::ParameterValues,
}

async fn execute_in_terminal(execution: TerminalExecution<'_>) -> (&'static str, Option<i32>) {
    let TerminalExecution {
        state,
        run_id,
        terminal_id,
        config,
        secrets,
        cancellation,
        limit,
        parameters,
    } = execution;
    if cancellation.is_cancelled() || limit.is_zero() || config.validate().is_err() {
        return ("cancelled", None);
    }
    let Ok(broker) = state.terminals.begin_broker(terminal_id) else {
        return ("command_failed", None);
    };
    let shell = broker.shell();
    let mut events = broker.subscribe();
    broker.add_redaction_secrets(secrets);
    let mut files = TemporaryFiles { paths: Vec::new() };
    let Some(command) = terminal_command(
        state, run_id, shell, config, secrets, parameters, &mut files,
    ) else {
        return ("command_failed", None);
    };
    if broker.write(command.as_bytes()).is_err() {
        return ("command_failed", None);
    }

    let marker = format!("__SECRETBRIDGE_RUN_{}:", run_id.simple());
    let deadline = tokio::time::sleep(limit);
    tokio::pin!(deadline);
    let mut recent = String::new();
    let mut pending_output = String::new();
    let result = loop {
        tokio::select! {
            () = cancellation.cancelled() => {
                let _ = broker.terminate();
                break ("cancelled", None);
            }
            () = &mut deadline => {
                let _ = broker.terminate();
                break ("timed_out", None);
            }
            event = events.recv() => match event {
                Ok(crate::terminal::TerminalEvent::Output { data, .. }) => {
                    let text = String::from_utf8_lossy(&data);
                    recent.push_str(&text);
                    pending_output.extend(text.chars().filter(|character| {
                        !character.is_control() || matches!(character, '\n' | '\r' | '\t')
                    }));
                    if recent.len() > 16_384 {
                        let keep = recent.floor_char_boundary(recent.len() - 8_192);
                        recent.drain(..keep);
                    }
                    if let Some(exit) = terminal_exit_marker(&recent, &marker) {
                        if let Some(position) = pending_output.rfind(&marker) {
                            pending_output.truncate(position);
                        }
                        break (if exit == 0 { "command_ok" } else { "command_failed" }, Some(exit));
                    }
                    if pending_output.len() > 256 {
                        let end = pending_output.floor_char_boundary(pending_output.len() - 128);
                        if state.catalog.append_output(run_id, "terminal", &pending_output[..end]).is_err() {
                            let _ = broker.terminate();
                            return ("command_failed", None);
                        }
                        pending_output.drain(..end);
                        let _ = state.changes.send(());
                    }
                }
                Ok(crate::terminal::TerminalEvent::Exited(code)) => {
                    break ("command_failed", i32::try_from(code).ok());
                }
                Ok(crate::terminal::TerminalEvent::Terminated | crate::terminal::TerminalEvent::Failed)
                | Err(_) => break ("command_failed", None),
            }
        }
    };
    if state
        .catalog
        .append_output(run_id, "terminal", &pending_output)
        .is_err()
    {
        let _ = broker.terminate();
        return ("command_failed", None);
    }
    let _ = state.changes.send(());
    if !files.cleanup() {
        return ("command_cleanup_failed", result.1);
    }
    result
}

fn terminal_exit_marker(output: &str, marker: &str) -> Option<i32> {
    let tail = output.rsplit_once(marker)?.1;
    let digits = tail
        .trim_start_matches(&['\r', '\n'][..])
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

fn terminal_command(
    state: &AppState,
    run_id: Uuid,
    shell: crate::terminal::TerminalShell,
    config: &CommandConfig,
    secrets: &[Zeroizing<String>],
    parameters: &crate::parameters::ParameterValues,
    files: &mut TemporaryFiles,
) -> Option<Zeroizing<String>> {
    let mut arguments = config.arguments.clone();
    for argument in &mut arguments {
        for (name, value) in parameters {
            if *argument == format!("{{{{param:{name}}}}}") {
                *argument = crate::parameters::argument(value);
            }
        }
    }
    let mut secret_paths = Vec::new();
    for secret in secrets {
        secret_paths.push(secret_file(&state.command_directory, files, secret).ok()?);
    }
    let stdin_path = match &config.stdin_content {
        Some(content) => Some(
            secret_file(
                &state.command_directory,
                files,
                &Zeroizing::new(content.clone()),
            )
            .ok()?,
        ),
        None => None,
    };
    let marker = format!("__SECRETBRIDGE_RUN_{}", run_id.simple());
    match shell {
        crate::terminal::TerminalShell::Bash | crate::terminal::TerminalShell::Zsh => {
            terminal_command_posix(
                config,
                &arguments,
                &secret_paths,
                stdin_path.as_deref(),
                &marker,
            )
        }
        crate::terminal::TerminalShell::PowerShell => terminal_command_powershell(
            config,
            &arguments,
            &secret_paths,
            stdin_path.as_deref(),
            &marker,
        ),
        crate::terminal::TerminalShell::Cmd | crate::terminal::TerminalShell::Synthetic => None,
    }
}

fn terminal_command_posix(
    config: &CommandConfig,
    arguments: &[String],
    secret_paths: &[PathBuf],
    stdin_path: Option<&Path>,
    marker: &str,
) -> Option<Zeroizing<String>> {
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\"'\"'"));
    let mut command = format!(" cd -- {} && ", quote(&config.working_directory));
    let mut stdin = stdin_path.map(|path| quote(&path.to_string_lossy()));
    for (slot, path) in config.slots.iter().zip(secret_paths) {
        let path = quote(&path.to_string_lossy());
        match slot.injection {
            Injection::Environment => {
                command.push_str(slot.environment_variable.as_deref()?);
                command.push_str("=\"$(cat -- ");
                command.push_str(&path);
                command.push_str(")\" ");
            }
            Injection::Stdin => stdin = Some(path),
            Injection::Argument | Injection::File | Injection::Protocol => {}
        }
    }
    if let Some(path) = stdin {
        command.push_str("cat -- ");
        command.push_str(&path);
        command.push_str(" | ");
    }
    command.push_str(&quote(&config.program));
    for argument in arguments {
        command.push(' ');
        let mut rendered = None;
        for (slot, path) in config.slots.iter().zip(secret_paths) {
            if is_credential_placeholder(argument, &slot.name) {
                let path = quote(&path.to_string_lossy());
                rendered = Some(if slot.injection == Injection::Argument {
                    format!("\"$(cat -- {path})\"")
                } else {
                    path
                });
            }
        }
        if let Some(rendered) = rendered {
            command.push_str(&rendered);
        } else {
            command.push_str(&quote(argument));
        }
    }
    let _ = writeln!(
        command,
        "; __sb_ec=$?; printf '\\n{marker}:%s\\n' \"$__sb_ec\""
    );
    Some(Zeroizing::new(command))
}

fn terminal_command_powershell(
    config: &CommandConfig,
    arguments: &[String],
    secret_paths: &[PathBuf],
    stdin_path: Option<&Path>,
    marker: &str,
) -> Option<Zeroizing<String>> {
    let quote = |value: &str| format!("'{}'", value.replace('\'', "''"));
    let mut command = format!(
        "Set-Location -LiteralPath {}; ",
        quote(&config.working_directory)
    );
    let mut restore = String::new();
    let mut stdin = stdin_path.map(|path| quote(&path.to_string_lossy()));
    for (index, (slot, path)) in config.slots.iter().zip(secret_paths).enumerate() {
        let path = quote(&path.to_string_lossy());
        match slot.injection {
            Injection::Environment => {
                let variable = slot.environment_variable.as_deref()?;
                let _ = write!(
                    command,
                    "$__sb_old_{index}=$env:{variable};$env:{variable}=[IO.File]::ReadAllText({path});"
                );
                let _ = write!(restore, "$env:{variable}=$__sb_old_{index};");
            }
            Injection::Stdin => stdin = Some(path),
            Injection::Argument | Injection::File | Injection::Protocol => {}
        }
    }
    if let Some(path) = stdin {
        let _ = write!(command, "[IO.File]::ReadAllText({path}) | ");
    }
    command.push_str("& ");
    command.push_str(&quote(&config.program));
    for argument in arguments {
        command.push(' ');
        let mut rendered = None;
        for (slot, path) in config.slots.iter().zip(secret_paths) {
            if is_credential_placeholder(argument, &slot.name) {
                let path = quote(&path.to_string_lossy());
                rendered = Some(if slot.injection == Injection::Argument {
                    format!("([IO.File]::ReadAllText({path}))")
                } else {
                    path
                });
            }
        }
        if let Some(rendered) = rendered {
            command.push_str(&rendered);
        } else {
            command.push_str(&quote(argument));
        }
    }
    let _ = write!(
        command,
        ";$__sb_ec=$LASTEXITCODE;{restore}Write-Output \"{marker}:$__sb_ec\"\r\n"
    );
    Some(Zeroizing::new(command))
}

struct TemporaryFiles {
    paths: Vec<PathBuf>,
}
impl Drop for TemporaryFiles {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl TemporaryFiles {
    fn cleanup(&mut self) -> bool {
        self.paths.retain(|path| {
            std::fs::remove_file(path).is_err_and(|e| e.kind() != std::io::ErrorKind::NotFound)
        });
        self.paths.is_empty()
    }
}

pub(crate) fn cleanup_files(directory: &Path) -> std::io::Result<()> {
    if !directory.exists() {
        return Ok(());
    }
    if std::fs::symlink_metadata(directory)?
        .file_type()
        .is_symlink()
    {
        return Err(std::io::Error::other("invalid command directory"));
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "secret")
            && path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| Uuid::parse_str(s).is_ok())
            && entry.file_type()?.is_file()
        {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn secret_file(
    directory: &Path,
    files: &mut TemporaryFiles,
    secret: &str,
) -> std::io::Result<PathBuf> {
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(directory) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    if std::fs::symlink_metadata(directory)?
        .file_type()
        .is_symlink()
    {
        return Err(std::io::Error::other("invalid command directory"));
    }
    let path = directory.join(format!("{}.secret", Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    files.paths.push(path.clone());
    file.write_all(secret.as_bytes())?;
    Ok(path)
}

#[allow(
    clippy::too_many_lines,
    reason = "process setup, streaming and cleanup form one execution lifetime"
)]
fn execute(
    state: &AppState,
    id: Uuid,
    config: &CommandConfig,
    secrets: &[Zeroizing<String>],
    cancel: &CancellationToken,
    limit: Duration,
    parameters: &crate::parameters::ParameterValues,
) -> (&'static str, Option<i32>) {
    if cancel.is_cancelled() || limit.is_zero() {
        return ("cancelled", None);
    }
    if config.validate().is_err() {
        return ("command_failed", None);
    }
    let mut command = Command::new(&config.program);
    let git_operation = config.git.as_ref().map(|git| git.operation);
    let prepared = config.git.as_ref().map(|git| git.prepare(config, secrets));
    let (config, secrets) = if let Some(prepared) = &prepared {
        let Ok((prepared_config, prepared_secrets)) = prepared else {
            return ("command_failed", None);
        };
        crate::git_task::configure_environment(&mut command);
        (prepared_config, prepared_secrets.as_slice())
    } else {
        (config, secrets)
    };
    command
        .current_dir(&config.working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut arguments = Zeroizing::new(config.arguments.clone());
    for argument in arguments.iter_mut() {
        for (name, value) in parameters {
            if *argument == format!("{{{{param:{name}}}}}") {
                *argument = crate::parameters::argument(value);
                break;
            }
        }
    }
    let mut files = TemporaryFiles { paths: Vec::new() };
    for (slot, secret) in config.slots.iter().zip(secrets) {
        match slot.injection {
            Injection::Environment => {
                command.env(
                    slot.environment_variable
                        .as_ref()
                        .expect("validated variable"),
                    secret.as_str(),
                );
            }
            Injection::Argument | Injection::File => {
                let value = if slot.injection == Injection::File {
                    let Ok(path) = secret_file(&state.command_directory, &mut files, secret) else {
                        return ("command_failed", None);
                    };
                    Zeroizing::new(path.to_string_lossy().into_owned())
                } else {
                    secret.clone()
                };
                for (index, original) in config.arguments.iter().enumerate() {
                    if is_credential_placeholder(original, &slot.name) {
                        arguments[index].clone_from(&value);
                    }
                }
            }
            Injection::Stdin | Injection::Protocol => {}
        }
    }
    command.args(arguments.iter());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let Ok(mut child) = command.spawn() else {
        return ("command_failed", None);
    };
    drop(command);
    drop(arguments);
    let stdin = child.stdin.take().expect("piped stdin");
    let input = config
        .stdin_content
        .as_ref()
        .map(|content| Zeroizing::new(content.clone()))
        .or_else(|| {
            config
                .slots
                .iter()
                .zip(secrets)
                .find(|(s, _)| s.injection == Injection::Stdin)
                .map(|(_, s)| s.clone())
        });
    std::thread::spawn(move || {
        let mut stdin = stdin;
        if let Some(input) = input {
            let _ = stdin.write_all(input.as_bytes());
        }
    });
    let (sender, receiver) = mpsc::sync_channel(16);
    for (stream, reader) in [
        (
            "stdout",
            Box::new(child.stdout.take().expect("piped stdout")) as Box<dyn Read + Send>,
        ),
        (
            "stderr",
            Box::new(child.stderr.take().expect("piped stderr")) as Box<dyn Read + Send>,
        ),
    ] {
        let sender = sender.clone();
        let secrets = secrets.to_vec();
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut redactor = Redactor::new(&secrets);
            let mut decoder = Utf8Decoder::default();
            drop(secrets);
            let mut buffer = Zeroizing::new(vec![0u8; 4096]);
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => {
                        let bytes = redactor.feed(&[], true);
                        let _ = sender.send((stream, decoder.feed(&bytes, true)));
                        break;
                    }
                    Ok(count) => {
                        let bytes = redactor.feed(&buffer[..count], false);
                        if sender.send((stream, decoder.feed(&bytes, false))).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
    drop(sender);
    let start = Instant::now();
    let mut status = "command_failed";
    let mut exit = None;
    let mut finished = None;
    loop {
        if finished.is_none() && (cancel.is_cancelled() || start.elapsed() >= limit) {
            stop_tree(&mut child);
            status = if cancel.is_cancelled() {
                "cancelled"
            } else {
                "timed_out"
            };
            finished = Some(Instant::now());
        }
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok((stream, bytes)) => {
                if state.catalog.append_output(id, stream, &bytes).is_err() {
                    stop_tree(&mut child);
                    return ("command_failed", None);
                }
                let _ = state.changes.send(());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if finished.is_some() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if finished.is_none() {
            match child.try_wait() {
                Ok(Some(result)) => {
                    exit = result.code();
                    status = if result.success() {
                        "command_ok"
                    } else {
                        "command_failed"
                    };
                    finished = Some(Instant::now());
                }
                Ok(None) => {}
                Err(_) => {
                    stop_tree(&mut child);
                    finished = Some(Instant::now());
                }
            }
        }
        // Descendants must not keep the operation and output pipes alive indefinitely.
        if finished.is_some_and(|t| t.elapsed() > Duration::from_secs(2)) {
            stop_tree(&mut child);
            break;
        }
    }
    let _ = child.wait();
    if !files.cleanup() {
        return ("command_cleanup_failed", exit);
    }
    if let Some(operation) = git_operation {
        let summary = serde_json::json!({"kind":"git", "operation":operation, "exit_code":exit, "error_code":match status {"command_ok" => None, "timed_out" => Some("timed_out"), "cancelled" => Some("cancelled"), _ => Some("git_failed")}}).to_string();
        let mut redactor = Redactor::new(secrets);
        let filtered = redactor.feed(summary.as_bytes(), true);
        if state
            .catalog
            .append_output(id, "stdout", &String::from_utf8_lossy(&filtered))
            .is_err()
        {
            return ("command_failed", exit);
        }
    }
    (status, exit)
}

fn stop_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if child.try_wait().is_ok_and(|result| result.is_none())
            && let Some(root) = std::env::var_os("SystemRoot")
        {
            let _ = Command::new(PathBuf::from(root).join("System32/taskkill.exe"))
                .args(["/PID", &child.id().to_string(), "/T", "/F"])
                .creation_flags(0x0800_0000)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    let _ = child.kill();
}

#[cfg(test)]
#[path = "command_tests.rs"]
pub(crate) mod tests;
