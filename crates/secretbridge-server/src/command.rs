// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    catalog::{Catalog, CatalogError, RunState},
    redaction::{Redactor, Utf8Decoder},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
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
    pub http: Option<crate::http_task::HttpConfig>,
    #[serde(default)]
    pub parameters: Vec<crate::parameters::ParameterDefinition>,
    pub program: String,
    pub working_directory: String,
    pub arguments: Vec<String>,
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

impl CommandConfig {
    pub fn validate(&self) -> Result<(), CatalogError> {
        crate::parameters::validate(&self.parameters)?;
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
            || self
                .arguments
                .iter()
                .any(|a| a.len() > 2048 || a.contains('\0'))
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
                    if !self.arguments.contains(&format!("{{{{{}}}}}", slot.name)) {
                        return Err(CatalogError::Invalid);
                    }
                }
            }
            if slot.injection != Injection::Environment && slot.environment_variable.is_some() {
                return Err(CatalogError::Invalid);
            }
        }
        for argument in &self.arguments {
            if argument.contains("{{")
                && !self.slots.iter().any(|s| {
                    matches!(s.injection, Injection::Argument | Injection::File)
                        && *argument == format!("{{{{{}}}}}", s.name)
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
}

impl Catalog {
    pub fn append_output(&self, id: Uuid, stream: &str, text: &str) -> Result<(), CatalogError> {
        if text.is_empty() {
            return Ok(());
        }
        let connection = self.lock();
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        let mut remaining = text;
        while !remaining.is_empty() {
            let end = remaining.floor_char_boundary(4096);
            let (chunk, tail) = remaining.split_at(end);
            transaction.execute("INSERT INTO run_output(run_id, sequence, stream, text) SELECT ?1, COALESCE(MAX(sequence),0)+1, ?2, ?3 FROM run_output WHERE run_id=?1", rusqlite::params![id.to_string(),stream,chunk]).map_err(|_| CatalogError::Storage)?;
            remaining = tail;
        }
        // 64 chunks of at most 4 KiB: only already-redacted bytes are stored.
        transaction.execute("DELETE FROM run_output WHERE run_id=?1 AND sequence <= (SELECT COALESCE(MAX(sequence),0)-64 FROM run_output WHERE run_id=?1)", [id.to_string()]).map_err(|_| CatalogError::Storage)?;
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
        let mut statement = connection.prepare("SELECT sequence,stream,text FROM run_output WHERE run_id=?1 AND sequence>?2 ORDER BY sequence LIMIT 16").map_err(|_| CatalogError::Storage)?;
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
    let mut secrets = Vec::new();
    for slot in &config.slots {
        let store = state.secret_store.clone();
        let credential_id = slot.credential_id;
        let Ok(Ok(secret)) = tokio::task::spawn_blocking(move || store.get(credential_id)).await
        else {
            let _ = state
                .catalog
                .complete_command_run(id, "credential_unavailable", None);
            return;
        };
        if secret.is_empty() {
            let _ = state
                .catalog
                .complete_command_run(id, "credential_unavailable", None);
            return;
        }
        secrets.push(secret);
    }
    let remaining = context
        .approval
        .expires_at_unix_ms
        .saturating_sub(super::now_unix_ms());
    let limit =
        Duration::from_secs(context.template.timeout_seconds).min(Duration::from_millis(remaining));
    if let Some(http) = &config.http {
        crate::http_task::drive(
            state,
            id,
            http,
            &config,
            &parameters,
            &secrets,
            cancellation,
            limit,
        )
        .await;
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
                let placeholder = format!("{{{{{}}}}}", slot.name);
                for (index, original) in config.arguments.iter().enumerate() {
                    if *original == placeholder {
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
        .slots
        .iter()
        .zip(secrets)
        .find(|(s, _)| s.injection == Injection::Stdin)
        .map(|(_, s)| s.clone());
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
pub(crate) mod tests {
    use super::*;
    use crate::catalog::{
        CreateActionTemplate, CreateApproval, CreateCredentialReference, CreateSyntheticRun,
        CreateTarget, DecideApproval,
    };

    pub(crate) fn fixture(mode: &str, id: Uuid) -> CommandConfig {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let (program, mut arguments) = if cfg!(windows) {
            let root = std::env::var_os("SystemRoot").expect("Windows root");
            (
                PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-File".into(),
                    directory
                        .join("tests/fixtures/credential-command.ps1")
                        .to_string_lossy()
                        .into_owned(),
                    mode.into(),
                ],
            )
        } else {
            (
                PathBuf::from("/bin/sh"),
                vec![
                    directory
                        .join("tests/fixtures/credential-command.sh")
                        .to_string_lossy()
                        .into_owned(),
                    mode.into(),
                ],
            )
        };
        if matches!(mode, "argument" | "file") {
            arguments.push("{{password}}".into());
        }
        CommandConfig {
            http: None,
            parameters: Vec::new(),
            program: program.to_string_lossy().into_owned(),
            working_directory: directory.to_string_lossy().into_owned(),
            arguments,
            slots: vec![CredentialSlot {
                name: "password".into(),
                credential_id: id,
                injection: match mode {
                    "environment" => Injection::Environment,
                    "argument" => Injection::Argument,
                    "file" => Injection::File,
                    _ => Injection::Stdin,
                },
                environment_variable: (mode == "environment").then(|| "SB_TEST_SECRET".into()),
            }],
        }
    }

    pub(crate) fn configure(state: &AppState, mode: &str, timeout: u64) -> (Uuid, Uuid) {
        let credential: CreateCredentialReference = serde_json::from_value(
            serde_json::json!({"name":"Synthetic command test","kind":"password"}),
        )
        .unwrap();
        let credential = state
            .catalog
            .create_credential_reference(&credential)
            .unwrap();
        state
            .secret_store
            .set(credential.id, "Synthetic-SB-command_A&z")
            .unwrap();
        state
            .catalog
            .set_credential_secret_state(credential.id, credential.version, true)
            .unwrap();
        let target: CreateTarget = serde_json::from_value(
            serde_json::json!({"name":"Local command","kind":"http_service","environment":"test"}),
        )
        .unwrap();
        let target = state.catalog.create_target(&target).unwrap();
        let template:CreateActionTemplate=serde_json::from_value(serde_json::json!({"name":"Credential echo fixture","target_id":target.id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"command":fixture(mode,credential.id)})).unwrap();
        let template = state.catalog.create_action_template(&template).unwrap();
        let request: CreateApproval = serde_json::from_value(
            serde_json::json!({"action_template_id":template.id,"expires_in_seconds":60}),
        )
        .unwrap();
        let approval = state.catalog.create_approval(&request).unwrap();
        let decision: DecideApproval =
            serde_json::from_value(serde_json::json!({"expected_version":approval.version}))
                .unwrap();
        state
            .catalog
            .approve_approval(approval.id, &decision)
            .unwrap();
        (approval.id, credential.id)
    }

    async fn wait(state: &AppState, id: Uuid) -> OutputPage {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let page = state.catalog.output(id, 0).unwrap();
                if !matches!(page.state, RunState::Queued | RunState::Running) {
                    return page;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("command reaches a terminal state")
    }

    #[tokio::test]
    async fn real_program_uses_all_injections_without_persisting_plaintext() {
        for mode in ["stdin", "environment", "argument", "file"] {
            let (state, _) = AppState::new([]);
            let (approval, credential) = configure(&state, mode, 10);
            assert!(matches!(
                state.catalog.delete_credential_reference(credential),
                Err(CatalogError::ResourceInUse)
            ));
            let request = CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            };
            let result = crate::create_run_for_state(&state, request).await.unwrap();
            let page = wait(&state, result.run.id).await;
            assert_eq!(page.state, RunState::Succeeded, "{mode}");
            assert_eq!(page.exit_code, Some(0));
            let output = page
                .items
                .iter()
                .map(|c| c.text.as_str())
                .collect::<String>();
            assert!(output.contains("[REDACTED]"), "{mode}: {output}");
            assert!(output.contains("stdout-marker") && output.contains("stderr-marker"));
            assert!(!output.contains("Synthetic-SB-command_A&z"));
            let retained: Vec<String> = state
                .catalog
                .lock()
                .prepare("SELECT text FROM run_output")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert!(
                retained
                    .iter()
                    .all(|text| !text.contains("Synthetic-SB-command_A&z"))
            );
            assert!(
                state
                    .catalog
                    .output(result.run.id, page.next_cursor)
                    .unwrap()
                    .items
                    .is_empty()
            );
            if mode == "file" {
                assert_eq!(
                    std::fs::read_dir(&*state.command_directory)
                        .unwrap()
                        .count(),
                    0
                );
                std::fs::remove_dir(&*state.command_directory).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn command_timeout_and_explicit_cancellation_stop_real_processes() {
        for cancel in [false, true] {
            let (state, _) = AppState::new([]);
            let (approval, _) = configure(&state, "sleep", if cancel { 10 } else { 1 });
            let outcome = crate::create_run_for_state(
                &state,
                CreateSyntheticRun {
                    approval_id: approval,
                    idempotency_key: Uuid::new_v4().to_string(),
                },
            )
            .await
            .unwrap();
            if cancel {
                tokio::time::sleep(Duration::from_millis(400)).await;
                let run = state.catalog.get_synthetic_run(outcome.run.id).unwrap();
                crate::cancel_run_for_state(
                    &state,
                    outcome.run.id,
                    crate::catalog::CancelSyntheticRun {
                        expected_version: run.version,
                    },
                )
                .await
                .unwrap();
            }
            let page = wait(&state, outcome.run.id).await;
            assert_eq!(
                page.state,
                if cancel {
                    RunState::Cancelled
                } else {
                    RunState::Failed
                }
            );
            if !cancel {
                assert_eq!(
                    state
                        .catalog
                        .get_synthetic_run(outcome.run.id)
                        .unwrap()
                        .result_status
                        .as_deref(),
                    Some("timed_out")
                );
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if state.command_capacity.available_permits() == 4 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[test]
    fn invalid_placeholder_and_duplicate_stdin_are_rejected() {
        let mut config = fixture("argument", Uuid::new_v4());
        config.arguments.push("prefix{{password}}".into());
        assert!(config.validate().is_err());
        let mut config = fixture("stdin", Uuid::new_v4());
        let mut second = config.slots[0].clone();
        second.name = "second".into();
        config.slots.push(second);
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn parameterized_commands_freeze_values_and_do_not_expand_them_again() {
        let (state, _) = AppState::new([]);
        let (_, credential) = configure(&state, "argument", 10);
        let template = state.catalog.list_action_templates().unwrap().remove(0);
        let mut config = fixture("argument", credential);
        config.arguments.push("{{param:company}}".into());
        config.parameters = serde_json::from_value(serde_json::json!([{
            "name":"company","label":"公司","kind":"string","required":true,
            "default":"天津; {{password}} & 100","choices":[],"max_length":128
        }]))
        .unwrap();
        let update = serde_json::from_value(serde_json::json!({
            "target_id":template.target_id,"name":template.name,"operation":"command_execution",
            "result_scope":"sanitized_output","timeout_seconds":10,"enabled":true,
            "expected_version":template.version,"command":config
        }))
        .unwrap();
        let template = state
            .catalog
            .update_action_template(template.id, &update)
            .unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "action_template_id":template.id,"expires_in_seconds":60,"authorization_mode":"time_window"
        })).unwrap();
        let approval = state.catalog.create_approval(&request).unwrap();
        assert_eq!(approval.parameters["company"], "天津; {{password}} & 100");
        let decision =
            serde_json::from_value(serde_json::json!({"expected_version":approval.version}))
                .unwrap();
        state
            .catalog
            .approve_approval(approval.id, &decision)
            .unwrap();
        for _ in 0..2 {
            let key = Uuid::new_v4().to_string();
            let request = CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: key.clone(),
            };
            let result = crate::create_run_for_state(&state, request).await.unwrap();
            let page = wait(&state, result.run.id).await;
            assert_eq!(page.state, RunState::Succeeded);
            let output = page
                .items
                .iter()
                .map(|c| c.text.as_str())
                .collect::<String>();
            assert!(
                output.contains("|parameter:天津; {{password}} & 100|"),
                "{output}"
            );
            assert!(output.contains("[REDACTED]"));
            assert!(!output.contains("Synthetic-SB-command_A&z"));
            let replay = state
                .catalog
                .create_synthetic_run(&CreateSyntheticRun {
                    approval_id: approval.id,
                    idempotency_key: key,
                })
                .unwrap();
            assert!(replay.replayed);
            assert_eq!(replay.run.id, result.run.id);
        }
        let current = state.catalog.get_approval(approval.id).unwrap();
        state
            .catalog
            .revoke_approval(
                approval.id,
                &crate::catalog::DecideApproval {
                    expected_version: current.version,
                    note: None,
                },
            )
            .unwrap();
        assert!(
            state
                .catalog
                .create_synthetic_run(&CreateSyntheticRun {
                    approval_id: approval.id,
                    idempotency_key: Uuid::new_v4().to_string()
                })
                .is_err()
        );
    }

    #[test]
    fn retained_output_reports_gaps_and_rotation_invalidates_approval() {
        let (state, _) = AppState::new([]);
        let (approval, credential) = configure(&state, "stdin", 10);
        let outcome = state
            .catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            })
            .unwrap();
        for _ in 0..70 {
            state
                .catalog
                .append_output(outcome.run.id, "stdout", "中\n")
                .unwrap();
        }
        let page = state.catalog.output(outcome.run.id, 0).unwrap();
        assert!(page.truncated && page.has_more);
        assert_eq!(page.oldest_cursor, 7);
        assert_eq!(page.items.len(), 16);
        assert!(state.catalog.output(outcome.run.id, 71).is_err());
        assert!(
            !state
                .catalog
                .output(outcome.run.id, page.next_cursor)
                .unwrap()
                .truncated
        );
        let current = state.catalog.get_credential_reference(credential).unwrap();
        state
            .catalog
            .set_credential_secret_state(credential, current.version, true)
            .unwrap();
        assert!(matches!(
            state.catalog.start_run(outcome.run.id),
            Err(CatalogError::PolicyDenied)
        ));
    }

    pub(crate) async fn web_request(
        state: &AppState,
        token: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;
        let response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("origin", "http://127.0.0.1:8787")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16_384).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn web_parameter_approval_and_time_window_use_the_real_executor() {
        use axum::http::StatusCode;
        use serde_json::json;
        let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
        let (_, credential) = configure(&state, "argument", 10);
        let template = state.catalog.list_action_templates().unwrap().remove(0);
        let mut config = fixture("argument", credential);
        config.arguments.push("{{param:company}}".into());
        config.parameters=serde_json::from_value(json!([{"name":"company","label":"公司","kind":"string","required":true,"default":"100","choices":["100","101"],"max_length":3}])).unwrap();
        let update=serde_json::from_value(json!({"target_id":template.target_id,"name":template.name,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":10,"enabled":true,"expected_version":template.version,"command":config})).unwrap();
        state
            .catalog
            .update_action_template(template.id, &update)
            .unwrap();
        let (token, _) = state.issue_session().await;
        for parameters in [
            json!({"company":100}),
            json!({"company":"102"}),
            json!({"unknown":"100"}),
        ] {
            let (status,_)=web_request(&state,&token,"/api/v1/approvals",json!({"action_template_id":template.id,"expires_in_seconds":60,"parameters":parameters})).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status,approval)=web_request(&state,&token,"/api/v1/approvals",json!({"action_template_id":template.id,"expires_in_seconds":60,"authorization_mode":"time_window"})).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(approval["parameters"]["company"], "100");
        let id = approval["id"].as_str().unwrap();
        let (status, approved) = web_request(
            &state,
            &token,
            &format!("/api/v1/approvals/{id}/approve"),
            json!({"expected_version":approval["version"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for _ in 0..2 {
            let request = json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()});
            let (status, result) =
                web_request(&state, &token, "/api/v1/runs", request.clone()).await;
            assert_eq!(status, StatusCode::CREATED);
            let run = Uuid::parse_str(result["run"]["id"].as_str().unwrap()).unwrap();
            let page = wait(&state, run).await;
            assert_eq!(page.state, RunState::Succeeded);
            let output = page
                .items
                .iter()
                .map(|c| c.text.as_str())
                .collect::<String>();
            assert!(output.contains("|parameter:100|"));
            assert!(!output.contains("Synthetic-SB-command_A&z"));
            let (_, replay) = web_request(&state, &token, "/api/v1/runs", request).await;
            assert_eq!(replay["replayed"], true);
            assert_eq!(replay["run"]["id"], result["run"]["id"]);
        }
        let (status, _) = web_request(
            &state,
            &token,
            &format!("/api/v1/approvals/{id}/revoke"),
            json!({"expected_version":approved["version"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = web_request(
            &state,
            &token,
            "/api/v1/runs",
            json!({"approval_id":id,"idempotency_key":Uuid::new_v4().to_string()}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn output_api_is_authenticated_origin_checked_and_does_not_notify_on_read() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let origin = "http://127.0.0.1:8787";
        let (state, _) = AppState::new([origin.to_owned()]);
        let (approval, _) = configure(&state, "stdin", 10);
        let run = state
            .catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            })
            .unwrap()
            .run;
        state
            .catalog
            .append_output(run.id, "stdout", "[REDACTED]")
            .unwrap();
        let (token, _) = state.issue_session().await;
        let mut changes = state.changes.subscribe();
        for (provided_origin, provided_token, body, expected) in [
            (
                origin,
                "invalid",
                r#"{"cursor":0}"#,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "http://untrusted.invalid",
                token.as_str(),
                r#"{"cursor":0}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                origin,
                token.as_str(),
                r#"{"cursor":0,"wait_ms":5001}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                origin,
                token.as_str(),
                r#"{"cursor":0,"secret":"not-accepted"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (origin, token.as_str(), r#"{"cursor":0}"#, StatusCode::OK),
        ] {
            let response = crate::router(state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/runs/{}/output", run.id))
                        .header("origin", provided_origin)
                        .header("authorization", format!("Bearer {provided_token}"))
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), changes.recv())
                .await
                .is_err()
        );
    }

    #[test]
    fn recovery_cleanup_removes_only_owned_regular_secret_files() {
        let directory = std::env::temp_dir().join(format!("sb-clean-{}", Uuid::new_v4()));
        let mut files = TemporaryFiles { paths: Vec::new() };
        let path = secret_file(&directory, &mut files, "synthetic-cleanup").unwrap();
        let unrelated = directory.join("notes.secret");
        std::fs::write(&unrelated, b"not a managed file").unwrap();
        cleanup_files(&directory).unwrap();
        assert!(!path.exists());
        assert!(unrelated.exists());
        std::fs::remove_file(unrelated).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
