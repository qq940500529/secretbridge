// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    env,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU8, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use portable_pty::{
    Child, ChildKiller, CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

const MAX_TERMINALS: usize = 8;
const BACKLOG_LIMIT: usize = 64 * 1024;
const EVENT_CAPACITY: usize = 256;
const MAX_NAME_BYTES: usize = 80;
const MAX_WORKING_DIRECTORY_BYTES: usize = 4096;
const MAX_ENVIRONMENT_VARIABLES: usize = 32;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 4096;

const STATUS_RUNNING: u8 = 0;
const STATUS_EXITED: u8 = 1;
const STATUS_TERMINATED: u8 = 2;
const STATUS_FAILED: u8 = 3;

#[derive(Clone)]
pub struct TerminalManager {
    sessions: Arc<RwLock<HashMap<Uuid, Arc<TerminalSession>>>>,
    creation_lock: Arc<Mutex<()>>,
    launcher: TerminalLauncher,
    changes: broadcast::Sender<()>,
}

#[derive(Clone)]
enum TerminalLauncher {
    System,
    Synthetic(PathBuf),
}

struct TerminalSession {
    id: Uuid,
    name: String,
    shell: TerminalShell,
    working_directory: String,
    process_id: Option<u32>,
    environment_variable_count: usize,
    created_at_unix_ms: u64,
    status: Arc<AtomicU8>,
    exit_code: Arc<Mutex<Option<u32>>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    output: Arc<Mutex<OutputBuffer>>,
    input_lease: Mutex<Option<InputLease>>,
    events: broadcast::Sender<TerminalEvent>,
    changes: broadcast::Sender<()>,
}

struct InputLease {
    client_id: Uuid,
    connection_id: Uuid,
}

struct OutputBuffer {
    oldest_cursor: u64,
    next_cursor: u64,
    bytes: VecDeque<u8>,
}

struct PreparedTerminalLaunch {
    id: Uuid,
    name: String,
    shell: TerminalShell,
    working_directory: String,
    environment_variable_count: usize,
    rows: u16,
    cols: u16,
    command: CommandBuilder,
}

#[derive(Clone, Debug)]
pub enum TerminalEvent {
    Output { cursor: u64, data: Arc<[u8]> },
    Exited(u32),
    Terminated,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStatus {
    Running,
    Exited,
    Terminated,
    Failed,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TerminalShell {
    #[serde(rename = "powershell")]
    PowerShell,
    Cmd,
    Bash,
    Zsh,
    #[doc(hidden)]
    Synthetic,
}

impl TerminalShell {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::PowerShell => "PowerShell",
            Self::Cmd => "Command Prompt",
            Self::Bash => "Bash",
            Self::Zsh => "Zsh",
            Self::Synthetic => "Synthetic test shell",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTerminal {
    pub rows: u16,
    pub cols: u16,
    pub shell: Option<TerminalShell>,
    pub name: Option<String>,
    pub working_directory: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TerminalCapabilities {
    pub platform: &'static str,
    pub default_shell: Option<TerminalShell>,
    pub shells: Vec<TerminalShellCapability>,
    pub max_sessions: usize,
    pub max_environment_variables: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TerminalShellCapability {
    pub shell: TerminalShell,
    pub display_name: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct TerminalSummary {
    pub id: Uuid,
    pub name: String,
    pub shell: TerminalShell,
    pub working_directory: String,
    pub process_id: Option<u32>,
    pub environment_variable_count: usize,
    pub created_at_unix_ms: u64,
    pub status: TerminalStatus,
    pub exit_code: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalError {
    Capacity,
    Closed,
    InputLeaseRequired,
    InvalidInput,
    InvalidEnvironment,
    InvalidName,
    InvalidSize,
    InvalidWorkingDirectory,
    NotFound,
    SpawnFailed,
    UnsupportedShell,
}

impl TerminalManager {
    #[must_use]
    pub fn system() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            creation_lock: Arc::new(Mutex::new(())),
            launcher: TerminalLauncher::System,
            changes: broadcast::channel(64).0,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn synthetic(program: PathBuf) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            creation_lock: Arc::new(Mutex::new(())),
            launcher: TerminalLauncher::Synthetic(program),
            changes: broadcast::channel(64).0,
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> TerminalCapabilities {
        match &self.launcher {
            TerminalLauncher::System => system_capabilities(),
            TerminalLauncher::Synthetic(_) => TerminalCapabilities {
                platform: platform_name(),
                default_shell: Some(TerminalShell::Synthetic),
                shells: vec![TerminalShellCapability {
                    shell: TerminalShell::Synthetic,
                    display_name: TerminalShell::Synthetic.display_name(),
                }],
                max_sessions: MAX_TERMINALS,
                max_environment_variables: MAX_ENVIRONMENT_VARIABLES,
            },
        }
    }

    pub fn create(&self, request: &CreateTerminal) -> Result<TerminalSummary, TerminalError> {
        validate_size(request.rows, request.cols)?;
        validate_environment(&request.environment)?;
        let _creation_guard = self
            .creation_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.read_sessions().len() >= MAX_TERMINALS {
            return Err(TerminalError::Capacity);
        }

        let launch = self.prepare_launch(request)?;
        let session = spawn_terminal(launch, self.changes.clone())?;
        let summary = session.summary();
        self.write_sessions().insert(summary.id, session);
        let _ = self.changes.send(());
        Ok(summary)
    }

    fn prepare_launch(
        &self,
        request: &CreateTerminal,
    ) -> Result<PreparedTerminalLaunch, TerminalError> {
        let id = Uuid::new_v4();
        let shell = match (&self.launcher, request.shell) {
            (TerminalLauncher::Synthetic(_), None | Some(TerminalShell::Synthetic)) => {
                TerminalShell::Synthetic
            }
            (TerminalLauncher::Synthetic(_), Some(_))
            | (TerminalLauncher::System, Some(TerminalShell::Synthetic)) => {
                return Err(TerminalError::UnsupportedShell);
            }
            (TerminalLauncher::System, Some(shell)) => shell,
            (TerminalLauncher::System, None) => {
                default_system_shell().ok_or(TerminalError::UnsupportedShell)?
            }
        };
        let working_directory = resolve_working_directory(request.working_directory.as_deref())?;
        let name = resolve_name(
            request.name.as_deref(),
            shell,
            self.read_sessions().len().saturating_add(1),
        )?;
        let mut command = self.command(shell, id)?;
        command.cwd(&working_directory);
        for (key, value) in &request.environment {
            command.env(key, value);
        }
        #[cfg(unix)]
        if !request.environment.contains_key("TERM") {
            command.env("TERM", "xterm-256color");
        }
        Ok(PreparedTerminalLaunch {
            id,
            name,
            shell,
            working_directory: display_path(&working_directory),
            environment_variable_count: request.environment.len(),
            rows: request.rows,
            cols: request.cols,
            command,
        })
    }

    fn command(&self, shell: TerminalShell, id: Uuid) -> Result<CommandBuilder, TerminalError> {
        match &self.launcher {
            TerminalLauncher::Synthetic(program) if shell == TerminalShell::Synthetic => {
                let mut command = CommandBuilder::new(program);
                command.arg("--synthetic-terminal-child");
                command.arg(id.to_string());
                Ok(command)
            }
            TerminalLauncher::System => system_shell_command(shell),
            TerminalLauncher::Synthetic(_) => Err(TerminalError::UnsupportedShell),
        }
    }

    #[must_use]
    pub fn list(&self) -> Vec<TerminalSummary> {
        let mut sessions = self
            .read_sessions()
            .values()
            .map(|session| session.summary())
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| session.created_at_unix_ms);
        sessions
    }

    pub fn change_notifier(&self) -> broadcast::Sender<()> {
        self.changes.clone()
    }

    pub fn attach(
        &self,
        id: Uuid,
        client_id: Uuid,
        request_input: bool,
        cursor: Option<u64>,
    ) -> Result<(TerminalConnection, TerminalSnapshot), TerminalError> {
        let session = self
            .read_sessions()
            .get(&id)
            .cloned()
            .ok_or(TerminalError::NotFound)?;
        let connection_id = Uuid::new_v4();
        let input_granted = session.acquire_input(client_id, connection_id, request_input);
        let output = session
            .output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = session.events.subscribe();
        let replay = output.snapshot(cursor);
        let snapshot = TerminalSnapshot {
            summary: session.summary(),
            replay_from: replay.replay_from,
            next_cursor: replay.next_cursor,
            replay_truncated: replay.truncated,
            retained_bytes: output.bytes.len(),
            retention_capacity: BACKLOG_LIMIT,
            output: replay.output,
            events,
            input_granted,
        };
        drop(output);
        Ok((
            TerminalConnection {
                session,
                connection_id,
            },
            snapshot,
        ))
    }

    pub fn remove(&self, id: Uuid) -> Result<(), TerminalError> {
        let session = self
            .write_sessions()
            .remove(&id)
            .ok_or(TerminalError::NotFound)?;
        let result = session.terminate();
        let _ = self.changes.send(());
        result
    }

    fn read_sessions(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Uuid, Arc<TerminalSession>>> {
        self.sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_sessions(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<Uuid, Arc<TerminalSession>>> {
        self.sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn spawn_terminal(
    launch: PreparedTerminalLaunch,
    changes: broadcast::Sender<()>,
) -> Result<Arc<TerminalSession>, TerminalError> {
    let pair = NativePtySystem::default()
        .openpty(PtySize {
            rows: launch.rows,
            cols: launch.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|_| TerminalError::SpawnFailed)?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| TerminalError::SpawnFailed)?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| TerminalError::SpawnFailed)?;
    let child = pair
        .slave
        .spawn_command(launch.command)
        .map_err(|_| TerminalError::SpawnFailed)?;
    let process_id = child.process_id();
    let killer = child.clone_killer();
    drop(pair.slave);

    let status = Arc::new(AtomicU8::new(STATUS_RUNNING));
    let exit_code = Arc::new(Mutex::new(None));
    let output = Arc::new(Mutex::new(OutputBuffer::new()));
    let (events, _) = broadcast::channel(EVENT_CAPACITY);
    let (output_activity, output_activity_rx) = std::sync::mpsc::channel();
    let session = Arc::new(TerminalSession {
        id: launch.id,
        name: launch.name,
        shell: launch.shell,
        working_directory: launch.working_directory,
        process_id,
        environment_variable_count: launch.environment_variable_count,
        created_at_unix_ms: now_unix_ms(),
        status: Arc::clone(&status),
        exit_code: Arc::clone(&exit_code),
        master: Mutex::new(pair.master),
        writer: Mutex::new(writer),
        killer: Mutex::new(killer),
        output: Arc::clone(&output),
        input_lease: Mutex::new(None),
        events: events.clone(),
        changes: changes.clone(),
    });
    spawn_terminal_reader(launch.id, reader, output, events.clone(), output_activity)?;
    spawn_terminal_waiter(
        launch.id,
        child,
        status,
        exit_code,
        events,
        output_activity_rx,
        changes,
    )?;
    Ok(session)
}

fn spawn_terminal_reader(
    id: Uuid,
    mut reader: Box<dyn Read + Send>,
    output: Arc<Mutex<OutputBuffer>>,
    events: broadcast::Sender<TerminalEvent>,
    output_activity: std::sync::mpsc::Sender<()>,
) -> Result<(), TerminalError> {
    thread::Builder::new()
        .name(format!("secretbridge-terminal-reader-{id}"))
        .spawn(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(count) if count > 0 => {
                        let chunk: Arc<[u8]> = Arc::from(&buffer[..count]);
                        let mut output = output
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let cursor = output.append(&chunk);
                        // Keep append and publication atomic with respect to attach snapshots.
                        let _ = events.send(TerminalEvent::Output {
                            cursor,
                            data: chunk,
                        });
                        let _ = output_activity.send(());
                    }
                    Ok(_) | Err(_) => break,
                }
            }
        })
        .map(|_| ())
        .map_err(|_| TerminalError::SpawnFailed)
}

fn spawn_terminal_waiter(
    id: Uuid,
    mut child: Box<dyn Child + Send + Sync>,
    status: Arc<AtomicU8>,
    exit_code: Arc<Mutex<Option<u32>>>,
    events: broadcast::Sender<TerminalEvent>,
    output_activity: std::sync::mpsc::Receiver<()>,
    changes: broadcast::Sender<()>,
) -> Result<(), TerminalError> {
    thread::Builder::new()
        .name(format!("secretbridge-terminal-wait-{id}"))
        .spawn(move || {
            let Ok(exit) = child.wait() else {
                status.store(STATUS_FAILED, Ordering::Release);
                let _ = events.send(TerminalEvent::Failed);
                let _ = changes.send(());
                return;
            };
            // Drain PTY bytes that became readable as the child exited before publishing its
            // terminal status. ConPTY readers can remain open, so use a quiet interval, not join.
            while output_activity
                .recv_timeout(Duration::from_millis(100))
                .is_ok()
            {}
            let code = exit.exit_code();
            *exit_code
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(code);
            let previous = status.load(Ordering::Acquire);
            if previous == STATUS_RUNNING {
                status.store(STATUS_EXITED, Ordering::Release);
                let _ = events.send(TerminalEvent::Exited(code));
            } else if previous == STATUS_TERMINATED {
                let _ = events.send(TerminalEvent::Terminated);
            }
            let _ = changes.send(());
        })
        .map(|_| ())
        .map_err(|_| TerminalError::SpawnFailed)
}

pub struct TerminalSnapshot {
    pub summary: TerminalSummary,
    pub replay_from: u64,
    pub next_cursor: u64,
    pub replay_truncated: bool,
    pub retained_bytes: usize,
    pub retention_capacity: usize,
    pub output: Vec<u8>,
    pub events: broadcast::Receiver<TerminalEvent>,
    pub input_granted: bool,
}

pub struct TerminalConnection {
    session: Arc<TerminalSession>,
    connection_id: Uuid,
}

#[derive(Serialize)]
pub struct TerminalRead {
    pub terminal: TerminalSummary,
    pub cursor: u64,
    pub next_cursor: u64,
    pub oldest_cursor: u64,
    pub available_cursor: u64,
    pub truncated: bool,
    pub has_more: bool,
    /// UTF-8 preview; use bytes for lossless decoding across read boundaries.
    pub text: String,
    pub bytes: Vec<u8>,
}

impl TerminalConnection {
    pub fn summary(&self) -> TerminalSummary {
        self.session.summary()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TerminalEvent> {
        self.session.events.subscribe()
    }

    pub fn read(&self, cursor: u64, max_bytes: usize) -> TerminalRead {
        let output = self
            .session
            .output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut replay = output.snapshot(Some(cursor));
        replay.output.truncate(max_bytes);
        let next_cursor = replay.replay_from + replay.output.len() as u64;
        TerminalRead {
            terminal: self.summary(),
            cursor: replay.replay_from,
            next_cursor,
            oldest_cursor: output.oldest_cursor,
            available_cursor: output.next_cursor,
            truncated: replay.truncated,
            has_more: next_cursor < output.next_cursor,
            text: String::from_utf8_lossy(&replay.output).into_owned(),
            bytes: replay.output,
        }
    }
    #[must_use]
    pub fn output_bounds(&self) -> (u64, u64) {
        let output = self
            .session
            .output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (output.oldest_cursor, output.next_cursor)
    }

    pub fn write(&self, input: &[u8]) -> Result<(), TerminalError> {
        if input.len() > 4096 {
            return Err(TerminalError::InvalidInput);
        }
        self.ensure_input_lease()?;
        self.session.ensure_running()?;
        let mut writer = self
            .session
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        writer
            .write_all(input)
            .and_then(|()| writer.flush())
            .map_err(|_| TerminalError::Closed)
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), TerminalError> {
        validate_size(rows, cols)?;
        self.ensure_input_lease()?;
        self.session.ensure_running()?;
        self.session
            .master
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|_| TerminalError::Closed)
    }

    pub fn terminate(&self) -> Result<(), TerminalError> {
        self.ensure_input_lease()?;
        self.session.terminate()
    }

    fn ensure_input_lease(&self) -> Result<(), TerminalError> {
        self.session
            .owns_input(self.connection_id)
            .then_some(())
            .ok_or(TerminalError::InputLeaseRequired)
    }
}

impl Drop for TerminalConnection {
    fn drop(&mut self) {
        self.session.release_input(self.connection_id);
    }
}

impl TerminalSession {
    fn summary(&self) -> TerminalSummary {
        TerminalSummary {
            id: self.id,
            name: self.name.clone(),
            shell: self.shell,
            working_directory: self.working_directory.clone(),
            process_id: self.process_id,
            environment_variable_count: self.environment_variable_count,
            created_at_unix_ms: self.created_at_unix_ms,
            status: terminal_status(self.status.load(Ordering::Acquire)),
            exit_code: *self
                .exit_code
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }

    fn ensure_running(&self) -> Result<(), TerminalError> {
        (self.status.load(Ordering::Acquire) == STATUS_RUNNING)
            .then_some(())
            .ok_or(TerminalError::Closed)
    }

    fn acquire_input(&self, client_id: Uuid, connection_id: Uuid, requested: bool) -> bool {
        if !requested {
            return false;
        }
        let mut lease = self
            .input_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match lease.as_ref() {
            None => {
                *lease = Some(InputLease {
                    client_id,
                    connection_id,
                });
                true
            }
            Some(existing) if existing.client_id == client_id => {
                *lease = Some(InputLease {
                    client_id,
                    connection_id,
                });
                true
            }
            Some(_) => false,
        }
    }

    fn owns_input(&self, connection_id: Uuid) -> bool {
        self.input_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|lease| lease.connection_id == connection_id)
    }

    fn release_input(&self, connection_id: Uuid) {
        let mut lease = self
            .input_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lease
            .as_ref()
            .is_some_and(|lease| lease.connection_id == connection_id)
        {
            *lease = None;
        }
    }

    fn terminate(&self) -> Result<(), TerminalError> {
        if self.status.load(Ordering::Acquire) != STATUS_RUNNING {
            return Ok(());
        }
        self.status.store(STATUS_TERMINATED, Ordering::Release);
        let _ = self.changes.send(());
        let graceful = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write_all(b"exit\r\n");
        let forced = self
            .killer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .kill();
        if graceful.is_ok() || forced.is_ok() {
            Ok(())
        } else {
            Err(TerminalError::Closed)
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if self.status.load(Ordering::Acquire) != STATUS_RUNNING {
            return;
        }
        self.status.store(STATUS_TERMINATED, Ordering::Release);
        if let Ok(writer) = self.writer.get_mut() {
            let _ = writer.write_all(b"exit\r\n");
            let _ = writer.flush();
        }
        if let Ok(killer) = self.killer.get_mut() {
            let _ = killer.kill();
        }
    }
}

fn validate_size(rows: u16, cols: u16) -> Result<(), TerminalError> {
    ((2..=200).contains(&rows) && (2..=500).contains(&cols))
        .then_some(())
        .ok_or(TerminalError::InvalidSize)
}

fn resolve_name(
    requested: Option<&str>,
    shell: TerminalShell,
    ordinal: usize,
) -> Result<String, TerminalError> {
    let Some(requested) = requested else {
        return Ok(format!("{} {ordinal}", shell.display_name()));
    };
    let name = requested.trim();
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(TerminalError::InvalidName);
    }
    Ok(name.to_owned())
}

fn resolve_working_directory(requested: Option<&str>) -> Result<PathBuf, TerminalError> {
    let path = match requested {
        Some(value) => {
            let value = value.trim();
            if value.is_empty()
                || value.len() > MAX_WORKING_DIRECTORY_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(TerminalError::InvalidWorkingDirectory);
            }
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(TerminalError::InvalidWorkingDirectory);
            }
            path
        }
        None => env::current_dir().map_err(|_| TerminalError::InvalidWorkingDirectory)?,
    };
    let canonical = path
        .canonicalize()
        .map_err(|_| TerminalError::InvalidWorkingDirectory)?;
    canonical
        .is_dir()
        .then_some(canonical)
        .ok_or(TerminalError::InvalidWorkingDirectory)
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), TerminalError> {
    if environment.len() > MAX_ENVIRONMENT_VARIABLES {
        return Err(TerminalError::InvalidEnvironment);
    }
    let mut normalized = BTreeSet::new();
    for (name, value) in environment {
        let valid_name = !name.is_empty()
            && name.len() <= MAX_ENVIRONMENT_NAME_BYTES
            && name.bytes().enumerate().all(|(index, byte)| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'_' => true,
                b'0'..=b'9' => index > 0,
                _ => false,
            });
        if !valid_name || value.len() > MAX_ENVIRONMENT_VALUE_BYTES || value.contains('\0') {
            return Err(TerminalError::InvalidEnvironment);
        }
        let comparison_name = if cfg!(windows) {
            name.to_ascii_uppercase()
        } else {
            name.clone()
        };
        if !normalized.insert(comparison_name) {
            return Err(TerminalError::InvalidEnvironment);
        }
    }
    Ok(())
}

fn system_capabilities() -> TerminalCapabilities {
    let shells = supported_system_shells()
        .iter()
        .copied()
        .filter(|shell| resolve_system_shell(*shell).is_some())
        .map(|shell| TerminalShellCapability {
            shell,
            display_name: shell.display_name(),
        })
        .collect::<Vec<_>>();
    TerminalCapabilities {
        platform: platform_name(),
        default_shell: shells.first().map(|capability| capability.shell),
        shells,
        max_sessions: MAX_TERMINALS,
        max_environment_variables: MAX_ENVIRONMENT_VARIABLES,
    }
}

fn default_system_shell() -> Option<TerminalShell> {
    supported_system_shells()
        .iter()
        .copied()
        .find(|shell| resolve_system_shell(*shell).is_some())
}

fn system_shell_command(shell: TerminalShell) -> Result<CommandBuilder, TerminalError> {
    let program = resolve_system_shell(shell).ok_or(TerminalError::UnsupportedShell)?;
    let mut command = CommandBuilder::new(program);
    match shell {
        TerminalShell::PowerShell => {
            command.arg("-NoLogo");
        }
        TerminalShell::Cmd => {
            command.arg("/Q");
        }
        TerminalShell::Bash | TerminalShell::Zsh => {
            command.arg("-l");
        }
        TerminalShell::Synthetic => return Err(TerminalError::UnsupportedShell),
    }
    Ok(command)
}

#[cfg(windows)]
fn supported_system_shells() -> &'static [TerminalShell] {
    &[TerminalShell::PowerShell, TerminalShell::Cmd]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn supported_system_shells() -> &'static [TerminalShell] {
    &[TerminalShell::Bash]
}

#[cfg(target_os = "macos")]
fn supported_system_shells() -> &'static [TerminalShell] {
    &[TerminalShell::Zsh]
}

#[cfg(not(any(windows, unix)))]
fn supported_system_shells() -> &'static [TerminalShell] {
    &[]
}

fn resolve_system_shell(shell: TerminalShell) -> Option<PathBuf> {
    if !supported_system_shells().contains(&shell) {
        return None;
    }
    match shell {
        TerminalShell::PowerShell => resolve_powershell(),
        TerminalShell::Cmd => resolve_cmd(),
        TerminalShell::Bash => find_executable(&["/bin/bash", "/usr/bin/bash", "bash"]),
        TerminalShell::Zsh => find_executable(&["/bin/zsh", "/usr/bin/zsh", "zsh"]),
        TerminalShell::Synthetic => None,
    }
}

#[cfg(windows)]
fn resolve_powershell() -> Option<PathBuf> {
    if let Some(path) = find_executable(&["pwsh.exe", "pwsh"]) {
        return Some(path);
    }
    let system = env::var_os("SystemRoot").map(PathBuf::from).map(|root| {
        root.join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    });
    system
        .filter(|path| path.is_file())
        .or_else(|| find_executable(&["powershell.exe", "powershell"]))
}

#[cfg(not(windows))]
fn resolve_powershell() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn resolve_cmd() -> Option<PathBuf> {
    let system = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32").join("cmd.exe"));
    system
        .filter(|path| path.is_file())
        .or_else(|| find_executable(&["cmd.exe", "cmd"]))
}

#[cfg(not(windows))]
fn resolve_cmd() -> Option<PathBuf> {
    None
}

fn find_executable(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        if path.components().count() > 1 {
            return path.is_file().then(|| path.to_path_buf());
        }
        env::var_os("PATH").and_then(|paths| {
            env::split_paths(&paths)
                .map(|directory| directory.join(candidate))
                .find(|candidate| candidate.is_file())
        })
    })
}

const fn platform_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(unix) {
        "linux"
    } else {
        "unsupported"
    }
}

fn display_path(path: &Path) -> String {
    let display = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(path) = display.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{path}");
        }
        if let Some(path) = display.strip_prefix(r"\\?\") {
            return path.to_owned();
        }
    }
    display.into_owned()
}

struct OutputReplay {
    replay_from: u64,
    next_cursor: u64,
    truncated: bool,
    output: Vec<u8>,
}

impl OutputBuffer {
    fn new() -> Self {
        Self {
            oldest_cursor: 0,
            next_cursor: 0,
            bytes: VecDeque::with_capacity(BACKLOG_LIMIT),
        }
    }

    fn append(&mut self, chunk: &[u8]) -> u64 {
        let cursor = self.next_cursor;
        self.next_cursor = self
            .next_cursor
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let overflow = self
            .bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(BACKLOG_LIMIT);
        let drain_count = overflow.min(self.bytes.len());
        self.bytes.drain(..drain_count);
        self.oldest_cursor = self
            .oldest_cursor
            .saturating_add(u64::try_from(drain_count).unwrap_or(u64::MAX));
        if chunk.len() > BACKLOG_LIMIT {
            let retained = &chunk[chunk.len() - BACKLOG_LIMIT..];
            self.bytes.clear();
            self.bytes.extend(retained);
            self.oldest_cursor = self.next_cursor.saturating_sub(BACKLOG_LIMIT as u64);
        } else {
            self.bytes.extend(chunk);
        }
        cursor
    }

    fn snapshot(&self, requested_cursor: Option<u64>) -> OutputReplay {
        let (replay_from, truncated) = match requested_cursor {
            Some(cursor) if (self.oldest_cursor..=self.next_cursor).contains(&cursor) => {
                (cursor, false)
            }
            Some(_) => (self.oldest_cursor, true),
            None => (self.oldest_cursor, self.oldest_cursor > 0),
        };
        let skip = usize::try_from(replay_from.saturating_sub(self.oldest_cursor))
            .unwrap_or(self.bytes.len())
            .min(self.bytes.len());
        OutputReplay {
            replay_from,
            next_cursor: self.next_cursor,
            truncated,
            output: self.bytes.iter().skip(skip).copied().collect(),
        }
    }
}

fn terminal_status(value: u8) -> TerminalStatus {
    match value {
        STATUS_RUNNING => TerminalStatus::Running,
        STATUS_EXITED => TerminalStatus::Exited,
        STATUS_TERMINATED => TerminalStatus::Terminated,
        _ => TerminalStatus::Failed,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        BACKLOG_LIMIT, MAX_ENVIRONMENT_VARIABLES, OutputBuffer, TerminalError, TerminalShell,
        resolve_name, resolve_working_directory, system_capabilities, validate_environment,
        validate_size,
    };

    #[test]
    fn terminal_size_has_safe_bounds() {
        assert_eq!(validate_size(24, 80), Ok(()));
        assert_eq!(validate_size(1, 80), Err(TerminalError::InvalidSize));
        assert_eq!(validate_size(24, 501), Err(TerminalError::InvalidSize));
    }

    #[test]
    fn session_name_and_working_directory_are_validated() {
        assert_eq!(
            resolve_name(Some("  Build shell  "), TerminalShell::Bash, 1),
            Ok("Build shell".to_owned())
        );
        assert_eq!(
            resolve_name(Some("\n"), TerminalShell::Bash, 1),
            Err(TerminalError::InvalidName)
        );
        assert!(resolve_working_directory(None).is_ok());
        assert_eq!(
            resolve_working_directory(Some("relative/path")),
            Err(TerminalError::InvalidWorkingDirectory)
        );
    }

    #[test]
    fn ordinary_environment_is_bounded_and_portable() {
        let valid = BTreeMap::from([
            ("LANG".to_owned(), "zh_CN.UTF-8".to_owned()),
            ("BUILD_NUMBER_2".to_owned(), "42".to_owned()),
        ]);
        assert_eq!(validate_environment(&valid), Ok(()));
        assert_eq!(
            validate_environment(&BTreeMap::from([(
                "INVALID-NAME".to_owned(),
                "value".to_owned()
            )])),
            Err(TerminalError::InvalidEnvironment)
        );
        let too_many = (0..=MAX_ENVIRONMENT_VARIABLES)
            .map(|index| (format!("VAR_{index}"), String::new()))
            .collect();
        assert_eq!(
            validate_environment(&too_many),
            Err(TerminalError::InvalidEnvironment)
        );
    }

    #[test]
    fn current_platform_exposes_an_installed_default_shell() {
        let capabilities = system_capabilities();
        assert!(!capabilities.shells.is_empty());
        assert_eq!(
            capabilities.default_shell,
            capabilities.shells.first().map(|item| item.shell)
        );
        #[cfg(windows)]
        assert!(
            capabilities
                .shells
                .iter()
                .any(|item| item.shell == TerminalShell::Cmd)
        );
    }

    #[test]
    fn backlog_retains_only_the_newest_bytes() {
        let mut output = OutputBuffer::new();
        output.append(&vec![1; BACKLOG_LIMIT]);
        output.append(&[2, 3]);
        let replay = output.snapshot(Some(0));
        assert_eq!(replay.output.len(), BACKLOG_LIMIT);
        assert_eq!(replay.output[BACKLOG_LIMIT - 2], 2);
        assert_eq!(replay.output[BACKLOG_LIMIT - 1], 3);
        assert_eq!(replay.replay_from, 2);
        assert_eq!(replay.next_cursor, (BACKLOG_LIMIT + 2) as u64);
        assert!(replay.truncated);
    }

    #[test]
    fn valid_cursor_replays_only_missing_output() {
        let mut output = OutputBuffer::new();
        output.append(b"first second");
        let replay = output.snapshot(Some(6));
        assert_eq!(replay.replay_from, 6);
        assert_eq!(replay.output, b"second");
        assert!(!replay.truncated);
    }

    #[test]
    fn oversized_chunk_preserves_cursor_and_only_retains_the_tail() {
        let mut output = OutputBuffer::new();
        let chunk = (0..BACKLOG_LIMIT + 17)
            .map(|index| u8::try_from(index % 251).expect("bounded byte"))
            .collect::<Vec<_>>();
        output.append(&chunk);
        let replay = output.snapshot(Some(0));
        assert_eq!(replay.replay_from, 17);
        assert_eq!(replay.next_cursor, (BACKLOG_LIMIT + 17) as u64);
        assert_eq!(replay.output, chunk[17..]);
        assert!(replay.truncated);
    }

    #[test]
    fn future_cursor_is_reported_as_truncated() {
        let mut output = OutputBuffer::new();
        output.append(b"available");
        let replay = output.snapshot(Some(100));
        assert_eq!(replay.replay_from, 0);
        assert_eq!(replay.output, b"available");
        assert!(replay.truncated);
    }
}
