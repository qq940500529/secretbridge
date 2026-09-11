// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU8, Ordering},
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use portable_pty::{ChildKiller, CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

const MAX_TERMINALS: usize = 8;
const BACKLOG_LIMIT: usize = 64 * 1024;
const EVENT_CAPACITY: usize = 256;

const STATUS_RUNNING: u8 = 0;
const STATUS_EXITED: u8 = 1;
const STATUS_TERMINATED: u8 = 2;
const STATUS_FAILED: u8 = 3;

#[derive(Clone)]
pub struct TerminalManager {
    sessions: Arc<RwLock<HashMap<Uuid, Arc<TerminalSession>>>>,
    creation_lock: Arc<Mutex<()>>,
    program: PathBuf,
}

struct TerminalSession {
    id: Uuid,
    created_at_unix_ms: u64,
    status: Arc<AtomicU8>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    output: Arc<Mutex<OutputBuffer>>,
    input_lease: Mutex<Option<InputLease>>,
    events: broadcast::Sender<TerminalEvent>,
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

#[derive(Clone, Debug, Serialize)]
pub struct TerminalSummary {
    pub id: Uuid,
    pub created_at_unix_ms: u64,
    pub status: TerminalStatus,
    pub mode: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalError {
    Capacity,
    Closed,
    InputLeaseRequired,
    InvalidInput,
    InvalidSize,
    NotFound,
    SpawnFailed,
}

impl TerminalManager {
    #[must_use]
    pub fn new(program: PathBuf) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            creation_lock: Arc::new(Mutex::new(())),
            program,
        }
    }

    pub fn create(&self, rows: u16, cols: u16) -> Result<TerminalSummary, TerminalError> {
        validate_size(rows, cols)?;
        let _creation_guard = self
            .creation_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.read_sessions().len() >= MAX_TERMINALS {
            return Err(TerminalError::Capacity);
        }

        let id = Uuid::new_v4();
        let pair = NativePtySystem::default()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|_| TerminalError::SpawnFailed)?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|_| TerminalError::SpawnFailed)?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|_| TerminalError::SpawnFailed)?;

        let mut command = CommandBuilder::new(&self.program);
        command.arg("--synthetic-terminal-child");
        command.arg(id.to_string());
        let mut child = pair
            .slave
            .spawn_command(command)
            .map_err(|_| TerminalError::SpawnFailed)?;
        let killer = child.clone_killer();
        drop(pair.slave);

        let status = Arc::new(AtomicU8::new(STATUS_RUNNING));
        let output = Arc::new(Mutex::new(OutputBuffer::new()));
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let session = Arc::new(TerminalSession {
            id,
            created_at_unix_ms: now_unix_ms(),
            status: Arc::clone(&status),
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            killer: Mutex::new(killer),
            output: Arc::clone(&output),
            input_lease: Mutex::new(None),
            events: events.clone(),
        });

        let reader_status = Arc::clone(&status);
        let reader_events = events.clone();
        thread::Builder::new()
            .name(format!("secretbridge-terminal-reader-{id}"))
            .spawn(move || {
                let mut buffer = [0_u8; 4096];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => {
                            let chunk: Arc<[u8]> = Arc::from(&buffer[..count]);
                            let mut output_guard = output
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let cursor = output_guard.append(&chunk);
                            // Keep append and publication atomic with respect to attach snapshots.
                            let _ = reader_events.send(TerminalEvent::Output {
                                cursor,
                                data: chunk,
                            });
                            drop(output_guard);
                        }
                        Err(_) => {
                            if reader_status.load(Ordering::Acquire) == STATUS_RUNNING {
                                reader_status.store(STATUS_FAILED, Ordering::Release);
                                let _ = reader_events.send(TerminalEvent::Failed);
                            }
                            break;
                        }
                    }
                }
            })
            .map_err(|_| TerminalError::SpawnFailed)?;

        let wait_status = Arc::clone(&status);
        thread::Builder::new()
            .name(format!("secretbridge-terminal-wait-{id}"))
            .spawn(move || {
                if let Ok(exit) = child.wait() {
                    let previous = wait_status.load(Ordering::Acquire);
                    if previous == STATUS_RUNNING {
                        wait_status.store(STATUS_EXITED, Ordering::Release);
                        let _ = events.send(TerminalEvent::Exited(exit.exit_code()));
                    } else if previous == STATUS_TERMINATED {
                        let _ = events.send(TerminalEvent::Terminated);
                    }
                } else {
                    wait_status.store(STATUS_FAILED, Ordering::Release);
                    let _ = events.send(TerminalEvent::Failed);
                }
            })
            .map_err(|_| TerminalError::SpawnFailed)?;

        self.write_sessions().insert(id, Arc::clone(&session));
        Ok(session.summary())
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
        session.terminate()
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

impl TerminalConnection {
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
            created_at_unix_ms: self.created_at_unix_ms,
            status: terminal_status(self.status.load(Ordering::Acquire)),
            mode: "synthetic_only",
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
    use super::{BACKLOG_LIMIT, OutputBuffer, TerminalError, validate_size};

    #[test]
    fn terminal_size_has_safe_bounds() {
        assert_eq!(validate_size(24, 80), Ok(()));
        assert_eq!(validate_size(1, 80), Err(TerminalError::InvalidSize));
        assert_eq!(validate_size(24, 501), Err(TerminalError::InvalidSize));
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
