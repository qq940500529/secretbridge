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
    backlog: Arc<Mutex<VecDeque<u8>>>,
    events: broadcast::Sender<TerminalEvent>,
}

#[derive(Clone, Debug)]
pub enum TerminalEvent {
    Output(Arc<[u8]>),
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
        let backlog = Arc::new(Mutex::new(VecDeque::with_capacity(BACKLOG_LIMIT)));
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let session = Arc::new(TerminalSession {
            id,
            created_at_unix_ms: now_unix_ms(),
            status: Arc::clone(&status),
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            killer: Mutex::new(killer),
            backlog: Arc::clone(&backlog),
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
                            append_backlog(&backlog, &chunk);
                            let _ = reader_events.send(TerminalEvent::Output(chunk));
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

    pub fn get(&self, id: Uuid) -> Result<TerminalHandle, TerminalError> {
        self.read_sessions()
            .get(&id)
            .cloned()
            .map(|session| TerminalHandle { session })
            .ok_or(TerminalError::NotFound)
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

#[derive(Clone)]
pub struct TerminalHandle {
    session: Arc<TerminalSession>,
}

impl TerminalHandle {
    #[must_use]
    pub fn summary(&self) -> TerminalSummary {
        self.session.summary()
    }

    #[must_use]
    pub fn snapshot_and_subscribe(
        &self,
    ) -> (TerminalSummary, Vec<u8>, broadcast::Receiver<TerminalEvent>) {
        let backlog = self
            .session
            .backlog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = self.session.events.subscribe();
        let snapshot = backlog.iter().copied().collect();
        (self.summary(), snapshot, events)
    }

    pub fn write(&self, input: &[u8]) -> Result<(), TerminalError> {
        if input.len() > 4096 {
            return Err(TerminalError::Closed);
        }
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
        self.session.terminate()
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

fn append_backlog(backlog: &Mutex<VecDeque<u8>>, chunk: &[u8]) {
    let mut backlog = backlog
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let overflow = backlog
        .len()
        .saturating_add(chunk.len())
        .saturating_sub(BACKLOG_LIMIT);
    let drain_count = overflow.min(backlog.len());
    backlog.drain(..drain_count);
    backlog.extend(chunk);
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
    use std::{collections::VecDeque, sync::Mutex};

    use super::{BACKLOG_LIMIT, TerminalError, append_backlog, validate_size};

    #[test]
    fn terminal_size_has_safe_bounds() {
        assert_eq!(validate_size(24, 80), Ok(()));
        assert_eq!(validate_size(1, 80), Err(TerminalError::InvalidSize));
        assert_eq!(validate_size(24, 501), Err(TerminalError::InvalidSize));
    }

    #[test]
    fn backlog_retains_only_the_newest_bytes() {
        let backlog = Mutex::new(VecDeque::new());
        append_backlog(&backlog, &vec![1; BACKLOG_LIMIT]);
        append_backlog(&backlog, &[2, 3]);
        let backlog = backlog.into_inner().expect("backlog lock");
        assert_eq!(backlog.len(), BACKLOG_LIMIT);
        assert_eq!(backlog[BACKLOG_LIMIT - 2], 2);
        assert_eq!(backlog[BACKLOG_LIMIT - 1], 3);
    }
}
