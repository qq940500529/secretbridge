// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rmcp::ErrorData;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{task, time::timeout};
use uuid::Uuid;

use crate::terminal::{
    CreateTerminal, TerminalConnection, TerminalError, TerminalManager, TerminalStatus,
};

const ATTACHMENT_TTL: Duration = Duration::from_secs(60);
const MAX_ATTACHMENTS: usize = 32;

#[derive(Clone, Default)]
pub struct TerminalControls {
    attachments: Arc<Mutex<HashMap<(Uuid, Uuid), Attachment>>>,
}

struct Attachment {
    connection: Arc<TerminalConnection>,
    expires: Instant,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminalIdParams {
    pub id: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachParams {
    pub id: String,
    #[serde(default)]
    pub request_input: bool,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteParams {
    pub id: String,
    pub data: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadParams {
    pub id: String,
    pub cursor: u64,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default)]
    pub wait_ms: u64,
}

const fn default_max_bytes() -> usize {
    8192
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResizeParams {
    pub id: String,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalRequest {
    Capabilities,
    List,
    Create { request: CreateTerminal },
    Attach { request: AttachParams },
    Read { request: ReadParams },
    Write { request: WriteParams },
    Resize { request: ResizeParams },
    Interrupt { request: TerminalIdParams },
    Detach { request: TerminalIdParams },
    Close { request: TerminalIdParams },
    Release,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedTerminalRequest {
    // Internal MCP-session identity, never taken from a public tool argument.
    pub actor: Uuid,
    pub request: TerminalRequest,
}

impl TerminalControls {
    pub fn expire(&self) {
        self.attachments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, attachment| attachment.expires > Instant::now());
    }

    fn release(&self, actor: Uuid, id: Option<Uuid>) {
        self.attachments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(owner, terminal), _| *owner != actor || id.is_some_and(|id| *terminal != id));
    }

    fn connection(&self, actor: Uuid, id: Uuid) -> Result<Arc<TerminalConnection>, ErrorData> {
        self.expire();
        let mut attachments = self
            .attachments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let attachment = attachments
            .get_mut(&(actor, id))
            .ok_or_else(|| ErrorData::invalid_params("terminal_attach_required", None))?;
        attachment.expires = Instant::now() + ATTACHMENT_TTL;
        Ok(attachment.connection.clone())
    }

    fn attach(
        &self,
        manager: &TerminalManager,
        actor: Uuid,
        request: &AttachParams,
    ) -> Result<Value, ErrorData> {
        let id = identifier(&request.id)?;
        let mut attachments = self
            .attachments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if attachments.len() >= MAX_ATTACHMENTS && !attachments.contains_key(&(actor, id)) {
            return Err(ErrorData::invalid_params("capacity_exceeded", None));
        }
        let (connection, snapshot) = manager
            .attach(id, actor, request.request_input, None)
            .map_err(terminal_error)?;
        attachments.insert(
            (actor, id),
            Attachment {
                connection: Arc::new(connection),
                expires: Instant::now() + ATTACHMENT_TTL,
            },
        );
        Ok(
            json!({"terminal": snapshot.summary, "input_granted": snapshot.input_granted,
            "oldest_cursor": snapshot.replay_from, "next_cursor": snapshot.next_cursor,
            "idle_timeout_seconds": ATTACHMENT_TTL.as_secs()}),
        )
    }

    pub async fn execute(
        &self,
        manager: &TerminalManager,
        owned: OwnedTerminalRequest,
    ) -> Result<Value, ErrorData> {
        self.expire();
        let actor = owned.actor;
        match owned.request {
            TerminalRequest::Capabilities => encode(manager.capabilities()),
            TerminalRequest::List => Ok(json!({"items": manager.list()})),
            TerminalRequest::Create { request } => {
                let manager = manager.clone();
                let terminal = task::spawn_blocking(move || manager.create(&request))
                    .await
                    .map_err(|_| internal_error())?
                    .map_err(terminal_error)?;
                Ok(json!({"terminal": terminal}))
            }
            TerminalRequest::Attach { request } => self.attach(manager, actor, &request),
            TerminalRequest::Read { request } => {
                if !(1..=16384).contains(&request.max_bytes) || request.wait_ms > 5000 {
                    return Err(ErrorData::invalid_params("invalid_request", None));
                }
                let connection = self.connection(actor, identifier(&request.id)?)?;
                let mut events = connection.subscribe();
                let mut output = connection.read(request.cursor, request.max_bytes);
                if output.bytes.is_empty()
                    && output.terminal.status == TerminalStatus::Running
                    && request.wait_ms > 0
                {
                    let _ = timeout(Duration::from_millis(request.wait_ms), events.recv()).await;
                    output = connection.read(request.cursor, request.max_bytes);
                }
                encode(output)
            }
            TerminalRequest::Write { request } => {
                let connection = self.connection(actor, identifier(&request.id)?)?;
                task::spawn_blocking(move || {
                    connection
                        .write(request.data.as_bytes())
                        .map_err(terminal_error)?;
                    Ok(json!({"terminal": connection.summary(), "input_written": true}))
                })
                .await
                .map_err(|_| internal_error())?
            }
            TerminalRequest::Resize { request } => {
                let connection = self.connection(actor, identifier(&request.id)?)?;
                task::spawn_blocking(move || {
                    connection
                        .resize(request.rows, request.cols)
                        .map_err(terminal_error)?;
                    Ok(json!({"terminal": connection.summary()}))
                })
                .await
                .map_err(|_| internal_error())?
            }
            TerminalRequest::Interrupt { request } => {
                let connection = self.connection(actor, identifier(&request.id)?)?;
                task::spawn_blocking(move || {
                    connection.write(b"\x03").map_err(terminal_error)?;
                    Ok(json!({"terminal": connection.summary(), "interrupt_sent": true}))
                })
                .await
                .map_err(|_| internal_error())?
            }
            TerminalRequest::Detach { request } => {
                let id = identifier(&request.id)?;
                self.release(actor, Some(id));
                Ok(json!({"id": id, "detached": true}))
            }
            TerminalRequest::Close { request } => {
                let id = identifier(&request.id)?;
                let connection = self.connection(actor, id)?;
                let manager = manager.clone();
                task::spawn_blocking(move || {
                    connection.terminate().map_err(terminal_error)?;
                    manager.remove(id).map_err(terminal_error)
                })
                .await
                .map_err(|_| internal_error())??;
                // Other attachments cannot operate the removed process.
                self.attachments
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|(_, terminal), _| *terminal != id);
                Ok(json!({"id": id, "closed": true}))
            }
            TerminalRequest::Release => {
                self.release(actor, None);
                Ok(json!({"released": true}))
            }
        }
    }
}

fn identifier(value: &str) -> Result<Uuid, ErrorData> {
    Uuid::parse_str(value).map_err(|_| ErrorData::invalid_params("invalid_request", None))
}

fn encode(value: impl Serialize) -> Result<Value, ErrorData> {
    serde_json::to_value(value).map_err(|_| internal_error())
}

fn internal_error() -> ErrorData {
    ErrorData::internal_error("secretbridge_operation_failed", None)
}

fn terminal_error(error: TerminalError) -> ErrorData {
    let code = match error {
        TerminalError::NotFound => "not_found",
        TerminalError::InputLeaseRequired => "terminal_input_required",
        TerminalError::Busy => "approved_command_running",
        TerminalError::Closed => "terminal_closed",
        TerminalError::Capacity => "capacity_exceeded",
        TerminalError::SpawnFailed => "terminal_spawn_failed",
        TerminalError::UnsupportedShell => "terminal_unsupported_shell",
        _ => "invalid_request",
    };
    ErrorData::invalid_params(code, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_mcp_attachment_releases_input_but_preserves_process() {
        let manager = TerminalManager::system();
        let terminal = manager
            .create(&CreateTerminal {
                rows: 24,
                cols: 80,
                shell: None,
                name: None,
                working_directory: None,
                environment: std::collections::BTreeMap::default(),
            })
            .expect("real terminal");
        let controls = TerminalControls::default();
        let actor = Uuid::new_v4();
        let attached = controls
            .execute(
                &manager,
                OwnedTerminalRequest {
                    actor,
                    request: TerminalRequest::Attach {
                        request: AttachParams {
                            id: terminal.id.to_string(),
                            request_input: true,
                        },
                    },
                },
            )
            .await
            .expect("attach");
        assert_eq!(attached["input_granted"], true);
        controls
            .attachments
            .lock()
            .expect("attachments")
            .get_mut(&(actor, terminal.id))
            .expect("attachment")
            .expires = Instant::now();
        controls.expire();
        assert!(controls.connection(actor, terminal.id).is_err());
        let (user, snapshot) = manager
            .attach(terminal.id, Uuid::new_v4(), true, None)
            .expect("user attaches");
        assert!(
            snapshot.input_granted,
            "crashed MCP client cannot retain the input lease forever"
        );
        assert_eq!(snapshot.summary.status, TerminalStatus::Running);
        let read = user.read(snapshot.replay_from, 1);
        assert!(read.bytes.len() <= 1);
        assert_eq!(read.next_cursor - read.cursor, read.bytes.len() as u64);
        manager.remove(terminal.id).expect("cleanup terminal");
    }

    #[test]
    fn internal_actor_and_read_limits_are_not_silently_coerced() {
        assert!(
            serde_json::from_value::<ReadParams>(json!({"id":"id", "cursor":0, "actor":"spoofed"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<OwnedTerminalRequest>(
                json!({"actor":"invalid", "request":{"operation":"list"}})
            )
            .is_err()
        );
        let defaults: ReadParams =
            serde_json::from_value(json!({"id":"id", "cursor":0})).expect("defaults");
        assert_eq!(defaults.max_bytes, 8192);
        assert_eq!(defaults.wait_ms, 0);
    }
}
