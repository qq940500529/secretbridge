// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unused_async_trait_impl,
    reason = "in-memory protocol fixture implements the async SFTP contract"
)]

use super::*;
use crate::{
    catalog::{CreateSyntheticRun, DecideApproval, RunState},
    ssh_task::tests::{Fixture, SECRET, server, wait},
};
use russh_sftp::protocol::{Attrs, Data, Handle, Status, Version};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

pub(crate) type RemoteFiles = Arc<Mutex<HashMap<String, Vec<u8>>>>;
pub(crate) struct MemorySftp {
    files: RemoteFiles,
    slow: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    handles: HashMap<String, String>,
}
impl MemorySftp {
    pub fn new(files: RemoteFiles, slow: Arc<AtomicBool>, writes: Arc<AtomicUsize>) -> Self {
        Self {
            files,
            slow,
            writes,
            handles: HashMap::new(),
        }
    }
    fn status(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "ok".into(),
            language_tag: "en".into(),
        }
    }
    fn attrs(&self, id: u32, path: &str) -> Result<Attrs, StatusCode> {
        let files = self.files.lock().unwrap();
        let bytes = files.get(path).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(bytes.len() as u64),
                permissions: Some(0o100_600),
                ..FileAttributes::default()
            },
        })
    }
}
impl russh_sftp::server::Handler for MemorySftp {
    type Error = StatusCode;
    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }
    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, StatusCode> {
        let mut version = Version::new();
        if !self.files.lock().unwrap().contains_key("/no-posix") {
            version.extensions.insert(POSIX_RENAME.into(), "1".into());
        }
        Ok(version)
    }
    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        self.attrs(id, &path)
    }
    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, StatusCode> {
        self.attrs(id, self.handles.get(&handle).ok_or(StatusCode::Failure)?)
    }
    async fn open(
        &mut self,
        id: u32,
        path: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, StatusCode> {
        let mut files = self.files.lock().unwrap();
        if flags.contains(OpenFlags::CREATE) {
            if flags.contains(OpenFlags::EXCLUDE) && files.contains_key(&path) {
                return Err(StatusCode::Failure);
            }
            files.entry(path.clone()).or_default();
        }
        if !files.contains_key(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = Uuid::new_v4().to_string();
        self.handles.insert(handle.clone(), path);
        Ok(Handle { id, handle })
    }
    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusCode> {
        self.handles.remove(&handle);
        Ok(Self::status(id))
    }
    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusCode> {
        let path = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let files = self.files.lock().unwrap();
        let data = files.get(path).ok_or(StatusCode::NoSuchFile)?;
        if data.starts_with(b"FAILREAD") {
            return Err(StatusCode::Failure);
        }
        let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        if offset >= data.len() {
            return Err(StatusCode::Eof);
        }
        Ok(Data {
            id,
            data: data[offset..(offset + len as usize).min(data.len())].to_vec(),
        })
    }
    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusCode> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.slow.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let path = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let mut files = self.files.lock().unwrap();
        let bytes = files.get_mut(path).ok_or(StatusCode::NoSuchFile)?;
        let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        bytes.resize((start + data.len()).max(bytes.len()), 0);
        bytes[start..start + data.len()].copy_from_slice(&data);
        if data.starts_with(b"FAILWRITE") {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(Self::status(id))
    }
    async fn remove(&mut self, id: u32, path: String) -> Result<Status, StatusCode> {
        if self.files.lock().unwrap().contains_key("/reject-cleanup") {
            return Err(StatusCode::PermissionDenied);
        }
        self.files
            .lock()
            .unwrap()
            .remove(&path)
            .ok_or(StatusCode::NoSuchFile)?;
        Ok(Self::status(id))
    }
    async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, StatusCode> {
        let mut files = self.files.lock().unwrap();
        if files.contains_key(&to) {
            return Err(StatusCode::Failure);
        }
        let data = files.remove(&from).ok_or(StatusCode::NoSuchFile)?;
        files.insert(to, data);
        Ok(Self::status(id))
    }
    async fn extended(
        &mut self,
        id: u32,
        name: String,
        mut data: Vec<u8>,
    ) -> Result<Packet, StatusCode> {
        if name != POSIX_RENAME {
            return Err(StatusCode::OpUnsupported);
        }
        let mut paths = Vec::new();
        for _ in 0..2 {
            let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
            paths.push(String::from_utf8(data[4..4 + len].to_vec()).unwrap());
            data.drain(..4 + len);
        }
        let mut files = self.files.lock().unwrap();
        let bytes = files.remove(&paths[0]).ok_or(StatusCode::NoSuchFile)?;
        files.insert(paths[1].clone(), bytes);
        Ok(Packet::Status(Self::status(id)))
    }
}

pub(crate) struct LocalDirectory(pub PathBuf);
impl LocalDirectory {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("secretbridge-transfer-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for LocalDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn configure(
    state: &AppState,
    fixture: &Fixture,
    local: &Path,
    direction: Direction,
    overwrite: bool,
    timeout: u64,
) -> Uuid {
    let template = crate::ssh_task::tests::configure(state, fixture, timeout);
    let template = state
        .catalog
        .list_action_templates()
        .unwrap()
        .into_iter()
        .find(|t| t.id == template)
        .unwrap();
    let mut command = template.command.unwrap();
    command.parameters.clear();
    let ssh = command.ssh.as_mut().unwrap();
    ssh.arguments.clear();
    ssh.remote_program.clear();
    ssh.transfer = Some(TransferConfig {
        direction,
        local_path: local.to_string_lossy().into_owned(),
        remote_path: "/fixture.bin".into(),
        overwrite,
        max_bytes: 1_048_576,
    });
    state.catalog.update_action_template(template.id, &serde_json::from_value(json!({"name":template.name,"target_id":template.target_id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"expected_version":template.version,"enabled":true,"command":command})).unwrap()).unwrap().id
}
pub(crate) async fn start(state: &AppState, template: Uuid) -> Uuid {
    let approval = state
        .catalog
        .create_approval(
            &serde_json::from_value(json!({"action_template_id":template,"expires_in_seconds":60}))
                .unwrap(),
        )
        .unwrap();
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
    crate::create_run_for_state(
        state,
        CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: Uuid::new_v4().to_string(),
        },
    )
    .await
    .unwrap()
    .run
    .id
}
pub(crate) fn output(page: &crate::command::OutputPage) -> String {
    page.items.iter().map(|i| i.text.as_str()).collect()
}

#[tokio::test]
async fn real_sftp_upload_download_and_overwrite_preserve_complete_files() {
    let fixture = server().await;
    let directory = LocalDirectory::new();
    let source = directory.0.join("原始 文件.bin");
    let bytes = (0..70000)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect::<Vec<_>>();
    std::fs::write(&source, &bytes).unwrap();
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, &source, Direction::Upload, false, 10);
    let page = wait(&state, start(&state, template).await).await;
    assert_eq!(page.state, RunState::Succeeded, "{}", output(&page));
    assert_eq!(page.exit_code, Some(0));
    assert!(output(&page).contains("70000"));
    assert!(!output(&page).contains(SECRET));
    assert_eq!(fixture.files.lock().unwrap()["/fixture.bin"], bytes);
    let page = wait(&state, start(&state, template).await).await;
    assert_eq!(page.state, RunState::Failed);
    assert!(output(&page).contains("destination_exists"));
    let destination = directory.0.join("下载.bin");
    let template = configure(
        &state,
        &fixture,
        &destination,
        Direction::Download,
        false,
        10,
    );
    let page = wait(&state, start(&state, template).await).await;
    assert_eq!(page.state, RunState::Succeeded, "{}", output(&page));
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    std::fs::write(&source, b"new complete file").unwrap();
    let template = configure(&state, &fixture, &source, Direction::Upload, true, 10);
    assert_eq!(
        wait(&state, start(&state, template).await).await.state,
        RunState::Succeeded
    );
    assert_eq!(
        fixture.files.lock().unwrap()["/fixture.bin"],
        b"new complete file"
    );
    let template = configure(
        &state,
        &fixture,
        &destination,
        Direction::Download,
        true,
        10,
    );
    assert_eq!(
        wait(&state, start(&state, template).await).await.state,
        RunState::Succeeded
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"new complete file");
    assert!(!fixture.files.lock().unwrap().keys().any(|p| {
        Path::new(p)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("part"))
    }));
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[tokio::test]
async fn real_sftp_timeout_and_cancel_clean_partial_upload_without_replacing_destination() {
    for cancelling in [false, true] {
        let fixture = server().await;
        fixture.slow_writes.store(true, Ordering::SeqCst);
        fixture
            .files
            .lock()
            .unwrap()
            .insert("/fixture.bin".into(), b"preserved".to_vec());
        let directory = LocalDirectory::new();
        let source = directory.0.join("source.bin");
        std::fs::write(&source, vec![1u8; 1_048_576]).unwrap();
        let (state, _) = AppState::new([]);
        let template = configure(
            &state,
            &fixture,
            &source,
            Direction::Upload,
            true,
            if cancelling { 10 } else { 1 },
        );
        let id = start(&state, template).await;
        if cancelling {
            tokio::time::timeout(Duration::from_secs(5), async {
                while fixture.write_hits.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let current = state.catalog.get_synthetic_run(id).unwrap();
            crate::cancel_run_for_state(
                &state,
                id,
                crate::catalog::CancelSyntheticRun {
                    expected_version: current.version,
                },
            )
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while state
                    .run_cancellations
                    .active
                    .lock()
                    .await
                    .contains_key(&id)
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        let page = wait(&state, id).await;
        assert_eq!(
            page.state,
            if cancelling {
                RunState::Cancelled
            } else {
                RunState::Failed
            }
        );
        assert!(output(&page).contains(if cancelling { "cancelled" } else { "timed_out" }));
        assert!(output(&page).contains("\"cleanup_ok\":true"));
        let files = fixture.files.lock().unwrap();
        assert_eq!(files["/fixture.bin"], b"preserved");
        assert_eq!(files.len(), 1);
    }
}

#[tokio::test]
async fn sftp_size_limit_and_missing_source_leave_no_download_file() {
    let fixture = server().await;
    fixture
        .files
        .lock()
        .unwrap()
        .insert("/fixture.bin".into(), vec![1u8; 1_048_577]);
    let directory = LocalDirectory::new();
    let destination = directory.0.join("target.bin");
    let (state, _) = AppState::new([]);
    let template = configure(
        &state,
        &fixture,
        &destination,
        Direction::Download,
        false,
        10,
    );
    let page = wait(&state, start(&state, template).await).await;
    assert!(output(&page).contains("size_limit"));
    assert!(!destination.exists());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    fixture.files.lock().unwrap().clear();
    let page = wait(&state, start(&state, template).await).await;
    assert!(output(&page).contains("source_missing"));
    assert!(!destination.exists());
}

#[test]
fn sftp_paths_and_limits_are_validated() {
    let directory = LocalDirectory::new();
    let mut config = TransferConfig {
        direction: Direction::Download,
        local_path: directory.0.join("file").to_string_lossy().into_owned(),
        remote_path: "/file".into(),
        overwrite: false,
        max_bytes: 1,
    };
    assert!(config.validate().is_ok());
    for remote in ["file", "/file/", "/../file", "/./file", "/file\n"] {
        config.remote_path = remote.into();
        assert!(config.validate().is_err());
    }
    config.remote_path = "/file".into();
    config.max_bytes = 0;
    assert!(config.validate().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn web_creates_sftp_and_git_templates_approves_executes_and_reads_results() {
    use crate::command::tests::web_request;
    use crate::git_task::{Operation, integration_tests as git};
    use axum::http::StatusCode;
    let fixture = server().await;
    let git = git::server().await;
    let directory = LocalDirectory::new();
    let source = directory.0.join("source.bin");
    std::fs::write(&source, b"Web transfer contents").unwrap();
    for transferring in [true, false] {
        let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
        let template = if transferring {
            configure(&state, &fixture, &source, Direction::Upload, false, 10)
        } else {
            git::configure(&state, &git, Operation::Inspect, &git.url, 10)
        };
        let current = state
            .catalog
            .list_action_templates()
            .unwrap()
            .into_iter()
            .find(|t| t.id == template)
            .unwrap();
        let (token, _) = state.issue_session().await;
        let (status, template) = web_request(&state, &token, "/api/v1/action-templates", json!({"name":"Web connector fixture","target_id":current.target_id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":10,"command":current.command})).await;
        assert_eq!(status, StatusCode::CREATED, "{template}");
        let (status, approval) = web_request(
            &state,
            &token,
            "/api/v1/approvals",
            json!({"action_template_id":template["id"],"expires_in_seconds":60}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
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
        assert!(!page.to_string().contains(SECRET));
        assert!(!page.to_string().contains(git::TOKEN));
        if transferring {
            assert_eq!(
                fixture.files.lock().unwrap()["/fixture.bin"],
                b"Web transfer contents"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn transfer_and_git_configuration_and_results_survive_sqlite_reopen() {
    use crate::git_task::{Operation, integration_tests as git};
    let fixture = server().await;
    let git = git::server().await;
    let directory = LocalDirectory::new();
    let source = directory.0.join("source.bin");
    let path = directory.0.join("catalog.sqlite3");
    std::fs::write(&source, b"persistent transfer contents").unwrap();
    let (mut state, _) = AppState::new([]);
    state.catalog = crate::catalog::Catalog::open(&path).unwrap();
    let sftp = configure(&state, &fixture, &source, Direction::Upload, false, 10);
    let git = git::configure(&state, &git, Operation::Inspect, &git.url, 10);
    let mut ids = Vec::new();
    for template in [sftp, git] {
        let id = start(&state, template).await;
        assert_eq!(wait(&state, id).await.state, RunState::Succeeded);
        ids.push(id);
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.run_cancellations.active.lock().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(state);
    let catalog = crate::catalog::Catalog::open(&path).unwrap();
    let templates = catalog.list_action_templates().unwrap();
    assert_eq!(templates.len(), 2);
    for template in &templates {
        assert!(template.command.as_ref().unwrap().validate().is_ok());
    }
    for id in ids {
        assert_eq!(catalog.output(id, 0).unwrap().exit_code, Some(0));
    }
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .windows(git::TOKEN.len())
            .any(|b| b == git::TOKEN.as_bytes())
    );
}

#[tokio::test]
async fn sftp_failed_download_cleans_local_partial_and_preserves_existing_file() {
    let fixture = server().await;
    fixture
        .files
        .lock()
        .unwrap()
        .insert("/fixture.bin".into(), b"FAILREAD".to_vec());
    let directory = LocalDirectory::new();
    let destination = directory.0.join("file.bin");
    std::fs::write(&destination, b"preserved").unwrap();
    let (state, _) = AppState::new([]);
    let template = configure(
        &state,
        &fixture,
        &destination,
        Direction::Download,
        true,
        10,
    );
    let page = wait(&state, start(&state, template).await).await;
    assert_eq!(page.state, RunState::Failed);
    assert!(output(&page).contains("remote_read_failed"));
    assert!(output(&page).contains("\"cleanup_ok\":true"));
    assert_eq!(std::fs::read(&destination).unwrap(), b"preserved");
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[tokio::test]
async fn sftp_reports_cleanup_failure_and_missing_atomic_rename_without_erasing_destination() {
    for unsupported in [false, true] {
        let fixture = server().await;
        fixture
            .files
            .lock()
            .unwrap()
            .insert("/fixture.bin".into(), b"preserved".to_vec());
        fixture.files.lock().unwrap().insert(
            if unsupported {
                "/no-posix"
            } else {
                "/reject-cleanup"
            }
            .into(),
            vec![],
        );
        let directory = LocalDirectory::new();
        let source = directory.0.join("file.bin");
        std::fs::write(&source, b"FAILWRITE").unwrap();
        let (state, _) = AppState::new([]);
        let template = configure(&state, &fixture, &source, Direction::Upload, true, 10);
        let page = wait(&state, start(&state, template).await).await;
        assert_eq!(page.state, RunState::Failed);
        assert!(output(&page).contains(if unsupported {
            "atomic_overwrite_unsupported"
        } else {
            "remote_write_failed"
        }));
        assert!(output(&page).contains(if unsupported {
            "\"cleanup_ok\":true"
        } else {
            "\"cleanup_ok\":false"
        }));
        assert_eq!(fixture.files.lock().unwrap()["/fixture.bin"], b"preserved");
        assert_eq!(
            fixture.files.lock().unwrap().len(),
            if unsupported { 2 } else { 3 }
        );
    }
}
