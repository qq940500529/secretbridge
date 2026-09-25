// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::{
    AppState,
    catalog::RunState,
    sftp_task::tests::{LocalDirectory, output, start},
    ssh_task::tests::wait,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Response, StatusCode},
    routing::any,
};
use serde_json::json;
use std::{
    io::Write,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

pub(crate) const TOKEN: &str = "Synthetic-Git-token_A&z";
const USER: &str = "synthetic-user";
pub(crate) struct Fixture {
    directory: LocalDirectory,
    pub git: PathBuf,
    pub work: PathBuf,
    bare: PathBuf,
    pub url: String,
    pub hits: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    fn shutdown(&self) {
        self.server.abort();
    }
}
pub(crate) fn executable() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join(if cfg!(windows) { "git.exe" } else { "git" }))
        .find(|p| p.is_file())
        .expect("Git must be installed for connector integration tests")
}
fn git_command(git: &Path, work: &Path, arguments: &[&str]) -> String {
    let result = Command::new(git)
        .current_dir(work)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

#[derive(Clone)]
struct HttpState {
    git: PathBuf,
    root: PathBuf,
    hits: Arc<AtomicUsize>,
}

#[allow(
    clippy::too_many_lines,
    reason = "local smart-HTTP fixture translates one CGI request without external services"
)]
async fn backend(State(state): State<HttpState>, request: Request) -> Response<Body> {
    let expected = format!("Basic {}", STANDARD.encode(format!("{USER}:{TOKEN}")));
    if request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        != Some(&expected)
    {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=fixture")
            .body(Body::from("authentication required"))
            .unwrap();
    }
    state.hits.fetch_add(1, Ordering::SeqCst);
    let path = request.uri().path().to_owned();
    if path.starts_with("/slow.git/") {
        tokio::time::sleep(Duration::from_secs(5)).await;
        return Response::builder().status(503).body(Body::empty()).unwrap();
    }
    if path.starts_with("/redirect.git/") {
        return Response::builder()
            .status(302)
            .header("location", "/trap.git/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
    }
    if path.starts_with("/trap.git/") {
        state.hits.fetch_add(1000, Ordering::SeqCst);
    }
    if path.starts_with("/error.git/") {
        return Response::builder()
            .status(401)
            .header(
                "WWW-Authenticate",
                format!("Basic realm={expected}-{TOKEN}"),
            )
            .body(Body::empty())
            .unwrap();
    }
    let method = request.method().to_string();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = to_bytes(request.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(&state.git)
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", &state.root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env("REQUEST_METHOD", method)
            .env("CONTENT_TYPE", content_type)
            .env("CONTENT_LENGTH", body.len().to_string())
            .env("REMOTE_USER", USER)
            .env("SERVER_PROTOCOL", "HTTP/1.1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&body).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let boundary = output
            .stdout
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&output.stdout[..boundary]);
        let mut response = Response::builder();
        for line in headers.lines() {
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("status") {
                response = response.status(
                    value
                        .trim()
                        .split(' ')
                        .next()
                        .unwrap()
                        .parse::<u16>()
                        .unwrap(),
                );
            } else {
                response = response.header(name.trim(), value.trim());
            }
        }
        response
            .body(Body::from(output.stdout[boundary + 4..].to_vec()))
            .unwrap()
    })
    .await
    .unwrap()
}

pub(crate) async fn server() -> Fixture {
    let directory = LocalDirectory::new();
    let git = executable();
    let bare = directory.0.join("repo.git");
    let work = directory.0.join("work");
    std::fs::create_dir(&work).unwrap();
    git_command(
        &git,
        &directory.0,
        &["init", "--bare", bare.to_str().unwrap()],
    );
    git_command(&git, &work, &["init", "-b", "main"]);
    git_command(
        &git,
        &work,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ],
    );
    git_command(&git, &work, &["push", bare.to_str().unwrap(), "main"]);
    git_command(&git, &bare, &["config", "http.receivepack", "true"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/repo.git", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/{*path}", any(backend))
        .with_state(HttpState {
            git: git.clone(),
            root: directory.0.clone(),
            hits: hits.clone(),
        });
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        directory,
        git,
        work,
        bare,
        url,
        hits,
        server,
    }
}

pub(crate) fn configure(
    state: &AppState,
    fixture: &Fixture,
    operation: Operation,
    url: &str,
    timeout: u64,
) -> Uuid {
    let credential = state
        .catalog
        .create_credential_reference(
            &serde_json::from_value(json!({"name":"Git fixture","kind":"api_token"})).unwrap(),
        )
        .unwrap();
    state.secret_store.set(credential.id, TOKEN).unwrap();
    state
        .catalog
        .set_credential_secret_state(credential.id, credential.version, true)
        .unwrap();
    let target = state
        .catalog
        .create_target(
            &serde_json::from_value(
                json!({"name":"Git fixture","kind":"http_service","environment":"test"}),
            )
            .unwrap(),
        )
        .unwrap();
    let command = json!({"program":fixture.git,"working_directory":fixture.work,"arguments":[],"slots":[{"name":"token","credential_id":credential.id,"injection":"protocol","environment_variable":null}],"git":{"operation":operation,"remote_url":url,"branch":"main","username":USER,"token_slot":"token"}});
    state.catalog.create_action_template(&serde_json::from_value(json!({"name":"Git fixture","target_id":target.id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"command":command})).unwrap()).unwrap().id
}

#[tokio::test(flavor = "multi_thread")]
async fn git_http_auth_inspect_fetch_push_use_real_git_and_leave_no_credentials() {
    let fixture = server().await;
    let (state, _) = AppState::new([]);
    for operation in [Operation::Inspect, Operation::Fetch, Operation::Push] {
        if operation == Operation::Fetch {
            let seed = fixture.directory.0.join("seed");
            git_command(
                &fixture.git,
                &fixture.directory.0,
                &[
                    "clone",
                    "-b",
                    "main",
                    fixture.bare.to_str().unwrap(),
                    seed.to_str().unwrap(),
                ],
            );
            git_command(
                &fixture.git,
                &seed,
                &[
                    "-c",
                    "user.name=Synthetic",
                    "-c",
                    "user.email=synthetic@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-m",
                    "remote next",
                ],
            );
            git_command(&fixture.git, &seed, &["push", "origin", "main"]);
        }
        if operation == Operation::Push {
            git_command(
                &fixture.git,
                &fixture.work,
                &["merge", "--ff-only", "refs/remotes/secretbridge/main"],
            );
            git_command(
                &fixture.git,
                &fixture.work,
                &[
                    "-c",
                    "user.name=Synthetic",
                    "-c",
                    "user.email=synthetic@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-m",
                    "next",
                ],
            );
        }
        let template = configure(&state, &fixture, operation, &fixture.url, 10);
        let page = wait(&state, start(&state, template).await).await;
        assert_eq!(page.state, RunState::Succeeded, "{}", output(&page));
        assert_eq!(page.exit_code, Some(0));
        if operation == Operation::Fetch {
            let remote = git_command(&fixture.git, &fixture.bare, &["rev-parse", "main"]);
            assert_eq!(
                git_command(
                    &fixture.git,
                    &fixture.work,
                    &["rev-parse", "refs/remotes/secretbridge/main"]
                ),
                remote
            );
            assert_ne!(
                git_command(&fixture.git, &fixture.work, &["rev-parse", "main"]),
                remote,
                "fetch must not update the working branch"
            );
        }
        assert!(!output(&page).contains(TOKEN));
        assert!(!output(&page).contains(&STANDARD.encode(format!("{USER}:{TOKEN}"))));
    }
    assert!(fixture.hits.load(Ordering::SeqCst) >= 5);
    assert_eq!(
        git_command(&fixture.git, &fixture.work, &["rev-parse", "main"]),
        git_command(&fixture.git, &fixture.bare, &["rev-parse", "main"])
    );
    assert!(
        git_command(
            &fixture.git,
            &fixture.work,
            &["rev-parse", "refs/remotes/secretbridge/main"]
        )
        .len()
            >= 40
    );
    let config = std::fs::read_to_string(fixture.work.join(".git/config")).unwrap();
    assert!(!config.contains(TOKEN));
    assert!(!config.contains("extraHeader"));
    assert_eq!(std::fs::read_dir(&fixture.work).unwrap().count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redirect_error_timeout_and_cancel_have_bounded_results() {
    let fixture = server().await;
    let (state, _) = AppState::new([]);
    for suffix in ["redirect", "error", "missing"] {
        let url = fixture.url.replace("repo.git", &format!("{suffix}.git"));
        let template = configure(&state, &fixture, Operation::Inspect, &url, 10);
        let page = wait(&state, start(&state, template).await).await;
        assert_eq!(page.state, RunState::Failed);
        assert!(!output(&page).contains(TOKEN));
        assert!(!output(&page).contains(&STANDARD.encode(format!("{USER}:{TOKEN}"))));
    }
    assert!(
        fixture.hits.load(Ordering::SeqCst) < 1000,
        "redirect destination must not be contacted"
    );
    for cancelling in [false, true] {
        let url = fixture.url.replace("repo.git", "slow.git");
        let before = fixture.hits.load(Ordering::SeqCst);
        let template = configure(
            &state,
            &fixture,
            Operation::Inspect,
            &url,
            if cancelling { 10 } else { 1 },
        );
        let id = start(&state, template).await;
        if cancelling {
            tokio::time::timeout(Duration::from_secs(5), async {
                while fixture.hits.load(Ordering::SeqCst) == before {
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
        assert_eq!(
            state
                .catalog
                .get_synthetic_run(id)
                .unwrap()
                .result_status
                .as_deref(),
            Some(if cancelling { "cancelled" } else { "timed_out" })
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn git_service_interruption_returns_a_bounded_sanitized_failure() {
    let fixture = server().await;
    let (state, _) = AppState::new([]);
    let url = fixture.url.replace("repo.git", "slow.git");
    let template = configure(&state, &fixture, Operation::Inspect, &url, 10);
    let id = start(&state, template).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fixture.shutdown();
    let page = wait(&state, id).await;
    assert_eq!(page.state, RunState::Failed);
    let text = output(&page);
    assert!(text.contains("git_failed"), "{text}");
    assert!(!text.contains(TOKEN));
    assert!(!text.contains(&STANDARD.encode(format!("{USER}:{TOKEN}"))));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.run_cancellations.active.lock().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.command_capacity.available_permits(), 4);
}

#[tokio::test]
async fn git_schema_rejects_credential_urls_non_loopback_http_and_missing_slot() {
    let fixture = server().await;
    let (state, _) = AppState::new([]);
    let template = configure(&state, &fixture, Operation::Inspect, &fixture.url, 10);
    let mut command = state
        .catalog
        .list_action_templates()
        .unwrap()
        .into_iter()
        .find(|t| t.id == template)
        .unwrap()
        .command
        .unwrap();
    for url in [
        "http://example.com/repo.git",
        "ssh://example.com/repo.git",
        "https://example.com/repo.git?token=x",
        "https://example.com/repo.git#x",
        "https://user@example.com/repo.git",
    ] {
        command.git.as_mut().unwrap().remote_url = url.into();
        assert!(command.validate().is_err());
    }
    command
        .git
        .as_mut()
        .unwrap()
        .remote_url
        .clone_from(&fixture.url);
    assert!(command.validate().is_ok());
    let prepared = command
        .git
        .as_ref()
        .unwrap()
        .prepare(&command, &[Zeroizing::new(TOKEN.into())])
        .unwrap();
    assert!(!prepared.0.arguments.iter().any(|a| a.contains(TOKEN)));
    for secret in &prepared.1 {
        let mut redactor = crate::application::redaction::Redactor::new(&prepared.1);
        let text = redactor.feed(secret.as_bytes(), true);
        assert_eq!(String::from_utf8(text).unwrap(), "[REDACTED]");
    }
    command.slots.clear();
    assert!(command.validate().is_err());
}
