// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use secretbridge_server::{AppState, router};
use std::{fs, process::Command};
use tower::ServiceExt;

#[tokio::test]
async fn offline_cli_inspects_restores_and_refuses_overwriting_existing_directory() {
    let directory = std::env::temp_dir().join(format!(
        "secretbridge-maintenance-cli-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&directory).unwrap();
    let origin = "http://127.0.0.1:8787";
    let (state, bootstrap) = AppState::new([origin.to_owned()]);
    let app = router(state);
    let paired = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/pair")
                .header("authorization", format!("Bearer {bootstrap}"))
                .header("origin", origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paired.status(), StatusCode::OK);
    let paired: serde_json::Value =
        serde_json::from_slice(&paired.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let backup = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/maintenance/backup")
                .header(
                    "authorization",
                    format!("Bearer {}", paired["session_token"].as_str().unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(backup.status(), StatusCode::OK);
    let path = directory.join("backup.sqlite3");
    fs::write(
        &path,
        backup.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    let executable = env!("CARGO_BIN_EXE_secretbridge-server");
    let inspected = Command::new(executable)
        .args(["--inspect-backup"])
        .arg(&path)
        .env_remove("SECRETBRIDGE_DATA_DIR")
        .output()
        .unwrap();
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(report["integrity_ok"], true);
    let target = directory.join("restored");
    let restored = Command::new(executable)
        .arg("--restore-backup")
        .arg(&path)
        .env("SECRETBRIDGE_DATA_DIR", &target)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(target.join("secretbridge.sqlite3").is_file());
    assert!(!target.join("mcp-bridge.json").exists());
    let before = fs::read(target.join("secretbridge.sqlite3")).unwrap();
    let overwrite = Command::new(executable)
        .arg("--restore-backup")
        .arg(&path)
        .env("SECRETBRIDGE_DATA_DIR", &target)
        .output()
        .unwrap();
    assert!(!overwrite.status.success());
    assert_eq!(
        fs::read(target.join("secretbridge.sqlite3")).unwrap(),
        before
    );
    let implicit = Command::new(executable)
        .arg("--restore-backup")
        .arg(&path)
        .env_remove("SECRETBRIDGE_DATA_DIR")
        .output()
        .unwrap();
    assert!(!implicit.status.success());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn maintenance_cli_rejects_missing_path_without_starting_broker() {
    let result = Command::new(env!("CARGO_BIN_EXE_secretbridge-server"))
        .arg("--inspect-backup")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("maintenance_requires_backup_path"));
}
