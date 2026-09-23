// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
mod installation;
mod startup;
use secretbridge_server::{BrokerController, RuntimeStatus};
use serde::Deserialize;
use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
pub(super) type Result<T> = std::result::Result<T, &'static str>;

pub(super) async fn handle(
    arguments: &[OsString],
) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    let command = arguments
        .first()
        .and_then(|item| item.to_str())
        .unwrap_or("start");
    match command {
        "--version" if arguments.len() == 1 => println!("{}", env!("CARGO_PKG_VERSION")),
        "start"
            if arguments.len() <= 2 && arguments.get(1).is_none_or(|item| item == "--no-open") =>
        {
            let status = start(arguments.get(1).is_none()).await?;
            println!("{}", serde_json::to_string(&status)?);
        }
        "open" if arguments.len() == 1 => {
            controller()?
                .open()
                .await
                .map_err(|_| "browser_open_failed")?;
        }
        "status" if arguments.len() == 1 => {
            let status = controller()?.status().await.ok();
            println!(
                "{}",
                serde_json::json!({"running":status.is_some(),"runtime":status,"installation":installation::summary()?})
            );
        }
        "stop" if arguments.len() == 1 => {
            stop().await?;
            println!("{}", serde_json::json!({"running":false}));
        }
        "install"
            if arguments.len() == 2 || (arguments.len() == 3 && arguments[2] == "--no-open") =>
        {
            installation::install(Path::new(&arguments[1]), arguments.len() == 3).await?;
        }
        "verify-package" if arguments.len() == 2 => {
            let verification = installation::verify(Path::new(&arguments[1]))?;
            println!("{}", serde_json::to_string_pretty(&verification)?);
        }
        "rollback" if arguments.len() == 1 => {
            installation::rollback().await?;
        }
        "autostart" if arguments.len() == 2 && (arguments[1] == "on" || arguments[1] == "off") => {
            installation::autostart(arguments[1] == "on")?;
        }
        "uninstall"
            if arguments.len() == 1
                || (arguments.len() == 2 && arguments[1] == "--remove-configuration") =>
        {
            installation::uninstall(arguments.len() == 2).await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}
fn controller() -> Result<BrokerController> {
    Ok(BrokerController::new(&super::data_directory()?))
}
pub(super) async fn stop() -> Result<()> {
    let controller = controller()?;
    if wait_for_runtime_or_shutdown(&controller).await?.is_none() {
        return Ok(());
    }
    controller.stop().await.map_err(|_| "broker_stop_failed")?;
    tokio::time::timeout(Duration::from_secs(20), async {
        while controller.status().await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "broker_stop_timeout")
}
async fn start(open: bool) -> Result<RuntimeStatus> {
    let controller = controller()?;
    if let Some(status) = wait_for_runtime_or_shutdown(&controller).await? {
        if open {
            controller.open().await.map_err(|_| "browser_open_failed")?;
        }
        return Ok(status);
    }
    let (executable, web) = installation::active_paths()?.unwrap_or((
        env::current_exe().map_err(|_| "executable_unavailable")?,
        env::var_os("SECRETBRIDGE_WEB_ROOT").map_or_else(super::default_web_root, PathBuf::from),
    ));
    launch(&executable, &web).await?;
    let status = controller
        .status()
        .await
        .map_err(|_| "broker_start_failed")?;
    if open {
        controller.open().await.map_err(|_| "browser_open_failed")?;
    }
    Ok(status)
}

/// Distinguishes an older reachable broker from a current broker that is between
/// closing its runtime-control listener and finishing process shutdown. The latter
/// is a normal lifecycle transition on Unix and must not make an immediate upgrade
/// look like an unsupported legacy installation.
async fn wait_for_runtime_or_shutdown(
    controller: &BrokerController,
) -> Result<Option<RuntimeStatus>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(status) = controller.status().await {
            return Ok(Some(status));
        }
        if !controller.is_reachable().await {
            return Ok(None);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("legacy_broker_requires_manual_stop");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
pub(super) async fn launch(executable: &Path, web: &Path) -> Result<RuntimeStatus> {
    let version = executable_version(executable)?;
    validate_web_build_for(web, &version)?;
    let directory = super::data_directory()?;
    super::create_private_data_directory(&directory).map_err(|_| "data_directory_unavailable")?;
    #[cfg(windows)]
    {
        launch_windows(executable, web, &directory).await
    }
    #[cfg(unix)]
    {
        launch_unix(executable, web, &directory).await
    }
}
#[cfg(unix)]
async fn launch_unix(executable: &Path, web: &Path, directory: &Path) -> Result<RuntimeStatus> {
    let mut command = Command::new(executable);
    command
        .arg("--serve")
        .env("SECRETBRIDGE_DATA_DIR", directory)
        .env("SECRETBRIDGE_WEB_ROOT", web)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach(&mut command);
    let mut child = command.spawn().map_err(|_| "broker_start_failed")?;
    let controller = BrokerController::new(directory);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if child
            .try_wait()
            .map_err(|_| "broker_start_failed")?
            .is_some()
        {
            return Err("broker_start_failed");
        }
        if let Ok(status) = controller.status().await
            && status.process_id == child.id()
        {
            return Ok(status);
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("broker_start_timeout");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
#[cfg(windows)]
async fn launch_windows(executable: &Path, web: &Path, directory: &Path) -> Result<RuntimeStatus> {
    // ShellExecute isolates inheritable caller pipe handles. The helper holds the
    // Process object until authenticated readiness, and kills only that object on failure.
    let executable = executable
        .to_str()
        .filter(|text| !text.chars().any(char::is_control))
        .ok_or("executable_unavailable")?
        .replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $p=$null; try {{ $exe='{executable}'; $p=Start-Process -FilePath $exe -ArgumentList '--serve' -WindowStyle Hidden -PassThru; $end=[DateTime]::UtcNow.AddSeconds(20); while([DateTime]::UtcNow -lt $end) {{ $p.Refresh(); if($p.HasExited) {{ exit 1 }}; try {{ $s=((& $exe status 2>$null) -join [Environment]::NewLine) | ConvertFrom-Json; if($s.running -and $s.runtime.process_id -eq $p.Id) {{ $s.runtime | ConvertTo-Json -Compress -Depth 6; exit 0 }} }} catch {{ }}; Start-Sleep -Milliseconds 100 }}; $p.Kill(); exit 1 }} catch {{ if($null -ne $p) {{ try {{ $p.Kill() }} catch {{ }} }}; exit 1 }}"
    );
    let shell = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or("broker_start_failed")?
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let web = web.to_owned();
    let directory = directory.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(shell);
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .env("SECRETBRIDGE_DATA_DIR", directory)
            .env("SECRETBRIDGE_WEB_ROOT", web)
            .stdin(Stdio::null());
        detach(&mut command);
        let output = command.output().map_err(|_| "broker_start_failed")?;
        if !output.status.success() {
            return Err("broker_start_failed");
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "broker_start_failed")
    })
    .await
    .map_err(|_| "broker_start_failed")?
}
#[cfg(windows)]
fn detach(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000 | 0x0000_0200);
}
#[cfg(unix)]
fn detach(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebBuild {
    format_version: u32,
    version: String,
}
pub(super) fn validate_web_build(path: &Path) -> Result<()> {
    validate_web_build_for(path, env!("CARGO_PKG_VERSION"))
}
fn executable_version(executable: &Path) -> Result<String> {
    let mut command = Command::new(executable);
    command.arg("--version");
    detach(&mut command);
    let output = command.output().map_err(|_| "executable_unavailable")?;
    if !output.status.success() || output.stdout.len() > 128 {
        return Err("executable_version_invalid");
    }
    String::from_utf8(output.stdout)
        .map(|version| version.trim().to_owned())
        .map_err(|_| "executable_version_invalid")
}
fn validate_web_build_for(path: &Path, expected_version: &str) -> Result<()> {
    let bytes = fs::read(path.join("secretbridge-build.json")).map_err(|_| "web_build_missing")?;
    if bytes.len() > 1024 {
        return Err("web_build_invalid");
    }
    let build: WebBuild = serde_json::from_slice(&bytes).map_err(|_| "web_build_invalid")?;
    if build.format_version != 1 || build.version != expected_version {
        return Err("web_build_version_mismatch");
    }
    if !path.join("index.html").is_file() {
        return Err("web_build_missing");
    }
    Ok(())
}
pub(super) fn private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
