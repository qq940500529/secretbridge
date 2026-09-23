// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]
mod lifecycle;

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, BufRead, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use secretbridge_server::{AppState, LocalMcpBridge, router_with_web, serve_mcp_stdio_bridge};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::{FilterExt, filter_fn},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

const DEFAULT_ADDRESS: &str = "127.0.0.1:8787";
const BRIDGE_CONNECTION_FILE: &str = "mcp-bridge.json";
const MAX_SYNTHETIC_FLOOD_BYTES: usize = 2 * 1024 * 1024;
const MAX_SYNTHETIC_WAIT_MILLIS: usize = 30_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| argument == OsStr::new("--synthetic-terminal-child"))
    {
        return run_synthetic_terminal();
    }
    if run_maintenance(&arguments)? {
        return Ok(());
    }
    if lifecycle::handle(&arguments).await? {
        return Ok(());
    }
    let startup_mode = parse_startup_mode(&arguments)?;

    let log_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("secretbridge_server=info"))
        .and(filter_fn(|metadata| {
            application_log_target(metadata.target())
        }));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(io::stderr)
                .with_target(false)
                .with_filter(log_filter),
        )
        .init();

    if startup_mode == StartupMode::McpStdio {
        serve_mcp_stdio_bridge(data_directory()?.join(BRIDGE_CONNECTION_FILE))
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error })?;
        return Ok(());
    }

    let requested_address = require_loopback(
        env::var("SECRETBRIDGE_BIND")
            .unwrap_or_else(|_| DEFAULT_ADDRESS.to_owned())
            .parse::<SocketAddr>()?,
    )?;

    let listener = TcpListener::bind(requested_address).await?;
    let address = listener.local_addr()?;
    let origin = format!("http://{address}");
    let mut trusted_origins = vec![origin.clone()];
    if cfg!(debug_assertions) {
        trusted_origins.extend([
            "http://127.0.0.1:5173".to_owned(),
            "http://localhost:5173".to_owned(),
        ]);
    }

    let web_root =
        env::var_os("SECRETBRIDGE_WEB_ROOT").map_or_else(default_web_root, PathBuf::from);
    lifecycle::validate_web_build(&web_root)?;
    let data_directory = data_directory()?;
    create_private_data_directory(&data_directory)?;
    let database_path = data_directory.join("secretbridge.sqlite3");
    let (mut state, _) = AppState::new_persistent(trusted_origins, &database_path)?;
    let cancellation = CancellationToken::new();
    state.enable_runtime_control(origin, cancellation.clone());
    let bridge = LocalMcpBridge::bind(&data_directory, state.clone())?;
    let app = router_with_web(state.clone(), web_root);

    info!(%address, mode = "controlled_operations", "SecretBridge local broker started");
    let http_cancellation = cancellation.clone();
    let http_service = async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(http_cancellation.cancelled_owned())
            .await
    };
    let bridge_service = bridge.serve(cancellation.clone());
    tokio::pin!(http_service);
    tokio::pin!(bridge_service);
    tokio::select! {
        result = &mut http_service => {
            state.shutdown_operations().await;
            cancellation.cancel();
            result?;
            bridge_service.await?;
        }
        result = &mut bridge_service => {
            state.shutdown_operations().await;
            cancellation.cancel();
            result?;
            http_service.await?;
        }
        () = shutdown_signal() => {
            state.shutdown_operations().await;
            cancellation.cancel();
            http_service.await?;
            bridge_service.await?;
        }
    }
    Ok(())
}

fn run_maintenance(arguments: &[std::ffi::OsString]) -> Result<bool, Box<dyn std::error::Error>> {
    if !arguments
        .first()
        .is_some_and(|argument| argument == "--inspect-backup" || argument == "--restore-backup")
    {
        return Ok(false);
    }
    if arguments.len() != 2 {
        return Err("maintenance_requires_backup_path".into());
    }
    let path = PathBuf::from(&arguments[1]);
    let report = if arguments[0] == "--inspect-backup" {
        secretbridge_server::inspect_configuration_backup(&path)?
    } else {
        let directory = env::var_os("SECRETBRIDGE_DATA_DIR")
            .map(PathBuf::from)
            .ok_or("restore_requires_explicit_data_directory")?;
        secretbridge_server::restore_configuration_backup(&path, &directory)?
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupMode {
    Broker,
    McpStdio,
}

fn parse_startup_mode(arguments: &[impl AsRef<OsStr>]) -> Result<StartupMode, &'static str> {
    match arguments {
        [] => Ok(StartupMode::Broker),
        [argument] if argument.as_ref() == OsStr::new("--mcp-stdio") => Ok(StartupMode::McpStdio),
        [argument] if argument.as_ref() == OsStr::new("--serve") => Ok(StartupMode::Broker),
        _ => Err(
            "usage: secretbridge-server [start [--no-open] | open | stop | status | verify-package PACKAGE | install PACKAGE | rollback | autostart on|off | uninstall | --serve | --mcp-stdio]",
        ),
    }
}

fn data_directory() -> Result<PathBuf, &'static str> {
    let override_path = env::var_os("SECRETBRIDGE_DATA_DIR");
    resolve_data_directory(override_path.as_deref())
}

fn resolve_data_directory(override_path: Option<&OsStr>) -> Result<PathBuf, &'static str> {
    let path = if let Some(path) = override_path {
        PathBuf::from(path)
    } else {
        default_data_directory()
            .ok_or("the operating system did not provide a local application data directory")?
    };
    if !path.is_absolute() {
        return Err("the SecretBridge data directory must be an absolute path");
    }
    Ok(path)
}

#[cfg(windows)]
fn default_data_directory() -> Option<PathBuf> {
    env::var_os("LOCALAPPDATA").map(|path| PathBuf::from(path).join("SecretBridge"))
}

#[cfg(target_os = "macos")]
fn default_data_directory() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from).map(|path| {
        path.join("Library")
            .join("Application Support")
            .join("SecretBridge")
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_data_directory() -> Option<PathBuf> {
    env::var_os("XDG_DATA_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|path| path.join("secretbridge"))
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|path| path.join(".local").join("share").join("secretbridge"))
        })
}

#[cfg(not(any(windows, unix)))]
fn default_data_directory() -> Option<PathBuf> {
    None
}

fn create_private_data_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(windows)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid data directory",
            ));
        }
        secretbridge_windows_pipe_acl::protect_directory(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn run_synthetic_terminal() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    writeln!(stdout, "SecretBridge synthetic terminal")?;
    writeln!(
        stdout,
        "No system shell, credentials, files, or network targets are available."
    )?;
    writeln!(stdout, "Type 'help' to list the safe built-in commands.\r")?;
    write!(stdout, "secretbridge> ")?;
    stdout.flush()?;

    for line in stdin.lock().lines() {
        let line = line?;
        match line.trim() {
            "help" => writeln!(
                stdout,
                "help             show this message\r\nstatus           show the isolated mode\r\nflood <bytes>    emit bounded synthetic output\r\nwait <ms>        pause for cancellation testing\r\nclear            clear the screen\r\nexit             close this synthetic terminal"
            )?,
            "status" => writeln!(
                stdout,
                "mode=synthetic_only credentials=disabled shell=disabled"
            )?,
            "clear" => write!(stdout, "\x1b[2J\x1b[H")?,
            "exit" => {
                writeln!(stdout, "Synthetic terminal closed.")?;
                stdout.flush()?;
                break;
            }
            "" => {}
            input if command_name(input) == "flood" => {
                if let Some(bytes) = bounded_argument(input, "flood", MAX_SYNTHETIC_FLOOD_BYTES) {
                    write_synthetic_flood(&mut stdout, bytes)?;
                } else {
                    writeln!(
                        stdout,
                        "usage: flood <bytes>, where bytes is 1..={MAX_SYNTHETIC_FLOOD_BYTES}"
                    )?;
                }
            }
            input if command_name(input) == "wait" => {
                if let Some(milliseconds) =
                    bounded_argument(input, "wait", MAX_SYNTHETIC_WAIT_MILLIS)
                {
                    writeln!(stdout, "wait begin milliseconds={milliseconds}")?;
                    stdout.flush()?;
                    std::thread::sleep(Duration::from_millis(milliseconds as u64));
                    writeln!(stdout, "wait complete milliseconds={milliseconds}")?;
                } else {
                    writeln!(
                        stdout,
                        "usage: wait <milliseconds>, where milliseconds is 1..={MAX_SYNTHETIC_WAIT_MILLIS}"
                    )?;
                }
            }
            input => writeln!(stdout, "echo: {input}")?,
        }
        write!(stdout, "secretbridge> ")?;
        stdout.flush()?;
    }
    Ok(())
}

fn command_name(input: &str) -> &str {
    input.split_whitespace().next().unwrap_or_default()
}

fn bounded_argument(input: &str, command: &str, maximum: usize) -> Option<usize> {
    let mut parts = input.split_whitespace();
    if parts.next()? != command {
        return None;
    }
    let value = parts.next()?.parse::<usize>().ok()?;
    (value > 0 && value <= maximum && parts.next().is_none()).then_some(value)
}

fn write_synthetic_flood(stdout: &mut impl Write, bytes: usize) -> io::Result<()> {
    writeln!(stdout, "flood begin bytes={bytes}")?;
    let chunk = [b'x'; 8 * 1024];
    let mut remaining = bytes;
    while remaining > 0 {
        let count = remaining.min(chunk.len());
        stdout.write_all(&chunk[..count])?;
        remaining -= count;
    }
    writeln!(stdout, "\r\nflood complete bytes={bytes}")
}

fn default_web_root() -> PathBuf {
    if let Ok(executable) = env::current_exe()
        && let Some(root) = executable.parent().and_then(Path::parent)
    {
        let packaged = root.join("web");
        if packaged.join("secretbridge-build.json").is_file() {
            return packaged;
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("web")
        .join("dist")
}

// Protocol-library logs are upstream of credential redaction. RUST_LOG must not
// opt raw packets, authentication material or response text into broker stderr.
fn application_log_target(target: &str) -> bool {
    target == "secretbridge_server" || target.starts_with("secretbridge_server::")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn require_loopback(address: SocketAddr) -> Result<SocketAddr, &'static str> {
    address
        .ip()
        .is_loopback()
        .then_some(address)
        .ok_or("SECRETBRIDGE_BIND must use a loopback address")
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, net::SocketAddr};

    #[test]
    fn global_trace_logging_cannot_enable_raw_protocol_output() {
        use std::{
            io::{self, Write},
            sync::{Arc, Mutex},
        };
        use tracing_subscriber::{
            EnvFilter, Layer,
            filter::{FilterExt, filter_fn},
            layer::SubscriberExt,
        };
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let capture = bytes.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_writer(move || Capture(capture.clone()))
                .with_filter(
                    EnvFilter::new("trace,russh::client=trace,reqwest=trace")
                        .and(filter_fn(|m| super::application_log_target(m.target()))),
                ),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target:"secretbridge_server::command", "fixed-application-status");
            tracing::trace!(target:"russh::client", "synthetic-unfiltered-protocol-value");
            tracing::info!(target:"reqwest", "synthetic-unfiltered-protocol-value");
            tracing::warn!(target:"secretbridge_server_other", "synthetic-unfiltered-protocol-value");
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains("fixed-application-status"));
        assert!(!output.contains("synthetic-unfiltered-protocol-value"));
    }

    use super::{
        StartupMode, bounded_argument, parse_startup_mode, require_loopback, resolve_data_directory,
    };

    #[test]
    fn startup_mode_accepts_only_the_documented_forms() {
        let no_arguments: [&OsStr; 0] = [];
        assert_eq!(parse_startup_mode(&no_arguments), Ok(StartupMode::Broker));
        assert_eq!(
            parse_startup_mode(&[OsStr::new("--mcp-stdio")]),
            Ok(StartupMode::McpStdio)
        );
        assert!(parse_startup_mode(&[OsStr::new("--unknown")]).is_err());
        assert!(
            parse_startup_mode(&[OsStr::new("--mcp-stdio"), OsStr::new("unexpected")]).is_err()
        );
    }

    #[test]
    fn loopback_bind_addresses_are_allowed() {
        for address in ["127.0.0.1:8787", "[::1]:8787"] {
            let address = address.parse::<SocketAddr>().expect("valid address");
            assert_eq!(require_loopback(address), Ok(address));
        }
    }

    #[test]
    fn non_loopback_bind_addresses_are_rejected() {
        for address in ["0.0.0.0:8787", "192.0.2.1:8787", "[::]:8787"] {
            let address = address.parse::<SocketAddr>().expect("valid address");
            assert!(require_loopback(address).is_err());
        }
    }

    #[test]
    fn synthetic_stress_arguments_are_bounded() {
        assert_eq!(
            bounded_argument("flood 65536", "flood", 65_536),
            Some(65_536)
        );
        assert_eq!(bounded_argument("flood 65537", "flood", 65_536), None);
        assert_eq!(bounded_argument("flood 1 extra", "flood", 65_536), None);
        assert_eq!(bounded_argument("flood 0", "flood", 65_536), None);
    }

    #[test]
    fn relative_data_directory_overrides_are_rejected() {
        assert!(resolve_data_directory(Some(OsStr::new("relative-data"))).is_err());
    }

    #[test]
    fn absolute_data_directory_overrides_are_accepted() {
        let path = std::env::temp_dir().join("secretbridge-data-override-test");
        assert_eq!(resolve_data_directory(Some(path.as_os_str())), Ok(path));
    }
}
