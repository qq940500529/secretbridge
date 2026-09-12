// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, BufRead, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use secretbridge_server::{AppState, router_with_web, serve_mcp_stdio_bridge};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use zeroize::Zeroizing;

const DEFAULT_ADDRESS: &str = "127.0.0.1:8787";
const BRIDGE_CONNECTION_FILE: &str = "mcp-bridge.json";
const BRIDGE_CONNECTION_SCHEMA: u8 = 1;
#[cfg(test)]
const MAX_BRIDGE_CONNECTION_BYTES: u64 = 4 * 1024;
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
    let startup_mode = parse_startup_mode(&arguments)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("secretbridge_server=info")),
        )
        .with_writer(io::stderr)
        .with_target(false)
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

    let data_directory = data_directory()?;
    create_private_data_directory(&data_directory)?;
    let database_path = data_directory.join("secretbridge.sqlite3");
    let (state, bootstrap_token) = AppState::new_persistent(trusted_origins, &database_path)?;
    let bridge_token = Zeroizing::new(new_bridge_token());
    let _bridge_connection = BridgeConnectionGuard::create(
        &data_directory.join(BRIDGE_CONNECTION_FILE),
        address,
        bridge_token.as_str(),
    )?;
    state.install_mcp_bridge_token(bridge_token.as_str()).await;
    let web_root =
        env::var_os("SECRETBRIDGE_WEB_ROOT").map_or_else(default_web_root, PathBuf::from);
    let app = router_with_web(state.clone(), web_root);

    let pairing_url = format!("{origin}/#pair={bootstrap_token}");
    webbrowser::open(&pairing_url)
        .map_err(|error| format!("failed to open the pairing URL: {error}"))?;
    info!(%address, mode = "controlled_operations", "SecretBridge local broker started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
        _ => Err("usage: secretbridge-server [--mcp-stdio]"),
    }
}

#[cfg(test)]
#[derive(Deserialize)]
struct BridgeConnectionDocument {
    schema_version: u8,
    #[serde(rename = "instance_id")]
    _instance_id: Uuid,
    address: SocketAddr,
    token: String,
}

#[derive(Serialize)]
struct BridgeConnectionDocumentRef<'a> {
    schema_version: u8,
    instance_id: Uuid,
    address: SocketAddr,
    token: &'a str,
}

#[derive(Deserialize)]
struct BridgeConnectionIdentity {
    instance_id: Uuid,
}

#[cfg(test)]
struct BridgeConnection {
    address: SocketAddr,
    token: Zeroizing<String>,
}

struct BridgeConnectionGuard {
    path: PathBuf,
    instance_id: Uuid,
}

impl BridgeConnectionGuard {
    fn create(
        path: &Path,
        address: SocketAddr,
        token: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let instance_id = Uuid::new_v4();
        let document = BridgeConnectionDocumentRef {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            instance_id,
            address,
            token,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&document)?);
        let temporary_path = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
        let write_result = write_private_file(&temporary_path, &encoded).and_then(|()| {
            if path.exists() {
                fs::remove_file(path)?;
            }
            fs::rename(&temporary_path, path)
        });
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result?;
        Ok(Self {
            path: path.to_owned(),
            instance_id,
        })
    }
}

impl Drop for BridgeConnectionGuard {
    fn drop(&mut self) {
        let Ok(contents) = fs::read_to_string(&self.path) else {
            return;
        };
        let contents = Zeroizing::new(contents);
        let Ok(document) = serde_json::from_str::<BridgeConnectionIdentity>(&contents) else {
            return;
        };
        if document.instance_id == self.instance_id {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(test)]
fn read_bridge_connection(path: &Path) -> io::Result<BridgeConnection> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the SecretBridge broker is not running or its bridge file is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_BRIDGE_CONNECTION_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge bridge file is invalid",
        ));
    }
    let contents = Zeroizing::new(fs::read_to_string(path)?);
    let document = serde_json::from_str::<BridgeConnectionDocument>(&contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge bridge file is invalid",
        )
    })?;
    if document.schema_version != BRIDGE_CONNECTION_SCHEMA
        || !document.address.ip().is_loopback()
        || document.token.len() != 64
        || !document.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge bridge file is invalid",
        ));
    }
    Ok(BridgeConnection {
        address: document.address,
        token: Zeroizing::new(document.token),
    })
}

fn new_bridge_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("web")
        .join("dist")
}

async fn shutdown_signal() {
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
    use std::{ffi::OsStr, fs, net::SocketAddr};

    use uuid::Uuid;

    use super::{
        BridgeConnectionGuard, StartupMode, bounded_argument, new_bridge_token, parse_startup_mode,
        read_bridge_connection, require_loopback, resolve_data_directory,
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

    #[test]
    fn bridge_connection_file_round_trips_and_is_removed_by_its_owner() {
        let directory =
            std::env::temp_dir().join(format!("secretbridge-bridge-file-test-{}", Uuid::new_v4()));
        fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("mcp-bridge.json");
        let address = "127.0.0.1:38787"
            .parse::<SocketAddr>()
            .expect("valid address");
        let token = new_bridge_token();
        let guard = BridgeConnectionGuard::create(&path, address, &token)
            .expect("write bridge connection file");
        let connection = read_bridge_connection(&path).expect("read bridge connection file");
        assert_eq!(connection.address, address);
        assert_eq!(connection.token.as_str(), token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path)
                    .expect("bridge metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        drop(guard);
        assert!(!path.exists());
        fs::remove_dir(&directory).expect("remove test directory");
    }

    #[test]
    fn bridge_connection_file_rejects_invalid_data() {
        let directory = std::env::temp_dir().join(format!(
            "secretbridge-invalid-bridge-test-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("mcp-bridge.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"instance_id":"00000000-0000-0000-0000-000000000000","address":"192.0.2.1:8787","token":"short"}"#,
        )
        .expect("write invalid bridge file");
        assert!(read_bridge_connection(&path).is_err());
        fs::remove_file(path).expect("remove invalid bridge file");
        fs::remove_dir(directory).expect("remove test directory");
    }
}
