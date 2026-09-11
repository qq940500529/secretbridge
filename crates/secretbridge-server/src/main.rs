// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::OsStr,
    io::{self, BufRead, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use secretbridge_server::{AppState, router_with_web};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_ADDRESS: &str = "127.0.0.1:8787";
const MAX_SYNTHETIC_FLOOD_BYTES: usize = 2 * 1024 * 1024;
const MAX_SYNTHETIC_WAIT_MILLIS: usize = 30_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).as_deref() == Some(OsStr::new("--synthetic-terminal-child")) {
        return run_synthetic_terminal();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("secretbridge_server=info")),
        )
        .with_target(false)
        .init();

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

    let (state, bootstrap_token) = AppState::new(trusted_origins);
    let web_root =
        env::var_os("SECRETBRIDGE_WEB_ROOT").map_or_else(default_web_root, PathBuf::from);
    let app = router_with_web(state, web_root);

    let pairing_url = format!("{origin}/#pair={bootstrap_token}");
    webbrowser::open(&pairing_url)
        .map_err(|error| format!("failed to open the pairing URL: {error}"))?;
    info!(%address, mode = "synthetic_only", "SecretBridge local service started");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
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
    use std::net::SocketAddr;

    use super::{bounded_argument, require_loopback};

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
}
