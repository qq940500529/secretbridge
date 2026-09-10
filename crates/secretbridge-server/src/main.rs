// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::{env, net::SocketAddr, path::PathBuf};

use secretbridge_server::{AppState, router_with_web};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_ADDRESS: &str = "127.0.0.1:8787";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    use super::require_loopback;

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
}
