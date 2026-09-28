// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    database_task::{DatabaseConfig, DatabaseOperation},
    domain::resources::{
        ConnectionOptions, HttpAuthentication, Resource, database_command, ssh_command,
    },
};
use std::time::Duration;
use zeroize::Zeroizing;

/// Performs only an explicit human-initiated handshake/HEAD/SELECT 1, never a user command.
pub(crate) async fn test(state: &AppState, resource: &Resource) -> Result<(), &'static str> {
    if !resource.missing_connection_fields().is_empty() {
        return Err("configuration_incomplete");
    }
    let secrets = authentication_values(state, resource).await?;
    let host = resource.target.address.as_deref().unwrap_or("");
    let username = resource.target.username.as_deref().unwrap_or("");
    match &resource.connection {
        ConnectionOptions::None | ConnectionOptions::Telnet { .. } => Err("test_not_configured"),
        ConnectionOptions::Database {
            engine,
            port,
            database,
            tls_mode,
            ca_certificate,
        } => {
            let db = DatabaseConfig {
                engine: *engine,
                operation: DatabaseOperation::Check,
                host: host.into(),
                port: *port,
                database: database.clone(),
                username: username.into(),
                password_slot: "authentication".into(),
                tls_mode: *tls_mode,
                ca_certificate: ca_certificate.clone(),
                query: String::new(),
                columns: vec![],
                max_rows: 1,
                expected_min_rows: None,
            };
            let config = database_command(db, resource.target.id);
            crate::database_task::test_connection(&config, &secrets).await
        }
        ConnectionOptions::Ssh {
            port,
            host_key_sha256,
        } => {
            let config = ssh_command(
                host,
                username,
                *port,
                host_key_sha256,
                resource.authentication.kind,
                resource.target.id,
            );
            config.validate().map_err(|_| "invalid_configuration")?;
            let (session, _transport) = crate::ssh_task::connect(
                config.ssh.as_ref().ok_or("invalid_configuration")?,
                &config,
                &secrets,
            )
            .await?;
            session
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "connection test complete",
                    "en",
                )
                .await
                .map_err(|_| "disconnect_failed")?;
            Ok(())
        }
        ConnectionOptions::Http {
            authentication,
            header_name,
        } => {
            test_http(
                host,
                username,
                *authentication,
                header_name.as_deref(),
                &secrets,
            )
            .await
        }
    }
}

async fn authentication_values(
    state: &AppState,
    resource: &Resource,
) -> Result<Vec<Zeroizing<String>>, &'static str> {
    let requires_secret = !matches!(
        resource.connection,
        ConnectionOptions::None
            | ConnectionOptions::Telnet { .. }
            | ConnectionOptions::Http {
                authentication: HttpAuthentication::None,
                ..
            }
    );
    if requires_secret {
        if resource.authentication.secret_state != crate::catalog::SecretState::Available {
            return Err("authentication_not_configured");
        }
        Ok(vec![
            state
                .secret_reads
                .get(
                    state.secret_store.clone(),
                    resource.target.id,
                    Duration::from_secs(5),
                    None,
                )
                .await
                .map_err(|_| "credential_unavailable")?,
        ])
    } else {
        Ok(vec![Zeroizing::new(String::new())])
    }
}

async fn test_http(
    host: &str,
    username: &str,
    authentication: HttpAuthentication,
    header_name: Option<&str>,
    secrets: &[Zeroizing<String>],
) -> Result<(), &'static str> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_sslkeylogfile(false)
        .build()
        .map_err(|_| "invalid_configuration")?;
    let request = client.head(host);
    let request = match authentication {
        HttpAuthentication::None => request,
        HttpAuthentication::Bearer => request.bearer_auth(secrets[0].as_str()),
        HttpAuthentication::Basic => request.basic_auth(username, Some(secrets[0].as_str())),
        HttpAuthentication::ApiKey => request.header(
            header_name.ok_or("invalid_configuration")?,
            secrets[0].as_str(),
        ),
    };
    let response = request.send().await.map_err(|_| "connection_failed")?;
    if response.status().is_success() {
        Ok(())
    } else if matches!(response.status().as_u16(), 401 | 403) {
        Err("authentication_failed")
    } else {
        Err("http_status_rejected")
    }
}
