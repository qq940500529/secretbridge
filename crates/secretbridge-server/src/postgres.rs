// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{future::Future, pin::Pin};

use rustls_tokio_postgres::{MakeRustlsConnect, config_platform_verifier};
use tokio_postgres::{Config, IsolationLevel, config::SslMode};

use crate::catalog::PostgresTargetConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresCheckOutcome {
    ConnectionOk,
    ConnectionFailed,
    ConfigurationInvalid,
}

pub trait PostgresExecutor: Send + Sync {
    fn connection_check<'a>(
        &'a self,
        target: &'a PostgresTargetConfig,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = PostgresCheckOutcome> + Send + 'a>>;
}

#[derive(Default)]
pub struct NativePostgresExecutor;

impl PostgresExecutor for NativePostgresExecutor {
    fn connection_check<'a>(
        &'a self,
        target: &'a PostgresTargetConfig,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = PostgresCheckOutcome> + Send + 'a>> {
        Box::pin(async move { native_connection_check(target, password).await })
    }
}

async fn native_connection_check(
    target: &PostgresTargetConfig,
    password: &str,
) -> PostgresCheckOutcome {
    let Ok(tls_config) = config_platform_verifier() else {
        return PostgresCheckOutcome::ConfigurationInvalid;
    };
    let mut config = Config::new();
    config
        .host(&target.host)
        .port(target.port)
        .dbname(&target.database)
        .user(&target.username)
        .password(password.as_bytes())
        .application_name("SecretBridge")
        .ssl_mode(SslMode::Require);

    let Ok((mut client, connection)) = config.connect(MakeRustlsConnect::new(tls_config)).await
    else {
        return PostgresCheckOutcome::ConnectionFailed;
    };
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let checked = async {
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(true)
            .start()
            .await
            .ok()?;
        let row = transaction.query_one("SELECT 1::INTEGER", &[]).await.ok()?;
        let probe = row.try_get::<_, i32>(0).ok()?;
        transaction.rollback().await.ok()?;
        (probe == 1).then_some(())
    }
    .await;
    drop(client);
    connection_task.abort();
    if checked.is_some() {
        PostgresCheckOutcome::ConnectionOk
    } else {
        PostgresCheckOutcome::ConnectionFailed
    }
}

#[cfg(test)]
pub struct TestPostgresExecutor {
    outcome: PostgresCheckOutcome,
    delay: std::time::Duration,
}

#[cfg(test)]
impl TestPostgresExecutor {
    pub const fn succeeding() -> Self {
        Self {
            outcome: PostgresCheckOutcome::ConnectionOk,
            delay: std::time::Duration::ZERO,
        }
    }

    pub const fn delayed(delay: std::time::Duration) -> Self {
        Self {
            outcome: PostgresCheckOutcome::ConnectionOk,
            delay,
        }
    }
}

#[cfg(test)]
impl PostgresExecutor for TestPostgresExecutor {
    fn connection_check<'a>(
        &'a self,
        _target: &'a PostgresTargetConfig,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = PostgresCheckOutcome> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.outcome
        })
    }
}
