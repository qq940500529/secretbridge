// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{env, fs, future::Future, path::Path, pin::Pin};

use rustls_tokio_postgres::{
    MakeRustlsConnect, config_from_ca_cert, config_platform_verifier, rustls::ClientConfig,
};
use tokio_postgres::{Config, IsolationLevel, config::SslMode};

use crate::catalog::PostgresTargetConfig;

const POSTGRES_CA_CERT_ENV: &str = "SECRETBRIDGE_POSTGRES_CA_CERT";
const MAX_CA_CERT_BYTES: u64 = 64 * 1024;

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
    let ca_certificate = env::var_os(POSTGRES_CA_CERT_ENV);
    native_connection_check_with_ca(target, password, ca_certificate.as_deref().map(Path::new))
        .await
}

async fn native_connection_check_with_ca(
    target: &PostgresTargetConfig,
    password: &str,
    ca_certificate: Option<&Path>,
) -> PostgresCheckOutcome {
    let Ok(tls_config) = postgres_tls_config(ca_certificate) else {
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

fn postgres_tls_config(ca_certificate: Option<&Path>) -> Result<ClientConfig, ()> {
    let Some(path) = ca_certificate else {
        return config_platform_verifier().map_err(|_| ());
    };
    if !path.is_absolute() {
        return Err(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CA_CERT_BYTES
    {
        return Err(());
    }
    config_from_ca_cert(path).map_err(|_| ())
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

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::{
        MAX_CA_CERT_BYTES, PostgresCheckOutcome, native_connection_check,
        native_connection_check_with_ca, postgres_tls_config,
    };
    use crate::catalog::{PostgresTargetConfig, PostgresTlsMode};
    use uuid::Uuid;

    #[test]
    fn custom_ca_path_must_be_absolute_regular_and_bounded() {
        assert!(postgres_tls_config(Some(std::path::Path::new("relative-ca.pem"))).is_err());
        assert!(
            postgres_tls_config(Some(std::path::Path::new("Z:/secretbridge-missing-ca.pem")))
                .is_err()
        );

        let test_directory =
            env::temp_dir().join(format!("secretbridge-postgres-ca-test-{}", Uuid::new_v4()));
        fs::create_dir(&test_directory).expect("temporary CA directory must be created");
        let empty = test_directory.join("empty.pem");
        fs::write(&empty, []).expect("empty CA fixture must be written");
        assert!(postgres_tls_config(Some(&empty)).is_err());
        let oversized = test_directory.join("oversized.pem");
        fs::write(
            &oversized,
            vec![b'x'; usize::try_from(MAX_CA_CERT_BYTES + 1).expect("size must fit")],
        )
        .expect("oversized CA fixture must be written");
        assert!(postgres_tls_config(Some(&oversized)).is_err());
        fs::remove_dir_all(test_directory).expect("temporary CA directory must be removed");
    }

    #[tokio::test]
    #[ignore = "requires an explicitly provisioned PostgreSQL TLS test target"]
    async fn native_adapter_verifies_real_tls_authentication_and_hostname_failures() {
        let host = required_environment("SECRETBRIDGE_TEST_POSTGRES_HOST");
        let mismatch_host = required_environment("SECRETBRIDGE_TEST_POSTGRES_MISMATCH_HOST");
        let port = required_environment("SECRETBRIDGE_TEST_POSTGRES_PORT")
            .parse::<u16>()
            .expect("test port must be a u16");
        let unavailable_port = required_environment("SECRETBRIDGE_TEST_POSTGRES_UNAVAILABLE_PORT")
            .parse::<u16>()
            .expect("unavailable test port must be a u16");
        let database = required_environment("SECRETBRIDGE_TEST_POSTGRES_DATABASE");
        let username = required_environment("SECRETBRIDGE_TEST_POSTGRES_USERNAME");
        let password = required_environment("SECRETBRIDGE_TEST_POSTGRES_PASSWORD");
        let stale_password = required_environment("SECRETBRIDGE_TEST_POSTGRES_STALE_PASSWORD");
        let ca_certificate =
            PathBuf::from(required_environment("SECRETBRIDGE_TEST_POSTGRES_CA_CERT"));
        let target = PostgresTargetConfig {
            host,
            port,
            database,
            username,
            tls_mode: PostgresTlsMode::VerifyFull,
        };

        assert_eq!(
            native_connection_check(&target, &password).await,
            PostgresCheckOutcome::ConnectionOk
        );
        assert_eq!(
            native_connection_check_with_ca(&target, &password, Some(&ca_certificate)).await,
            PostgresCheckOutcome::ConnectionOk
        );
        assert_eq!(
            native_connection_check_with_ca(&target, &stale_password, Some(&ca_certificate)).await,
            PostgresCheckOutcome::ConnectionFailed
        );
        assert_eq!(
            native_connection_check_with_ca(&target, &password, None).await,
            PostgresCheckOutcome::ConnectionFailed
        );
        let mismatched = PostgresTargetConfig {
            host: mismatch_host,
            ..target
        };
        assert_eq!(
            native_connection_check_with_ca(&mismatched, &password, Some(&ca_certificate)).await,
            PostgresCheckOutcome::ConnectionFailed
        );
        let unavailable = PostgresTargetConfig {
            host: "127.0.0.1".to_owned(),
            port: unavailable_port,
            ..mismatched
        };
        assert_eq!(
            native_connection_check_with_ca(&unavailable, &password, Some(&ca_certificate)).await,
            PostgresCheckOutcome::ConnectionFailed
        );
    }

    fn required_environment(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("{name} is required for this ignored test"))
    }
}
