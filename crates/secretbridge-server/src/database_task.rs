// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    catalog::CatalogError,
    command::{CommandConfig, Injection},
    parameters::{ParameterType, ParameterValues},
    redaction::Redactor,
};
use futures_util::{StreamExt, pin_mut};
use mysql_async::{Conn, OptsBuilder, SslOpts, TxOpts, prelude::Queryable};
use rustls_tokio_postgres::MakeRustlsConnect;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashSet, fmt::Write as _, net::IpAddr, path::Path, time::Duration};
use tokio_postgres::{
    Config,
    config::SslMode,
    types::{ToSql, Type},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const OUTPUT_LIMIT: usize = 196_608;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEngine {
    Postgres,
    Mysql,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseOperation {
    Check,
    Version,
    Query,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseTls {
    VerifyFull,
    LoopbackPlaintext,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub engine: DatabaseEngine,
    pub operation: DatabaseOperation,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password_slot: String,
    pub tls_mode: DatabaseTls,
    pub ca_certificate: Option<String>,
    pub query: String,
    pub columns: Vec<String>,
    pub max_rows: u32,
}

impl DatabaseConfig {
    pub fn validate(&self, config: &CommandConfig) -> Result<(), CatalogError> {
        let invalid = || CatalogError::Invalid;
        if self.host.is_empty()
            || self.host.len() > 253
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'))
            || self.port == 0
            || self.database.is_empty()
            || self.username.is_empty()
            || [&self.database, &self.username]
                .iter()
                .any(|s| s.len() > 128 || s.contains(['\0', '\r', '\n']))
            || !(1..=1000).contains(&self.max_rows)
            || !config.program.is_empty()
            || !config.working_directory.is_empty()
            || !config.arguments.is_empty()
            || config.slots.len() != 1
            || config.slots[0].name != self.password_slot
            || !crate::command::identifier(&self.password_slot)
            || config.slots[0].injection != Injection::Protocol
            || config.slots[0].environment_variable.is_some()
        {
            return Err(invalid());
        }
        if self.tls_mode == DatabaseTls::LoopbackPlaintext
            && (self.ca_certificate.is_some()
                || !self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
        {
            return Err(invalid());
        }
        if self
            .ca_certificate
            .as_ref()
            .is_some_and(|p| p.len() > 1024 || !Path::new(p).is_absolute() || p.contains('\0'))
        {
            return Err(invalid());
        }
        if self.operation == DatabaseOperation::Query {
            let mut columns = HashSet::new();
            if self.columns.is_empty()
                || self.columns.len() > 32
                || self.columns.iter().any(|c| {
                    c.is_empty()
                        || c.len() > 128
                        || c.contains(['\0', '\r', '\n'])
                        || !columns.insert(c)
                })
            {
                return Err(invalid());
            }
            compile_query(&self.query, self.engine, config)?;
        } else if !self.query.is_empty()
            || !self.columns.is_empty()
            || !config.parameters.is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn sql(&self, config: &CommandConfig) -> Result<(String, Vec<String>), CatalogError> {
        let (sql, names) = match self.operation {
            DatabaseOperation::Check => ("SELECT 1 AS connection_ok".into(), Vec::new()),
            DatabaseOperation::Version => ("SELECT version() AS version".into(), Vec::new()),
            DatabaseOperation::Query => compile_query(&self.query, self.engine, config)?,
        };
        let columns = self.output_columns();
        let quoted: Vec<_> = columns
            .iter()
            .map(|c| match self.engine {
                DatabaseEngine::Postgres => format!("sb.\"{}\"::text", c.replace('"', "\"\"")),
                DatabaseEngine::Mysql => format!("sb.`{}`", c.replace('`', "``")),
            })
            .collect();
        let select = match self.engine {
            DatabaseEngine::Postgres => format!("json_build_array({})::text", quoted.join(",")),
            DatabaseEngine::Mysql => quoted.join(","),
        };
        Ok((
            format!(
                "SELECT {select} FROM (\n{sql}\n) AS sb LIMIT {}",
                self.max_rows + 1
            ),
            names,
        ))
    }

    fn output_columns(&self) -> Vec<String> {
        match self.operation {
            DatabaseOperation::Check => vec!["connection_ok".into()],
            DatabaseOperation::Version => vec!["version".into()],
            DatabaseOperation::Query => self.columns.clone(),
        }
    }
}

// This is a placeholder lexer, not a SQL authorizer. Trusted registered SQL is
// additionally wrapped as a derived SELECT and executed in a read-only transaction.
#[allow(
    clippy::too_many_lines,
    reason = "SQL lexical states must agree on placeholder boundaries"
)]
fn compile_query(
    sql: &str,
    engine: DatabaseEngine,
    config: &CommandConfig,
) -> Result<(String, Vec<String>), CatalogError> {
    if sql.is_empty() || sql.len() > 16_384 || sql.contains('\0') {
        return Err(CatalogError::Invalid);
    }
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut out = String::new();
    let mut names = Vec::new();
    let mut first_word = None;
    while i < bytes.len() {
        let start = i;
        if sql[i..].starts_with("--") || (engine == DatabaseEngine::Mysql && bytes[i] == b'#') {
            i = sql[i..].find('\n').map_or(bytes.len(), |n| i + n);
        } else if sql[i..].starts_with("/*") {
            if sql[i..].starts_with("/*!") || sql[i..].starts_with("/*+") {
                return Err(CatalogError::Invalid);
            }
            i += 2;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if sql[i..].starts_with("/*") {
                    depth += 1;
                    i += 2;
                } else if sql[i..].starts_with("*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += sql[i..]
                        .chars()
                        .next()
                        .ok_or(CatalogError::Invalid)?
                        .len_utf8();
                }
            }
            if depth != 0 {
                return Err(CatalogError::Invalid);
            }
        } else if matches!(bytes[i], b'\'' | b'"' | b'`') {
            let quote = bytes[i];
            i += 1;
            let mut closed = false;
            while i < bytes.len() {
                // Backslash SQL modes differ. Require doubled quotes instead.
                if bytes[i] == b'\\' {
                    return Err(CatalogError::Invalid);
                }
                if bytes[i] == quote {
                    i += 1;
                    if bytes.get(i) == Some(&quote) {
                        i += 1;
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    i += sql[i..]
                        .chars()
                        .next()
                        .ok_or(CatalogError::Invalid)?
                        .len_utf8();
                }
            }
            if !closed {
                return Err(CatalogError::Invalid);
            }
        } else if bytes[i] == b'$' && engine == DatabaseEngine::Postgres {
            let tail = &sql[i + 1..];
            let Some(end) = tail.find('$') else {
                return Err(CatalogError::Invalid);
            };
            let tag = &tail[..end];
            if !tag.is_empty() && !crate::command::identifier(tag) {
                return Err(CatalogError::Invalid);
            }
            let delimiter = &sql[i..i + end + 2];
            i += delimiter.len();
            let Some(close) = sql[i..].find(delimiter) else {
                return Err(CatalogError::Invalid);
            };
            i += close + delimiter.len();
        } else if sql[i..].starts_with("{{param:") {
            let Some(end) = sql[i + 8..].find("}}") else {
                return Err(CatalogError::Invalid);
            };
            let name = &sql[i + 8..i + 8 + end];
            if !config.parameters.iter().any(|p| p.name == name) || names.len() >= 64 {
                return Err(CatalogError::Invalid);
            }
            names.push(name.to_owned());
            match engine {
                DatabaseEngine::Postgres => {
                    let _ = write!(out, "${}", names.len());
                }
                DatabaseEngine::Mysql => out.push('?'),
            }
            i += 8 + end + 2;
            continue;
        } else {
            if matches!(bytes[i], b';' | b'?') || sql[i..].starts_with("{{") {
                return Err(CatalogError::Invalid);
            }
            if bytes[i].is_ascii_alphabetic() {
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if first_word.is_none() {
                    first_word = Some(sql[start..i].to_ascii_uppercase());
                }
            } else {
                i += sql[i..]
                    .chars()
                    .next()
                    .ok_or(CatalogError::Invalid)?
                    .len_utf8();
            }
        }
        out.push_str(&sql[start..i]);
    }
    if !matches!(first_word.as_deref(), Some("SELECT" | "WITH"))
        || config.parameters.iter().any(|p| !names.contains(&p.name))
    {
        return Err(CatalogError::Invalid);
    }
    Ok((out, names))
}

#[derive(Default)]
struct Sessions {
    postgres: Option<tokio_postgres::Client>,
    connection: Option<tokio::task::JoinHandle<()>>,
    mysql: Option<Conn>,
}
impl Drop for Sessions {
    fn drop(&mut self) {
        if let Some(task) = self.connection.take() {
            task.abort();
        }
    }
}

fn ca_path(database: &DatabaseConfig) -> Result<Option<&Path>, &'static str> {
    let Some(p) = &database.ca_certificate else {
        return Ok(None);
    };
    let path = Path::new(p);
    let meta = std::fs::symlink_metadata(path).map_err(|_| "tls_configuration_failed")?;
    if !path.is_absolute()
        || meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.len() == 0
        || meta.len() > 65_536
    {
        return Err("tls_configuration_failed");
    }
    Ok(Some(path))
}

fn mysql_options(database: &DatabaseConfig, password: &str) -> Result<OptsBuilder, &'static str> {
    let tls = if database.tls_mode == DatabaseTls::VerifyFull {
        let ssl = SslOpts::default();
        Some(if let Some(path) = ca_path(database)? {
            ssl.with_root_certs(vec![path.to_owned().into()])
        } else {
            ssl
        })
    } else {
        None
    };
    Ok(OptsBuilder::default()
        .ip_or_hostname(&database.host)
        .tcp_port(database.port)
        .db_name(Some(&database.database))
        .user(Some(&database.username))
        .pass(Some(password))
        .prefer_socket(false)
        .ssl_opts(tls)
        .max_allowed_packet(Some(262_144))
        .stmt_cache_size(0))
}

fn filter_text(text: &str, secrets: &[Zeroizing<String>]) -> String {
    String::from_utf8_lossy(&Redactor::new(secrets).feed(text.as_bytes(), true)).into_owned()
}
fn filter_value(value: &mut Value, secrets: &[Zeroizing<String>]) {
    match value {
        Value::String(s) => *s = filter_text(s, secrets),
        Value::Array(a) => {
            for v in a {
                filter_value(v, secrets);
            }
        }
        Value::Object(o) => {
            let previous = std::mem::take(o);
            for (k, mut v) in previous {
                filter_value(&mut v, secrets);
                o.insert(filter_text(&k, secrets), v);
            }
        }
        Value::Number(n) => {
            let text = n.to_string();
            let filtered = filter_text(&text, secrets);
            if filtered != text {
                *value = Value::String(filtered);
            }
        }
        _ => {}
    }
}

struct ResultRows {
    rows: Vec<Value>,
    bytes: usize,
    truncated: bool,
}
impl ResultRows {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            bytes: 0,
            truncated: false,
        }
    }
    fn add(
        &mut self,
        mut row: Value,
        max_rows: u32,
        secrets: &[Zeroizing<String>],
    ) -> Result<bool, &'static str> {
        if self.rows.len() >= max_rows as usize {
            self.truncated = true;
            return Ok(false);
        }
        filter_value(&mut row, secrets);
        let size = serde_json::to_vec(&row)
            .map_err(|_| "result_conversion_failed")?
            .len();
        if size > OUTPUT_LIMIT {
            return Err("result_too_large");
        }
        if self.bytes + size > OUTPUT_LIMIT - 8192 {
            self.truncated = true;
            return Ok(false);
        }
        self.bytes += size + 1;
        self.rows.push(row);
        Ok(true)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "native protocol branches share one result contract"
)]
async fn request(
    database: &DatabaseConfig,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
    sessions: &mut Sessions,
    limit: Duration,
) -> Result<Value, &'static str> {
    config.validate().map_err(|_| "invalid_configuration")?;
    let (sql, names) = database.sql(config).map_err(|_| "invalid_configuration")?;
    let values: Vec<_> = names
        .iter()
        .map(|n| parameters.get(n).ok_or("invalid_input"))
        .collect::<Result<_, _>>()?;
    let password = secrets.first().ok_or("credential_unavailable")?;
    let mut result = ResultRows::new();
    match database.engine {
        DatabaseEngine::Postgres => {
            let mut options = Config::new();
            options
                .host(&database.host)
                .port(database.port)
                .dbname(&database.database)
                .user(&database.username)
                .password(password.as_bytes())
                .application_name("SecretBridge");
            let (client, connection) = if database.tls_mode == DatabaseTls::LoopbackPlaintext {
                options.ssl_mode(SslMode::Disable);
                let (client, connection) = options
                    .connect(tokio_postgres::NoTls)
                    .await
                    .map_err(|_| "connection_failed")?;
                (
                    client,
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
            } else {
                options.ssl_mode(SslMode::Require);
                let tls = crate::postgres::postgres_tls_config(ca_path(database)?)
                    .map_err(|()| "tls_configuration_failed")?;
                let (client, connection) = options
                    .connect(MakeRustlsConnect::new(tls))
                    .await
                    .map_err(|_| "connection_failed")?;
                (
                    client,
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
            };
            sessions.postgres = Some(client);
            sessions.connection = Some(connection);
            let client = sessions.postgres.as_mut().ok_or("connection_failed")?;
            let tx = client
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(|_| "read_only_transaction_failed")?;
            tx.batch_execute(&format!(
                "SET LOCAL statement_timeout = {}",
                limit.as_millis().clamp(1, 600_000)
            ))
            .await
            .map_err(|_| "query_failed")?;
            let bound: Vec<Box<dyn ToSql + Sync + Send>> = values
                .iter()
                .map(|v| match v {
                    Value::String(s) => Ok(Box::new(s.clone()) as Box<dyn ToSql + Sync + Send>),
                    Value::Bool(b) => Ok(Box::new(*b) as Box<dyn ToSql + Sync + Send>),
                    Value::Number(n) => n
                        .as_i64()
                        .map(|n| Box::new(n) as Box<dyn ToSql + Sync + Send>)
                        .ok_or("invalid_input"),
                    _ => Err("invalid_input"),
                })
                .collect::<Result<_, _>>()?;
            let typed: Vec<_> = names
                .iter()
                .zip(&bound)
                .map(|(n, v)| {
                    let kind = config
                        .parameters
                        .iter()
                        .find(|p| p.name == *n)
                        .map(|p| p.kind);
                    (
                        v.as_ref() as &(dyn ToSql + Sync),
                        match kind {
                            Some(ParameterType::Integer) => Type::INT8,
                            Some(ParameterType::Boolean) => Type::BOOL,
                            _ => Type::TEXT,
                        },
                    )
                })
                .collect();
            let stream = tx
                .query_typed_raw(&sql, typed)
                .await
                .map_err(|_| "query_failed")?;
            pin_mut!(stream);
            while let Some(row) = stream.next().await {
                let row = row.map_err(|_| "query_failed")?;
                let text: Zeroizing<String> =
                    Zeroizing::new(row.try_get(0).map_err(|_| "result_conversion_failed")?);
                if text.len() > 262_144 {
                    return Err("result_too_large");
                }
                let value = serde_json::from_str(&text).map_err(|_| "result_conversion_failed")?;
                if !result.add(value, database.max_rows, secrets)? {
                    break;
                }
            }
            // Dropping an unfinished stream before rollback is intentional; the
            // bounded LIMIT caps returned rows while statement_timeout caps work.
            tx.rollback().await.map_err(|_| "query_failed")?;
        }
        DatabaseEngine::Mysql => {
            let connection = Conn::new(mysql_options(database, password)?)
                .await
                .map_err(|_| "connection_failed")?;
            sessions.mysql = Some(connection);
            let conn = sessions.mysql.as_mut().ok_or("connection_failed")?;
            conn.query_drop(format!(
                "SET SESSION max_execution_time = {}",
                limit.as_millis().clamp(1, 600_000)
            ))
            .await
            .map_err(|_| "query_failed")?;
            let mut opts = TxOpts::default();
            opts.with_readonly(true);
            let mut tx = conn
                .start_transaction(opts)
                .await
                .map_err(|_| "read_only_transaction_failed")?;
            let bound: Vec<_> = values
                .iter()
                .map(|v| match v {
                    Value::String(s) => Ok(mysql_async::Value::Bytes(s.as_bytes().to_vec())),
                    Value::Bool(b) => Ok(mysql_async::Value::Int(i64::from(*b))),
                    Value::Number(n) => n
                        .as_i64()
                        .map(mysql_async::Value::Int)
                        .ok_or("invalid_input"),
                    _ => Err("invalid_input"),
                })
                .collect::<Result<_, _>>()?;
            let mut query = tx
                .exec_iter(&sql, bound)
                .await
                .map_err(|_| "query_failed")?;
            while let Some(row) = query.next().await.map_err(|_| "query_failed")? {
                let values = row
                    .unwrap()
                    .into_iter()
                    .map(mysql_value)
                    .collect::<Result<Vec<_>, _>>()?;
                if !result.add(Value::Array(values), database.max_rows, secrets)? {
                    break;
                }
            }
            query.drop_result().await.map_err(|_| "query_failed")?;
            tx.rollback().await.map_err(|_| "query_failed")?;
        }
    }
    let mut columns = json!(database.output_columns());
    filter_value(&mut columns, secrets);
    Ok(
        json!({"kind":"database", "engine":database.engine, "operation":database.operation,
        "columns":columns, "row_count":result.rows.len(), "rows":result.rows, "truncated":result.truncated}),
    )
}

fn mysql_value(value: mysql_async::Value) -> Result<Value, &'static str> {
    use mysql_async::Value as M;
    Ok(match value {
        M::NULL => Value::Null,
        M::Int(n) => json!(n.to_string()),
        M::UInt(n) => json!(n.to_string()),
        M::Float(n) => json!(n.to_string()),
        M::Double(n) => json!(n.to_string()),
        M::Bytes(b) => {
            Value::String(String::from_utf8(b).map_err(|_| "unsupported_binary_result")?)
        }
        M::Date(year, month, day, hour, minute, second, micros) => json!(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
        )),
        M::Time(negative, days, hours, minutes, seconds, micros) => json!(format!(
            "{}{}:{minutes:02}:{seconds:02}.{micros:06}",
            if negative { "-" } else { "" },
            days * 24 + u32::from(hours)
        )),
    })
}

async fn cleanup(
    sessions: &mut Sessions,
    database: &DatabaseConfig,
    secrets: &[Zeroizing<String>],
    interrupted: bool,
) -> bool {
    let mut cleaned = true;
    if let Some(client) = &sessions.postgres
        && interrupted
    {
        cleaned = tokio::time::timeout(Duration::from_secs(1), async {
            if database.tls_mode == DatabaseTls::LoopbackPlaintext {
                client
                    .cancel_token()
                    .cancel_query(tokio_postgres::NoTls)
                    .await
                    .is_ok()
            } else if let Ok(path) = ca_path(database)
                && let Ok(tls) = crate::postgres::postgres_tls_config(path)
            {
                client
                    .cancel_token()
                    .cancel_query(MakeRustlsConnect::new(tls))
                    .await
                    .is_ok()
            } else {
                false
            }
        })
        .await
        .unwrap_or(false);
    }
    let mut killed = false;
    if let Some(conn) = &sessions.mysql
        && interrupted
    {
        // Keep the original connection outside the cancellation future, so a
        // stalled second authentication does not defer its shutdown via Drop.
        killed = tokio::time::timeout(Duration::from_secs(1), async {
            if let Some(secret) = secrets.first()
                && let Ok(opts) = mysql_options(database, secret)
                && let Ok(mut cancel) = Conn::new(opts).await
            {
                let killed = cancel
                    .query_drop(format!("KILL CONNECTION {}", conn.id()))
                    .await
                    .is_ok();
                let _ = cancel.disconnect().await;
                killed
            } else {
                false
            }
        })
        .await
        .unwrap_or(false);
        cleaned = killed;
    }
    if let Some(conn) = sessions.mysql.take() {
        let disconnected = tokio::time::timeout(Duration::from_secs(1), conn.disconnect())
            .await
            .is_ok_and(|r| r.is_ok());
        cleaned &= killed || disconnected;
    }
    sessions.postgres.take();
    if let Some(task) = sessions.connection.take() {
        task.abort();
    }
    cleaned
}

#[allow(
    clippy::too_many_arguments,
    reason = "shares the existing approved credential execution context"
)]
pub async fn drive(
    state: &AppState,
    id: Uuid,
    database: &DatabaseConfig,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
    cancellation: &CancellationToken,
    limit: Duration,
) {
    let mut sessions = Sessions::default();
    let (status, mut output) = tokio::select! {
        biased;
        () = cancellation.cancelled() => ("cancelled", json!({"kind":"database", "error_code":"cancelled"})),
        result = tokio::time::timeout(limit, request(database, config, parameters, secrets, &mut sessions, limit)) => match result {
            Ok(Ok(output)) => ("command_ok", output),
            Ok(Err(code)) => ("command_failed", json!({"kind":"database", "error_code":code})),
            Err(_) => ("timed_out", json!({"kind":"database", "error_code":"timed_out"})),
        }
    };
    output["cleanup_ok"] =
        json!(cleanup(&mut sessions, database, secrets, status != "command_ok").await);
    filter_value(&mut output, secrets);
    let text = Zeroizing::new(serde_json::to_string(&output).unwrap_or_default());
    let _ = state.catalog.append_output(id, "stdout", &text);
    let _ = state.catalog.complete_command_run(id, status, None);
    let _ = state.changes.send(());
}

#[cfg(test)]
pub(crate) mod tests;
