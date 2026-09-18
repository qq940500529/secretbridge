// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::catalog::{CreateSyntheticRun, DecideApproval, RunState};

pub(crate) const PASSWORD: &str = "Synthetic_db_password_30";
pub(crate) fn config(engine: DatabaseEngine, port: u16, credential: Uuid) -> CommandConfig {
    serde_json::from_value(json!({"program":"","working_directory":"","arguments":[],
        "slots":[{"name":"password","credential_id":credential,"injection":"protocol","environment_variable":null}],
        "database":{"engine":engine,"operation":"query","host":"127.0.0.1","port":port,
            "database":"secretbridge","username":"secretbridge","password_slot":"password","tls_mode":"loopback_plaintext",
            "ca_certificate":null,"query":"SELECT {{param:company}} AS company, {{param:amount}} AS amount, {{param:ready}} AS ready, NULL AS empty_value, '12345678901234567890.123456' AS precise, 'not-selected' AS hidden",
            "columns":["company","amount","ready","empty_value","precise"],"max_rows":100},
        "parameters":[{"name":"company","label":"公司","kind":"string","required":true,"default":"100","choices":[],"max_length":128},
            {"name":"amount","label":"数量","kind":"integer","default":7,"choices":[],"max_length":null},
            {"name":"ready","label":"启用","kind":"boolean","default":true,"choices":[],"max_length":null}]})).unwrap()
}

pub(crate) fn configured(state: &AppState, command: &mut CommandConfig, timeout: u64) -> Uuid {
    let credential = state
        .catalog
        .create_credential_reference(
            &serde_json::from_value(json!({"name":"Database fixture", "kind":"password"})).unwrap(),
        )
        .unwrap();
    state.secret_store.set(credential.id, PASSWORD).unwrap();
    state
        .catalog
        .set_credential_secret_state(credential.id, credential.version, true)
        .unwrap();
    command.slots[0].credential_id = credential.id;
    let target = state
        .catalog
        .create_target(
            &serde_json::from_value(
                json!({"name":"Database fixture","kind":"database","environment":"test"}),
            )
            .unwrap(),
        )
        .unwrap();
    state.catalog.create_action_template(&serde_json::from_value(json!({"name":"Database query", "target_id":target.id,
        "operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"command":command})).unwrap()).unwrap().id
}
pub(crate) fn approve(state: &AppState, template: Uuid, parameters: &ParameterValues) -> Uuid {
    let approval = state.catalog.create_approval(&serde_json::from_value(json!({"action_template_id":template,"parameters":parameters,"expires_in_seconds":60,"authorization_mode":"time_window"})).unwrap()).unwrap();
    state
        .catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    approval.id
}
pub(crate) async fn wait(state: &AppState, id: Uuid) -> Value {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = state.catalog.output(id, 0).unwrap();
            if !matches!(page.state, RunState::Running | RunState::Queued)
                && !state
                    .run_cancellations
                    .active
                    .lock()
                    .await
                    .contains_key(&id)
            {
                let text = page
                    .items
                    .iter()
                    .map(|c| c.text.as_str())
                    .collect::<String>();
                assert!(!text.contains(PASSWORD));
                return serde_json::from_str(&text).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
pub(crate) fn port(engine: DatabaseEngine) -> u16 {
    std::env::var(match engine {
        DatabaseEngine::Postgres => "SECRETBRIDGE_TEST_PG_PORT",
        DatabaseEngine::Mysql => "SECRETBRIDGE_TEST_MYSQL_PORT",
    })
    .expect("explicit local fixture port is required")
    .parse()
    .unwrap()
}

#[test]
fn placeholder_lexer_ignores_literals_comments_and_dollar_quotes() {
    let command = config(DatabaseEngine::Postgres, 5432, Uuid::new_v4());
    let sql = "/* SELECT ?; {{param:nope}} */ WITH v AS (SELECT '{{param:nope}};?' AS v) SELECT {{param:company}}, {{param:amount}}, {{param:ready}}, $tag${{param:nope}};$tag$, 'it''s fine' -- {{param:nope}};?\n";
    let (compiled, names) = compile_query(sql, DatabaseEngine::Postgres, &command).unwrap();
    assert!(compiled.contains("SELECT $1, $2, $3"));
    assert!(compiled.contains("$tag${{param:nope}};$tag$"));
    assert_eq!(names, ["company", "amount", "ready"]);
    let mysql = "SELECT {{param:company}}, {{param:amount}}, {{param:ready}}, '{{param:nope}}' AS `?;` # {{param:nope}}\n";
    assert!(
        compile_query(mysql, DatabaseEngine::Mysql, &command)
            .unwrap()
            .0
            .contains("SELECT ?, ?, ?")
    );
}
#[test]
fn reject_unbound_native_parameters_extra_statements_unknown_names_and_ambiguous_escapes() {
    let mut command = config(DatabaseEngine::Postgres, 5432, Uuid::new_v4());
    command.parameters.clear();
    for query in [
        "SELECT 1;",
        "SELECT $1",
        "SELECT ?",
        "SELECT {{param:nope}}",
        "DELETE FROM x",
        "SELECT 'bad\\'x'",
        "SELECT $$bad",
        "SELECT 1 /*! bad */",
        "SELECT 1 /* bad",
        "SELECT 'bad",
    ] {
        assert!(
            compile_query(query, DatabaseEngine::Postgres, &command).is_err(),
            "{query}"
        );
    }
    assert!(compile_query("SELECT 'hello; world'", DatabaseEngine::Postgres, &command).is_ok());
    command.parameters = config(DatabaseEngine::Postgres, 5432, Uuid::new_v4()).parameters;
    assert!(compile_query("SELECT 1", DatabaseEngine::Postgres, &command).is_err());
}
#[test]
fn validate_protocol_modes_paths_limits_and_exclusive_configuration() {
    let original = config(DatabaseEngine::Postgres, 5432, Uuid::new_v4());
    assert!(original.validate().is_ok());
    for field in [
        "host",
        "port",
        "max_rows",
        "columns",
        "password_slot",
        "ca_certificate",
    ] {
        let mut json = serde_json::to_value(&original).unwrap();
        json["database"][field] = match field {
            "port" | "max_rows" => json!(0),
            "columns" => json!([]),
            "ca_certificate" => json!("/tmp/ca.pem"),
            _ => json!(""),
        };
        assert!(
            serde_json::from_value::<CommandConfig>(json)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for host in ["localhost", "db.example.com", "192.0.2.10"] {
        let mut c = original.clone();
        c.database.as_mut().unwrap().host = host.into();
        assert!(c.validate().is_err());
    }
    let mut c = original.clone();
    c.database.as_mut().unwrap().tls_mode = DatabaseTls::VerifyFull;
    c.database.as_mut().unwrap().host = "db.example.com".into();
    assert!(c.validate().is_ok());
    c.database.as_mut().unwrap().ca_certificate = Some("relative.pem".into());
    assert!(c.validate().is_err());
    let mut c = original.clone();
    c.slots[0].injection = Injection::Environment;
    assert!(c.validate().is_err());
    let mut c = original.clone();
    c.database.as_mut().unwrap().operation = DatabaseOperation::Version;
    assert!(c.validate().is_err());
    let mut c = original;
    c.http =
        Some(serde_json::from_value(json!({"method":"GET","url":"https://example.com"})).unwrap());
    assert!(c.validate().is_err());
}
#[test]
fn selected_columns_are_identifier_quoted_and_result_filter_precedes_json_encoding() {
    let mut c = config(DatabaseEngine::Postgres, 5432, Uuid::new_v4());
    c.database.as_mut().unwrap().columns = vec!["金额\"编号".into()];
    assert!(
        c.database
            .as_ref()
            .unwrap()
            .sql(&c)
            .unwrap()
            .0
            .contains("sb.\"金额\"\"编号\"::text")
    );
    let secrets = vec![Zeroizing::new("quote\"secret".to_string())];
    let mut rows = ResultRows::new();
    assert!(
        rows.add(
            json!(["quote\"secret", null, "12345678901234567890.123456"]),
            1,
            &secrets
        )
        .unwrap()
    );
    assert!(!rows.add(json!(["more"]), 1, &secrets).unwrap());
    assert!(rows.truncated);
    assert_eq!(rows.rows[0][0], "[REDACTED]");
    assert_eq!(rows.rows[0][2], "12345678901234567890.123456");
    assert_eq!(
        mysql_value(mysql_async::Value::UInt(u64::MAX)).unwrap(),
        json!(u64::MAX.to_string())
    );
    assert!(mysql_value(mysql_async::Value::Bytes(vec![255])).is_err());
}

async fn roundtrip(engine: DatabaseEngine) {
    let (state, _) = AppState::new([]);
    let mut command = config(engine, port(engine), Uuid::nil());
    let template = configured(&state, &mut command, 5);
    let approval = approve(
        &state,
        template,
        &ParameterValues::from([("company".into(), json!(PASSWORD))]),
    );
    let key = Uuid::new_v4().to_string();
    let run = crate::create_run_for_state(
        &state,
        CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: key.clone(),
        },
    )
    .await
    .unwrap();
    let value = wait(&state, run.run.id).await;
    assert_eq!(
        state.catalog.get_synthetic_run(run.run.id).unwrap().state,
        RunState::Succeeded,
        "{value}"
    );
    assert_eq!(value["rows"][0][0], "[REDACTED]");
    assert_eq!(value["rows"][0][1], "7");
    assert_eq!(value["rows"][0][3], Value::Null);
    assert_eq!(value["rows"][0][4], "12345678901234567890.123456");
    assert!(!value.to_string().contains("not-selected"));
    assert_eq!(value["cleanup_ok"], true);
    assert!(
        crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: key
            }
        )
        .await
        .unwrap()
        .replayed
    );
    let params = crate::parameters::resolve(
        &command.parameters,
        &ParameterValues::from([("company".into(), json!("x' UNION SELECT 'injected"))]),
    )
    .unwrap();
    let mut sessions = Sessions::default();
    let direct = request(
        command.database.as_ref().unwrap(),
        &command,
        &params,
        &[Zeroizing::new(PASSWORD.into())],
        &mut sessions,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(direct["rows"][0][0], "x' UNION SELECT 'injected");
    assert!(
        cleanup(
            &mut sessions,
            command.database.as_ref().unwrap(),
            &[Zeroizing::new(PASSWORD.into())],
            false
        )
        .await
    );
    for operation in [DatabaseOperation::Check, DatabaseOperation::Version] {
        command.parameters.clear();
        let db = command.database.as_mut().unwrap();
        db.query.clear();
        db.columns.clear();
        db.operation = operation;
        let mut sessions = Sessions::default();
        let result = request(
            command.database.as_ref().unwrap(),
            &command,
            &ParameterValues::new(),
            &[Zeroizing::new(PASSWORD.into())],
            &mut sessions,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(result["row_count"], 1);
        cleanup(
            &mut sessions,
            command.database.as_ref().unwrap(),
            &[Zeroizing::new(PASSWORD.into())],
            false,
        )
        .await;
    }
}
#[allow(
    clippy::too_many_lines,
    reason = "shared real-service failure and lifecycle contract"
)]
async fn failures_limits_and_cancel(engine: DatabaseEngine) {
    let (state, _) = AppState::new([]);
    let mut command = config(engine, port(engine), Uuid::nil());
    command.parameters.clear();
    let db = command.database.as_mut().unwrap();
    db.query = "SELECT 1 AS n UNION ALL SELECT 2 AS n UNION ALL SELECT 3 AS n".into();
    db.columns = vec!["n".into()];
    db.max_rows = 2;
    let secrets = [Zeroizing::new(PASSWORD.into())];
    let mut sessions = Sessions::default();
    let result = request(
        command.database.as_ref().unwrap(),
        &command,
        &ParameterValues::new(),
        &secrets,
        &mut sessions,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(result["rows"], json!([["1"], ["2"]]));
    assert_eq!(result["truncated"], true);
    cleanup(
        &mut sessions,
        command.database.as_ref().unwrap(),
        &secrets,
        false,
    )
    .await;
    let mut sessions = Sessions::default();
    assert!(
        request(
            command.database.as_ref().unwrap(),
            &command,
            &ParameterValues::new(),
            &[Zeroizing::new("Synthetic_wrong_password".into())],
            &mut sessions,
            Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    command.database.as_mut().unwrap().columns = vec!["missing".into()];
    let mut sessions = Sessions::default();
    assert_eq!(
        request(
            command.database.as_ref().unwrap(),
            &command,
            &ParameterValues::new(),
            &secrets,
            &mut sessions,
            Duration::from_secs(5)
        )
        .await
        .unwrap_err(),
        "query_failed"
    );
    cleanup(
        &mut sessions,
        command.database.as_ref().unwrap(),
        &secrets,
        true,
    )
    .await;
    command.database.as_mut().unwrap().query = match engine {
        DatabaseEngine::Postgres => "SELECT pg_sleep(10) AS n",
        DatabaseEngine::Mysql => "SELECT SLEEP(10) AS n",
    }
    .into();
    command.database.as_mut().unwrap().columns = vec!["n".into()];
    for cancel in [false, true] {
        let template = configured(&state, &mut command, if cancel { 5 } else { 1 });
        let approval = approve(&state, template, &ParameterValues::new());
        let run = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .unwrap();
        if cancel {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let current = state.catalog.get_synthetic_run(run.run.id).unwrap();
            crate::cancel_run_for_state(
                &state,
                run.run.id,
                crate::catalog::CancelSyntheticRun {
                    expected_version: current.version,
                },
            )
            .await
            .unwrap();
        }
        let output = wait(&state, run.run.id).await;
        assert_eq!(
            output["error_code"],
            if cancel { "cancelled" } else { "timed_out" }
        );
        assert_eq!(output["cleanup_ok"], true);
    }
}
#[tokio::test]
#[ignore = "requires explicitly provisioned local PostgreSQL fixture"]
async fn real_postgres_query_version_binding_redaction_and_replay() {
    roundtrip(DatabaseEngine::Postgres).await;
}
#[tokio::test]
#[ignore = "requires explicitly provisioned local MySQL fixture"]
async fn real_mysql_query_version_binding_redaction_and_replay() {
    roundtrip(DatabaseEngine::Mysql).await;
}
#[tokio::test]
#[ignore = "requires explicitly provisioned local PostgreSQL fixture"]
async fn real_postgres_limits_failures_timeout_and_api_cancellation() {
    failures_limits_and_cancel(DatabaseEngine::Postgres).await;
}
#[tokio::test]
#[ignore = "requires explicitly provisioned local MySQL fixture"]
async fn real_mysql_limits_failures_timeout_and_api_cancellation() {
    failures_limits_and_cancel(DatabaseEngine::Mysql).await;
}

#[test]
fn bounded_rows_and_configuration_reopen_preserve_no_secret_values() {
    let mut rows = ResultRows::new();
    let secrets = [Zeroizing::new(PASSWORD.into())];
    assert!(
        rows.add(json!(["x".repeat(100_000)]), 1000, &secrets)
            .unwrap()
    );
    assert!(
        !rows
            .add(json!(["y".repeat(100_000)]), 1000, &secrets)
            .unwrap()
    );
    assert!(rows.truncated);
    assert!(
        ResultRows::new()
            .add(json!(["z".repeat(OUTPUT_LIMIT)]), 1000, &secrets)
            .is_err()
    );
    let path = std::env::temp_dir().join(format!("sb-db-{}.sqlite3", Uuid::new_v4()));
    let (mut state, _) = AppState::new([]);
    state.catalog = crate::catalog::Catalog::open(&path).unwrap();
    let template = configured(
        &state,
        &mut config(DatabaseEngine::Postgres, 5432, Uuid::nil()),
        5,
    );
    let approval = approve(&state, template, &ParameterValues::new());
    drop(state);
    let catalog = crate::catalog::Catalog::open(&path).unwrap();
    let restored = catalog
        .list_action_templates()
        .unwrap()
        .into_iter()
        .find(|t| t.id == template)
        .unwrap();
    assert!(restored.command.unwrap().validate().is_ok());
    assert_eq!(
        catalog.get_approval(approval).unwrap().parameters["company"],
        "100"
    );
    drop(catalog);
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .windows(PASSWORD.len())
            .any(|b| b == PASSWORD.as_bytes())
    );
    std::fs::remove_file(path).unwrap();
}

#[allow(
    clippy::too_many_lines,
    reason = "paired native setup, write rejection and owned fixture teardown"
)]
async fn read_only(engine: DatabaseEngine) {
    let mut command = config(engine, port(engine), Uuid::nil());
    command.parameters.clear();
    let database = command.database.as_mut().unwrap();
    let name = format!("sb_probe_{}", Uuid::new_v4().simple());
    let function = format!("{name}_fn");
    let setup = match engine {
        DatabaseEngine::Postgres => format!(
            "CREATE TABLE {name}(n integer); CREATE FUNCTION {function}() RETURNS integer LANGUAGE plpgsql AS $$ BEGIN INSERT INTO {name} VALUES(1); RETURN 1; END $$"
        ),
        DatabaseEngine::Mysql => format!("CREATE TABLE {name}(n integer)"),
    };
    let mut sessions = Sessions::default();
    database.query = "SELECT 1 AS n".into();
    database.columns = vec!["n".into()];
    request(
        command.database.as_ref().unwrap(),
        &command,
        &ParameterValues::new(),
        &[Zeroizing::new(PASSWORD.into())],
        &mut sessions,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    match engine {
        DatabaseEngine::Postgres => sessions
            .postgres
            .as_ref()
            .unwrap()
            .batch_execute(&setup)
            .await
            .unwrap(),
        DatabaseEngine::Mysql => {
            let conn = sessions.mysql.as_mut().unwrap();
            conn.query_drop(&setup).await.unwrap();
            conn.query_drop(format!("CREATE FUNCTION {function}() RETURNS INT MODIFIES SQL DATA BEGIN INSERT INTO {name} VALUES(1); RETURN 1; END")).await.unwrap();
        }
    }
    cleanup(
        &mut sessions,
        command.database.as_ref().unwrap(),
        &[Zeroizing::new(PASSWORD.into())],
        false,
    )
    .await;
    command.database.as_mut().unwrap().query = format!("SELECT {function}() AS n");
    let mut sessions = Sessions::default();
    let rejected = request(
        command.database.as_ref().unwrap(),
        &command,
        &ParameterValues::new(),
        &[Zeroizing::new(PASSWORD.into())],
        &mut sessions,
        Duration::from_secs(5),
    )
    .await;
    cleanup(
        &mut sessions,
        command.database.as_ref().unwrap(),
        &[Zeroizing::new(PASSWORD.into())],
        true,
    )
    .await;
    command.database.as_mut().unwrap().query = format!("SELECT COUNT(*) AS n FROM {name}");
    let mut sessions = Sessions::default();
    let counts = request(
        command.database.as_ref().unwrap(),
        &command,
        &ParameterValues::new(),
        &[Zeroizing::new(PASSWORD.into())],
        &mut sessions,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    match engine {
        DatabaseEngine::Postgres => sessions
            .postgres
            .as_ref()
            .unwrap()
            .batch_execute(&format!("DROP FUNCTION {function}(); DROP TABLE {name}"))
            .await
            .unwrap(),
        DatabaseEngine::Mysql => {
            let conn = sessions.mysql.as_mut().unwrap();
            conn.query_drop(format!("DROP FUNCTION {function}"))
                .await
                .unwrap();
            conn.query_drop(format!("DROP TABLE {name}")).await.unwrap();
        }
    }
    cleanup(
        &mut sessions,
        command.database.as_ref().unwrap(),
        &[Zeroizing::new(PASSWORD.into())],
        false,
    )
    .await;
    assert_eq!(rejected.unwrap_err(), "query_failed");
    assert_eq!(counts["rows"][0][0], "0");
}
#[tokio::test]
#[ignore = "requires explicitly provisioned local PostgreSQL fixture"]
async fn real_postgres_read_only_transaction_blocks_function_writes() {
    read_only(DatabaseEngine::Postgres).await;
}
#[tokio::test]
#[ignore = "requires local MySQL with log_bin_trust_function_creators enabled"]
async fn real_mysql_read_only_transaction_blocks_function_writes() {
    read_only(DatabaseEngine::Mysql).await;
}

async fn tls_validation(engine: DatabaseEngine) {
    let mut command = config(engine, port(engine), Uuid::nil());
    command.parameters.clear();
    let database = command.database.as_mut().unwrap();
    database.operation = DatabaseOperation::Check;
    database.query.clear();
    database.columns.clear();
    database.tls_mode = DatabaseTls::VerifyFull;
    database.ca_certificate =
        Some(std::env::var("SECRETBRIDGE_TEST_DB_CA").expect("private CA fixture is required"));
    if engine == DatabaseEngine::Mysql {
        let probe = Conn::new(mysql_options(database, PASSWORD).unwrap())
            .await
            .expect("native TLS fixture must authenticate");
        probe.disconnect().await.unwrap();
    }
    let mut sessions = Sessions::default();
    request(
        command.database.as_ref().unwrap(),
        &command,
        &ParameterValues::new(),
        &[Zeroizing::new(PASSWORD.into())],
        &mut sessions,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    cleanup(
        &mut sessions,
        command.database.as_ref().unwrap(),
        &[Zeroizing::new(PASSWORD.into())],
        false,
    )
    .await;
    // The fixture certificate has only an IP SAN for 127.0.0.1, not localhost.
    command.database.as_mut().unwrap().host = "localhost".into();
    let mut sessions = Sessions::default();
    assert!(
        request(
            command.database.as_ref().unwrap(),
            &command,
            &ParameterValues::new(),
            &[Zeroizing::new(PASSWORD.into())],
            &mut sessions,
            Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    command.database.as_mut().unwrap().host = "127.0.0.1".into();
    command.database.as_mut().unwrap().ca_certificate = None;
    let mut sessions = Sessions::default();
    assert!(
        request(
            command.database.as_ref().unwrap(),
            &command,
            &ParameterValues::new(),
            &[Zeroizing::new(PASSWORD.into())],
            &mut sessions,
            Duration::from_secs(5)
        )
        .await
        .is_err()
    );
}
#[tokio::test]
#[ignore = "requires local PostgreSQL TLS and private CA fixtures"]
async fn real_postgres_tls_accepts_private_ca_rejects_untrusted_and_mismatched_host() {
    tls_validation(DatabaseEngine::Postgres).await;
}
#[tokio::test]
#[ignore = "requires local MySQL TLS and private CA fixtures"]
async fn real_mysql_tls_accepts_private_ca_rejects_untrusted_and_mismatched_host() {
    tls_validation(DatabaseEngine::Mysql).await;
}

#[tokio::test]
#[ignore = "requires both explicitly provisioned local database fixtures"]
async fn real_database_web_configuration_approval_execute_and_read() {
    use crate::command::tests::web_request;
    use axum::http::StatusCode;
    for engine in [DatabaseEngine::Postgres, DatabaseEngine::Mysql] {
        let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
        let template = configured(&state, &mut config(engine, port(engine), Uuid::nil()), 5);
        let template = state
            .catalog
            .list_action_templates()
            .unwrap()
            .into_iter()
            .find(|t| t.id == template)
            .unwrap();
        let (token, _) = state.issue_session().await;
        let (status, created) = web_request(&state, &token, "/api/v1/action-templates", json!({"name":"Web query","target_id":template.target_id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":5,"command":template.command})).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = web_request(
            &state,
            &token,
            "/api/v1/approvals",
            json!({"action_template_id":created["id"],"expires_in_seconds":60,"parameters":{"amount":"7"}}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, approval) = web_request(
            &state,
            &token,
            "/api/v1/approvals",
            json!({"action_template_id":created["id"],"expires_in_seconds":60}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = web_request(
            &state,
            &token,
            &format!(
                "/api/v1/approvals/{}/approve",
                approval["id"].as_str().unwrap()
            ),
            json!({"expected_version":approval["version"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, run) = web_request(
            &state,
            &token,
            "/api/v1/runs",
            json!({"approval_id":approval["id"],"idempotency_key":Uuid::new_v4().to_string()}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = Uuid::parse_str(run["run"]["id"].as_str().unwrap()).unwrap();
        assert_eq!(wait(&state, id).await["rows"][0][0], "100");
        let (status, output) = web_request(
            &state,
            &token,
            &format!("/api/v1/runs/{id}/output"),
            json!({"cursor":0,"wait_ms":0}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(output["exit_code"].is_null());
        assert!(output.to_string().contains("database"));
    }
}
