// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    AppState,
    application::redaction::Redactor,
    catalog::CatalogError,
    command::{CommandConfig, Injection},
    parameters::ParameterValues,
};
use reqwest::{
    Method, Url,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::HashSet, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const BODY_LIMIT: usize = 262_144;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<HttpField>,
    #[serde(default)]
    pub query: Vec<HttpField>,
    #[serde(default)]
    pub body: Vec<HttpField>,
    #[serde(default)]
    pub response_fields: Vec<ResponseField>,
    #[serde(default)]
    pub accepted_statuses: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpField {
    pub name: String,
    pub source: ValueSource,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSource {
    Literal { value: String },
    Parameter { name: String },
    Credential { name: String, prefix: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseField {
    pub name: String,
    pub pointer: String,
}

impl HttpConfig {
    pub fn validate(&self, config: &CommandConfig) -> Result<(), CatalogError> {
        let invalid = || CatalogError::Invalid;
        let url = Url::parse(&self.url).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.url.len() > 2048
            || !matches!(
                self.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
            )
            || (!self.body.is_empty() && matches!(self.method.as_str(), "GET" | "HEAD"))
            || !config.program.is_empty()
            || !config.working_directory.is_empty()
            || !config.arguments.is_empty()
            || config.slots.len() > 8
            || self.response_fields.len() > 32
            || self.accepted_statuses.len() > 32
            || self
                .accepted_statuses
                .iter()
                .any(|s| !(200..=599).contains(s))
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > 32768
        {
            return Err(invalid());
        }
        let mut slots = HashSet::new();
        for slot in &config.slots {
            if !crate::parameters::identifier(&slot.name)
                || !slots.insert(slot.name.as_str())
                || slot.injection != Injection::Protocol
                || slot.environment_variable.is_some()
            {
                return Err(invalid());
            }
        }
        self.validate_fields(config, &slots)?;
        let mut names = HashSet::new();
        for field in &self.response_fields {
            if !crate::parameters::identifier(&field.name)
                || !names.insert(&field.name)
                || field.pointer.len() > 512
                || (!field.pointer.is_empty() && !field.pointer.starts_with('/'))
                || field.pointer.contains('\0')
                || !valid_pointer(&field.pointer)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn validate_fields(
        &self,
        config: &CommandConfig,
        slots: &HashSet<&str>,
    ) -> Result<(), CatalogError> {
        let invalid = || CatalogError::Invalid;
        let mut used = HashSet::new();
        for (fields, headers, query) in [
            (&self.headers, true, false),
            (&self.query, false, true),
            (&self.body, false, false),
        ] {
            if fields.len() > 32 {
                return Err(invalid());
            }
            let mut names = HashSet::new();
            for field in fields {
                if field.name.is_empty()
                    || field.name.len() > 128
                    || field.name.contains('\0')
                    || !names.insert(if headers {
                        field.name.to_ascii_lowercase()
                    } else {
                        field.name.clone()
                    })
                {
                    return Err(invalid());
                }
                if headers {
                    HeaderName::from_bytes(field.name.as_bytes()).map_err(|_| invalid())?;
                    if matches!(
                        field.name.to_ascii_lowercase().as_str(),
                        "host"
                            | "content-length"
                            | "transfer-encoding"
                            | "connection"
                            | "accept-encoding"
                            | "content-type"
                    ) {
                        return Err(invalid());
                    }
                }
                match &field.source {
                    ValueSource::Literal { value } => {
                        if value.len() > 8192 || value.contains('\0') {
                            return Err(invalid());
                        }
                        if headers {
                            HeaderValue::from_str(value).map_err(|_| invalid())?;
                        }
                    }
                    ValueSource::Parameter { name } => {
                        if !config.parameters.iter().any(|p| p.name == *name) {
                            return Err(invalid());
                        }
                    }
                    ValueSource::Credential { name, prefix } => {
                        if query
                            || !slots.contains(name.as_str())
                            || prefix.len() > 128
                            || prefix.contains(['\r', '\n', '\0'])
                        {
                            return Err(invalid());
                        }
                        used.insert(name.as_str());
                    }
                }
            }
        }
        if &used != slots {
            return Err(invalid());
        }
        Ok(())
    }
}

fn valid_pointer(pointer: &str) -> bool {
    let mut chars = pointer.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

fn resolve(
    source: &ValueSource,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
) -> Result<Value, &'static str> {
    match source {
        ValueSource::Literal { value } => Ok(Value::String(value.clone())),
        ValueSource::Parameter { name } => parameters.get(name).cloned().ok_or("invalid_input"),
        ValueSource::Credential { name, prefix } => config
            .slots
            .iter()
            .position(|s| s.name == *name)
            .and_then(|i| secrets.get(i))
            .map(|s| Value::String(format!("{prefix}{}", s.as_str())))
            .ok_or("credential_unavailable"),
    }
}

async fn request(
    http: &HttpConfig,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
) -> Result<Value, &'static str> {
    config.validate().map_err(|_| "invalid_configuration")?;
    // Reuse ring from the PostgreSQL TLS stack; installing twice is harmless.
    let _ = rustls_tokio_postgres::rustls::crypto::ring::default_provider().install_default();
    // Never follow redirects, use environment proxies, or export TLS traffic keys.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_sslkeylogfile(false)
        .build()
        .map_err(|_| "tls_configuration_failed")?;
    let mut url = Url::parse(&http.url).map_err(|_| "invalid_configuration")?;
    if !http.query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for field in &http.query {
            pairs.append_pair(
                &field.name,
                &crate::parameters::argument(&resolve(&field.source, config, parameters, secrets)?),
            );
        }
    }
    let mut request = client.request(
        Method::from_bytes(http.method.as_bytes()).map_err(|_| "invalid_configuration")?,
        url,
    );
    for field in &http.headers {
        let text =
            crate::parameters::argument(&resolve(&field.source, config, parameters, secrets)?);
        let mut value = HeaderValue::from_str(&text).map_err(|_| "invalid_header")?;
        value.set_sensitive(true);
        request = request.header(&field.name, value);
    }
    if !http.body.is_empty() {
        let mut body = Map::new();
        for field in &http.body {
            body.insert(
                field.name.clone(),
                resolve(&field.source, config, parameters, secrets)?,
            );
        }
        request = request
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).map_err(|_| "invalid_input")?);
    }
    let mut response = request.send().await.map_err(|_| "connection_failed")?;
    let status = response.status().as_u16();
    let accepted = if http.accepted_statuses.is_empty() {
        (200..300).contains(&status)
    } else {
        http.accepted_statuses.contains(&status)
    };
    let mut output = json!({"kind":"http", "status_code":status, "accepted":accepted});
    if !accepted {
        return Ok(output);
    }
    if !http.response_fields.is_empty() {
        if response
            .content_length()
            .is_some_and(|n| n > BODY_LIMIT as u64)
        {
            return Err("response_too_large");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| "response_read_failed")? {
            if bytes.len() + chunk.len() > BODY_LIMIT {
                return Err("response_too_large");
            }
            bytes.extend_from_slice(&chunk);
        }
        let parsed: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_json_response")?;
        let mut selected = Map::new();
        for field in &http.response_fields {
            selected.insert(
                field.name.clone(),
                parsed
                    .pointer(&field.pointer)
                    .cloned()
                    .ok_or("response_field_missing")?,
            );
        }
        output["fields"] = Value::Object(selected);
    }
    // Repeated pointers must not multiply a bounded response into huge output.
    let encoded = Zeroizing::new(serde_json::to_vec(&output).map_err(|_| "invalid_json_response")?);
    if encoded.len() > BODY_LIMIT {
        return Err("response_too_large");
    }
    Ok(output)
}

#[allow(
    clippy::too_many_arguments,
    reason = "shares the existing credential execution context"
)]
pub async fn drive(
    state: &AppState,
    id: Uuid,
    http: &HttpConfig,
    config: &CommandConfig,
    parameters: &ParameterValues,
    secrets: &[Zeroizing<String>],
    cancellation: &CancellationToken,
    limit: Duration,
) {
    let (status, output) = tokio::select! {
        biased;
        () = cancellation.cancelled() => ("cancelled", json!({"kind":"http", "error_code":"cancelled"})),
        result = tokio::time::timeout(limit, request(http, config, parameters, secrets)) => match result {
            Ok(Ok(value)) => (if value["accepted"] == true { "command_ok" } else { "command_failed" }, value),
            Ok(Err(code)) => ("command_failed", json!({"kind":"http", "error_code":code})),
            Err(_) => ("timed_out", json!({"kind":"http", "error_code":"timed_out"})),
        }
    };
    let text = Zeroizing::new(serde_json::to_string(&output).unwrap_or_default());
    let mut redactor = Redactor::new(secrets);
    let filtered = redactor.feed(text.as_bytes(), true);
    let _ = state
        .catalog
        .append_output(id, "stdout", &String::from_utf8_lossy(&filtered));
    // HTTP statuses are not process exit codes.
    let _ = state.catalog.complete_command_run(id, status, None);
    let _ = state.changes.send(());
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::catalog::{CreateSyntheticRun, DecideApproval, RunState};
    use axum::{
        Json, Router,
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        response::Redirect,
        routing::{get, post},
    };
    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    pub(crate) const SECRET: &str = "Synthetic-http-token_A&z";
    pub(crate) struct Fixture {
        pub url: String,
        pub hits: Arc<AtomicUsize>,
        pub server: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    pub(crate) async fn server() -> Fixture {
        async fn echo(
            State(hits): State<Arc<AtomicUsize>>,
            headers: HeaderMap,
            Query(query): Query<BTreeMap<String, String>>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            hits.fetch_add(1, Ordering::SeqCst);
            assert_eq!(headers["authorization"], format!("Bearer {SECRET}"));
            assert_eq!(body["password"], SECRET);
            assert_eq!(body["count"], 7);
            assert_eq!(body["ready"], true);
            assert_eq!(query["company"], "100 & 101");
            Json(
                json!({"data":{"company":query["company"],"count":body["count"],"ready":body["ready"],"echo":SECRET},"hidden":"not-selected"}),
            )
        }
        async fn trap(State(hits): State<Arc<AtomicUsize>>) -> StatusCode {
            hits.fetch_add(100, Ordering::SeqCst);
            StatusCode::OK
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/echo", post(echo))
            .route("/redirect", get(|| async { Redirect::temporary("/trap") }))
            .route("/trap", get(trap))
            .route(
                "/error",
                get(|| async { (StatusCode::UNAUTHORIZED, SECRET) }),
            )
            .route(
                "/large",
                get(|| async { Json(json!({"blob":"x".repeat(BODY_LIMIT+1)})) }),
            )
            .route("/invalid", get(|| async { SECRET }))
            .route(
                "/json",
                get(|| async { Json(json!({"version":"1.2.3","empty":null,"a/b":{"~":true}})) }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    StatusCode::OK
                }),
            )
            .with_state(hits.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Fixture { url, hits, server }
    }
    pub(crate) fn config(url: &str, credential: Uuid) -> CommandConfig {
        serde_json::from_value(json!({"program":"","working_directory":"","arguments":[],
            "slots":[{"name":"token","credential_id":credential,"injection":"protocol","environment_variable":null}],
            "parameters":[{"name":"company","label":"公司","kind":"string","required":true,"default":"100 & 101","max_length":32},{"name":"count","label":"数量","kind":"integer","required":true,"default":7},{"name":"ready","label":"就绪","kind":"boolean","required":true,"default":true}],
            "http":{"method":"POST","url":format!("{url}/echo"),
                "headers":[{"name":"Authorization","source":{"kind":"credential","name":"token","prefix":"Bearer "}}],
                "query":[{"name":"company","source":{"kind":"parameter","name":"company"}}],
                "body":[{"name":"password","source":{"kind":"credential","name":"token","prefix":""}},{"name":"count","source":{"kind":"parameter","name":"count"}},{"name":"ready","source":{"kind":"parameter","name":"ready"}}],
                "response_fields":[{"name":"data","pointer":"/data"}]}})).unwrap()
    }
    pub(crate) fn configure(state: &AppState, url: &str, timeout: u64) -> Uuid {
        let credential = state
            .catalog
            .create_credential_reference(
                &serde_json::from_value(json!({"name":"HTTP fixture","kind":"password"})).unwrap(),
            )
            .unwrap();
        state.secret_store.set(credential.id, SECRET).unwrap();
        state
            .catalog
            .set_credential_secret_state(credential.id, credential.version, true)
            .unwrap();
        let target = state
            .catalog
            .create_target(
                &serde_json::from_value(
                    json!({"name":"HTTP fixture","kind":"http_service","environment":"test"}),
                )
                .unwrap(),
            )
            .unwrap();
        state.catalog.create_action_template(&serde_json::from_value(json!({"name":"HTTP echo","target_id":target.id,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":timeout,"command":config(url,credential.id)})).unwrap()).unwrap().id
    }
    fn approve(state: &AppState, template: Uuid) -> Uuid {
        let approval=state.catalog.create_approval(&serde_json::from_value(json!({"action_template_id":template,"expires_in_seconds":60,"authorization_mode":"time_window"})).unwrap()).unwrap();
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
    async fn wait(state: &AppState, id: Uuid) -> crate::command::OutputPage {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let page = state.catalog.output(id, 0).unwrap();
                if !matches!(page.state, RunState::Queued | RunState::Running) {
                    return page;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn real_http_uses_typed_parameters_filters_output_and_replays_without_resending() {
        let server = server().await;
        let (state, _) = AppState::new([]);
        let template = configure(&state, &server.url, 5);
        let approval = approve(&state, template);
        let request = CreateSyntheticRun {
            approval_id: approval,
            idempotency_key: Uuid::new_v4().to_string(),
        };
        let run = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: request.approval_id,
                idempotency_key: request.idempotency_key.clone(),
            },
        )
        .await
        .unwrap();
        let page = wait(&state, run.run.id).await;
        assert_eq!(page.state, RunState::Succeeded);
        assert_eq!(page.exit_code, None);
        let output = page
            .items
            .iter()
            .map(|c| c.text.as_str())
            .collect::<String>();
        assert!(!output.contains(SECRET));
        assert!(!output.contains("not-selected"));
        assert!(output.contains("[REDACTED]"));
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["status_code"], 200);
        assert_eq!(value["fields"]["data"]["count"], 7);
        assert_eq!(value["fields"]["data"]["ready"], true);
        let replay = crate::create_run_for_state(&state, request).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
        let repeated = crate::create_run_for_state(
            &state,
            CreateSyntheticRun {
                approval_id: approval,
                idempotency_key: Uuid::new_v4().to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            wait(&state, repeated.run.id).await.state,
            RunState::Succeeded
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
        let events =
            serde_json::to_string(&state.catalog.list_safe_events(Some(run.run.id)).unwrap())
                .unwrap();
        assert!(!events.contains(SECRET));
    }
    #[tokio::test]
    async fn redirects_errors_size_invalid_json_and_missing_fields_are_bounded() {
        let server = server().await;
        let mut config = config(&server.url, Uuid::new_v4());
        config.slots.clear();
        let http = config.http.as_mut().unwrap();
        http.method = "GET".into();
        http.headers.clear();
        http.body.clear();
        http.query.clear();
        let secrets = [];
        let params = ParameterValues::new();
        for (path, expected, code) in [
            ("redirect", Some(307), ""),
            ("error", Some(401), ""),
            ("large", None, "response_too_large"),
            ("invalid", None, "invalid_json_response"),
            ("json", None, "response_field_missing"),
        ] {
            config.http.as_mut().unwrap().url = format!("{}/{path}", server.url);
            let result = request(config.http.as_ref().unwrap(), &config, &params, &secrets).await;
            if let Some(status) = expected {
                let value = result.unwrap();
                assert_eq!(value["status_code"], status);
                assert!(!value.to_string().contains(SECRET));
            } else {
                assert_eq!(result.unwrap_err(), code);
            }
        }
        assert_eq!(server.hits.load(Ordering::SeqCst), 0);
        config.http.as_mut().unwrap().url = format!("{}/json", server.url);
        config.http.as_mut().unwrap().response_fields = vec![
            ResponseField {
                name: "version".into(),
                pointer: "/version".into(),
            },
            ResponseField {
                name: "escaped".into(),
                pointer: "/a~1b/~0".into(),
            },
            ResponseField {
                name: "empty".into(),
                pointer: "/empty".into(),
            },
        ];
        let fields = request(config.http.as_ref().unwrap(), &config, &params, &secrets)
            .await
            .unwrap();
        assert_eq!(fields["fields"]["version"], "1.2.3");
        assert_eq!(fields["fields"]["escaped"], true);
        assert!(fields["fields"]["empty"].is_null());
        config.http.as_mut().unwrap().url = format!("{}/trap", server.url);
        config.http.as_mut().unwrap().response_fields.clear();
        assert_eq!(
            request(config.http.as_ref().unwrap(), &config, &params, &secrets)
                .await
                .unwrap()["status_code"],
            200
        );
    }
    #[tokio::test]
    async fn timeout_and_cancellation_complete_without_a_process_exit_code() {
        let server = server().await;
        for cancel in [false, true] {
            let (state, _) = AppState::new([]);
            let template = configure(&state, &server.url, 1);
            let item = state.catalog.list_action_templates().unwrap().remove(0);
            let mut config = item.command.unwrap();
            config.http.as_mut().unwrap().url = format!("{}/slow", server.url);
            config.http.as_mut().unwrap().method = "GET".into();
            config.http.as_mut().unwrap().body.clear();
            state.catalog.update_action_template(template,&serde_json::from_value(json!({"target_id":item.target_id,"name":item.name,"operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":1,"enabled":true,"expected_version":item.version,"command":config})).unwrap()).unwrap();
            let approval = approve(&state, template);
            let created = state
                .catalog
                .create_synthetic_run(&CreateSyntheticRun {
                    approval_id: approval,
                    idempotency_key: Uuid::new_v4().to_string(),
                })
                .unwrap();
            state.catalog.start_run(created.run.id).unwrap();
            let cancellation = CancellationToken::new();
            let future = crate::command::drive(&state, created.run.id, &cancellation);
            tokio::pin!(future);
            if cancel {
                tokio::select! {()=&mut future=>panic!("slow request must be in flight"),()=tokio::time::sleep(Duration::from_millis(100))=>cancellation.cancel()};
            }
            future.await;
            let page = state.catalog.output(created.run.id, 0).unwrap();
            assert_eq!(
                page.state,
                if cancel {
                    RunState::Cancelled
                } else {
                    RunState::Failed
                }
            );
            assert_eq!(page.exit_code, None);
            assert!(
                page.items[0]
                    .text
                    .contains(if cancel { "cancelled" } else { "timed_out" })
            );
        }
    }

    #[tokio::test]
    async fn refused_connection_and_interrupted_response_use_fixed_bounded_errors() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        let mut command = config(&closed_url, Uuid::new_v4());
        command.slots.clear();
        command.parameters.clear();
        let http = command.http.as_mut().unwrap();
        http.method = "GET".into();
        http.headers.clear();
        http.query.clear();
        http.body.clear();
        http.response_fields.clear();
        let refused = tokio::time::timeout(
            Duration::from_secs(3),
            request(
                command.http.as_ref().unwrap(),
                &command,
                &ParameterValues::new(),
                &[],
            ),
        )
        .await
        .expect("connection refusal is bounded");
        assert_eq!(refused.unwrap_err(), "connection_failed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let interrupted_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"data\":",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        command.http.as_mut().unwrap().url = interrupted_url;
        command.http.as_mut().unwrap().response_fields = vec![ResponseField {
            name: "data".into(),
            pointer: "/data".into(),
        }];
        let interrupted = tokio::time::timeout(
            Duration::from_secs(3),
            request(
                command.http.as_ref().unwrap(),
                &command,
                &ParameterValues::new(),
                &[],
            ),
        )
        .await
        .expect("interrupted response is bounded");
        assert_eq!(interrupted.unwrap_err(), "response_read_failed");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn web_configure_approve_execute_and_read_http_output() {
        use crate::command::tests::web_request;
        let fixture = server().await;
        let (state, _) = AppState::new(["http://127.0.0.1:8787".into()]);
        configure(&state, &fixture.url, 5);
        let template = state.catalog.list_action_templates().unwrap().remove(0);
        let (token, _) = state.issue_session().await.expect("issue session");
        let(status,created)=web_request(&state,&token,"/api/v1/action-templates",json!({"target_id":template.target_id,"name":"HTTP Web task","operation":"command_execution","result_scope":"sanitized_output","timeout_seconds":5,"command":template.command})).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["command"]["http"]["method"], "POST");
        let(status,_)=web_request(&state,&token,"/api/v1/approvals",json!({"action_template_id":created["id"],"expires_in_seconds":60,"parameters":{"count":"7"}})).await;
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
        assert_eq!(wait(&state, id).await.state, RunState::Succeeded);
        let (status, page) = web_request(
            &state,
            &token,
            &format!("/api/v1/runs/{id}/output"),
            json!({"cursor":0,"wait_ms":0}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(page["exit_code"].is_null());
        assert!(page.to_string().contains("[REDACTED]"));
        assert!(!page.to_string().contains(SECRET));
    }

    #[test]
    fn http_templates_and_frozen_parameters_survive_database_reopen() {
        let path = std::env::temp_dir().join(format!("sb-http-{}.sqlite3", Uuid::new_v4()));
        let (mut state, _) = AppState::new([]);
        state.catalog = crate::catalog::Catalog::open(&path).unwrap();
        let template = configure(&state, "https://example.com", 5);
        let approval = approve(&state, template);
        drop(state);
        let catalog = crate::catalog::Catalog::open(&path).unwrap();
        let restored = catalog.list_action_templates().unwrap().remove(0);
        let command = restored.command.unwrap();
        assert!(command.validate().is_ok());
        assert_eq!(command.http.unwrap().url, "https://example.com/echo");
        let approval = catalog.get_approval(approval).unwrap();
        assert_eq!(approval.parameters["count"], 7);
        assert_eq!(approval.parameters["ready"], true);
        assert!(
            !serde_json::to_string(&catalog.list_action_templates().unwrap())
                .unwrap()
                .contains(SECRET)
        );
        drop(catalog);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn header_newlines_are_rejected_before_transmitting_credentials() {
        let server = server().await;
        let config = config(&server.url, Uuid::new_v4());
        let params =
            crate::parameters::resolve(&config.parameters, &ParameterValues::new()).unwrap();
        let secrets = [Zeroizing::new("synthetic\r\ninjected: header".to_owned())];
        assert_eq!(
            request(config.http.as_ref().unwrap(), &config, &params, &secrets)
                .await
                .unwrap_err(),
            "invalid_header"
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn invalid_configs_cannot_change_authentication_destination_or_protocol() {
        let original = config("https://example.com", Uuid::new_v4());
        assert!(original.validate().is_ok());
        for url in [
            "https://example.com/?token=x",
            "https://example.com/#secret",
            "file:///tmp/x",
        ] {
            let mut c = original.clone();
            c.http.as_mut().unwrap().url = url.into();
            assert!(c.validate().is_err());
        }
        let mut credentials_url = Url::parse("https://example.com/").unwrap();
        credentials_url.set_username("synthetic-user").unwrap();
        credentials_url
            .set_password(Some("synthetic-password"))
            .unwrap();
        let mut c = original.clone();
        c.http.as_mut().unwrap().url = credentials_url.to_string();
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.http.as_mut().unwrap().query.push(HttpField {
            name: "secret".into(),
            source: ValueSource::Credential {
                name: "token".into(),
                prefix: String::new(),
            },
        });
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.http.as_mut().unwrap().headers[0].name = "Host".into();
        assert!(c.validate().is_err());
        let mut c = original.clone();
        let duplicate = c.http.as_ref().unwrap().headers[0].clone();
        c.http.as_mut().unwrap().headers.push(duplicate);
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.slots[0].injection = Injection::Argument;
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.program = "/bin/sh".into();
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.http.as_mut().unwrap().response_fields[0].pointer = "/bad~2".into();
        assert!(c.validate().is_err());
        let mut c = original;
        c.http = None;
        assert!(c.validate().is_err());
    }
}
