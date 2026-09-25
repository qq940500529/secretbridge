// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    error::Error,
    fs,
    io::{self, Write as _},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rmcp::ErrorData;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Semaphore,
    task, time,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::adapters::mcp::bridge_response::safe_bridge_error_code;
use crate::adapters::mcp::errors::remote_error;
use crate::{AppState, constant_time_equal, token_digest};

const BRIDGE_CONNECTION_FILE: &str = "mcp-bridge.json";
pub(crate) const BRIDGE_CONNECTION_SCHEMA: u8 = 2;
pub(crate) const BRIDGE_PROTOCOL: &str = "secretbridge-native-ipc-v1";
const MAX_BRIDGE_REQUEST_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const MAX_BRIDGE_PIPE_BUFFER_BYTES: u32 = 16 * 1024;
const MAX_BRIDGE_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_BRIDGE_CONNECTION_BYTES: u64 = 4 * 1024;
const MAX_BRIDGE_CONNECTIONS: usize = 32;
#[cfg(windows)]
const MAX_BRIDGE_PIPE_INSTANCES: usize = MAX_BRIDGE_CONNECTIONS + 1;
const BRIDGE_IO_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const OP_HEALTH: &str = "health";
pub(crate) const OP_BEGIN_CONVERSATION: &str = "begin_conversation";
pub(crate) const OP_LIST_TEMPLATES: &str = "list_action_templates";
pub(crate) const OP_LIST_CATALOG: &str = "list_catalog";
pub(crate) const OP_EVALUATE_POLICY: &str = "evaluate_policy";
pub(crate) const OP_REQUEST_APPROVAL: &str = "request_approval";
pub(crate) const OP_CONFIRM_APPROVAL: &str = "confirm_approval";
pub(crate) const OP_REQUEST_COMMAND: &str = "request_command";
pub(crate) const OP_REQUEST_SSH: &str = "request_ssh";
pub(crate) const OP_GET_APPROVAL: &str = "get_approval";
pub(crate) const OP_CREATE_RUN: &str = "create_run";
pub(crate) const OP_GET_RUN: &str = "get_run";
pub(crate) const OP_READ_OUTPUT: &str = "read_run_output";
pub(crate) const OP_CANCEL_RUN: &str = "cancel_run";
pub(crate) const OP_LIST_RUN_EVENTS: &str = "list_run_events";
pub(crate) const OP_TERMINAL: &str = "terminal";
pub(crate) const OP_RUNTIME: &str = "runtime_control";

/// Authenticated lifecycle client for the local CLI; not advertised as an MCP tool.
pub struct BrokerController {
    client: BridgeClient,
}
impl BrokerController {
    /// Checks the authenticated bridge even if an older broker lacks runtime control.
    pub async fn is_reachable(&self) -> bool {
        self.client.health().await.is_ok()
    }
    #[must_use]
    pub fn new(data_directory: &Path) -> Self {
        Self {
            client: BridgeClient::from_file(data_directory.join(BRIDGE_CONNECTION_FILE)),
        }
    }
    /// Reads authenticated runtime state without returning connection or pairing tokens.
    /// # Errors
    /// Returns an error if the broker cannot be reached or rejects the request.
    pub async fn status(&self) -> Result<crate::RuntimeStatus, ErrorData> {
        self.client
            .call(OP_RUNTIME, &crate::runtime::RuntimeRequest::Status)
            .await
    }
    /// Opens a fresh one-time pairing URL in the broker's browser.
    /// # Errors
    /// Returns an error if the broker or browser is unavailable.
    pub async fn open(&self) -> Result<crate::RuntimeStatus, ErrorData> {
        self.client
            .call(OP_RUNTIME, &crate::runtime::RuntimeRequest::Open)
            .await
    }
    /// Requests graceful broker shutdown without acting on a saved PID.
    /// # Errors
    /// Returns an error if authenticated control is unavailable.
    pub async fn stop(&self) -> Result<crate::RuntimeStatus, ErrorData> {
        self.client
            .call(OP_RUNTIME, &crate::runtime::RuntimeRequest::Stop)
            .await
    }
}

#[derive(Clone)]
pub(crate) struct BridgeClient {
    connection_file: Arc<PathBuf>,
}

pub(crate) struct BridgeConnection {
    pub(crate) endpoint: BridgeEndpoint,
    token: Zeroizing<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub(crate) enum BridgeEndpoint {
    #[cfg(unix)]
    UnixSocket { path: PathBuf },
    #[cfg(windows)]
    WindowsNamedPipe { name: String },
}

pub struct LocalMcpBridge {
    listener: BridgeListener,
    state: AppState,
    token_digest: [u8; 32],
    _connection_guard: BridgeConnectionGuard,
}

enum BridgeListener {
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        owner_uid: u32,
    },
    #[cfg(windows)]
    Windows {
        server: NamedPipeServer,
        name: String,
    },
}

impl BridgeClient {
    pub(crate) fn from_file(path: PathBuf) -> Self {
        Self {
            connection_file: Arc::new(path),
        }
    }

    async fn connection(&self) -> Result<BridgeConnection, ErrorData> {
        let path = Arc::clone(&self.connection_file);
        task::spawn_blocking(move || read_bridge_connection(&path))
            .await
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))
    }

    pub(crate) async fn health(&self) -> Result<(), ErrorData> {
        let health: BridgeHealth = self.call(OP_HEALTH, &BridgeEmpty {}).await?;
        if health.status == "ready" && health.protocol == BRIDGE_PROTOCOL {
            Ok(())
        } else {
            Err(ErrorData::internal_error(
                "secretbridge_bridge_unavailable",
                None,
            ))
        }
    }

    pub(crate) async fn call<T, B>(&self, operation: &str, payload: &B) -> Result<T, ErrorData>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let connection = self.connection().await?;
        let request = BridgeRequestRef {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            token: connection.token.as_str(),
            operation,
            payload,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| {
            ErrorData::internal_error("secretbridge_bridge_request_rejected", None)
        })?);
        if encoded.len() > MAX_BRIDGE_REQUEST_BYTES {
            return Err(ErrorData::invalid_params(
                "secretbridge_bridge_request_rejected",
                None,
            ));
        }
        let exchange = async {
            let mut stream = connect_bridge(&connection.endpoint).await?;
            write_frame(&mut stream, &encoded, MAX_BRIDGE_REQUEST_BYTES).await?;
            read_frame(&mut stream, MAX_BRIDGE_RESPONSE_BYTES).await
        };
        let response = time::timeout(BRIDGE_IO_TIMEOUT, exchange)
            .await
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?
            .map_err(|_| ErrorData::internal_error("secretbridge_bridge_unavailable", None))?;
        let response = serde_json::from_slice::<BridgeResponse>(&response).map_err(|_| {
            ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
        })?;
        if response.schema_version != BRIDGE_CONNECTION_SCHEMA {
            return Err(ErrorData::internal_error(
                "secretbridge_bridge_response_rejected",
                None,
            ));
        }
        if response.ok {
            let payload = response.payload.ok_or_else(|| {
                ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
            })?;
            if response.error.is_some() {
                return Err(ErrorData::internal_error(
                    "secretbridge_bridge_response_rejected",
                    None,
                ));
            }
            serde_json::from_value(payload).map_err(|_| {
                ErrorData::internal_error("secretbridge_bridge_response_rejected", None)
            })
        } else {
            if response.payload.is_some() {
                return Err(ErrorData::internal_error(
                    "secretbridge_bridge_response_rejected",
                    None,
                ));
            }
            Err(remote_error(
                response.error.as_deref().unwrap_or_default(),
                response.error_data,
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BridgeConnectionDocument {
    schema_version: u8,
    #[serde(rename = "instance_id")]
    _instance_id: Uuid,
    endpoint: BridgeEndpoint,
    token: String,
}

pub(crate) fn read_bridge_connection(path: &Path) -> io::Result<BridgeConnection> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the SecretBridge broker connection file is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_BRIDGE_CONNECTION_BYTES
        || !valid_bridge_connection_metadata(&metadata, path)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        ));
    }
    let contents = Zeroizing::new(fs::read_to_string(path)?);
    let document = serde_json::from_str::<BridgeConnectionDocument>(&contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        )
    })?;
    if document.schema_version != BRIDGE_CONNECTION_SCHEMA
        || !valid_bridge_endpoint(&document.endpoint, path)
        || document.token.len() != 64
        || !document.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SecretBridge broker connection file is invalid",
        ));
    }
    Ok(BridgeConnection {
        endpoint: document.endpoint,
        token: Zeroizing::new(document.token),
    })
}

#[derive(Serialize)]
pub(super) struct BridgeConnectionDocumentRef<'a> {
    schema_version: u8,
    instance_id: Uuid,
    endpoint: &'a BridgeEndpoint,
    token: &'a str,
}

#[derive(Deserialize)]
pub(super) struct BridgeConnectionIdentity {
    instance_id: Uuid,
}

#[derive(Serialize)]
pub(super) struct BridgeRequestRef<'a, T: Serialize + ?Sized> {
    schema_version: u8,
    token: &'a str,
    operation: &'a str,
    payload: &'a T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BridgeRequest {
    schema_version: u8,
    token: String,
    operation: String,
    payload: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgeResponse {
    pub(crate) schema_version: u8,
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_data: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgeEmpty {}

#[derive(Deserialize, Serialize)]
pub(crate) struct BridgeHealth {
    pub(crate) status: String,
    pub(crate) protocol: String,
}

impl LocalMcpBridge {
    /// Creates the native bridge endpoint and publishes its ephemeral connection document.
    ///
    /// # Errors
    ///
    /// Returns an error when the data directory is not a private absolute directory, the
    /// platform endpoint cannot be created, or another bridge owns the connection document.
    pub fn bind(data_directory: &Path, state: AppState) -> Result<Self, Box<dyn Error>> {
        validate_bridge_data_directory(data_directory)?;
        let connection_path = data_directory.join(BRIDGE_CONNECTION_FILE);
        prepare_bridge_connection_path(&connection_path)?;
        let instance_id = Uuid::new_v4();
        let token = Zeroizing::new(new_bridge_token());
        let token_digest = token_digest(token.as_str());
        let (listener, endpoint, socket_path) = bind_bridge_listener(data_directory, instance_id)?;
        let connection_guard = match BridgeConnectionGuard::create(
            &connection_path,
            instance_id,
            &endpoint,
            token.as_str(),
            socket_path.as_deref(),
        ) {
            Ok(guard) => guard,
            Err(error) => {
                #[cfg(unix)]
                if let Some(socket_path) = socket_path {
                    let _ = fs::remove_file(socket_path);
                }
                return Err(error);
            }
        };
        crate::command::cleanup_files(&state.command_directory)?;
        Ok(Self {
            listener,
            state,
            token_digest,
            _connection_guard: connection_guard,
        })
    }

    /// Serves bounded native bridge requests until cancellation or a listener error.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when accepting a connection or creating the next Windows pipe
    /// instance fails.
    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let Self {
            listener,
            state,
            token_digest,
            _connection_guard,
        } = self;
        let capacity = Arc::new(Semaphore::new(MAX_BRIDGE_CONNECTIONS));
        let controls = state.terminal_controls.clone();
        tokio::select! {
            result = serve_bridge_listener(listener, state, token_digest, capacity, cancellation) => result,
            () = async move {
                loop {
                    time::sleep(Duration::from_secs(5)).await;
                    controls.expire();
                }
            } => Ok(()),
        }
    }
}

pub(super) struct BridgeConnectionGuard {
    path: PathBuf,
    instance_id: Uuid,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl BridgeConnectionGuard {
    fn create(
        path: &Path,
        instance_id: Uuid,
        endpoint: &BridgeEndpoint,
        token: &str,
        socket_path: Option<&Path>,
    ) -> Result<Self, Box<dyn Error>> {
        #[cfg(windows)]
        let _ = &socket_path;
        let document = BridgeConnectionDocumentRef {
            schema_version: BRIDGE_CONNECTION_SCHEMA,
            instance_id,
            endpoint,
            token,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&document)?);
        let temporary_path = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
        let write_result = write_private_file(&temporary_path, &encoded)
            .and_then(|()| fs::hard_link(&temporary_path, path));
        let _ = fs::remove_file(&temporary_path);
        write_result?;
        Ok(Self {
            path: path.to_owned(),
            instance_id,
            #[cfg(unix)]
            socket_path: socket_path
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing Unix socket path")
                })?
                .to_owned(),
        })
    }
}

impl Drop for BridgeConnectionGuard {
    fn drop(&mut self) {
        if let Ok(contents) = fs::read_to_string(&self.path) {
            let contents = Zeroizing::new(contents);
            if serde_json::from_str::<BridgeConnectionIdentity>(&contents)
                .is_ok_and(|document| document.instance_id == self.instance_id)
            {
                let _ = fs::remove_file(&self.path);
            }
        }
        #[cfg(unix)]
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = secretbridge_local_access::create_private_file(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

pub(crate) fn validate_bridge_data_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the SecretBridge data directory is invalid",
        ));
    }
    if !secretbridge_local_access::is_private_path(path)? {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

pub(crate) fn prepare_bridge_connection_path(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection = read_bridge_connection(path)?;
    if bridge_endpoint_is_active(&connection.endpoint) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "another SecretBridge broker owns the data directory",
        ));
    }
    #[cfg(unix)]
    {
        let BridgeEndpoint::UnixSocket { path: socket_path } = &connection.endpoint;
        match fs::remove_file(socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::remove_file(path)
}

#[cfg(unix)]
pub(crate) fn bridge_endpoint_is_active(endpoint: &BridgeEndpoint) -> bool {
    use std::os::unix::net::UnixStream as StdUnixStream;

    let BridgeEndpoint::UnixSocket { path } = endpoint;
    StdUnixStream::connect(path).is_ok()
}

#[cfg(windows)]
pub(crate) fn bridge_endpoint_is_active(endpoint: &BridgeEndpoint) -> bool {
    let BridgeEndpoint::WindowsNamedPipe { name } = endpoint;
    match ClientOptions::new().open(name) {
        Ok(_) => true,
        Err(error) => error.raw_os_error() == Some(231),
    }
}

pub(crate) fn valid_bridge_connection_metadata(_metadata: &fs::Metadata, path: &Path) -> bool {
    secretbridge_local_access::is_private_connection_path(path).unwrap_or(false)
}

pub(crate) fn new_bridge_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

async fn handle_bridge_stream<S>(
    mut stream: S,
    state: AppState,
    expected_token: [u8; 32],
    peer_authorized: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let exchange = async {
        let request = read_frame(&mut stream, MAX_BRIDGE_REQUEST_BYTES).await?;
        let response =
            process_bridge_request(&state, expected_token, peer_authorized, &request).await;
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bridge response failed"))?;
        write_frame(&mut stream, &encoded, MAX_BRIDGE_RESPONSE_BYTES).await
    };
    let _ = time::timeout(BRIDGE_IO_TIMEOUT, exchange).await;
}

pub(crate) async fn process_bridge_request(
    state: &AppState,
    expected_token: [u8; 32],
    peer_authorized: bool,
    encoded: &[u8],
) -> BridgeResponse {
    let Ok(mut request) = serde_json::from_slice::<BridgeRequest>(encoded) else {
        return BridgeResponse::error("invalid_request");
    };
    let token = Zeroizing::new(mem::take(&mut request.token));
    if !peer_authorized
        || request.schema_version != BRIDGE_CONNECTION_SCHEMA
        || !constant_time_equal(&token_digest(token.as_str()), &expected_token)
    {
        return BridgeResponse::error("bridge_unauthorized");
    }
    match crate::adapters::mcp::bridge_dispatch::dispatch_bridge_request(
        state.clone(),
        &request.operation,
        request.payload,
    )
    .await
    {
        Ok(payload) => BridgeResponse::success(payload),
        Err(error) => {
            let code = safe_bridge_error_code(error.message.as_ref());
            let _ = state.catalog.record_diagnostic_failure(&code);
            let _ = state.catalog.record_encrypted_diagnostic(
                "event",
                serde_json::json!({ "source": "mcp", "code": code }),
            );
            BridgeResponse::from_error(error)
        }
    }
}

async fn read_frame<S>(stream: &mut S, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid bridge frame"))?;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bridge frame",
        ));
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame<S>(stream: &mut S, payload: &[u8], maximum: usize) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.is_empty() || payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bridge frame",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid bridge frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.shutdown().await
}

#[cfg(unix)]
fn bind_bridge_listener(
    data_directory: &Path,
    instance_id: Uuid,
) -> io::Result<(BridgeListener, BridgeEndpoint, Option<PathBuf>)> {
    let identifier = instance_id.simple().to_string();
    let socket_path = data_directory.join(format!("sb-{}", &identifier[..16]));
    let listener = UnixListener::bind(&socket_path)?;
    let private_socket = (|| -> io::Result<u32> {
        secretbridge_local_access::protect_socket(&socket_path)?;
        let owner_uid = fs::metadata(data_directory)?.uid();
        if fs::symlink_metadata(&socket_path)?.uid() != owner_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the SecretBridge socket owner is invalid",
            ));
        }
        Ok(owner_uid)
    })();
    let owner_uid = match private_socket {
        Ok(owner_uid) => owner_uid,
        Err(error) => {
            drop(listener);
            let _ = fs::remove_file(&socket_path);
            return Err(error);
        }
    };
    Ok((
        BridgeListener::Unix {
            listener,
            owner_uid,
        },
        BridgeEndpoint::UnixSocket {
            path: socket_path.clone(),
        },
        Some(socket_path),
    ))
}

#[cfg(windows)]
fn bind_bridge_listener(
    _data_directory: &Path,
    instance_id: Uuid,
) -> io::Result<(BridgeListener, BridgeEndpoint, Option<PathBuf>)> {
    let name = format!(r"\\.\pipe\secretbridge-{}", instance_id.simple());
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(MAX_BRIDGE_PIPE_INSTANCES)
        .in_buffer_size(MAX_BRIDGE_PIPE_BUFFER_BYTES)
        .out_buffer_size(64 * 1024);
    let server = secretbridge_local_access::create_private_named_pipe(&options, &name)?;
    Ok((
        BridgeListener::Windows {
            server,
            name: name.clone(),
        },
        BridgeEndpoint::WindowsNamedPipe { name },
        None,
    ))
}

#[cfg(unix)]
async fn serve_bridge_listener(
    listener: BridgeListener,
    state: AppState,
    token_digest: [u8; 32],
    capacity: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let BridgeListener::Unix {
        listener,
        owner_uid,
    } = listener;
    loop {
        let permit = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = Arc::clone(&capacity).acquire_owned() => result.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "bridge capacity closed")
            })?,
        };
        let (stream, _) = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = listener.accept() => result?,
        };
        let peer_authorized = stream
            .peer_cred()
            .is_ok_and(|credentials| credentials.uid() == owner_uid);
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_bridge_stream(stream, state, token_digest, peer_authorized).await;
        });
    }
}

#[cfg(windows)]
async fn serve_bridge_listener(
    listener: BridgeListener,
    state: AppState,
    token_digest: [u8; 32],
    capacity: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let BridgeListener::Windows { mut server, name } = listener;
    loop {
        let permit = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = Arc::clone(&capacity).acquire_owned() => result.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "bridge capacity closed")
            })?,
        };
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = server.connect() => result?,
        }
        let connected = server;
        let mut options = ServerOptions::new();
        options
            .reject_remote_clients(true)
            .max_instances(MAX_BRIDGE_PIPE_INSTANCES)
            .in_buffer_size(MAX_BRIDGE_PIPE_BUFFER_BYTES)
            .out_buffer_size(64 * 1024);
        server = secretbridge_local_access::create_private_named_pipe(&options, &name)?;
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_bridge_stream(connected, state, token_digest, true).await;
        });
    }
}

#[cfg(unix)]
pub(crate) async fn connect_bridge(endpoint: &BridgeEndpoint) -> io::Result<UnixStream> {
    let BridgeEndpoint::UnixSocket { path } = endpoint;
    UnixStream::connect(path).await
}

#[cfg(windows)]
pub(crate) async fn connect_bridge(
    endpoint: &BridgeEndpoint,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let BridgeEndpoint::WindowsNamedPipe { name } = endpoint;
    loop {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(231) => {
                time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
#[allow(
    clippy::verbose_bit_mask,
    reason = "the security check intentionally names the group/other permission-bit mask"
)]
pub(crate) fn valid_bridge_endpoint(endpoint: &BridgeEndpoint, connection_file: &Path) -> bool {
    let BridgeEndpoint::UnixSocket { path } = endpoint;
    path.is_absolute()
        && path.parent() == connection_file.parent()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("sb-"))
            .is_some_and(|identifier| {
                identifier.len() == 16 && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        && fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.permissions().mode() & 0o077 == 0
                && fs::metadata(connection_file)
                    .is_ok_and(|connection| metadata.uid() == connection.uid())
        })
}

#[cfg(windows)]
pub(crate) fn valid_bridge_endpoint(endpoint: &BridgeEndpoint, _connection_file: &Path) -> bool {
    let BridgeEndpoint::WindowsNamedPipe { name } = endpoint;
    let Some(identifier) = name.strip_prefix(r"\\.\pipe\secretbridge-") else {
        return false;
    };
    identifier.len() == 32 && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
}
