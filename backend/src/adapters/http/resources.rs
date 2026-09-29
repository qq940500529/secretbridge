// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ApiError, AppState, AxumPath, CredentialService, HeaderMap, Json, Router, Serialize, State,
    StatusCode, map_catalog_error, map_credential_service_error, require_session, task,
    validate_origin,
};
use crate::domain::resources::{ConnectionTestResult, Resource, ResourceRequest};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Serialize)]
struct ResourceList {
    items: Vec<Resource>,
    storage: crate::ConfigurationStorage,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/resources", axum::routing::get(list).post(create))
        .route(
            "/api/v1/resources/{id}",
            axum::routing::put(update).delete(remove),
        )
        .route("/api/v1/resources/{id}/test", axum::routing::post(test))
        .route(
            "/api/v1/resources/{id}/ssh-host-key",
            axum::routing::post(probe_host_key),
        )
        .route(
            "/api/v1/resources/{id}/ssh-host-key/{probe_id}",
            axum::routing::delete(cancel_host_key_probe),
        )
        .route(
            "/api/v1/resources/{id}/secret",
            axum::routing::put(set_secret).delete(clear_secret),
        )
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ResourceList>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_resources())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(ResourceList {
        items,
        storage: state.configuration_storage,
    }))
}
async fn save(
    state: AppState,
    headers: HeaderMap,
    id: Option<Uuid>,
    request: ResourceRequest,
) -> Result<Json<Resource>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let catalog = state.catalog.clone();
    let item = task::spawn_blocking(move || catalog.save_resource(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(item))
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResourceRequest>,
) -> Result<(StatusCode, Json<Resource>), ApiError> {
    Ok((
        StatusCode::CREATED,
        save(state, headers, None, request).await?,
    ))
}
async fn update(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ResourceRequest>,
) -> Result<Json<Resource>, ApiError> {
    save(state, headers, Some(id), request).await
}
async fn remove(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    CredentialService::new(
        state.catalog.clone(),
        state.secret_store.clone(),
        state.native_secret_mutations.clone(),
    )
    .delete_resource(id)
    .await
    .map_err(map_credential_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn set_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    request: Json<super::SetCredentialSecretRequest>,
) -> Result<Json<Resource>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    state.catalog.get_resource(id).map_err(map_catalog_error)?;
    let _ = super::catalog_routes::set_credential_secret(
        State(state.clone()),
        AxumPath(id),
        headers,
        request,
    )
    .await?;
    Ok(Json(
        state.catalog.get_resource(id).map_err(map_catalog_error)?,
    ))
}
async fn clear_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    request: Json<super::ClearCredentialSecretRequest>,
) -> Result<Json<Resource>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    state.catalog.get_resource(id).map_err(map_catalog_error)?;
    let _ = super::catalog_routes::clear_credential_secret(
        State(state.clone()),
        AxumPath(id),
        headers,
        request,
    )
    .await?;
    Ok(Json(
        state.catalog.get_resource(id).map_err(map_catalog_error)?,
    ))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TestRequest {
    expected_version: u64,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostKeyRequest {
    expected_version: u64,
    probe_id: Uuid,
}
#[derive(Serialize)]
struct HostKeyObservation {
    resource_id: Uuid,
    resource_version: u64,
    code: &'static str,
    fingerprint: Option<String>,
    algorithm: Option<String>,
}
async fn probe_host_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<HostKeyRequest>,
) -> Result<Json<HostKeyObservation>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let resource = state.catalog.get_resource(id).map_err(map_catalog_error)?;
    if resource.target.version != request.expected_version {
        return Err(map_catalog_error(crate::CatalogError::VersionConflict));
    }
    let crate::domain::resources::ConnectionOptions::Ssh { port, .. } = resource.connection else {
        return Err(ApiError::BadRequest);
    };
    let lease = state.host_key_probes.begin(id, request.probe_id);
    let result = if let Ok(lease) = lease {
        tokio::select! {
            () = lease.stop.cancelled() => Err("cancelled"),
            result = tokio::time::timeout(Duration::from_secs(10), crate::ssh_task::observe_host_key(
                resource.target.address.as_deref().unwrap_or_default(), port,
            )) => result.unwrap_or(Err("timed_out")),
        }
    } else {
        Err("probe_busy")
    };
    // Recheck after the network await: edited/deleted resources cannot yield a usable observation.
    require_session(&state, &headers).await?;
    let current = state.catalog.get_resource(id).map_err(map_catalog_error)?;
    if current.target.version != request.expected_version {
        return Err(map_catalog_error(crate::CatalogError::VersionConflict));
    }
    let (code, fingerprint, algorithm) = match result {
        Ok((fingerprint, algorithm)) => ("observed_unverified", Some(fingerprint), Some(algorithm)),
        Err(code) => (code, None, None),
    };
    Ok(Json(HostKeyObservation {
        resource_id: id,
        resource_version: request.expected_version,
        code,
        fingerprint,
        algorithm,
    }))
}
async fn cancel_host_key_probe(
    State(state): State<AppState>,
    AxumPath((id, probe_id)): AxumPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    state.host_key_probes.cancel(id, probe_id);
    Ok(StatusCode::NO_CONTENT)
}
async fn test(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<TestRequest>,
) -> Result<Json<ConnectionTestResult>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.read().await;
    let resource = state.catalog.get_resource(id).map_err(map_catalog_error)?;
    if resource.target.version != request.expected_version {
        return Err(map_catalog_error(crate::CatalogError::VersionConflict));
    }
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        crate::application::resource_test::test(&state, &resource),
    )
    .await
    .unwrap_or(Err("timed_out"));
    Ok(Json(ConnectionTestResult {
        resource_id: id,
        success: result.is_ok(),
        missing_fields: resource.missing_connection_fields(),
        code: result.err().unwrap_or("connection_ok"),
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        tested_at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
    }))
}
