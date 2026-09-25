// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ActionTemplate, ActionTemplateListResponse, ApiError, AppState, Approval, ApprovalListResponse,
    AxumPath, ClearCredentialSecretRequest, CreateActionTemplate, CreateApproval,
    CreateCredentialReference, CreateTarget, CredentialReference, CredentialReferenceListResponse,
    CredentialService, DecideApproval, HeaderMap, Json, PolicyEvaluation,
    SetCredentialSecretRequest, State, StatusCode, Target, TargetListResponse, TerminalStatus,
    UpdateActionTemplate, UpdateCredentialReference, UpdateTarget, Uuid, map_catalog_error,
    map_credential_service_error, require_session, task, validate_origin,
};

pub(crate) async fn list_credential_references(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CredentialReferenceListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_credential_references())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(CredentialReferenceListResponse {
        items,
        storage: state.configuration_storage,
    }))
}

pub(crate) async fn create_credential_reference(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCredentialReference>,
) -> Result<(StatusCode, Json<CredentialReference>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let item = task::spawn_blocking(move || catalog.create_credential_reference(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(item)))
}

pub(crate) async fn update_credential_reference(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateCredentialReference>,
) -> Result<Json<CredentialReference>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let catalog = state.catalog.clone();
    let item = task::spawn_blocking(move || catalog.update_credential_reference(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(item))
}

pub(crate) async fn delete_credential_reference(
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
    .delete(id)
    .await
    .map_err(map_credential_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn set_credential_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<SetCredentialSecretRequest>,
) -> Result<Json<CredentialReference>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    if request.secret.is_empty() || request.secret.len() > 8 * 1024 || request.secret.contains('\0')
    {
        return Err(ApiError::BadRequest);
    }
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let secret = zeroize::Zeroizing::new(request.secret);
    let updated = CredentialService::new(
        state.catalog.clone(),
        state.secret_store.clone(),
        state.native_secret_mutations.clone(),
    )
    .set(id, request.expected_version, secret)
    .await
    .map_err(map_credential_service_error)?;
    Ok(Json(updated))
}

pub(crate) async fn clear_credential_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ClearCredentialSecretRequest>,
) -> Result<Json<CredentialReference>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let _mutation = state.credential_mutations.lock().await;
    let updated = CredentialService::new(
        state.catalog.clone(),
        state.secret_store.clone(),
        state.native_secret_mutations.clone(),
    )
    .clear(id, request.expected_version)
    .await
    .map_err(map_credential_service_error)?;
    Ok(Json(updated))
}

pub(crate) async fn list_targets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TargetListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_targets())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(TargetListResponse {
        items,
        storage: state.configuration_storage,
    }))
}

pub(crate) async fn create_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTarget>,
) -> Result<(StatusCode, Json<Target>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let target = task::spawn_blocking(move || catalog.create_target(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(target)))
}

pub(crate) async fn update_target(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateTarget>,
) -> Result<Json<Target>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let catalog = state.catalog.clone();
    let target = task::spawn_blocking(move || catalog.update_target(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(target))
}

pub(crate) async fn delete_target(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.delete_target(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn list_action_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ActionTemplateListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let mut items = task::spawn_blocking(move || catalog.list_action_templates())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    let terminals = state.terminals.list();
    for template in &mut items {
        if let Some(id) = template
            .command
            .as_ref()
            .and_then(|command| command.terminal_id)
        {
            template.terminal_available = terminals.iter().any(|terminal| {
                terminal.id == id
                    && terminal.status == TerminalStatus::Running
                    && !terminal.interactive_unverified
            });
        }
    }
    Ok(Json(ActionTemplateListResponse {
        items,
        storage: state.configuration_storage,
        execution_enabled: true,
    }))
}

pub(crate) async fn get_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ActionTemplate>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let mut template = task::spawn_blocking(move || catalog.get_action_template(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    if let Some(terminal_id) = template
        .command
        .as_ref()
        .and_then(|command| command.terminal_id)
    {
        template.terminal_available = state.terminals.list().iter().any(|terminal| {
            terminal.id == terminal_id
                && terminal.status == TerminalStatus::Running
                && !terminal.interactive_unverified
        });
    }
    Ok(Json(template))
}

pub(crate) async fn evaluate_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<PolicyEvaluation>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let evaluation = task::spawn_blocking(move || catalog.evaluate_action_template(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(evaluation))
}

pub(crate) async fn create_action_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateActionTemplate>,
) -> Result<(StatusCode, Json<ActionTemplate>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let template = task::spawn_blocking(move || catalog.create_action_template(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok((StatusCode::CREATED, Json(template)))
}

pub(crate) async fn update_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateActionTemplate>,
) -> Result<Json<ActionTemplate>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let _configuration = state.configuration_gate.write().await;
    let catalog = state.catalog.clone();
    let template = task::spawn_blocking(move || catalog.update_action_template(id, &request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(template))
}

pub(crate) async fn delete_action_template(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    task::spawn_blocking(move || catalog.delete_action_template(id))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApprovalListResponse>, ApiError> {
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let items = task::spawn_blocking(move || catalog.list_approvals())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    Ok(Json(ApprovalListResponse {
        items,
        storage: state.configuration_storage,
        execution_enabled: true,
    }))
}

pub(crate) async fn create_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateApproval>,
) -> Result<(StatusCode, Json<Approval>), ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let approval = task::spawn_blocking(move || catalog.create_approval(&request))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(map_catalog_error)?;
    crate::application::notifications::notify_pending_approval(&state, &approval);
    Ok((StatusCode::CREATED, Json(approval)))
}

pub(crate) async fn approve_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DecideApproval>,
) -> Result<Json<Approval>, ApiError> {
    transition_approval(state, headers, id, request, ApprovalDecision::Approve).await
}

pub(crate) async fn deny_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DecideApproval>,
) -> Result<Json<Approval>, ApiError> {
    transition_approval(state, headers, id, request, ApprovalDecision::Deny).await
}

pub(crate) async fn revoke_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DecideApproval>,
) -> Result<Json<Approval>, ApiError> {
    transition_approval(state, headers, id, request, ApprovalDecision::Revoke).await
}

#[derive(Clone, Copy)]
enum ApprovalDecision {
    Approve,
    Deny,
    Revoke,
}

async fn transition_approval(
    state: AppState,
    headers: HeaderMap,
    id: Uuid,
    request: DecideApproval,
    decision: ApprovalDecision,
) -> Result<Json<Approval>, ApiError> {
    validate_origin(&headers, &state)?;
    require_session(&state, &headers).await?;
    let catalog = state.catalog.clone();
    let approval = task::spawn_blocking(move || match decision {
        ApprovalDecision::Approve => catalog.approve_approval(id, &request),
        ApprovalDecision::Deny => catalog.deny_approval(id, &request),
        ApprovalDecision::Revoke => catalog.revoke_approval(id, &request),
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(map_catalog_error)?;
    if matches!(decision, ApprovalDecision::Revoke) {
        state.run_cancellations.cancel_approval(approval.id).await;
    }
    Ok(Json(approval))
}
