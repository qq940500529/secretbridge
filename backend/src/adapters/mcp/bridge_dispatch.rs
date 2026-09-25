// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    AppState, ErrorData, McpBackend, OP_BEGIN_CONVERSATION, OP_CANCEL_RUN, OP_CONFIRM_APPROVAL,
    OP_CREATE_RUN, OP_EVALUATE_POLICY, OP_GET_APPROVAL, OP_GET_RUN, OP_HEALTH, OP_LIST_CATALOG,
    OP_LIST_RUN_EVENTS, OP_LIST_TEMPLATES, OP_READ_OUTPUT, OP_REQUEST_APPROVAL, OP_REQUEST_COMMAND,
    OP_REQUEST_SSH, OP_TERMINAL, Serialize, ensure_bridge_ready,
};
use crate::adapters::native_ipc::{BRIDGE_PROTOCOL, BridgeEmpty, BridgeHealth, OP_RUNTIME};
use serde::de::DeserializeOwned;

pub(crate) async fn dispatch_bridge_request(
    state: AppState,
    operation: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, ErrorData> {
    if operation == OP_RUNTIME {
        return serialize_bridge_payload(
            crate::runtime::handle(&state, parse_bridge_payload(payload)?).await?,
        );
    }
    ensure_bridge_ready(&state, operation)?;
    let backend = McpBackend::Local(Box::new(state));
    match operation {
        OP_HEALTH => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(BridgeHealth {
                status: "ready".to_owned(),
                protocol: BRIDGE_PROTOCOL.to_owned(),
            })
        }
        OP_BEGIN_CONVERSATION => serialize_bridge_payload(
            backend
                .begin_conversation(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_LIST_TEMPLATES => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(backend.list_action_templates().await?)
        }
        OP_LIST_CATALOG => {
            parse_bridge_payload::<BridgeEmpty>(payload)?;
            serialize_bridge_payload(backend.list_catalog().await?)
        }
        OP_EVALUATE_POLICY => serialize_bridge_payload(
            backend
                .evaluate_policy(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_REQUEST_APPROVAL => serialize_bridge_payload(
            backend
                .request_approval(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_CONFIRM_APPROVAL => serialize_bridge_payload(
            backend
                .confirm_approval(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_REQUEST_COMMAND => serialize_bridge_payload(
            backend
                .request_command(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_REQUEST_SSH => {
            serialize_bridge_payload(backend.request_ssh(parse_bridge_payload(payload)?).await?)
        }
        OP_GET_APPROVAL => {
            serialize_bridge_payload(backend.get_approval(parse_bridge_payload(payload)?).await?)
        }
        OP_CREATE_RUN => {
            serialize_bridge_payload(backend.create_run(parse_bridge_payload(payload)?).await?)
        }
        OP_GET_RUN => {
            serialize_bridge_payload(backend.get_run(parse_bridge_payload(payload)?).await?)
        }
        OP_READ_OUTPUT => {
            serialize_bridge_payload(backend.read_output(parse_bridge_payload(payload)?).await?)
        }
        OP_CANCEL_RUN => {
            serialize_bridge_payload(backend.cancel_run(parse_bridge_payload(payload)?).await?)
        }
        OP_LIST_RUN_EVENTS => serialize_bridge_payload(
            backend
                .list_run_events(parse_bridge_payload(payload)?)
                .await?,
        ),
        OP_TERMINAL => {
            let _gate = match &backend {
                McpBackend::Local(state) => {
                    let gate = state.configuration_gate.read().await;
                    if state
                        .runtime_control
                        .as_ref()
                        .is_some_and(|control| control.stopping.is_cancelled())
                    {
                        return Err(ErrorData::internal_error("broker_stopping", None));
                    }
                    Some(gate)
                }
                McpBackend::Remote(_) => None,
            };
            backend
                .terminal_request(parse_bridge_payload(payload)?)
                .await
        }
        _ => Err(ErrorData::invalid_params("invalid_request", None)),
    }
}

fn parse_bridge_payload<T: DeserializeOwned>(payload: serde_json::Value) -> Result<T, ErrorData> {
    serde_json::from_value(payload).map_err(|_| ErrorData::invalid_params("invalid_request", None))
}

fn serialize_bridge_payload<T: Serialize>(payload: T) -> Result<serde_json::Value, ErrorData> {
    serde_json::to_value(payload)
        .map_err(|_| ErrorData::internal_error("secretbridge_operation_failed", None))
}
