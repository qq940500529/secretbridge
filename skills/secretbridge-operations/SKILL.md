---
name: secretbridge-operations
description: Use SecretBridge MCP tools to run user-requested local, SSH, database, HTTP, or other saved-connection operations while keeping credentials in the local broker. Use when the user asks an AI assistant to perform a controlled operation through SecretBridge; do not use for installation or ordinary repository development.
---

# SecretBridge controlled operations / 密桥受控操作

This skill describes the AI workflow. The MCP server is authoritative for tool schemas, live state, approval, credential access, output filtering, and permissions. Read [compatibility.json](references/compatibility.json) when connecting to a new broker version. If it differs, use the server's current `tools/list` schemas and responses; do not copy fields from this skill's examples until an updated skill is installed.

本 Skill 只指导 AI 选择工具和处理结果。工具 schema、实时状态、审批、凭据权限及脱敏均以本机 MCP 服务为准。不要把本 Skill 当成授权或安全控制。

## Before requesting an operation / 申请前

1. Start this AI conversation with `secretbridge_begin_conversation` and a brief summary without secrets. Keep the returned `id` as `conversation_id` for this conversation. Never reuse an ID from another chat.
2. Discover `secretbridge_terminal_capabilities`, `secretbridge_list_catalog`, and, when useful, `secretbridge_list_action_templates`. Use only IDs returned by the current broker. The catalog contains metadata, not credential values.
3. Prefer an existing structured connector or saved action that fits the exact target and intent. Use `secretbridge_request_ssh` for a one-time SSH command on a saved SSH connection. Use a secure terminal plus `secretbridge_request_command` for a changing local command. Save or modify a reusable template only when the user requests reuse through the human Web console.
4. For `secretbridge_request_command`, send an absolute executable and separate argv items. A credential argument or file slot occupies one complete argument as `{{secret:slot_name}}`; bind only the opaque credential ID. Other double braces remain literal. A non-secret script can go in bounded `stdin_content` only when it does not share stdin with a credential slot.

## Approval and execution / 审批与执行

5. Read the returned approval `state`, `id`, `version`, `preauthorized`, `next_actions`, and `console_url` if present. For `pending`, show the person the exact target, operation, ordinary parameters, opaque credential references, expiry, and risk, then wait for the local Web decision. Do not click or automate the Web console. `secretbridge_confirm_approval` is only for a current six-digit TOTP code that the person voluntarily supplied for that specific pending `id` and `version`. Never ask for or retain a PIN, setup key, QR code, or credential value.
6. For an already `approved` request, tell the person which standing policy applied and its risk before running. Use `secretbridge_create_run` only for an approved, unexpired request. Generate one stable `idempotency_key` per intended run and reuse it only to resolve uncertain delivery of that same intent. A new intent needs a new key.
7. Use the returned `run.id` with `secretbridge_get_run` and `secretbridge_read_run_output`. Continue from `next_cursor`. For live terminal output use `secretbridge_terminal_read` and its byte cursor. On `truncated`, report the missing range; do not rerun work merely to reconstruct output. For cancellation, fetch the current run `version` before `secretbridge_cancel_run`.
8. For ordinary non-secret terminal input, attach and request the input lease before `secretbridge_terminal_write`. A write error can mean delivery is uncertain: read terminal and run state before another write. Detach when yielding to the person; close only when the terminal should end.

## Recovery and stopping / 恢复与停止

- Follow current `next_actions` as guidance, and verify current state before any retry. [Recovery examples](references/recovery.json) cover common stable codes; the live response wins if it differs.
- `initialization_required`: ask the person to finish setup in the local management page. Do not handle the setup material.
- Approval consumed, expired, or changed: fetch current approval state and request a new approval only if the original intent still stands.
- Terminal context unknown or stopped: create a new terminal and approval; do not assume a command can safely be replayed.
- SSH host fingerprints must be verified by the person through an independent trusted channel. Do not accept an unknown or changed key automatically, or disable host verification.
- Stop when the broker's state is unresolved, the requested target or operation is ambiguous, or continuing would require a new user decision. Do not use a direct shell, browser automation, or helper script to bypass the broker.

Use the current `tools/list` input and output schemas. [Synthetic contract examples](references/examples.md) illustrate field locations and are checked against the server in this repository; their IDs and paths are not live values. Summarize the outcome in the user's language, distinguishing completed, pending, cancelled, failed, and uncertain states.
