---
name: secretbridge-workbuddy
description: Use the local SecretBridge MCP connector for user-requested SSH, database, HTTP and terminal operations with saved credentials, approval and filtered output. Not for installation or ordinary source editing.
description_zh: 通过 SecretBridge 本机连接器完成用户请求的 SSH、数据库、HTTP 和终端任务，使用已保存资源并等待人工审批，秘密不进入对话。
description_en: Use saved SecretBridge resources for approved SSH, database, HTTP and terminal operations without exposing credentials to the conversation.
version: 0.3.0-beta.4
author: 数链创元（天津）信息技术有限责任公司
---

# SecretBridge for WorkBuddy

This Skill accompanies the `secretbridge` MCP connector; installing the Skill alone does not establish a connection. Discover the connector's current tool schemas before calling tools. WorkBuddy may decorate their displayed names: identify the raw `secretbridge_*` tool exposed by this connector, not a similarly named tool from another service.

## Start an operation

1. Call `secretbridge_list_catalog` (no input parameters) and read `ui_language`. Use that language for names, summaries, approval reasons and other descriptive text sent to SecretBridge. Refresh after the user changes the management-page language. The catalog contains resource metadata, never secret values.
2. Call `secretbridge_begin_conversation` with a short, non-secret `summary`. Retain its returned `id` as the `conversation_id` for this WorkBuddy conversation. Do not borrow an ID from another conversation.
3. Discover live resource IDs and `secretbridge_list_action_templates`. Prefer a fitting saved action or structured SSH/database/HTTP tool. `secretbridge_terminal_capabilities` is a read-only connection check. The current server schemas define required fields and types; do not invent IDs, host fingerprints, protocol defaults or credential values.
4. For a one-time SSH command, use `secretbridge_request_ssh` with a saved SSH resource. For changing local commands, use the secure terminal and `secretbridge_request_command`: absolute executable, separate arguments, and opaque resource references. A secret slot occupies a complete argument as `{{secret:slot_name}}`. Do not substitute secrets in WorkBuddy's shell or scripts.

## Approval and results

- Read `state`, `id`, `version`, `next_actions`, `preauthorized` and `console_url` from the response. A pending request needs the person's decision in the local Web console. Explain the target and intended operation, then wait; do not click approval buttons or enter a PIN on their behalf. WorkBuddy's own tool approval does not replace SecretBridge approval.
- Never ask for PINs, recovery keys, passwords, API tokens, SSH private keys or setup QR codes. A voluntarily supplied current TOTP code may be sent only to `secretbridge_confirm_approval` for that exact pending request and version; do not retain it.
- For an approved request, disclose any standing authorization and its scope, then use `secretbridge_create_run`. One intended run has one stable `idempotency_key`; reuse it only to resolve uncertain delivery, not for another operation.
- Follow `secretbridge_get_run` and `secretbridge_read_run_output` with the returned run ID and `next_cursor`. For terminal output, use the byte cursor from `secretbridge_terminal_read`. Report truncation rather than replaying operations to reconstruct output. Fetch the current version before cancellation.
- Attach and obtain the input lease before `secretbridge_terminal_write` of ordinary, non-secret input. After uncertain delivery, read state before retrying. Detach when returning control to the person.

## Recovery

`initialization_required` means the person must finish the local management-page setup. On `denied`, address `decision_note` before proposing a different request. On expired/consumed authorization, fetch live state and request approval again only if the same intent still applies. An unknown or stopped terminal needs a fresh terminal and authorization; it is not evidence that the command failed to run.

SSH host-key observation is a human Web workflow, not an AI trust decision. The person checks the public fingerprint through an independent trusted channel, confirms it, and saves the resource. Never accept changed/unknown keys automatically or disable host verification.

The broker's responses are authoritative. On unresolved state or missing user decisions, stop and explain what is needed. Do not bypass SecretBridge using WorkBuddy's other shell, browser or file tools. Summarize completed, pending, cancelled, failed and uncertain outcomes separately.
