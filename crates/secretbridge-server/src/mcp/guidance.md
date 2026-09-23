# SecretBridge controlled operations / SecretBridge 安全操作

Follow the user's language. Use only SecretBridge MCP tools for brokered operations. The loopback Web console is for the human; never inspect, click, or automate it. Never request a PIN, passphrase, authenticator setup key, QR code, or credential value. A current six-digit TOTP code may be passed only when the human voluntarily supplies it for the exact pending approval ID and version; never retain, repeat, log, or reuse it.

## Choose a path / 选择路径

1. Start each AI chat with `secretbridge_begin_conversation` and a short non-secret summary. Pass its returned `id` as `conversation_id` to each request in that chat. Only the human sets conversation approval policy in Web. A policy may preapprove a request; disclose its scope and risk before running it.
2. Call `secretbridge_terminal_capabilities`, `secretbridge_list_catalog`, and, if useful, `secretbridge_list_action_templates`. The catalog exposes only non-secret connection and credential metadata. Prefer a structured connector for a saved connection; `secretbridge_request_ssh` handles a one-time SSH command without a helper script. Require a SHA-256 host fingerprint that the human verified through a trusted channel. Never turn off host-key checks or automatically trust an unknown/changed key.
3. For a changing local command, create a secure terminal and use `secretbridge_request_command` with an absolute executable and individual argv items. A template is **not** a prerequisite. Save a template only if the user explicitly wants a stable operation reused; use `secretbridge_request_approval` for an existing enabled template. Ordinary non-secret terminal input uses `secretbridge_terminal_attach` and `secretbridge_terminal_write`; never write a secret or bypass approval with a shell.
4. A credential argument or file slot must occupy one whole argv item as `{{secret:slot_name}}`. Other double braces, such as `{{.Names}}`, remain literal. Bind only opaque credential IDs from the catalog, never values.
5. A `pending` approval requires the human's decision in the local Web console, or a voluntarily supplied current TOTP code for `secretbridge_confirm_approval`. Show the exact approval ID, target, program/parameters, opaque credential references, expiry, and risk. Use its `console_url` if provided. For an `approved` preauthorized request, explain the standing grant and risk. Create a run only after approval, using one stable idempotency key per intended run.
6. Read `run.id`, then `secretbridge_get_run` and `secretbridge_read_run_output` with `next_cursor`; the latter is sanitized and persists after terminal closure. For live terminal text, use `secretbridge_terminal_read` with its byte cursor. Check `truncated`; never rerun a command merely to recover missing output. On timeout, context loss, or uncertain write delivery, inspect state and request a new terminal/approval rather than blindly retrying.

中文：每段 AI 对话先登记不含秘密的摘要，后续申请复用会话 ID。先查询能力、非秘密目录和可用模板；已有结构化连接优先用连接器，变化命令用一次性申请，只有用户明确要求复用才保存模板。SSH 指纹须由人通过可信渠道核实，首次未知或变更时不能自动信任。待审批时展示准确 ID、目标、参数、有效期和风险，邀请用户在本机网页处理；仅可转交用户主动提供给该请求的当前验证码。已预授权的申请执行前仍须提示风险。运行后按游标读取已脱敏输出；出错时按 `next_actions` 修复，不使用辅助脚本绕过代理。

## Contract examples / 契约示例

The JSON below is the exact input object or a **selected-fields excerpt** of MCP `structuredContent`; output objects contain additional fields defined by each tool's `outputSchema`. IDs and paths are synthetic. Choose an executable and working directory valid on the current platform. The examples show field locations, not values to copy into a live request. `next_actions` is machine-readable; display its meaning in the user's language.

### secretbridge_begin_conversation input
```json
{"summary":"Inspect a synthetic local test"}
```

### secretbridge_begin_conversation output
```json
{"id":"00000000-0000-4000-8000-000000000001","summary":"Inspect a synthetic local test","approval_policy":"every_task","version":1}
```

### secretbridge_terminal_create input
```json
{"rows":24,"cols":80,"shell":null,"name":"Synthetic local test","working_directory":null,"environment":{}}
```

### secretbridge_terminal_create output
```json
{"terminal":{"id":"00000000-0000-4000-8000-000000000002"}}
```

### secretbridge_request_command input
```json
{"name":"Read synthetic test status","connection_id":"00000000-0000-4000-8000-000000000003","conversation_id":"00000000-0000-4000-8000-000000000001","terminal_id":"00000000-0000-4000-8000-000000000002","program":"/usr/bin/id","working_directory":"/tmp","arguments":[],"credential_slots":[],"authorization_mode":"once","expires_in_seconds":300,"timeout_seconds":30,"reason":"Read synthetic test status","language":"en"}
```

### secretbridge_request_command output
```json
{"id":"00000000-0000-4000-8000-000000000004","state":"pending","version":1,"preauthorized":false,"console_url":"http://127.0.0.1:8787","next_actions":["show_pending_approval_details_to_user","user_approves_in_local_web_console","or_if_totp_configured_submit_current_code_with_secretbridge_confirm_approval"]}
```

### secretbridge_create_run input
```json
{"approval_id":"00000000-0000-4000-8000-000000000004","idempotency_key":"synthetic-read-001"}
```

### secretbridge_create_run output
```json
{"run":{"id":"00000000-0000-4000-8000-000000000005","state":"queued"},"replayed":false,"execution_mode":"credential_command"}
```

### secretbridge_read_run_output input
```json
{"id":"00000000-0000-4000-8000-000000000005","cursor":0,"wait_ms":1000}
```

### secretbridge_read_run_output output
```json
{"items":[],"next_cursor":0,"truncated":false,"state":"succeeded"}
```

Errors use a stable MCP error message and safe `data.next_actions` when recovery is possible. `initialization_required` provides a loopback `console_url`: ask the human to set the required PIN and optionally bind an authenticator. `approval_not_usable`, `approval_consumed`, or `version_conflict` require checking current state and, if still intended, a new approval. `terminal_context_unknown` or `secure_terminal_not_running` requires a new terminal. `ssh_credential_target_mismatch` requires the human to correct connection metadata; never loosen credential binding. Input/output schemas in `tools/list` are authoritative for every tool.

中文错误恢复：`initialization_required` 请人在本机管理页设置必填 PIN，可选绑定验证码；审批失效须查询状态并重新申请；终端上下文不明须新建终端；SSH 凭据目标不匹配须由人修正连接元数据，不能放宽绑定。所有操作仍应遵守工具公布的输入和输出 schema。
