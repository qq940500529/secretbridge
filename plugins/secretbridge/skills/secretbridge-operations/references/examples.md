# Synthetic MCP contract examples

These are exact input objects or selected-field excerpts of MCP `structuredContent`, not live values. Input/output schemas from the connected broker are authoritative. All IDs, paths, and the SSH fingerprint are synthetic; choose a valid executable and directory on the current platform.

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
{"name":"Read synthetic test status","connection_id":"00000000-0000-4000-8000-000000000003","conversation_id":"00000000-0000-4000-8000-000000000001","terminal_id":"00000000-0000-4000-8000-000000000002","program":"/bin/sh","working_directory":"/tmp","arguments":["-s"],"stdin_content":"printf '%s\\n' synthetic-status\n","credential_slots":[],"authorization_mode":"once","expires_in_seconds":300,"timeout_seconds":30,"reason":"Read synthetic test status","language":"en"}
```

### secretbridge_request_command output
```json
{"id":"00000000-0000-4000-8000-000000000004","state":"pending","version":1,"preauthorized":false,"console_url":"http://127.0.0.1:8787","next_actions":["show_pending_approval_details_to_user","user_approves_in_local_web_console","or_if_totp_configured_submit_current_code_with_secretbridge_confirm_approval"]}
```

### secretbridge_request_ssh input
```json
{"connection_id":"00000000-0000-4000-8000-000000000003","conversation_id":"00000000-0000-4000-8000-000000000001","name":"Read synthetic SSH status","host_key_sha256":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","port":22,"remote_program":"/usr/bin/id","working_directory":"/tmp","arguments":[],"expires_in_seconds":300,"timeout_seconds":30,"reason":"Read synthetic SSH status","language":"en"}
```

### secretbridge_request_ssh output
```json
{"id":"00000000-0000-4000-8000-000000000006","state":"pending","version":1,"preauthorized":false,"next_actions":["show_pending_approval_details_to_user","user_approves_in_local_web_console","or_if_totp_configured_submit_current_code_with_secretbridge_confirm_approval"]}
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
