# SecretBridge MCP / 密桥 MCP

This server exposes controlled local operations. Discover the current tools and schemas with `tools/list`; the schema and live response are authoritative. A separately installable `secretbridge-operations` Skill explains tool selection and recovery for clients that support Skills. The Skill is optional: these MCP tools remain usable without it.

The broker enforces credential, approval, target, and output boundaries. Tool calls cannot read credential values or change human approval policy. The Web console is for the person; do not automate it or ask for a PIN, setup key, QR code, passphrase, or credential. `secretbridge_confirm_approval` accepts only a current code voluntarily supplied by the person for one identified pending approval.

Register each AI conversation with `secretbridge_begin_conversation`; discover capabilities and non-secret catalog metadata before requesting an operation. A pending approval needs a human decision. Create a run only from an approved request and use one stable idempotency key for that intended run. Read sanitized output by the returned cursor; on uncertain delivery, query state before retrying. Treat `next_actions` as recovery hints and do not bypass the broker with direct shell input or Web automation.

中文：以当前 `tools/list` 的 schema 和返回状态为准。每段 AI 对话先登记，不把秘密写入摘要；申请待审批时等待用户在本机处理；批准后才创建运行，按游标读取脱敏输出。错误时先查询状态，再按 `next_actions` 恢复。Skill 是操作指引，审批和凭据边界始终由服务端执行。
