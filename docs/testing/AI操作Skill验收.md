# AI 操作 Skill 验收

[文档中心](../README.md) / AI 操作 Skill 验收

[SecretBridge 操作 Skill](../../skills/secretbridge-operations/SKILL.md) 是 AI 客户端的工作流说明，不是授权组件。MCP 工具 schema、服务端状态机与本机权限检查仍是执行时的事实来源。

## 自动化场景

以下测试均使用合成数据；可在仓库根目录运行 `cargo test -p secretbridge adapters::mcp::tests -- --nocapture`。检查的是协议和流程的不变量，不把测试夹具当作真实 AI 客户端或真实凭据库。

| 场景 | 可复现的自动化证据 |
|---|---|
| 首次初始化与能力发现 | `initialization_error_points_to_local_page_and_required_pin`、`advertises_only_the_bounded_tool_surface` |
| 会话登记与隔离 | `detached_stdio_bridge_authenticates_reloads_and_does_not_own_broker_lifecycle` |
| 结构化连接器 | `native_mcp_executes_http_without_exposing_authentication`、`native_mcp_executes_ssh_and_reads_filtered_remote_output` |
| 动态命令及终端前提 | `dynamic_command_uses_catalog_metadata_and_requires_a_running_secure_terminal` |
| 待审批与人工决策 | `approval_and_run_flow_requires_web_decision_and_returns_only_safe_data` |
| 已授权调用与幂等重试 | `native_mcp_reads_redacted_command_output_and_idempotent_runs` |
| 取消、游标与截断 | `native_mcp_controls_real_terminal_without_reexecuting_on_reconnect` 及终端游标测试 |
| 不确定结果与错误恢复 | `bridge_recovery_hints_are_fixed_and_survive_remote_transport`、`skill_compatibility_and_recovery_examples_follow_server` |

`skill_examples_follow_advertised_contracts` 还把 Skill 的示例输入、输出与当前公开工具 schema 比对，防止字段和必填项漂移。它与上述真实工具调用测试结合，提供可重复的改进证据；这里不声称已经测得 AI 模型的错误率。

## 真实客户端复核

社区可按[验证待办](../community/社区验证待办.md)在隔离环境中测试支持 Skill 与仅支持 MCP 的客户端，记录工具顺序、等待人工审批的位置、重复执行与恢复结果。反馈只需脱敏状态和错误码，不提交 PIN、恢复密钥、验证码、令牌或业务连接详情。
