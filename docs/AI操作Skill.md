# AI 操作 Skill 与 MCP 职责

[文档中心](README.md) / AI 操作 Skill

SecretBridge 的 [AI 操作 Skill](../skills/secretbridge-operations/SKILL.md) 指导支持 Skill 的助手选择工具、展示审批和处理不确定结果。它不增加权限；实际的凭据访问、审批、脱敏和输入校验始终由本机 MCP 服务执行。没有 Skill 的 MCP 客户端仍能通过 `tools/list` 和简短的 server instructions 使用相同接口。

## 职责归属

| 内容 | 唯一维护位置 | 其他位置保留什么 |
|---|---|---|
| 工具名、输入/输出 schema、状态和错误码 | `mcp.rs`、`mcp/errors.rs` 与服务端类型 | Skill 仅引用工具名和少量已校验示例 |
| 凭据、审批、目标、IPC、过滤与运行时校验 | 本机服务端 | Skill 解释边界，不能代替校验 |
| 工具选择、会话 ID、审批展示、游标、取消与恢复 | `skills/secretbridge-operations/SKILL.md` | MCP instructions 只留最小必要指引 |
| 例子中的字段位置和常见恢复动作 | Skill 的 `references/` | Rust 测试对照当前 schema 和错误动作 |
| 安装、首次初始化、升级与用户页面 | 部署和使用文档 | Skill 只处理已经可见的 MCP 工具 |

工具描述保留每次调用不可缺少的输入语义和安全限制。例如 SSH 指纹验证、验证码仅能对应一次审批、终端输入租约都必须在工具发现时可见。长流程不再复制到每个工具描述中。

## 安装与版本

先按 [部署指南](AI辅助部署.md) 安装代理并接通 MCP；Skill 不能替代 MCP 连接。仓库中的 `skills/secretbridge-operations/` 是完整的可复制目录。Codex 用户把整个目录复制到当前用户的 `$CODEX_HOME/skills/secretbridge-operations`；未设置 `CODEX_HOME` 时使用 Codex 用户技能目录 `.codex/skills/secretbridge-operations`，然后重启或刷新客户端。不要只复制 `SKILL.md`，因为示例和兼容性信息在 `references/` 中。

其他支持 Agent Skills 的客户端，应把完整目录安装到该客户端文档指定的 Skills 位置，同时单独配置 SecretBridge MCP。只支持 MCP 的客户端无需安装 Skill：它们仍能发现工具 schema、简短 server instructions 和响应中的 `next_actions`。客户端没有 MCP 时，Skill 不能执行受控操作。

Skill 的 [兼容性文件](../skills/secretbridge-operations/references/compatibility.json) 固定适配的 broker 和公开 API 版本；仓库 Git tag 固定 Skill 内容。更新代理时检查版本，若不匹配，更新对应 tag 的 Skill，再验证 MCP 工具列表。暂时无法更新时只按在线 schema 和响应操作，不照抄旧示例。不要把客户端私有目录、PIN、验证码、会话令牌或凭据加入 Skill。

## 可复现验收

`cargo test -p secretbridge-server skill_examples_follow_advertised_contracts` 检查 Skill 的合成 JSON 示例确实使用当前 MCP 工具字段、必填输入和可解析类型；`skill_compatibility_and_recovery_examples_follow_server` 检查版本及常见错误的 `next_actions`。服务端原有 MCP 测试仍覆盖 `tools/list`、授权、幂等、取消和游标。例子同步检查能防止文档和接口漂移，但不能单独证明模型执行正确。

人工或模型回归使用隔离的合成环境，每个场景记录“工具选择、是否在正确位置停下等待用户、是否重复执行、是否误用秘密或旧 ID”，并保存脱敏的调用序列。建议覆盖：

1. 首次初始化：收到 `initialization_required` 后引导人在本机页面操作，AI 不接触 PIN。
2. 新对话：登记新的 conversation ID，后续请求复用本次 ID。
3. 已保存连接：选择匹配的结构化连接器，不把密码值传给模型。
4. 变化命令：使用安全终端与一次性申请，参数逐项传入；不强迫先创建模板。
5. 待审批与已预授权：分别等待人工、说明现有策略和风险，批准后才运行。
6. 取消与截断：按最新 run version 取消；输出截断时报告缺口，不重跑命令。
7. 不确定交付：先查询审批、运行和终端状态；只有确认同一意图时复用幂等键。

比较升级前后的 AI 错误率时，应使用同一模型、任务、合成夹具和评分标准；未运行模型回归前，不宣称错误率下降。仓库测试提供可复现的契约一致性证据。

---

[开发设计](开发设计.md) · [安全连续终端](AI终端与实时状态.md) · [开发者入门](开发者入门.md)
