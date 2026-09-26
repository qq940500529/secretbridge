# AI 客户端接入

[项目首页](./README.zh-CN.md) / AI 客户端接入

SecretBridge 在本机运行一个执行代理。不同 AI 客户端连接的都是同一个 `--mcp-stdio` 桥接进程，不需要为每个客户端重复安装代理或复制凭据。首次使用应先按[安装说明](./README.zh-CN.md)完成本机安装和初始化；客户端配置只包含程序路径与本机数据目录，不包含 PIN、恢复密钥、配对链接或凭据。

## 生成当前安装的配置

从 `secretbridge status` 输出中的 `installation.binary` 获取正在使用的绝对程序路径。用这个程序运行 `client-config`：

```text
secretbridge client-config <client>
```

如果程序未加入 `PATH`，直接用 `installation.binary` 的绝对路径运行。在 PowerShell 中用 `& "<binary>" client-config codex`；在 Bash/Zsh 中用 `"<binary>" client-config codex`。`<binary>` 是占位说明，不要原样输入。支持的 `<client>`：`codex`、`claude-code`、`cursor`、`copilot-cli`、`opencode`、`workbuddy`、`deepseek-harness`、`generic`。

命令只**打印**与当前安装路径匹配的配置，不读取凭据，也不修改任何客户端文件。若提示 `not_installed`，先完成安装；不要把源码构建目录或临时解压目录当作长期 MCP 路径。升级或回退后重新生成配置并核对客户端引用的程序路径。

## 各客户端放置位置

| 客户端 | 接入方式 | 如何使用生成结果 | 连接验证 |
|---|---|---|---|
| Codex | MCP + 可选操作 Skill | 把 `client-config codex` 的 TOML 片段合并到用户 `config.toml`，不要覆盖其他 MCP 配置 | `codex mcp list`，再调用只读工具 |
| Claude Code | MCP + 可选操作 Skill | 在当前用户的 PowerShell（Windows）或 Bash/Zsh（Linux/macOS）中执行 `client-config claude-code` 打印的 `claude mcp add` 命令 | `claude mcp list` 或会话内 `/mcp` |
| Cursor | MCP + 可选操作 Skill | 把 `client-config cursor` 的 `mcpServers.secretbridge` 项合并到用户级 `~/.cursor/mcp.json`，或经 MCP 设置界面录入 | MCP 设置中的连接状态；CLI 可用 `agent mcp list` |
| GitHub Copilot CLI | MCP + 可选操作 Skill | 把 `client-config copilot-cli` 的 `mcpServers.secretbridge` 项合并到 `~/.copilot/mcp-config.json` | `copilot mcp list` 和 `copilot mcp get secretbridge` |
| OpenCode V2 | MCP + 可选操作 Skill | 把 `client-config opencode` 的 `mcp.servers.secretbridge` 项合并到用户级 `opencode.json`/`opencode.jsonc` | MCP 列表及只读工具 |
| WorkBuddy | 本机 MCP | 在“插件 → MCP 服务器 → 配置 MCP”中合并 `client-config workbuddy` 的 JSON；优先用户级配置 | 界面中的 MCP 连接状态 |
| DeepSeek Harness | MCP client 包 | 把 `client-config deepseek-harness` 的 YAML 条目加入所用 profile 的 MCP 客户端插件列表 | 检查 `mcp__secretbridge__*` 工具和只读调用 |

这些放置位置与格式以对应客户端的当前官方文档为准：[Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)、[Claude Code MCP](https://code.claude.com/docs/en/mcp)、[Cursor MCP](https://prod.cursor.com/help/customization/mcp)、[Copilot CLI MCP](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers)、[OpenCode V2 MCP](https://opencode.ai/v2/docs/mcp-servers)、[WorkBuddy MCP](https://www.workbuddy.ai/docs/zh/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/MCP-Guide)、[DeepSeek Harness MCP client](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.md)。DeepSeek Harness 输出是已有 profile 的一个插件条目，不是可独立启动的完整配置文件。若客户端使用的是旧版本或托管/云端运行环境，先核对其配置格式和本机进程能否被启动；云端客户端不能直接连接用户电脑上的 stdio 桥接。

## 其他 MCP 客户端

未列出的**本机**客户端如果支持启动 stdio MCP 服务，可运行 `secretbridge client-config generic` 获取通用 JSON。它使用常见的 `mcpServers.secretbridge` 结构，包含当前活动程序的绝对路径、`--mcp-stdio` 参数和同一数据目录。将该项合并到客户端配置，不要覆盖已有 MCP 服务。

部分客户端的配置不是 `mcpServers` JSON：应按该客户端文档把其中的 `command`、`args`、`env` 映射到它的字段，不要把通用 JSON 原样写入不兼容的格式。客户端还必须能够在**运行代理的这台机器上**启动程序；仅支持远程 HTTP MCP 或云端运行的客户端不能直接使用本机 stdio 配置。

## 操作 Skill

MCP 提供受控工具；[操作 Skill](./skills/secretbridge-operations/SKILL.md)指导 AI 选择工具、等待用户审批和处理不确定结果，不赋予新的权限。使用 Skill 的客户端应复制**整个** `skills/secretbridge-operations/` 目录，包括 `references/`，并与代理版本同步。

| 客户端 | 用户级 Skill 目录 |
|---|---|
| Codex | `~/.agents/skills/secretbridge-operations/` |
| Claude Code | `~/.claude/skills/secretbridge-operations/` |
| Cursor | `~/.cursor/skills/secretbridge-operations/` |
| GitHub Copilot CLI | `~/.copilot/skills/secretbridge-operations/` |
| OpenCode V2 | `~/.config/opencode/skills/secretbridge-operations/` |

Skill 目录来源：[Codex Skills](https://learn.chatgpt.com/docs/build-skills)、[Claude Code Skills](https://code.claude.com/docs/en/skills)、[Cursor Skills](https://prod.cursor.com/help/customization/skills)、[Copilot CLI Skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills)、[OpenCode V2 Skills](https://opencode.ai/v2/docs/skills)。WorkBuddy 和 DeepSeek Harness 首批通过 MCP 接入；不应把独立 Skill 文件当作已安装的 MCP 连接。

## 完成验收

1. 确认 `secretbridge status` 中 `running` 为 `true`，客户端报告 `secretbridge` 已连接。配置失败先检查绝对程序路径、数据目录和客户端对本机 stdio MCP 的支持，不要关闭 SecretBridge 的本机权限检查。
2. 在客户端发现 `secretbridge_terminal_capabilities` 并调用它。该工具只读；成功返回能力信息说明客户端、stdio 桥接和代理已连通。
3. 需要业务操作时，为**当前 AI 对话**登记新的 SecretBridge 会话，按当前 MCP 工具 schema 和响应操作。待审批的请求必须交给用户在本机管理页面决定；客户端接入成功不等于已经获准执行。

> [!IMPORTANT]
> SecretBridge 只约束通过其 MCP 工具发起的操作。若同一 AI 客户端同时具有不受限的终端、文件或网络工具，它仍可能绕过 SecretBridge 直接访问当前系统账号可读的数据。不要把“已接入 SecretBridge”理解为客户端所有能力都受它保护。
