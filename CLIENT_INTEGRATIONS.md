# AI 客户端接入

[项目首页](./README.zh-CN.md) / AI 客户端接入

SecretBridge 在本机运行一个执行代理。不同 AI 客户端连接的都是同一个 `--mcp-stdio` 桥接进程，不需要为每个客户端重复安装代理或复制凭据。首次使用应先按[安装说明](./README.zh-CN.md)完成本机安装和初始化；客户端配置只包含程序路径与本机数据目录，不包含 PIN、恢复密钥、配对链接或凭据。

## Codex：使用预构建插件

发行包已包含插件、操作 Skill 和 MCP 定义，安装时无需 Node.js、Rust 或源码构建。先在本机安装并初始化 SecretBridge，然后用活动程序导出一个**新的**本地插件市场目录：

```text
secretbridge client-plugin codex <absolute-empty-destination>
```

命令会复制经过安装包校验的插件，配置指向安装目录内固定的 MCP 启动入口；启动入口每次读取当前活动版本，因此升级和回退后不必重建插件，也不复制任何凭据。目标目录不得已存在。随后运行 `codex plugin marketplace add <absolute-destination>` 和 `codex plugin add secretbridge@secretbridge-local`，并在新会话中验证工具。若本机已有同名市场，先用 `codex plugin list` 核对其来源，不要覆盖已有市场或插件文件；也可以继续使用下述 MCP 配置方式。卸载代理后此入口会失效，属于预期行为。

## WorkBuddy：专用连接器与 Skill

发行包包含官方规范的连接器结构和专用 Skill。先完成 SecretBridge 初始化，再导出到一个不存在的绝对目录：

```text
secretbridge client-connector workbuddy <absolute-new-directory>
```

导出目录包含 `connector-meta.json`、`mcp.json`、软件图标和 `skills/secretbridge-workbuddy/SKILL.md`。MCP 配置引用固定启动入口，代理升级、回退后无需重新构建。元信息声明 WorkBuddy 4.24.0 及以上，使用标准本机 stdio，不要求 WorkBuddy 收集密码、PIN 或长期令牌。

个人本机使用时，在 WorkBuddy 的 MCP 配置界面合并导出的 `mcp.json`，不要替换其他 MCP 服务器；在技能市场的“添加技能”入口按[官方 Skill 说明](https://open.workbuddy.cn/docs/skill)导入整个 `secretbridge-workbuddy` 技能目录的 ZIP。**Skill 本身不会连接代理**，需同时启用 MCP。连接器文件也可用于开发者连接器审核流程；导出的启动路径属于当前机器，不应直接上传到公开市场。这里不代表已上架，也不假设客户端支持未经文档说明的本地连接器一键导入。

## DeepSeek Harness：原生插件

使用 Harness 原生 bundle，而不是 Codex 插件格式：

```text
secretbridge client-plugin deepseek-harness <absolute-new-directory>
dsh plugin --profile <profile> add <absolute-new-directory>
dsh --profile <profile> --dump-config
```

适用于 Harness 0.2.0-rc.1 及兼容的 0.2.x 运行时。插件由 `dsh.bundle`、Cordis patch 和直接可运行的 JavaScript 组成，复用宿主官方 MCP client，增加专用操作指导；没有安装期编译、生命周期脚本或另一份 Harness 运行时。导出配置引用固定 MCP 启动入口。宿主会检查插件的 `@deepseek-ai/dsh` 兼容声明；不要用版本豁免强行加载旧 API。

安装后应能发现 `mcp__secretbridge__secretbridge_terminal_capabilities`。使用 `dsh plugin --profile <profile> remove dsh-secretbridge` 卸载插件，不删除代理或凭据。不要在同一 profile 再登记第二个 `serverName: secretbridge` MCP client，以免工具命名冲突。详见[插件说明](./plugins/deepseek-harness/README.md)及[官方 bundle 文档](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md)。

## 独立下载附件

每个新 Release 同时提供 Codex 插件、WorkBuddy 连接器、WorkBuddy Skill、DeepSeek Harness bundle 和通用操作 Skill 的独立附件及 SHA-256，不需要为了获取集成文件重新下载完整软件包。附件与代理版本一致，保留源码引用和许可；完整软件包仍包含这些文件。

下载包使用可移植的 MCP 启动模板，不包含个人安装路径。若代理未加入客户端可见的 PATH，或使用自定义数据目录，先按上文导出个性化目录，或替换模板中的启动配置。Skill 本身不能连接代理。详见[客户端集成下载](./docs/release/客户端集成下载.md)。

## 生成普通 MCP 配置

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
| WorkBuddy | 专用连接器 + Skill，或普通本机 MCP | 优先按上文导出连接器并配置 MCP、导入 Skill；也可使用 `client-config workbuddy` | 界面中的 MCP 连接状态及只读工具 |
| DeepSeek Harness | 原生 bundle 插件，或 MCP patch | 优先按上文导出并安装插件；`client-config deepseek-harness` 是 JSON 格式的 YAML patch | 检查 `mcp__secretbridge__secretbridge_*` 工具和只读调用 |

这些放置位置与格式以对应客户端的当前官方文档为准：[Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)、[Claude Code MCP](https://code.claude.com/docs/en/mcp)、[Cursor MCP](https://prod.cursor.com/help/customization/mcp)、[Copilot CLI MCP](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers)、[OpenCode V2 MCP](https://opencode.ai/v2/docs/mcp-servers)、[WorkBuddy 连接器](https://open.workbuddy.cn/docs/connector)、[DeepSeek Harness MCP client](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.md)。DeepSeek Harness 普通配置输出是一个增加 MCP 客户端的 profile patch，不是可独立启动的完整配置文件。若客户端使用的是旧版本或托管/云端运行环境，先核对其配置格式和本机进程能否被启动；云端客户端不能直接连接用户电脑上的 stdio 桥接。

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

Skill 目录来源：[Codex Skills](https://learn.chatgpt.com/docs/build-skills)、[Claude Code Skills](https://code.claude.com/docs/en/skills)、[Cursor Skills](https://prod.cursor.com/help/customization/skills)、[Copilot CLI Skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills)、[OpenCode V2 Skills](https://opencode.ai/v2/docs/skills)。WorkBuddy 使用发行包内的专用 Skill；Harness bundle 自带操作指导。不应把独立 Skill 文件当作已安装的 MCP 连接。

## 完成验收

1. 确认 `secretbridge status` 中 `running` 为 `true`，客户端报告 `secretbridge` 已连接。配置失败先检查绝对程序路径、数据目录和客户端对本机 stdio MCP 的支持，不要关闭 SecretBridge 的本机权限检查。
2. 在客户端发现 `secretbridge_terminal_capabilities` 并调用它。该工具只读；成功返回能力信息说明客户端、stdio 桥接和代理已连通。
3. 需要业务操作时，为**当前 AI 对话**登记新的 SecretBridge 会话，按当前 MCP 工具 schema 和响应操作。待审批的请求必须交给用户在本机管理页面决定；客户端接入成功不等于已经获准执行。

> [!IMPORTANT]
> SecretBridge 只约束通过其 MCP 工具发起的操作。若同一 AI 客户端同时具有不受限的终端、文件或网络工具，它仍可能绕过 SecretBridge 直接访问当前系统账号可读的数据。不要把“已接入 SecretBridge”理解为客户端所有能力都受它保护。
