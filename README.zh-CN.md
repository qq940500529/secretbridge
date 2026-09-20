<div align="center">

# 密桥 SecretBridge

**让凭据留在本机，让授权决定操作。**

[English](README.md) · [下载 Beta](https://github.com/qq940500529/secretbridge/releases/tag/v0.2.0-beta.5) · [文档](docs/README.md) · [部署](docs/AI辅助部署.md) · [问题反馈](https://github.com/qq940500529/secretbridge/issues/new?template=bug_report.md) · [安全](SECURITY.md)

[![开源许可：AGPL v3+](https://img.shields.io/badge/开源许可-AGPL%20v3%2B-663399)](LICENSE)
[![Rust 1.98](https://img.shields.io/badge/Rust-1.98-000000?logo=rust)](rust-toolchain.toml)
[![Node.js 24](https://img.shields.io/badge/Node.js-24-339933?logo=node.js&logoColor=white)](.node-version)

</div>

> [!IMPORTANT]
> SecretBridge `0.2.0-beta.5` 是面向个人、单机使用的公开预发行版。请先使用合成凭据、保留独立备份，并阅读[许可协议与免责协议](docs/最终用户许可与免责声明.md)。它不提供凭据读取／导出接口；普通终端不是凭据隔离沙箱。

## 它解决什么问题

把密码交给 AI，会让秘密进入对话、命令或日志。SecretBridge 把凭据使用改成受控流程：AI 申请固定操作，用户在本机检查并批准，代理内部使用凭据，只返回允许的结果。

```mermaid
flowchart LR
    A["AI 申请操作"] --> B{"本机用户审批"}
    B -->|拒绝| X["不执行"]
    B -->|批准| C["本机代理"]
    K["系统凭据库"] -->|秘密只在内部使用| C
    C --> D["固定目标与操作"]
    D --> E["过滤结果与审计"]
    E --> A
```

## 主要能力

- **写入而不回读**：密码、令牌和私钥保存在操作系统凭据库；SQLite 只记录引用与状态。
- **明确审批**：执行前核对目标、参数、授权方式、有效期和结果范围。
- **受控连接器**：固定程序、HTTP、SSH、SFTP、Git HTTPS、PostgreSQL 和 MySQL。
- **持续终端**：浏览器或 MCP 断开后可重新连接同一个真实 Shell；普通终端不注入凭据。
- **受限结果**：凭据任务在保存前过滤输出，数据库和 HTTP 可限制返回字段与规模。
- **可追溯状态**：授权、运行和固定审计事件带版本保存；配置变化会使旧授权失效。
- **本机交付**：后台启动、状态、停止、登录自启动、升级、回滚、卸载、备份和恢复。

当前开源版专注个人本机使用。组织身份、集中策略、受管节点和多人审批属于独立企业产品方向，不是开源版 1.0 的前置条件。参见[版本边界](docs/开源版与企业版.md)。

## 快速开始

首次部署可以把下面的提示词直接交给能够展示命令、请求权限并在失败时停止的本机 AI 编码助手。不必先下载仓库，也不必切换到仓库目录；可在任意文件夹或全新对话中开始。

```text
请在当前机器部署 SecretBridge，仓库地址：https://github.com/qq940500529/secretbridge

你可以从任意目录开始，不要假设仓库已经下载。先检查 GitHub 最新 Release；如果有适合当前平台的安装包，就下载并校验摘要和包元数据后安装。如果没有可用 Release，再把最新 main 分支克隆到新建的非敏感目录，阅读 AGENTS.md 和部署文档，使用仓库锁定的工具版本与依赖构建并安装。保留已有文件；需要管理员权限或修改工作目录以外内容时先征求同意。不要索取或泄露真实凭据。安装后启动 SecretBridge，确认 status 正常且服务只监听本机回环地址。最后报告安装的版本或提交、安装位置和卸载命令。
```

[AI 辅助部署](docs/AI辅助部署.md)说明权限和安全边界；供助手直接读取的流程见 [AI 部署执行指南](docs/AI部署执行指南.md)。执行前仍应检查助手准备运行的命令。维护者需要完整源码与安装包验收时，再执行详细指南中的质量门禁。

用户不需要自己选择安装包、准备仓库或配置工具链；这些判断由助手完成，只在操作系统确实需要授权时向用户确认。服务只接受回环地址，首次打开会生成一次性浏览器配对链接。人工源码构建、升级和卸载见[安装与后台运行](docs/后台运行与安装交付.md)。

## 日常流程

1. 在“凭据”保存一次性测试凭据，确认页面不能回读。
2. 在“连接”登记固定目标和信任设置。
3. 在“任务”定义操作、普通参数、凭据插槽和结果范围。
4. AI 或用户申请授权；用户只在 Web 页面批准、拒绝或撤销。
5. 启动运行并查看受限结果和审计事件。
6. 不再需要时删除合成凭据并停止服务。

完整说明见[使用指南](docs/使用指南.md)和[工作台说明](docs/工作台使用说明.md)。

## 支持范围

| 平台 | 当前验收基线 | 默认 Shell |
|---|---|---|
| Windows | Windows 11 x64 | PowerShell / CMD |
| Linux | Ubuntu 24.04 x64 | Bash |
| macOS | macOS 14+ arm64/x64 | Zsh |

其他版本和架构属于实验性环境，必须单独验证。Beta 安装包尚未签名；支持状态和已知限制以每个公开 Release 的说明为准。

## 参与 Beta 测试

更广泛的实机验证现由社区用户共同完成。安装最新 Beta 后，请只使用合成数据，在自己的环境中检查安装、浏览器配对、凭据库写入／覆盖／删除、批准与拒绝、输出脱敏、重启或登录恢复、升级／回滚和卸载。不得为通过测试而关闭 TLS、SSH 主机验证、凭据库保护或其他系统安全机制。

可复现的普通缺陷请使用 [Beta 问题表单](https://github.com/qq940500529/secretbridge/issues/new?template=bug_report.md)。请提供包版本、平台、安装方式、已脱敏的复现步骤和清理结果；不要提交真实凭据、私人地址、用户路径或业务记录。可能属于漏洞的问题请使用[私密安全报告](https://github.com/qq940500529/secretbridge/security/advisories/new)。

## 安全边界

- MCP 不能读取秘密或替用户作出审批决定。
- TLS、SSH 主机指纹和目标系统权限不能为了通过测试而关闭。
- 输出过滤降低意外回显风险，但不等于程序沙箱，也不能判断所有业务数据是否适合发送给模型。
- 能以同一操作系统账号执行任意代码的恶意程序，可能绕过应用边界访问进程、文件或凭据库。
- 真实系统应使用短期、最小权限账号；问题报告只使用合成数据。

详见[安全模型](docs/安全模型与验收.md)和[自动化安全验收](docs/自动化安全验收.md)。安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告。

## 文档与参与

| 目标 | 入口 |
|---|---|
| 部署和使用 | [文档中心](docs/README.md) |
| 了解后续工作 | [路线图](ROADMAP.md) · [变更记录](CHANGELOG.md) |
| 建立开发环境 | [开发者入门](docs/开发者入门.md) · [开发设计](docs/开发设计.md) |
| 提交代码或文档 | [贡献指南](CONTRIBUTING.md) · [行为准则](CODE_OF_CONDUCT.md) |
| 了解许可 | [许可说明](LICENSING.md) · [商业许可](COMMERCIAL_LICENSE.md) |
| 查看首次运行条款 | [许可协议与免责协议](docs/最终用户许可与免责声明.md) |
| 反馈问题 | [公开缺陷报告](https://github.com/qq940500529/secretbridge/issues/new?template=bug_report.md) · [私密安全报告](https://github.com/qq940500529/secretbridge/security/advisories/new) |

Copyright (c) 2026 数链创元（天津）信息技术有限责任公司。开源代码采用 `AGPL-3.0-or-later`；第三方组件遵循各自许可，参见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
