<div align="center">

# 密桥 SecretBridge

**让凭据留在本机，让授权决定操作。**

[English](README.md) · [文档中心](docs/README.md) · [参与贡献](CONTRIBUTING.md) · [安全报告](SECURITY.md)

[![开源许可：AGPL v3+](https://img.shields.io/badge/开源许可-AGPL%20v3%2B-663399)](LICENSE)
[![商业许可：可申请](https://img.shields.io/badge/商业许可-联系版权方-0A7B83)](COMMERCIAL_LICENSE.md)
[![项目阶段：M1开发](https://img.shields.io/badge/项目阶段-M1%20工作流开发-147D92)](ROADMAP.md)

[![Rust](https://img.shields.io/badge/Rust%201.98-000000?logo=rust&logoColor=white)](Cargo.toml)
[![Axum](https://img.shields.io/badge/Axum%200.8-2E3440)](crates/secretbridge-server/Cargo.toml)
[![React](https://img.shields.io/badge/React%2019-20232A?logo=react&logoColor=61DAFB)](web/package.json)
[![TypeScript](https://img.shields.io/badge/TypeScript%207-3178C6?logo=typescript&logoColor=white)](web/package.json)
[![Vite](https://img.shields.io/badge/Vite%208-646CFF?logo=vite&logoColor=white)](web/package.json)

</div>

> [!IMPORTANT]
> **当前进入M1工作流开发，M0安全门槛仍未全部关闭。** 仓库已有可运行的本机Web管理端、回环地址Rust服务、一次性浏览器配对、隔离的合成终端，以及使用本机SQLite持久化的凭据引用、逻辑目标、受控操作模板、范围化审批、合成运行和安全事件。配置不接收秘密值和网络地址；运行只模拟内部状态，不会触发真实操作。真实凭据保存、注入、业务系统访问和系统Shell执行仍被禁用。

## 密桥解决什么问题？

将密码直接交给智能助手，会使秘密进入对话上下文或执行工具。密桥的目标是提供一条受控的本地执行通道：助手提出操作请求，用户确认权限，代理内部使用凭据，再返回经过审查的结果。

| 能力方向 | 使用体验 |
| :--- | :--- |
| 凭据代用 | 在本机配置凭据，向助手开放允许的操作，而非读取密码的接口。 |
| 明确审批 | 执行前确认目标、参数、权限和结果范围。 |
| 持久终端 | 窗口关闭或助手断线后，可以重新连接同一会话。 |
| 安全返回 | 筛选结果字段、过滤输出，并保留可追溯的审计事件。 |
| 三平台体验 | 浏览器管理端保持一致，后台服务分别适配各系统的凭据和进程机制。 |

当前已实现合成模式状态接口、一次性配对、可过期／撤销的页面会话、可断线重连的合成PTY，以及经过认证、可编辑并在本机SQLite中持久化的M1配置页面。“执行策略”页将内置合成操作和返回范围绑定到逻辑目标；审批中心会先展示服务端策略预检，再基于已启用模板创建限时授权。审批保存模板与目标版本，每条已批准审批最多创建一个合成运行，请求可幂等重试。批准、创建、开始和完成前均重新执行同一套策略，配置变化时旧授权默认失效。运行可查看排队、运行、完成、取消、授权失效停止或重启中断状态；“审计记录”只展示服务端生成的固定安全事件。整个运行过程只是内部短时状态模拟，不启动系统进程、不访问网络、不读取凭据、不接收操作参数。终端按输出游标续传未读内容，在多个连接间强制单写入者、其余只读；状态接口明确标记当前只是“同用户兼容模式，身份隔离未验证”。其余能力及准入条件见[路线图](ROADMAP.md)。

## 一次操作如何完成？

```mermaid
flowchart LR
    A["智能助手<br/>请求操作"] --> B["策略校验与审批"]
    U["使用者"] -->|"确认范围"| B
    B --> C["本地执行代理"]
    K["凭据库"] -->|"内部代用"| C
    C --> D["已授权目标"]
    D --> E["结果审查"]
    E -->|"仅返回允许内容"| A
```

凭据不作为工具结果返回。普通终端与使用凭据的操作分开管理，已登录的受控会话也不能直接变成任意命令终端。

> [!WARNING]
> 输出打码不能替代权限隔离。如果助手拥有凭据所有者同账号的任意执行权限，仍可能绕过应用取密。真实部署必须先验证系统身份与进程边界，详见[安全模型](docs/安全模型与验收.md)。

## 从哪里开始？

| 你希望了解 | 阅读入口 |
| :--- | :--- |
| 工作流程、适用场景和当前限制 | [使用指南](docs/使用指南.md) |
| 各类文档与阅读顺序 | [文档中心](docs/README.md) |
| 本地检查、开发约定和贡献流程 | [开发者入门](docs/开发者入门.md) · [贡献指南](CONTRIBUTING.md) |
| 系统实现与交互设计 | [开发设计](docs/开发设计.md) · [跨平台与UI规范](docs/跨平台与UI规范.md) |
| 术语、接口与安全边界 | [术语表](docs/术语表.md) · [安全模型与验收](docs/安全模型与验收.md) |

中英文首页保持相同的产品范围；详细工程文档当前以简体中文维护。

## 运行开发原型

需要Node.js 24、pnpm 11及Rust 1.98或更新的稳定工具链：

```sh
pnpm install --frozen-lockfile
pnpm build
cargo run -p secretbridge-server
```

服务仅监听`127.0.0.1:8787`并打开系统默认浏览器。启动令牌位于URL片段中，页面读取后立即清除；换页或刷新不会持久化会话。“凭据”“连接目标”“执行策略”“审批中心”“运行任务”和“审计记录”页面只处理非秘密、非地址配置与固定安全状态，并保存到操作系统的本机应用数据目录。合成运行没有命令或网络执行接口。“安全终端”页面只能运行密桥内置的合成程序，不会启动PowerShell、`cmd`、`sh`或用户命令；WebSocket断开和重连不会终止该合成PTY，页面从上次输出游标继续读取。受限的`flood`和`wait`命令只用于韧性验证。该原型不使用、也不计划引入桌面壳。

## 平台目标

| 平台 | 首轮验证基线 | 应用状态 |
| :--- | :--- | :--- |
| Windows | Windows 11 · x64 | 本地原型与CI合成路径已验证 |
| Linux | Ubuntu 24.04 · x64 · GNOME/KDE | CI合成路径已验证，桌面集成待验证 |
| macOS | macOS 14+ · arm64/x64 | CI合成路径已验证，桌面集成待验证 |

其他系统版本和架构需要独立验证。实际支持范围以未来发布版本的兼容性说明为准。

## 参与项目

项目处于M1开发阶段，M0安全验证仍在并行推进。欢迎参与安全评审、三平台适配、可访问性、测试与文档完善。开始贡献前请阅读[贡献指南](CONTRIBUTING.md)与[开发者入门](docs/开发者入门.md)。

## 许可与社区

Copyright (c) 2026 **数链创元（天津）信息技术有限责任公司**。

本仓库采用 **GNU Affero General Public License v3.0 or later**（`AGPL-3.0-or-later`）开源许可。如需将代码改造后闭源商用，将其嵌入、链接或打包进不按AGPL履约的商业软件，或实施任何超出开源许可范围的事项，须事先联系版权方取得书面商业许可。详见[许可说明](LICENSING.md)、[商业授权](COMMERCIAL_LICENSE.md)与[版权声明](COPYRIGHT.md)。

无论采用开源许可还是商业许可，第三方组件仍须遵守其各自条款，详见[第三方声明](THIRD_PARTY_NOTICES.md)与[依赖许可风险评估](docs/依赖许可风险评估.md)。

普通问题通过[GitHub Issues](https://github.com/qq940500529/secretbridge/issues)提交；安全漏洞使用[私人报告流程](SECURITY.md)。贡献者应遵循[贡献指南](CONTRIBUTING.md)与[社区准则](CODE_OF_CONDUCT.md)，不要提交真实凭据或业务数据。

---

[文档中心](docs/README.md) · [路线图](ROADMAP.md) · [变更记录](CHANGELOG.md)
