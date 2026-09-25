# AI 辅助部署

[项目首页](../../README.zh-CN.md) / [文档中心](../README.md) / AI 辅助部署

SecretBridge 涉及原生程序、Web 资源、系统凭据库和用户级后台启动。首次试用建议让**运行在本机、能够展示命令并等待确认的 AI 编程助手**优先安装公开发行包；没有适用发行包时再从主分支构建。这样可以减少漏装依赖和复制错误，但不会改变系统权限边界：AI 只能使用你明确允许的权限，也不能替你判断一个真实凭据是否适合交给当前操作系统账号。

仓库已经提供公开 Beta Release。助手应优先选择与当前平台和架构匹配的发行包；只有没有适用包时才使用最新 `main`，主分支构建仍属于开发候选版。

普通使用者只需复制“自动执行提示词”，不需要判断本机是否已经安装、平台安装包、Git 分支、工具链或构建命令。更换 AI 软件、模型或对话时，助手应先复用同一份本机安装，只为当前客户端增加 MCP 配置。

## 自动执行提示词

以下提示词可直接用于任意文件夹或全新对话，不需要预先克隆仓库。把它交给能够在本机执行命令并逐项请求权限的 AI 助手：

```text
请在当前机器部署 SecretBridge，仓库地址：https://github.com/qq940500529/secretbridge

要求：
1. 可以从任意目录开始，不要假设仓库已经下载。先从当前 AI 客户端已有 MCP 配置、PATH 和文档规定的默认安装位置检查本机是否已经安装 SecretBridge；只检查明确位置，不扫描整个用户目录。如果找到可执行文件，先运行 status。已有安装健康且版本可用时直接复用，不下载、不覆盖、不重复安装；服务未运行时使用现有安装启动。发现自定义安装迹象但无法定位时，只询问我一次，不要另建重复安装。
2. 仅在确认没有可用安装时，检查 GitHub 最新 Release；如果有适合当前系统和架构的安装包，下载它并校验随附摘要及包元数据后安装。
3. 如果没有适用 Release，把最新 main 分支克隆到新建的非敏感目录。完整阅读 AGENTS.md、SECURITY.md、docs/getting-started/AI辅助部署.md、docs/getting-started/自动化部署运行手册.md 和 docs/getting-started/安装与服务管理.md，再使用锁定工具版本与依赖构建、校验并安装。
4. 不要清理已有改动。需要 sudo/管理员权限或修改工作目录以外文件时，先显示原因、目标和命令并等待同意。任何探测、下载、校验、构建或安装失败都停止排查，不跳过检查、不降低安全设置。
5. 不读取或回显真实秘密，不把凭据放入 argv、环境变量、脚本、文件、日志或对话；共享结果时隐藏用户名、主机名、个人路径和内网地址。
6. 启动或复用 SecretBridge，确认 status 正常且只监听本机回环地址，并从 status 或 install 结果取得当前绝对 binary 路径。
7. 把 SecretBridge 接入我使用的 MCP AI 客户端。优先识别当前客户端，无法确定时只询问一次。先展示并备份将修改的配置，获得同意后，以 binary 作为 command，以 ["--mcp-stdio"] 作为 args；如果使用自定义 SECRETBRIDGE_DATA_DIR，桥接必须使用同一绝对路径。配置不得包含凭据、页面配对令牌或其他秘密。重载 AI 客户端，确认 SecretBridge 工具可见，并调用只读的 secretbridge_terminal_capabilities 验证连接。若不能安全自动配置，提供可直接粘贴的配置和准确重载步骤，不要猜测配置路径。
8. MCP 验证后，检查新装结果的 `management_page`。若为 `opened`，不要再次运行 `open` 使一次性配对页面失效；若为 `manual_open_required` 且当前机器有可交互桌面，使用已安装 binary 的 `open` 命令打开本机管理页。指导我完成许可确认、首次配对、PIN 设置、可选验证码绑定和需要的连接配置。复用已初始化且不需人工动作的安装时无需强制弹窗。不要读取或转发一次性配对链接。如果没有桌面、通过 SSH 远程部署，或 `open` 失败，应明确说明我需要在运行 SecretBridge 的本机桌面执行该 binary 的 `open`；不得改成公网监听、开放防火墙或通过 SSH 转发配对令牌。
9. 再次检查 status 和 MCP 只读能力。结束时报告复用或新装、版本或提交、服务与 MCP 状态、管理页打开或本机手动打开步骤、剩余初始化动作、数据保留规则和卸载命令；未完成的人机初始化不得写成已完成。
```

AI 应在执行前让你看到会修改机器的命令。提示词不是授权 AI 扩大范围、删除现有数据、修改防火墙或安装完整桌面环境。普通部署还应在有桌面时打开管理页并引导必要初始化；完整测试矩阵和发行验收属于维护者流程。

## 开始前

- 只在个人测试机或明确获准的设备上操作；先提交或备份现有工作。
- 使用本机 AI 助手，不要把 Webhook、Token、密码、私钥、数据库地址或未脱敏日志发送给远程模型。
- AI 必须先读本页、[安装与后台运行](./安装与服务管理.md)、[安全模型](../security/安全模型.md)和根目录 `AGENTS.md`。
- 要求 AI 先报告仓库提交、工作区状态、平台、架构和工具版本，再给出计划；每个需要管理员权限或会覆盖安装的操作都单独确认。
- 验收只使用一次性合成凭据。不得关闭系统安全提示、降低文件权限或把秘密写进命令行、环境变量、脚本和日志。

## 逐步指导提示词

如果你希望自己输入每条命令，让 AI 只负责解释和核对，可使用：

```text
请逐步指导我部署 SecretBridge，仓库地址：https://github.com/qq940500529/secretbridge。可以从任意目录开始。先检查当前 AI 客户端已有 MCP 配置、PATH 和文档规定的默认安装位置；若已有安装，运行 status 并在健康且版本可用时直接复用，不要重复下载或安装。只有确认不存在可用安装后，才查找适合当前平台的最新 GitHub Release，存在时校验并安装发行包，不存在时再指导我克隆最新 main、阅读部署文档并按锁定版本构建安装。每次只给一组可以审阅的命令，说明预期输出和风险，等我贴出脱敏结果后再继续。启动或复用服务后确认 status 正常且只监听本机回环地址，再指导我把 status 或 install 返回的绝对 binary 路径以 command 和 ["--mcp-stdio"] 参数接入当前 MCP AI 客户端。修改客户端配置前先展示差异并让我确认；重载后用只读 secretbridge_terminal_capabilities 验证连接。不要让我粘贴密码、Token、私钥或机器身份信息；任何探测、下载、校验、构建、安装或 MCP 连接失败都先诊断，不要建议跳过或关闭安全功能。
```

## 先发现并复用已有安装

不同 AI 客户端、模型或新对话不应各自安装一份 SecretBridge。助手按下面的最小范围发现现有安装：

1. 检查当前客户端已有的 `secretbridge` MCP 项；其 `command` 是首选候选路径。
2. 检查 PATH 中是否存在 `secretbridge`，以及[安装与后台运行](./安装与服务管理.md#避免重复安装)列出的当前平台默认安装记录。不得递归扫描用户目录、其他磁盘或无关配置。
3. 使用候选程序执行 `status`。结果中 `installation.binary` 是当前活动版本路径；`running` 为 `false` 时使用该路径启动，不要重新安装。
4. 只有候选程序不存在、安装记录无效或当前版本明确不适用时才进入下载流程。升级会改变程序路径，必须先说明原因并征得同意；不能仅因这是一次新对话就升级。
5. 如果安装使用了未知的自定义目录，询问用户提供安装位置或原 MCP 配置。无法确认时停止，不得用默认目录创建第二份安装。

## MCP 接入完成条件

安装只完成了本机代理部分。要让 AI 请求 SecretBridge 的受控工具，还必须把 stdio 桥接登记到用户实际使用的 MCP 宿主。

1. 从 `status` 的 `installation.binary` 或 `install` 的 `binary` 字段取得当前活动版本。不要指向临时解压目录或源码仓库中的 `target`。
2. 识别当前 AI 客户端支持的 MCP 配置格式。只有在配置文件和目标客户端可以可靠确认时才自动修改；修改前展示路径、备份位置和最小差异，并等待用户同意。
3. 把下列通用配置转换成该客户端的格式。默认数据目录不需要 `env`；只有安装时明确设置过自定义目录才添加同名变量。

```json
{
  "mcpServers": {
    "secretbridge": {
      "command": "/absolute/path/from-install-result/secretbridge",
      "args": ["--mcp-stdio"]
    }
  }
}
```

4. 重载或重启 AI 客户端，确认工具列表中出现 `secretbridge_*`。调用只读的 `secretbridge_terminal_capabilities`；它成功返回能力信息即可证明 stdio 桥接和本机代理已连通，不需要创建凭据或批准任务。
5. 如果客户端不支持 MCP、配置位置无法可靠识别或用户不同意自动修改，停止写入，只提供适配该客户端的可粘贴片段和重载步骤，并把这一项明确列为剩余人工步骤。

MCP 配置不需要密码、页面配对链接或桥接令牌。桥接从相同数据目录中的本机私有连接信息接入代理；不要复制该内部文件。升级或回退后应重新运行 `install`，并核对 MCP `command` 是否仍指向当前安装结果返回的 `binary`。

支持 Skill 的客户端在 MCP 连接通过后，可按 [AI 操作 Skill 与 MCP 职责](../user-guide/AI客户端接入.md) 安装同版本的操作 Skill。Skill 不是 MCP 连接的替代品；只支持 MCP 的客户端仍可用当前工具 schema 和服务端最小指引完成受控操作。

## AI 执行顺序

供自动化助手使用的精确命令和停止条件见 [AI 部署执行指南](./自动化部署运行手册.md)。该指南把环境检查、构建、打包、验证、安装、回滚和清理分开，便于工具逐段执行和留下不含秘密的结果摘要。

## 不使用 AI 的人工部署

人工构建需要仓库锁定版本的 Rust、Node.js、pnpm 和 Python。先运行完整检查，再生成并验证安装包：

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm format:web:check
pnpm typecheck
pnpm test
pnpm build
python -m pip install --disable-pip-version-check -r tools/requirements-dev.txt
python -m ruff format --check tools tests
python -m ruff check tools tests
python tools/checks/check_repository.py
python tools/checks/check_project_metadata.py
python -m unittest discover -s tests -v
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
python tools/checks/check_dependency_licenses.py
cargo build --release --locked
```

随后按平台执行打包；Windows 的二进制路径增加 `.exe`：

```sh
python tools/release/package_release.py --binary target/release/secretbridge --output dist/packages-a
python tools/release/package_release.py --binary target/release/secretbridge --output dist/packages-b
python tools/release/verify_reproducible_packages.py dist/packages-a dist/packages-b
python tools/release/test_packaged_delivery.py PATH_TO_ARCHIVE
```

解压已验证的包，在包目录执行 `verify-package` 和 `install`，保存安装结果中的 `binary` 路径，再按上面的“MCP 接入完成条件”配置当前 AI 客户端。准确参数、首次启动、MCP、升级、回退、用户数据保留与卸载行为以[后台运行与安装交付](./安装与服务管理.md)为准。

---

[后台运行与安装交付](./安装与服务管理.md) · [发行物验证与 SBOM](../release/发行物验证与SBOM.md) · [安全模型](../security/安全模型.md)
