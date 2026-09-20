# AI 辅助部署

[项目首页](../README.zh-CN.md) / [文档中心](README.md) / AI 辅助部署

SecretBridge 涉及原生程序、Web 资源、系统凭据库和用户级后台启动。首次试用建议让**运行在本机、能够展示命令并等待确认的 AI 编程助手**优先安装公开发行包；没有适用发行包时再从主分支构建。这样可以减少漏装依赖和复制错误，但不会改变系统权限边界：AI 只能使用你明确允许的权限，也不能替你判断一个真实凭据是否适合交给当前操作系统账号。

仓库目前没有公开 Release，因此当前会自动使用主分支源码。未来发布 Release 后，同一提示词会优先使用与当前平台匹配的发行包；主分支构建仍属于开发候选版。

普通使用者只需复制“自动执行提示词”，不需要判断平台安装包、Git 分支、工具链或构建命令。助手负责选择路径并验证服务，只在系统授权或可能影响已有文件时请求确认。

## 开始前

- 只在个人测试机或明确获准的设备上操作；先提交或备份现有工作。
- 使用本机 AI 助手，不要把 Webhook、Token、密码、私钥、数据库地址或未脱敏日志发送给远程模型。
- AI 必须先读本页、[后台运行与安装交付](后台运行与安装交付.md)、[安全模型](安全模型与验收.md)和根目录 `AGENTS.md`。
- 要求 AI 先报告仓库提交、工作区状态、平台、架构和工具版本，再给出计划；每个需要管理员权限或会覆盖安装的操作都单独确认。
- 验收只使用一次性合成凭据。不得关闭系统安全提示、降低文件权限或把秘密写进命令行、环境变量、脚本和日志。

## 自动执行提示词

以下提示词可直接用于任意文件夹或全新对话，不需要预先克隆仓库。把它交给能够在本机执行命令并逐项请求权限的 AI 助手：

```text
请在当前机器部署 SecretBridge，仓库地址：https://github.com/qq940500529/secretbridge

要求：
1. 可以从任意目录开始，不要假设仓库已经下载。先检查 GitHub 最新 Release；如果有适合当前系统和架构的安装包，下载它并校验随附摘要及包元数据后安装。
2. 如果没有适用 Release，把最新 main 分支克隆到新建的非敏感目录。完整阅读 AGENTS.md、SECURITY.md、docs/AI辅助部署.md、docs/AI部署执行指南.md 和 docs/后台运行与安装交付.md，再使用锁定工具版本与依赖构建、校验并安装。
3. 不要清理已有改动。需要 sudo/管理员权限或修改工作目录以外文件时，先显示原因、目标和命令并等待同意。任何下载、校验、构建或安装失败都停止排查，不跳过检查、不降低安全设置。
4. 不读取或回显真实秘密，不把凭据放入 argv、环境变量、脚本、文件、日志或对话；共享结果时隐藏用户名、主机名、个人路径和内网地址。
5. 安装后启动 SecretBridge，确认 status 正常且只监听本机回环地址。结束时报告安装的版本或提交、安装位置、数据保留规则和卸载命令。
```

AI 应在执行前让你看到会修改机器的命令。提示词不是授权 AI 扩大范围、删除现有数据、修改防火墙或安装完整桌面环境。普通部署只需确认服务正常；完整测试矩阵和发行验收属于维护者流程。

## 逐步指导提示词

如果你希望自己输入每条命令，让 AI 只负责解释和核对，可使用：

```text
请逐步指导我部署 SecretBridge，仓库地址：https://github.com/qq940500529/secretbridge。可以从任意目录开始；先查找适合当前平台的最新 GitHub Release，存在时校验并安装发行包，不存在时再指导我克隆最新 main、阅读部署文档并按锁定版本构建安装。每次只给一组可以审阅的命令，说明预期输出和风险，等我贴出脱敏结果后再继续。安装后确认 status 正常且只监听本机回环地址。不要让我粘贴密码、Token、私钥或机器身份信息；任何下载、校验、构建或安装失败都先诊断，不要建议跳过或关闭安全功能。
```

## AI 执行顺序

供自动化助手使用的精确命令和停止条件见 [AI 部署执行指南](AI部署执行指南.md)。该指南把环境检查、构建、打包、验证、安装、回滚和清理分开，便于工具逐段执行和留下不含秘密的结果摘要。

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
python tools/check_repository.py
python tools/check_project_metadata.py
python -m unittest discover -s tests -v
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
python tools/check_dependency_licenses.py
cargo build --release --locked
```

随后按平台执行打包；Windows 的二进制路径增加 `.exe`：

```sh
python tools/package_release.py --binary target/release/secretbridge-server --output dist/packages-a
python tools/package_release.py --binary target/release/secretbridge-server --output dist/packages-b
python tools/verify_reproducible_packages.py dist/packages-a dist/packages-b
python tools/test_packaged_delivery.py PATH_TO_ARCHIVE
```

解压已验证的包，在包目录执行 `verify-package` 和 `install`。准确参数、首次启动、升级、回退、用户数据保留与卸载行为以[后台运行与安装交付](后台运行与安装交付.md)为准。

---

[后台运行与安装交付](后台运行与安装交付.md) · [发行物验证与 SBOM](发行物验证与SBOM.md) · [安全模型](安全模型与验收.md)
