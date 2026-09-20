# AI 辅助部署

[项目首页](../README.zh-CN.md) / [文档中心](README.md) / AI 辅助部署

SecretBridge 涉及原生程序、Web 资源、系统凭据库和用户级后台启动。首次试用建议让**运行在本机、能够展示命令并等待确认的 AI 编程助手**代为检查环境、构建、安装和验证。这样可以减少漏装依赖和复制错误，但不会改变系统权限边界：AI 只能使用你明确允许的权限，也不能替你判断一个真实凭据是否适合交给当前操作系统账号。

仓库目前没有公开 Release。以下流程用于从可信源码提交构建开发候选包；不要把分支快照当作正式发行版。

## 开始前

- 只在个人测试机或明确获准的设备上操作；先提交或备份现有工作。
- 使用本机 AI 助手，不要把 Webhook、Token、密码、私钥、数据库地址或未脱敏日志发送给远程模型。
- AI 必须先读本页、[后台运行与安装交付](后台运行与安装交付.md)、[安全模型](安全模型与验收.md)和根目录 `AGENTS.md`。
- 要求 AI 先报告仓库提交、工作区状态、平台、架构和工具版本，再给出计划；每个需要管理员权限或会覆盖安装的操作都单独确认。
- 验收只使用一次性合成凭据。不得关闭系统安全提示、降低文件权限或把秘密写进命令行、环境变量、脚本和日志。

## 自动执行提示词

复制以下内容给位于 SecretBridge 仓库根目录的本机 AI 助手：

```text
请按照 AGENTS.md、docs/AI辅助部署.md 和 docs/后台运行与安装交付.md，在当前机器为我构建并安装 SecretBridge 开发候选包。

要求：
1. 先只读检查 Git 提交、工作区状态、操作系统、架构及 Rust 1.98.0、Node 24.21.0、pnpm 11.23.0、Python 版本；不要自动清理我的改动。
2. 先展示执行计划、安装目录、数据目录、将创建的后台启动项和回滚方法。需要 sudo/管理员权限或修改仓库外文件时暂停并说明原因。
3. 使用锁文件构建 Web 与 release 原生程序，运行仓库检查、测试、依赖许可和漏洞检查；任何门禁失败都停止，不跳过测试、不降低安全设置。
4. 使用 tools/package_release.py 生成包，验证摘要、SBOM、对应源码和可复现性，再用实际包执行隔离生命周期验收。
5. 安装前再次显示包版本、提交和目标目录。安装后检查 status、回环监听、浏览器配对页面和停止/重启；只使用一次性合成凭据做验收。
6. 不读取或回显任何真实秘密，不把凭据放入 argv、环境变量、脚本、文件、日志或对话。输出中隐藏用户名、主机名、个人路径和内网地址。
7. 失败时保留原安装并给出恢复步骤。结束时列出通过项、受限项、安装位置、数据保留规则和卸载命令。
```

AI 应在执行前让你看到将运行的命令。提示词不是授权 AI 扩大范围、删除现有数据、修改防火墙或安装完整桌面环境。

## 逐步指导提示词

如果你希望自己输入每条命令，让 AI 只负责解释和核对，可使用：

```text
请读取 AGENTS.md、docs/AI辅助部署.md 和 docs/后台运行与安装交付.md，逐步指导我从源码构建、验证并安装 SecretBridge。每次只给一组可以审阅的命令，说明预期输出、风险和回滚方式，等我贴出脱敏结果后再继续。不要让我粘贴密码、Token、私钥、用户名、主机名、用户目录或内网地址；遇到这些信息时先教我脱敏。任何测试或完整性检查失败都先诊断，不要建议跳过、关闭安全功能或强制安装。
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
