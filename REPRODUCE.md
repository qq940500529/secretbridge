# 复跑条件与命令

在被测源码提交的仓库根目录执行，使用 `rust-toolchain.toml`、`.node-version`、`package.json` 和锁文件固定的版本。Python 3.11+。所有数据仅用一次性合成测试数据；不要读取已有用户凭据。

## 浏览器

先完成 `pnpm install --frozen-lockfile` 和 `pnpm build`。

```sh
python tools/acceptance/test_browser_acceptance.py --browser chromium --output REPORT_DIR/browser-report.json
```

本轮使用系统 Chromium 151.0.7922.173，因锁定浏览器下载受到网络策略限制。通过仓库支持的 `PLAYWRIGHT_MODULE` 提供包装模块，复用已安装 Playwright API，仅将 chromium.launch 的 executablePath 指向系统 Chromium。截图捕获还遮盖了账号、地址及秘密字段；截图遮盖不改变功能断言或业务状态。

截图参数为 `SECRETBRIDGE_UI_SCREENSHOT`、`SECRETBRIDGE_RESOURCE_SCREENSHOT`，输出放在仓库外。SSH 脚本也自动保存桌面/窄屏截图。报告的 200% 是 CSS zoom，不是 OS 缩放。

## 真实数据库

需要 Docker、OpenSSL 和 Rust。运行脚本前把 `tools/acceptance/test_database_connectors.sh` 复制到仓库外，在副本中做精确替换：

```text
database_task::tests::real_
→ adapters::executors::database::tests::real_
```

在副本的 Cargo 命令中加 `--locked`。从仓库根目录运行副本。它创建 loopback-only PostgreSQL 17 / MySQL 8.4 容器、短期证书和合成认证，运行 11 项数据库测试及 1 项 MCP 测试，并通过 EXIT trap 清理自己的资源。不要输出测试认证值，不要关闭 TLS 认证或更改测试断言。

## 稳定性与同目录 4,000 次合成操作

在仓库外副本中，将 `tools/acceptance/test_stability_acceptance.py` 的旧过滤条件精确替换：

```text
catalog::tests::same_directory_soak_records_resource_trend_and_restores_history
→ adapters::persistence::tests::same_directory_soak_records_resource_trend_and_restores_history
```

副本的 ROOT 显式指向被测仓库；不要改应用或测试文件。然后运行：

```sh
python STABILITY_RUNNER_COPY --profile soak --iterations 3 --report REPORT_DIR/stability-report.json
```

本轮没有加 `--with-databases`，因为数据库已独立执行；不要把该字段 false 当作没有执行独立数据库验收。三个并行取消阶段每轮执行 1 项测试；同目录阶段由 runner 在同一个自建临时目录中执行测试两次，每次增加 2,000 次合成审批/运行。

检查非零测试数量、退出码、6 条 SOAK_METRIC、最终 4,000 条计数与 passed=true。原始旧过滤条件输出 0 tests；原长稳 runner 会因指标不足报 metrics_incomplete，不能称为成功。

## 限制

浏览器模拟 API、协议夹具、真实数据库、真实 Bash PTY、持久化重开及 Unix IPC 自动化各自提供不同证据。均不替代真实桌面 PIN/审批、原生凭据库提示、OS 通知、跨账号权限、全系统重启、数日驻留或 Windows/macOS 设备验收。
