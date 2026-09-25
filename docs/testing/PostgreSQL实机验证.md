# PostgreSQL 实机验证

[项目首页](../../README.zh-CN.md) / [文档中心](../README.md) / PostgreSQL 实机验证

本文说明如何在隔离的临时 PostgreSQL 上复现 SecretBridge 固定只读适配器的真实网络、TLS 和认证验证。它补充自动化替换执行器测试，不代表其他平台或业务环境已经验证。

> [!IMPORTANT]
> 只使用临时、非生产、最低权限身份和短期证书。测试密码、私钥、数据库目录及原始服务日志不得提交到仓库。完成后停止实例并删除全部临时材料。

## 2026-09-14 本机证据

验证在 Windows 本机隔离实例上完成，使用 PostgreSQL 18.6 x64 二进制归档、仅监听 `127.0.0.1` 的临时端口、SCRAM-SHA-256 和两天有效期的测试 CA。应用身份只有数据库 `CONNECT` 权限，没有超级用户、建库、建角色、继承、复制、绕过行级安全或 `public` schema 创建权限。

| 场景 | 预期 | 结果 |
|---|---|---|
| 有效短期凭据和指定 CA | 固定只读探针成功 | 通过 |
| 凭据轮换后的旧密码 | 认证失败，只返回固定失败状态 | 通过 |
| 未提供测试 CA | 私有证书链不受信，连接失败 | 通过 |
| 使用证书未覆盖的 IP 地址 | 主机名验证失败 | 通过 |
| 指向未监听端口 | 网络连接失败 | 通过 |
| TLS 会话和最低权限 | TLS 1.3；危险角色属性均关闭 | 通过 |

测试直接运行生产 PostgreSQL 适配器，而不是模拟执行器。成功路径仍只在可串行化只读事务中执行固定 `SELECT 1::INTEGER` 并主动回滚；失败路径不向调用方返回数据库原始错误。

尚未由本次本机证据覆盖：DNS 超时、执行中断网、服务执行中重启、审批撤销与活动连接联动、Linux／macOS 原生凭据库、三平台安装身份隔离，以及外部目标负责人授权和独立权限复核。这些项目不能根据本页结果标记为完成。

## 私有 CA 配置

默认情况下，SecretBridge 使用操作系统平台信任根。测试或企业环境使用私有 CA 时，可在启动后台服务前设置 `SECRETBRIDGE_POSTGRES_CA_CERT`，值为 CA PEM 文件的绝对路径。

```powershell
$env:SECRETBRIDGE_POSTGRES_CA_CERT = 'C:\absolute\path\to\postgres-ca.pem'
secretbridge.exe
```

```sh
export SECRETBRIDGE_POSTGRES_CA_CERT=/absolute/path/to/postgres-ca.pem
./secretbridge
```

安全约束：

- 路径必须为绝对路径，目标必须是直接的普通文件，符号链接会被拒绝；
- 文件不能为空且最大为 64 KiB；无效路径或无效 PEM 映射为“配置无效”；
- 指定私有 CA 不会关闭证书链或主机名验证，也不会启用明文连接；
- 该设置是后台服务进程级信任包，同一实例目前不能为不同目标选择不同私有 CA；
- CA 证书通常不是秘密，但其文件仍应由部署管理员维护，不应和私钥放在同一个公开目录。

> [!NOTE]
> 私有 CA 文件只用于构造 TLS 验证器。数据库密码仍由操作系统凭据库内部取得，不会放入连接串、命令参数或子进程环境变量。

## 复现适配器测试

维护者先自行建立获准的临时实例、短期测试 CA 和已完成一次密码轮换的最低权限角色，再为测试进程提供以下变量。不要把实际值写入脚本、CI 日志或版本库。

| 环境变量 | 用途 |
|---|---|
| `SECRETBRIDGE_POSTGRES_CA_CERT` | 生产适配器读取的私有 CA 绝对路径 |
| `SECRETBRIDGE_TEST_POSTGRES_HOST` | 与证书 SAN 匹配的成功主机名 |
| `SECRETBRIDGE_TEST_POSTGRES_MISMATCH_HOST` | 可到达服务、但不在证书 SAN 内的主机名或 IP |
| `SECRETBRIDGE_TEST_POSTGRES_PORT` | 临时实例端口 |
| `SECRETBRIDGE_TEST_POSTGRES_UNAVAILABLE_PORT` | 确认没有服务监听的端口 |
| `SECRETBRIDGE_TEST_POSTGRES_DATABASE` | 临时测试数据库 |
| `SECRETBRIDGE_TEST_POSTGRES_USERNAME` | 最低权限测试角色 |
| `SECRETBRIDGE_TEST_POSTGRES_PASSWORD` | 轮换后的当前短期密码 |
| `SECRETBRIDGE_TEST_POSTGRES_STALE_PASSWORD` | 轮换前、应被拒绝的旧密码 |
| `SECRETBRIDGE_TEST_POSTGRES_CA_CERT` | 测试辅助路径读取的同一 CA PEM |

```sh
cargo test -p secretbridge \
  postgres::tests::native_adapter_verifies_real_tls_authentication_and_hostname_failures \
  -- --ignored --exact --nocapture
```

该测试默认标记为 `ignored`，因此普通开发和公开 CI 不会尝试连接外部数据库。只有明确准备好隔离实例并在当前进程提供完整变量时才应执行。

## 清理检查

1. 停止临时 PostgreSQL，确认没有残留服务或监听端口；
2. 删除测试数据库、测试角色、密码文件、证书私钥、CA、数据目录和服务日志；
3. 清除当前终端中的测试环境变量；
4. 确认没有把临时 CA 导入操作系统信任库；如果导入过，应按精确指纹删除并复核；
5. 运行仓库敏感信息检查并确认 Git 差异只含代码、文档和非秘密结果摘要。

---

[使用指南](../user-guide/使用指南.md) · [安全模型与验收](../security/安全模型.md) · [开源版路线图](../../ROADMAP.md)
