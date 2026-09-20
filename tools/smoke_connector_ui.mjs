// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// UI-only fixture. Real authentication and operations are covered by Rust integration tests.
import assert from "node:assert/strict";
import { acceptLegalConsent, launchBrowser } from "./browser_test_support.mjs";
const url = process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799";
const { browser } = await launchBrowser();
try {
  const page = await browser.newPage({
    locale: "zh-CN",
    viewport: { width: 1440, height: 1100 },
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const credentials = [
    {
      id: "synthetic-password",
      name: "测试密码",
      kind: "password",
      secret_state: "available",
    },
    {
      id: "synthetic-token",
      name: "测试令牌",
      kind: "api_token",
      secret_state: "available",
    },
  ];
  const targets = [
    {
      id: "synthetic-target",
      name: "测试连接",
      kind: "http_service",
      environment: "test",
    },
  ];
  const items = [];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body = {};
    if (path === "/api/v1/status")
      body = {
        product: "SecretBridge",
        api_version: "v1",
        mode: "controlled_operations",
        configuration_storage: "sqlite",
        paired: true,
        real_credentials_enabled: true,
      };
    else if (path === "/api/v1/session/pair")
      body = {
        session_token: "synthetic-ui-session",
        token_type: "Bearer",
        expires_in_seconds: 3600,
      };
    else if (path === "/api/v1/session")
      body = {
        authenticated: true,
        mode: "controlled_operations",
        expires_in_seconds: 3600,
      };
    else if (path === "/api/v1/credential-references")
      body = { items: credentials };
    else if (path === "/api/v1/targets") body = { items: targets };
    else if (path === "/api/v1/runs" || path === "/api/v1/approvals")
      body = { items: [] };
    else if (path === "/api/v1/action-templates") {
      if (route.request().method() === "POST") {
        body = {
          ...route.request().postDataJSON(),
          id: `synthetic-${items.length}`,
          version: 1,
          enabled: true,
        };
        items.push(body);
      } else body = { items, execution_enabled: true };
    }
    await route.fulfill({
      status:
        route.request().method() === "POST" &&
        path === "/api/v1/action-templates"
          ? 201
          : 200,
      json: body,
    });
  });
  await page.goto(`${url}/#pair=synthetic-bootstrap`);
  await acceptLegalConsent(page);
  await page.getByText("已配对", { exact: true }).waitFor();
  await page.getByRole("button", { name: "新建操作模板", exact: true }).click();
  await page.getByLabel("模板名称").fill("SFTP UI 验证");
  await page.getByLabel("连接分组").selectOption("synthetic-target");
  await page.getByLabel("内置受控操作").selectOption("command_execution");
  await page.getByLabel("执行方式").selectOption("sftp");
  await page.getByLabel("固定主机地址").fill("example.com");
  await page.getByLabel("登录用户名").fill("operator");
  await page
    .getByLabel("可信主机指纹（SHA256）")
    .fill("SHA256:synthetic-ui-only");
  await page.getByLabel("密码凭据引用").selectOption("synthetic-password");
  await page.getByLabel("传输方向").selectOption("download");
  await page.getByLabel("本机文件绝对路径").fill("/tmp/output.bin");
  await page.getByLabel("远程文件绝对路径").fill("/srv/input.bin");
  await page.getByLabel("允许替换目标文件（每次审批显示）").check();
  assert.equal(await page.getByLabel("远程程序绝对路径").count(), 0);
  await page.getByRole("button", { name: "添加模板", exact: true }).click();
  await page.waitForFunction(
    () =>
      document.body.textContent.includes("SFTP UI 验证") &&
      document.querySelector("input").value === "",
  );
  assert.equal(items.length, 1);
  assert.equal(items[0].command.ssh.transfer.direction, "download");
  assert.equal(items[0].command.ssh.transfer.overwrite, true);
  assert.equal(items[0].command.slots[0].credential_id, "synthetic-password");
  assert.equal(items[0].command.ssh.remote_program, "");

  await page.getByRole("button", { name: "新建操作模板", exact: true }).click();
  await page.getByLabel("模板名称").fill("Git UI 验证");
  await page.getByLabel("连接分组").selectOption("synthetic-target");
  await page.getByLabel("内置受控操作").selectOption("command_execution");
  await page.getByLabel("执行方式").selectOption("git");
  await page.getByLabel("Git 操作").selectOption("fetch");
  await page.getByLabel("Git 程序绝对路径").fill("/usr/bin/git");
  await page.getByLabel("本机仓库目录").fill("/tmp/repo");
  await page
    .getByLabel("远程仓库 URL（不含凭据）")
    .fill("https://example.com/repo.git");
  await page.getByLabel("固定分支").fill("feature/task");
  await page.getByLabel("认证用户名").fill("owner");
  await page.getByLabel("令牌凭据引用").selectOption("synthetic-token");
  await page.getByRole("button", { name: "添加模板", exact: true }).click();
  await page.getByRole("button", { name: /Git UI 验证/ }).waitFor();
  assert.equal(items.length, 2);
  assert.equal(items[1].command.git.operation, "fetch");
  assert.equal(items[1].command.git.branch, "feature/task");
  assert.equal(items[1].command.ssh, null);
  assert.deepEqual(items[1].command.parameters, []);
  assert.equal(items[1].command.slots[0].injection, "protocol");
  await page.getByRole("button", { name: "新建操作模板", exact: true }).click();
  await page.getByLabel("模板名称").fill("Database UI 验证");
  await page.getByLabel("连接分组").selectOption("synthetic-target");
  await page.getByLabel("内置受控操作").selectOption("command_execution");
  await page.getByLabel("执行方式").selectOption("database");
  await page.getByLabel("数据库类型").selectOption("mysql");
  assert.equal(await page.getByLabel("数据库端口").inputValue(), "3306");
  await page.getByLabel("数据库操作").selectOption("query");
  await page.getByLabel("数据库主机").fill("db.example.com");
  await page.getByLabel("数据库名称").fill("operations");
  await page.getByLabel("数据库用户名").fill("reader");
  await page.getByLabel("数据库密码引用").selectOption("synthetic-password");
  await page.getByLabel("只读 SQL", { exact: true }).fill("SELECT 1 AS number");
  await page.getByLabel("允许返回的列（每行一项）").fill("number");
  await page.getByLabel("结果行数上限").fill("25");
  await page.getByRole("button", { name: "添加模板", exact: true }).click();
  await page.getByRole("button", { name: /Database UI 验证/ }).waitFor();
  assert.equal(items.length, 3);
  assert.equal(items[2].command.database.engine, "mysql");
  assert.equal(items[2].command.database.operation, "query");
  assert.equal(items[2].command.database.tls_mode, "verify_full");
  assert.equal(items[2].command.database.max_rows, 25);
  assert.deepEqual(items[2].command.database.columns, ["number"]);
  assert.equal(items[2].command.git, null);
  assert.equal(items[2].command.slots[0].injection, "protocol");

  await page.getByRole("button", { name: "新建操作模板", exact: true }).click();
  await page.getByLabel("模板名称").fill("Telnet UI 验证");
  await page.getByLabel("连接分组").selectOption("synthetic-target");
  await page.getByLabel("内置受控操作").selectOption("command_execution");
  await page.getByLabel("执行方式").selectOption("telnet");
  await page.getByLabel("固定主机地址").fill("legacy.example.com");
  await page.getByLabel("固定登录账号").fill("operator");
  await page.getByLabel("密码凭据引用").selectOption("synthetic-password");
  await page.getByLabel("账号提示符").fill("login: ");
  await page.getByLabel("密码提示符").fill("Password: ");
  await page.getByLabel("命令提示符").fill("legacy> ");
  await page
    .getByLabel("固定命令脚本（每行一条）")
    .fill("show status\nshow version");
  await page.getByLabel("输出上限（字节）").fill("32768");
  await page.getByRole("button", { name: "添加模板", exact: true }).click();
  await page.getByRole("button", { name: /Telnet UI 验证/ }).waitFor();
  assert.equal(items.length, 4);
  assert.equal(items[3].command.telnet.host, "legacy.example.com");
  assert.deepEqual(items[3].command.telnet.commands, [
    "show status",
    "show version",
  ]);
  assert.equal(items[3].command.telnet.max_output_bytes, 32768);
  assert.equal(items[3].command.slots[0].injection, "protocol");
  assert.equal(items[3].command.ssh, null);
  assert.deepEqual(errors, []);
  console.log(
    "Connector UI smoke passed: interactive SFTP, Git, database and Telnet configuration and submitted payloads.",
  );
} finally {
  await browser.close();
}
