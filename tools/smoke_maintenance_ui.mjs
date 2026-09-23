// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// UI-only synthetic fixture: no credential-store writes or business connections.
import assert from "node:assert/strict";
import { acceptLegalConsent, launchBrowser } from "./browser_test_support.mjs";
const { browser } = await launchBrowser();
try {
  const page = await browser.newPage({
    locale: "zh-CN",
    reducedMotion: "reduce",
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const bundle = {
    format: "secretbridge-configuration",
    format_version: 1,
    exported_at_unix_ms: 1,
    credentials: [],
    connections: [],
    templates: [],
  };
  const report = {
    digest: "synthetic-digest",
    credentials: 1,
    connections: 1,
    templates: 1,
    replayed: false,
    credentials_need_configuration: true,
  };
  let commitCount = 0;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    let status = 200,
      body = {};
    if (path === "/api/v1/ai-conversations") body = { items: [] };
    else if (path === "/api/v1/notification-settings")
      body = { channel: "browser" };
    else if (path.endsWith("/status"))
      body = {
        product: "SecretBridge",
        api_version: "v1",
        mode: "controlled_operations",
        configuration_storage: "sqlite",
        real_credentials_enabled: true,
        paired: true,
      };
    else if (path.endsWith("/session/pair"))
      body = {
        session_token: "synthetic-session",
        token_type: "Bearer",
        expires_in_seconds: 3600,
      };
    else if (path.endsWith("/session"))
      body = { authenticated: true, expires_in_seconds: 3600 };
    else if (path.endsWith("/session/methods"))
      body = {
        pin_enabled: false,
        totp_enabled: false,
        pairing_link_enabled: true,
      };
    else if (path.endsWith("/maintenance/configuration")) body = bundle;
    else if (path.endsWith("/configuration/preview")) {
      assert.deepEqual(request.postDataJSON(), bundle);
      body = report;
    } else if (path.endsWith("/configuration/import")) {
      assert.deepEqual(request.postDataJSON(), {
        bundle,
        expected_digest: report.digest,
      });
      commitCount++;
      if (commitCount === 1) {
        status = 500;
        body = { code: "internal_error" };
      } else body = { ...report, replayed: true };
    } else if (path.endsWith("/backup/preview"))
      body = {
        schema_version: 14,
        restore_schema_version: 16,
        integrity_ok: true,
        credentials: 1,
        connections: 1,
        templates: 1,
        runs: 2,
        requires_secret_reentry: true,
        restores_authorizations: false,
      };
    else if (path.endsWith("/maintenance/backup")) {
      await route.fulfill({
        status: 200,
        contentType: "application/vnd.sqlite3",
        body: Buffer.from("SQLite format 3\0synthetic"),
      });
      return;
    } else if (path.endsWith("/maintenance/diagnostics"))
      body = {
        format: "secretbridge-diagnostics",
        diagnostic_schema_version: 3,
        version: "0.1.0-test",
        platform: "windows",
        bridge_schema_version: 2,
        authentication_mode: "totp",
        generated_at_unix_ms: Date.now(),
        schema_version: 22,
        storage: "sqlite",
        credentials: 1,
        configured_credentials: 1,
        connections: 1,
        templates: 1,
        pending_authorizations: 0,
        failed_runs: 1,
        terminal_sessions: 0,
        run_states: { failed: 1 },
        failure_stages: { connection: 1 },
        error_codes: { ssh_connection_failed: 1 },
        terminal_states: { exited: 1 },
        stale_terminal_references: 0,
        run_failures: [
          {
            code: "ssh_connection_failed",
            stage: "connection",
            occurrences: 1,
            first_at_unix_ms: 100,
            last_at_unix_ms: 200,
          },
        ],
        mcp_failures: [
          {
            code: "terminal_busy",
            stage: "terminal_lease",
            occurrences: 2,
            first_at_unix_ms: 100,
            last_at_unix_ms: 200,
          },
        ],
      };
    else body = { items: [], storage: "sqlite" };
    await route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  });
  await page.goto(
    (process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799") +
      "/#pair=synthetic-bootstrap",
  );
  await acceptLegalConsent(page);
  const nav = (name) =>
    page
      .locator("nav[aria-label='主导航']")
      .getByRole("button", { name, exact: true });
  await nav("设置").click();
  await page.getByRole("heading", { name: "数据维护" }).waitFor();
  assert.equal(
    await page
      .getByRole("button", { name: "检查导入", exact: true })
      .isDisabled(),
    true,
  );
  let download = page.waitForEvent("download");
  await page.getByRole("button", { name: "导出配置", exact: true }).click();
  assert.equal(
    (await download).suggestedFilename(),
    "secretbridge-configuration.json",
  );
  await page.getByLabel("选择配置文件（最多 8 MiB）").setInputFiles({
    name: "configuration.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(bundle)),
  });
  await page.getByRole("button", { name: "检查导入", exact: true }).click();
  await page.getByRole("button", { name: "确认导入", exact: true }).click();
  await page.getByRole("alert").waitFor();
  await page.getByRole("button", { name: "确认导入", exact: true }).click();
  await page.getByText("此文件已导入，未重复新增。", { exact: true }).waitFor();
  assert.equal(commitCount, 2);
  await page.getByRole("button", { name: "备份与恢复", exact: true }).click();
  download = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "下载 SQLite 备份", exact: true })
    .click();
  assert.equal(
    (await download).suggestedFilename(),
    "secretbridge-backup.sqlite3",
  );
  await page.getByLabel("选择备份进行只读预检（最多 256 MiB）").setInputFiles({
    name: "backup.sqlite3",
    mimeType: "application/vnd.sqlite3",
    buffer: Buffer.from("SQLite format 3\0synthetic"),
  });
  await page.getByRole("button", { name: "检查备份", exact: true }).click();
  await page.getByText(/完整性检查通过/).waitFor();
  assert.equal(
    await page.getByRole("button", { name: "立即恢复", exact: true }).count(),
    0,
  );
  for (const width of [720, 390, 320]) {
    await page.setViewportSize({ width, height: 850 });
    await page.evaluate(
      () =>
        new Promise((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(resolve)),
        ),
    );
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      true,
      `no overflow ${width}`,
    );
  }
  if (process.env.SECRETBRIDGE_UI_SCREENSHOT)
    await page.screenshot({
      path: process.env.SECRETBRIDGE_UI_SCREENSHOT,
      fullPage: true,
    });
  await page.getByRole("button", { name: "诊断", exact: true }).click();
  await page.getByRole("button", { name: "预览诊断信息" }).click();
  await page.getByText("connection 1", { exact: false }).waitFor();
  await page
    .getByText("terminal_lease / terminal_busy", { exact: false })
    .waitFor();
  download = page.waitForEvent("download");
  await page.getByRole("button", { name: "下载诊断信息", exact: true }).click();
  assert.equal(
    (await download).suggestedFilename(),
    "secretbridge-diagnostics.json",
  );
  await page.getByRole("button", { name: "切换到英文" }).click();
  await page
    .getByRole("heading", { name: "Data maintenance", exact: true })
    .waitFor();
  assert.deepEqual(errors, []);
  console.log(
    "Maintenance UI smoke passed: exports, checked import, uncertain-result retry/replay, binary backup, read-only restore preflight, diagnostics, language and narrow layouts.",
  );
} finally {
  await browser.close();
}
