// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// UI-only fixture: no OS credential writes or business connections.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)(
  process.env.PLAYWRIGHT_MODULE || "playwright",
);
const browser = await chromium.launch({
  headless: true,
  channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
});
try {
  const page = await browser.newPage({
    locale: "zh-CN",
    reducedMotion: "reduce",
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const credentials = [],
    targets = [],
    tasks = [],
    approvals = [],
    runs = [];
  const now = Date.now();
  const metadata = {
    version: 1,
    created_at_unix_ms: now,
    updated_at_unix_ms: now,
  };
  let failTaskSave = true;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname,
      method = request.method();
    const input = ["POST", "PUT"].includes(method)
      ? request.postDataJSON()
      : {};
    let body = {},
      status = 200;
    if (path === "/api/v1/status")
      body = {
        product: "SecretBridge",
        api_version: "v1",
        mode: "controlled_operations",
        configuration_storage: "sqlite",
        real_credentials_enabled: true,
        paired: true,
      };
    else if (path === "/api/v1/session/pair")
      body = {
        session_token: "synthetic-session",
        token_type: "Bearer",
        expires_in_seconds: 3600,
      };
    else if (path === "/api/v1/session" && method === "DELETE") {
      await route.fulfill({ status: 204 });
      return;
    } else if (path === "/api/v1/session")
      body = { authenticated: true, expires_in_seconds: 3600 };
    else if (path === "/api/v1/credential-references") {
      if (method === "POST") {
        body = {
          ...metadata,
          ...input,
          id: "credential",
          purpose: input.purpose ?? null,
          secret_state: "not_configured",
        };
        credentials.push(body);
        status = 201;
      } else body = { items: credentials, storage: "sqlite" };
    } else if (path === "/api/v1/credential-references/credential/secret") {
      assert.equal(input.secret, "synthetic-secret-only");
      body = { ...credentials[0], version: 2, secret_state: "available" };
      credentials[0] = body;
    } else if (path === "/api/v1/targets") {
      if (method === "POST") {
        body = {
          ...metadata,
          ...input,
          id: "connection",
          postgres: input.postgres ?? null,
        };
        targets.push(body);
        status = 201;
      } else body = { items: targets, storage: "sqlite" };
    } else if (path === "/api/v1/action-templates") {
      if (method === "POST" && failTaskSave) {
        failTaskSave = false;
        status = 503;
        body = { code: "temporarily_unavailable" };
      } else if (method === "POST") {
        body = { ...metadata, ...input, id: "task", enabled: true };
        tasks.push(body);
        status = 201;
      } else body = { items: tasks };
    } else if (path === "/api/v1/action-templates/task/policy-evaluation")
      body = {
        decision: "eligible_for_approval",
        requirements: [],
        policy_version: "v1",
        action_template_version: 1,
        target_version: 1,
      };
    else if (path === "/api/v1/approvals") {
      if (method === "POST") {
        body = {
          ...metadata,
          ...input,
          id: "approval",
          action_template_version: 1,
          target_id: "connection",
          target_version: 1,
          operation: "command_execution",
          result_scope: "sanitized_output",
          parameters: input.parameters ?? {},
          state: "pending",
          expires_at_unix_ms: now + 3600000,
        };
        approvals.push(body);
        status = 201;
      } else body = { items: approvals };
    } else if (path === "/api/v1/approvals/approval/approve") {
      body = { ...approvals[0], state: "approved", version: 2 };
      approvals[0] = body;
      approvals.push(
        { ...body, id: "expired-approval", expires_at_unix_ms: now - 1000 },
        {
          ...body,
          id: "unrelated-approval",
          action_template_id: "another-task",
        },
      );
    } else if (path === "/api/v1/runs") {
      if (method === "POST") {
        body = {
          ...metadata,
          id: "run",
          approval_id: "approval",
          action_template_id: "task",
          target_id: "connection",
          target_version: 1,
          operation: "command_execution",
          state: "succeeded",
          result_status: "command_ok",
          started_at_unix_ms: now,
          finished_at_unix_ms: now + 100,
          result_scope: "sanitized_output",
        };
        runs.push(body);
        body = { run: body, replayed: false };
        status = 201;
      } else body = { items: runs };
    } else if (path === "/api/v1/runs/run/output")
      body = {
        items: [
          { sequence: 1, stream: "stdout", text: "synthetic-filtered-result" },
        ],
        next_cursor: 1,
        oldest_cursor: 0,
        truncated: false,
        has_more: false,
        exit_code: null,
        state: "succeeded",
      };
    else if (path.endsWith("/events") || path === "/api/v1/safe-events")
      body = { items: [] };
    await route.fulfill({ status, json: body });
  });
  await page.goto(
    `${process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799"}/#pair=synthetic-bootstrap`,
  );
  await page.getByText("已配对", { exact: true }).waitFor();
  assert.equal(
    await page
      .getByRole("navigation", { name: "主导航" })
      .getByRole("button")
      .count(),
    6,
  );
  const nav = (name) =>
    page
      .getByRole("navigation", { name: "主导航" })
      .getByRole("button", { name, exact: true });
  await nav("凭据").click();
  const add = page.getByRole("button", { name: "添加凭据引用", exact: true });
  await add.click();
  for (let index = 0; index < 10; index++) {
    await page.keyboard.press(index % 2 ? "Shift+Tab" : "Tab");
    assert.equal(
      await page
        .locator("dialog")
        .evaluate((dialog) => dialog.contains(document.activeElement)),
      true,
    );
  }
  assert.equal(
    await page
      .locator("dialog")
      .evaluate((dialog) => dialog.contains(document.activeElement)),
    true,
  );
  await page.keyboard.press("Escape");
  assert.equal(
    await add.evaluate((button) => document.activeElement === button),
    true,
  );
  await add.click();
  await page.getByLabel("引用名称").fill("工作台测试密码");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await page.getByLabel("输入新秘密值").fill("synthetic-secret-only");
  await page
    .getByRole("button", { name: "保存到系统凭据库", exact: true })
    .click();
  await page.getByText("已安全保存", { exact: true }).waitFor();
  assert.equal(await page.getByLabel("输入新秘密值").inputValue(), "");
  await nav("连接").click();
  await page.getByRole("button", { name: "新建连接", exact: true }).click();
  await page.getByLabel("连接名称").fill("工作台测试连接");
  await page.getByLabel("连接类型").selectOption("http_service");
  await page.getByLabel("关联凭据引用（可选）").selectOption("credential");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await page.getByRole("button", { name: "新建任务", exact: true }).click();
  await page.getByRole("button", { name: "新建操作模板", exact: true }).click();
  assert.equal(await page.getByLabel("连接分组").inputValue(), "connection");
  await page.getByLabel("模板名称").fill("工作台测试任务");
  await page.getByLabel("内置受控操作").selectOption("command_execution");
  await page.getByLabel("执行方式").selectOption("http");
  await page
    .getByLabel("固定请求地址（不含查询串、账户或密码）")
    .fill("https://example.com/status");
  const slots = page
    .locator("section")
    .filter({
      has: page.getByRole("heading", { name: "认证凭据插槽", exact: true }),
    })
    .last();
  await slots.getByRole("button", { name: "添加一行", exact: true }).click();
  await slots.getByLabel("凭据引用").selectOption("credential");
  const headers = page
    .locator("section")
    .filter({
      has: page.getByRole("heading", {
        name: "请求头（如 Authorization）",
        exact: true,
      }),
    })
    .last();
  await headers.getByRole("button", { name: "添加一行", exact: true }).click();
  await headers.getByLabel("字段名", { exact: true }).fill("Authorization");
  await headers.getByLabel("来源").selectOption("credential");
  await headers.getByLabel("插槽名").selectOption("secret_1");
  await headers.getByLabel("前缀（可用 Bearer 加空格）").fill("Bearer ");
  await page.getByRole("button", { name: "添加模板", exact: true }).click();
  await page.getByRole("dialog").getByRole("alert").waitFor();
  assert.equal(
    await page.getByLabel("模板名称").inputValue(),
    "工作台测试任务",
  );
  await page.getByRole("button", { name: "添加模板", exact: true }).click();
  await page.getByRole("button", { name: "申请授权", exact: true }).click();
  assert.equal(
    await page.getByRole("dialog").getByLabel("操作模板").inputValue(),
    "task",
  );
  await page.getByRole("button", { name: "提交审批", exact: true }).click();
  await page.getByRole("button", { name: "批准", exact: true }).click();
  await page.getByRole("button", { name: "执行与结果", exact: true }).click();
  await page.getByRole("button", { name: "新建运行请求", exact: true }).click();
  assert.equal(
    await page
      .getByRole("dialog")
      .getByLabel("已批准的授权")
      .locator("option")
      .count(),
    2,
  );
  await page.getByRole("button", { name: "启动受控运行", exact: true }).click();
  await page.getByText("synthetic-filtered-result", { exact: true }).waitFor();
  assert.equal(runs.length, 1);
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].command.slots[0].credential_id, "credential");
  await nav("历史").click();
  assert.equal(
    await page
      .getByRole("button", { name: "新建运行请求", exact: true })
      .count(),
    0,
  );
  await nav("连接").click();
  await page.getByRole("button", { name: /工作台测试任务 · 完成/ }).waitFor();
  await page.getByLabel("搜索记录").fill("不存在");
  await page.getByText("没有匹配记录", { exact: true }).waitFor();
  await page.getByLabel("搜索记录").fill("");
  await page.getByRole("button", { name: "切换到英文" }).click();
  await page
    .getByRole("heading", { name: "Connections", exact: true })
    .waitFor();
  await page.getByRole("button", { name: "Switch to Chinese" }).click();
  if (process.env.SECRETBRIDGE_UI_SCREENSHOT)
    await page.screenshot({
      path: process.env.SECRETBRIDGE_UI_SCREENSHOT.replace(
        /\.png$/,
        "-desktop.png",
      ),
      fullPage: true,
    });
  for (const width of [720, 390, 320]) {
    await page.setViewportSize({ width, height: 850 });
    await page.evaluate(async () => {
      await document.fonts.ready;
      await new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(resolve)),
      );
    });
    if (process.env.SECRETBRIDGE_UI_SCREENSHOT && width === 320)
      await page.screenshot({
        path: process.env.SECRETBRIDGE_UI_SCREENSHOT,
        fullPage: true,
      });
    const overflow = await page.evaluate(() =>
      [...document.querySelectorAll("body *")]
        .filter((element) => {
          const rect = element.getBoundingClientRect();
          return rect.width > 0 && rect.right > innerWidth + 1;
        })
        .slice(0, 12)
        .map((element) => ({
          tag: element.tagName,
          classes: element.className,
          right: element.getBoundingClientRect().right,
        })),
    );
    if (overflow.length)
      console.log("Overflow details:", JSON.stringify(overflow));
    assert.equal(
      overflow.some((item) => item.tag === "BUTTON"),
      false,
      `No clipped action buttons at ${width}px`,
    );
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
      true,
      `No page overflow at ${width}px`,
    );
  }
  if (process.env.SECRETBRIDGE_UI_SCREENSHOT)
    await page.screenshot({
      path: process.env.SECRETBRIDGE_UI_SCREENSHOT,
      fullPage: true,
    });
  await nav("设置").click();
  await page
    .getByRole("button", { name: "解除当前页面配对", exact: true })
    .click();
  await nav("凭据").click();
  await page.getByRole("heading", { name: "请先配对本机服务" }).waitFor();
  assert.deepEqual(errors, []);
  console.log(
    "Workbench UI smoke passed: six sections, credential/connection/task/authorization/run/result workflow, retry, focus, search, language, narrow layouts and unpairing.",
  );
} finally {
  await browser.close();
}
