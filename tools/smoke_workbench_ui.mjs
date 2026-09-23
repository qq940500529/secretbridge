// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// UI-only fixture: no OS credential writes or business connections.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import {
  acceptLegalConsent,
  assertNoSeriousAccessibilityViolations,
  launchBrowser,
} from "./browser_test_support.mjs";

const require = createRequire(import.meta.url);
const AxeBuilder = require("@axe-core/playwright").default;
const { browser, name: browserName } = await launchBrowser();
try {
  const context = await browser.newContext({
    locale: "zh-CN",
    reducedMotion: "reduce",
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
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
  const conversation = {
    ...metadata,
    id: "11111111-1111-4111-8111-111111111111",
    summary: "合成会话摘要",
    approval_policy: "every_task",
    grant_expires_at_unix_ms: null,
  };
  let notificationChannel = "browser";
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
    if (path === "/api/v1/ai-conversations") body = { items: [conversation] };
    else if (path === `/api/v1/ai-conversations/${conversation.id}/policy`) {
      if (input.approval_policy === "conversation_once")
        assert.equal(
          input.risk_acknowledgement,
          "allow_all_operations_in_this_ai_conversation",
        );
      conversation.approval_policy = input.approval_policy;
      conversation.grant_expires_at_unix_ms =
        input.approval_policy === "conversation_once" ? now + 3600000 : null;
      conversation.version++;
      body = conversation;
    } else if (path === "/api/v1/notification-settings") {
      if (method === "PUT") notificationChannel = input.channel;
      body = { channel: notificationChannel };
    } else if (path === "/api/v1/status")
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
    else if (path === "/api/v1/session/methods")
      body = {
        pin_enabled: false,
        totp_enabled: false,
        pairing_link_enabled: true,
      };
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
    } else if (path === "/api/v1/action-templates/task") body = tasks[0];
    else if (path === "/api/v1/action-templates/another-task") {
      status = 404;
      body = { code: "not_found" };
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
          conversation_id: conversation.id,
          preauthorized: false,
          expires_at_unix_ms: now + 3600000,
        };
        approvals.push(body, {
          ...body,
          id: "approval-2",
          created_at_unix_ms: now + 1,
        });
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
    } else if (path === "/api/v1/approvals/approval-2/deny") {
      body = { ...approvals[1], state: "denied", version: 2 };
      approvals[1] = body;
    } else if (path === "/api/v1/approvals/stale-approval/deny") {
      const index = approvals.findIndex((item) => item.id === "stale-approval");
      body = { ...approvals[index], state: "denied", version: 2 };
      approvals[index] = body;
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
    else throw new Error(`Unexpected fixture request: ${method} ${path}`);
    await route.fulfill({ status, json: body });
  });
  await page.goto(
    `${process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799"}/#pair=synthetic-bootstrap`,
  );
  await page
    .getByRole("heading", { name: "许可协议与免责协议", exact: true })
    .waitFor();
  assertNoSeriousAccessibilityViolations(
    await new AxeBuilder({ page }).analyze(),
    assert,
  );
  await acceptLegalConsent(page);
  assert.equal(
    await page.evaluate(() =>
      localStorage.getItem("secretbridge.legal-consent.v1"),
    ),
    "2026-09-beta-1",
  );
  await page.getByText("已配对", { exact: true }).waitFor();
  assert.equal(
    await page
      .getByRole("navigation", { name: "主导航" })
      .getByRole("button")
      .count(),
    9,
  );
  const nav = (name) =>
    page
      .getByRole("navigation", { name: "主导航" })
      .getByRole("button", { name, exact: true });
  await nav("凭据").click();
  const add = page.getByRole("button", { name: "添加凭据引用", exact: true });
  await add.click();
  const drawer = page.locator("dialog[data-presentation='side-drawer']");
  await drawer.evaluate((element) =>
    Promise.all(element.getAnimations().map((animation) => animation.finished)),
  );
  const drawerBox = await drawer.boundingBox();
  assert.ok(drawerBox);
  const viewportWidths = await page.evaluate(() => [
    window.innerWidth,
    document.documentElement.clientWidth,
  ]);
  const rightEdge = drawerBox.x + drawerBox.width;
  assert.ok(
    Math.min(...viewportWidths.map((width) => Math.abs(rightEdge - width))) <=
      1,
  );
  assert.equal(Math.round(drawerBox.height), 1000);
  for (let index = 0; index < 10; index++) {
    await page.keyboard.press(index % 2 ? "Shift+Tab" : "Tab");
    assert.equal(
      await page
        .locator("dialog[data-presentation='side-drawer']")
        .evaluate((dialog) => dialog.contains(document.activeElement)),
      true,
    );
  }
  assert.equal(
    await page
      .locator("dialog[data-presentation='side-drawer']")
      .evaluate((dialog) => dialog.contains(document.activeElement)),
    true,
  );
  await page.keyboard.press("Escape");
  const addHandle = await add.elementHandle();
  await page.waitForFunction(
    (button) => document.activeElement === button,
    addHandle,
    { timeout: 2_000 },
  );
  assert.equal(
    await add.evaluate((button) => document.activeElement === button),
    true,
  );
  await add.click();
  await page.getByLabel("引用名称").fill("工作台测试密码");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await drawer.waitFor({ state: "hidden" });
  await page.waitForFunction(
    (button) => document.activeElement === button,
    addHandle,
    { timeout: 2_000 },
  );
  await page.getByLabel("输入新秘密值").fill("synthetic-secret-only");
  await page
    .getByRole("button", { name: "保存到系统凭据库", exact: true })
    .click();
  await page.getByText("已安全保存", { exact: true }).waitFor();
  assert.equal(await page.getByLabel("输入新秘密值").inputValue(), "");
  const editCredential = page.getByRole("button", {
    name: "编辑",
    exact: true,
  });
  await editCredential.click();
  await drawer.waitFor({ state: "visible" });
  await page.keyboard.press("Escape");
  const editHandle = await editCredential.elementHandle();
  await page.waitForFunction(
    (button) => document.activeElement === button,
    editHandle,
    { timeout: 2_000 },
  );
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
  await nav("设置").click();
  await page.getByRole("button", { name: "系统级通知" }).click();
  await page
    .getByRole("button", { name: "系统级通知", pressed: true })
    .waitFor();
  assert.equal(notificationChannel, "system");
  await nav("任务").click();
  await nav("任务模板").click();
  await page.getByRole("button", { name: "申请授权", exact: true }).click();
  await page.waitForFunction(
    () => document.querySelector("#approval-template")?.value === "task",
  );
  assert.equal(
    await page.getByRole("dialog").getByLabel("操作模板").inputValue(),
    "task",
  );
  await page.getByRole("button", { name: "提交审批", exact: true }).click();
  const queue = page.getByRole("dialog", { name: "待审批请求" });
  await queue.waitFor();
  await queue.getByText("共 2 项，正在处理第 1 项；按申请时间排序").waitFor();
  for (const width of [3840, 1440]) {
    await page.setViewportSize({ width, height: 2160 });
    await page.evaluate(() => {
      document.documentElement.style.zoom = "200%";
    });
    const review = queue.getByText("查看 HTTP 请求与插槽", { exact: true });
    await review.waitFor();
    assert.equal(
      await review.evaluate((element) => element.parentElement?.open),
      true,
    );
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
      true,
      `approval review overflow at ${width}px and 200% zoom`,
    );
    if (process.env.SECRETBRIDGE_UI_SCREENSHOT && width === 3840)
      await page.screenshot({
        path: process.env.SECRETBRIDGE_UI_SCREENSHOT.replace(
          /\.png$/,
          "-approval-4k.png",
        ),
        fullPage: true,
      });
  }
  await page.evaluate(() => {
    document.documentElement.style.zoom = "";
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await queue.getByRole("button", { name: "批准当前项" }).click();
  await queue.getByText("共 1 项，正在处理第 1 项；按申请时间排序").waitFor();
  await queue.getByRole("button", { name: "拒绝当前项" }).click();
  await queue.waitFor({ state: "hidden" });
  await nav("执行与结果").click();
  await page.getByRole("button", { name: "新建运行请求", exact: true }).click();
  assert.equal(
    await page
      .getByRole("dialog")
      .getByLabel("已批准的授权")
      .locator("option")
      .count(),
    3,
  );
  await page.getByRole("button", { name: "启动受控运行", exact: true }).click();
  await page.getByText("synthetic-filtered-result", { exact: true }).waitFor();
  await nav("历史").click();
  await page.getByRole("button", { name: "AI 会话" }).click();
  await page.getByRole("heading", { name: "合成会话摘要" }).waitFor();
  await page.getByText(/任务与审批（\d+）/).waitFor();
  await page.getByLabel("我理解此会话内所有操作可自动获批").check();
  await page.getByRole("button", { name: "启用 1 小时全操作授权" }).click();
  await page.getByText(/高风险：1 个 AI 会话已允许所有操作/).waitFor();
  await page
    .getByRole("button", { name: "逐个任务审批 \/ 撤销预授权" })
    .click();
  await page
    .getByText(/高风险：1 个 AI 会话已允许所有操作/)
    .waitFor({ state: "hidden" });
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
  assert.equal(
    await page.evaluate(() => localStorage.getItem("secretbridge.language.v1")),
    "en",
  );
  await page
    .getByRole("heading", { name: "Connections", exact: true })
    .waitFor();
  await page.getByRole("button", { name: "Switch to Chinese" }).click();
  if (browserName === "chromium") {
    const accessibility = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    assertNoSeriousAccessibilityViolations(accessibility, assert);

    for (let index = 1; index < 100; index++) {
      targets.push({
        ...metadata,
        id: `scale-target-${String(index).padStart(3, "0")}`,
        name: `规模连接 ${String(index).padStart(3, "0")}`,
        kind: "http_service",
        environment: "test",
        description: "个人本机规模验收数据",
        credential_reference_id: null,
        postgres: null,
      });
    }
    for (let index = 1; index < 200; index++) {
      tasks.push({
        ...metadata,
        id: `scale-task-${String(index).padStart(3, "0")}`,
        target_id: `scale-target-${String((index % 99) + 1).padStart(3, "0")}`,
        name: `规模任务 ${String(index).padStart(3, "0")}`,
        operation: "synthetic_health_check",
        result_scope: "status_only",
        description: "个人本机规模验收数据",
        timeout_seconds: 30,
        enabled: true,
        command: null,
      });
    }
    for (let index = 1; index < 500; index++) {
      runs.push({
        ...metadata,
        id: `scale-run-${String(index).padStart(3, "0")}`,
        approval_id: "approval",
        action_template_id: `scale-task-${String(((index - 1) % 198) + 1).padStart(3, "0")}`,
        target_id: `scale-target-${String((index % 99) + 1).padStart(3, "0")}`,
        target_version: 1,
        operation: "synthetic_health_check",
        result_scope: "status_only",
        state: "succeeded",
        result_status: "synthetic_ok",
        started_at_unix_ms: now + index,
        finished_at_unix_ms: now + index + 20,
      });
    }
    runs.at(-1).action_template_id = "scale-task-199";
    runs.at(-1).target_id = "scale-target-099";

    const searchAndOpen = async (section, query, expected) => {
      const started = performance.now();
      await nav(section).click();
      const records = page.getByRole("complementary", { name: "记录列表" });
      await records.getByLabel("搜索记录").fill(query);
      const match = records.getByRole("button", { name: new RegExp(expected) });
      await match.waitFor();
      await match.click();
      await page
        .getByRole("region", { name: "记录详情" })
        .getByText(expected, { exact: true })
        .waitFor();
      const duration = performance.now() - started;
      assert.ok(
        duration <= 2_000,
        `${section} search took ${duration.toFixed(1)} ms`,
      );
      return Math.round(duration * 10) / 10;
    };
    const scaleDurations = {
      tasks_ms: await searchAndOpen("任务", "规模任务 199", "规模任务 199"),
      connections_ms: await searchAndOpen(
        "连接",
        "规模连接 099",
        "规模连接 099",
      ),
      history_ms: await searchAndOpen("历史", "规模任务 199", "规模连接 099"),
    };
    console.log(
      `Personal-scale UI passed: 100 connections, 200 tasks and 500 runs (${JSON.stringify(scaleDurations)}).`,
    );
    await nav("连接").click();
  }
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
  targets[0].version = 2;
  approvals.push({
    ...approvals[0],
    id: "stale-approval",
    state: "pending",
    version: 1,
    target_version: 1,
    created_at_unix_ms: now + 2,
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.reload();
  const staleQueue = page.getByRole("dialog", { name: "待审批请求" });
  await staleQueue.waitFor();
  await staleQueue
    .getByText("操作快照不可用或已变化", { exact: true })
    .waitFor();
  assert.equal(
    await staleQueue.getByRole("button", { name: "批准当前项" }).isDisabled(),
    true,
  );
  await staleQueue.getByRole("button", { name: "稍后处理" }).click();
  await nav("任务").click();
  await nav("授权与确认").click();
  await page
    .getByRole("complementary", { name: "记录列表" })
    .getByRole("button", { name: /connection · 待审批/ })
    .click();
  await page.getByText("操作或目标快照不可用、已变化或已停用").waitFor();
  assert.equal(
    await page.getByRole("button", { name: "批准", exact: true }).isDisabled(),
    true,
  );
  await page.getByRole("button", { name: "待审批 1" }).click();
  await staleQueue.getByRole("button", { name: "拒绝当前项" }).click();
  await staleQueue.waitFor({ state: "hidden" });
  await nav("设置").click();
  await page
    .getByRole("button", { name: "解除当前页面配对", exact: true })
    .click();
  await nav("凭据").click();
  await page.getByRole("heading", { name: "请先配对本机服务" }).waitFor();
  assert.deepEqual(errors, []);
  console.log(
    `Workbench UI smoke passed (${browserName}): six sections, credential/connection/task/authorization/run/result workflow, retry, focus, search, language, narrow layouts and unpairing.`,
  );
} finally {
  await browser.close();
}
