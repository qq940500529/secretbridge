// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic browser authentication fixture; never uses a native credential store.
import assert from "node:assert/strict";
import { acceptLegalConsent, launchBrowser } from "./browser_test_support.mjs";

const { browser } = await launchBrowser();
const baseUrl = process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799";

async function openCase({
  savedSession,
  failedMethodReads = 0,
  initialMethod = "totp",
}) {
  const context = await browser.newContext({ locale: "zh-CN" });
  const page = await context.newPage();
  if (savedSession) {
    await page.addInitScript(() => {
      sessionStorage.setItem(
        "secretbridge.page-session.v1",
        "synthetic-session",
      );
    });
  }
  let method = initialMethod;
  let reads = 0;
  let writes = 0;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/session/methods") {
      reads++;
      if (reads <= failedMethodReads) {
        await route.fulfill({ status: 503, json: { code: "unavailable" } });
        return;
      }
      await route.fulfill({
        json: {
          pin_enabled: method !== "pairing_link",
          totp_enabled: method === "totp",
          pairing_link_enabled: method === "pairing_link",
        },
      });
      return;
    }
    if (path === "/api/v1/session/method" && request.method() === "PUT") {
      writes++;
      method =
        request.postDataJSON().method === "disable_totp"
          ? "pin"
          : request.postDataJSON().method;
      if (initialMethod === "pairing_link" && writes === 1) {
        await route.fulfill({ json: { recovery_key: "a".repeat(64) } });
      } else {
        await route.fulfill({ status: 204 });
      }
      return;
    }
    let body = { items: [] };
    if (path === "/api/v1/notification-settings") body = { channel: "browser" };
    else if (path === "/api/v1/status")
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
        session_token: "synthetic-session",
        token_type: "Bearer",
        expires_in_seconds: 3600,
      };
    else if (path === "/api/v1/session")
      body = { authenticated: true, expires_in_seconds: 3600 };
    await route.fulfill({ json: body });
  });
  await page.goto(
    `${baseUrl}/${savedSession ? "" : "#pair=synthetic-bootstrap"}`,
  );
  await acceptLegalConsent(page);
  await page.getByText("已配对", { exact: true }).waitFor();
  async function showSettings() {
    await page
      .getByRole("navigation", { name: "主导航" })
      .getByRole("button", { name: "设置", exact: true })
      .click();
    await page.getByRole("heading", { name: "浏览器身份验证" }).waitFor();
  }
  if (initialMethod !== "pairing_link") await showSettings();
  return {
    context,
    page,
    showSettings,
    reads: () => reads,
    writes: () => writes,
  };
}

try {
  const unpairedContext = await browser.newContext({ locale: "zh-CN" });
  const unpairedPage = await unpairedContext.newPage();
  await unpairedPage.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json:
        path === "/api/v1/session/methods"
          ? {
              pin_enabled: false,
              totp_enabled: false,
              pairing_link_enabled: true,
            }
          : {
              product: "SecretBridge",
              api_version: "v1",
              mode: "controlled_operations",
              configuration_storage: "sqlite",
              paired: false,
              real_credentials_enabled: true,
            },
    });
  });
  await unpairedPage.goto(baseUrl);
  await unpairedPage
    .getByRole("heading", { name: "请先配对本机服务" })
    .waitFor();
  assert.equal(
    await unpairedPage.getByRole("dialog").count(),
    0,
    "unpaired browsers cannot be stranded in PIN enrollment",
  );
  await unpairedContext.close();

  const restored = await openCase({ savedSession: true });
  await restored.page.getByText("已设置 PIN，并绑定身份验证器").waitFor();
  await restored.page.getByRole("button", { name: "更换身份验证器" }).waitFor();
  await restored.page.reload();
  await restored.showSettings();
  await restored.page.getByText("已设置 PIN，并绑定身份验证器").waitFor();
  assert.ok(restored.reads() >= 2, "refresh reloads the configured method");
  await restored.page.getByRole("button", { name: "解除验证码绑定" }).click();
  assert.equal(restored.writes(), 0, "disabling requires confirmation");
  await restored.page
    .getByRole("button", { name: "取消", exact: true })
    .click();
  assert.equal(restored.writes(), 0);
  await restored.page.getByRole("button", { name: "解除验证码绑定" }).click();
  await restored.page.getByLabel("当前 PIN/口令").fill("synthetic-current-pin");
  await restored.page.getByRole("button", { name: "确认更改" }).click();
  await restored.page.getByText("已设置 PIN/口令").waitFor();
  assert.equal(restored.writes(), 1);
  await restored.context.close();

  const bootstrap = await openCase({ savedSession: false });
  await bootstrap.page.getByText("已设置 PIN，并绑定身份验证器").waitFor();
  assert.ok(
    bootstrap.reads() > 0,
    "bootstrap pairing loads the configured method",
  );
  await bootstrap.context.close();

  const failed = await openCase({ savedSession: true, failedMethodReads: 1 });
  await failed.page
    .getByRole("alert")
    .getByText("无法读取身份验证配置。", { exact: false })
    .waitFor();
  assert.equal(
    await failed.page.getByRole("button", { name: "绑定身份验证器" }).count(),
    0,
    "failed loading cannot appear unconfigured",
  );
  await failed.page.getByRole("button", { name: "重试" }).click();
  await failed.page.getByText("已设置 PIN，并绑定身份验证器").waitFor();
  await failed.context.close();

  const initial = await openCase({
    savedSession: false,
    initialMethod: "pairing_link",
  });
  await initial.page.getByRole("heading", { name: "设置本机 PIN" }).waitFor();
  const setupDialog = initial.page.getByRole("dialog");
  const boundsBeforeMismatch = await setupDialog.boundingBox();
  await initial.page.getByLabel("PIN / 口令").fill("123456");
  await initial.page.getByLabel("再次输入 PIN").fill("654321");
  await initial.page.getByText("两次输入不一致，请核对后重试。").waitFor();
  const boundsAfterMismatch = await setupDialog.boundingBox();
  assert.ok(boundsBeforeMismatch && boundsAfterMismatch);
  assert.ok(
    Math.abs(boundsBeforeMismatch.height - boundsAfterMismatch.height) <= 1,
    "PIN validation must not resize the dialog",
  );
  await initial.page.getByLabel("再次输入 PIN").fill("123456");
  await initial.page
    .getByRole("button", { name: "设置 PIN 并生成恢复密钥" })
    .click();
  await initial.page.getByText("立即保存恢复密钥").waitFor();
  assert.equal(
    await initial.page.getByRole("button", { name: "完成初始化" }).isDisabled(),
    true,
  );
  await initial.page.getByRole("checkbox").check();
  await initial.page.getByRole("button", { name: "完成初始化" }).click();
  await initial.showSettings();
  await initial.page.getByText("是否再绑定身份验证器验证码？").waitFor();
  await initial.page.getByRole("button", { name: "暂不绑定" }).click();
  assert.equal(initial.writes(), 1);
  await initial.context.close();

  console.log(
    "Browser authentication UI smoke passed: required PIN initialization, optional authenticator, saved session, refresh, confirmation and failed-load retry.",
  );
} finally {
  await browser.close();
}
