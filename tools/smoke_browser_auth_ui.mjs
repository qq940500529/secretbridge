// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic browser authentication fixture; never uses a native credential store.
import assert from "node:assert/strict";
import { acceptLegalConsent, launchBrowser } from "./browser_test_support.mjs";

const { browser } = await launchBrowser();
const baseUrl = process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799";

async function openCase({ savedSession, failedMethodReads = 0 }) {
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
  let method = "totp";
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
          pin_enabled: method === "pin",
          totp_enabled: method === "totp",
          pairing_link_enabled: method === "pairing_link",
        },
      });
      return;
    }
    if (path === "/api/v1/session/method" && request.method() === "PUT") {
      writes++;
      method = request.postDataJSON().method;
      await route.fulfill({ status: 204 });
      return;
    }
    let body = { items: [] };
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
  await showSettings();
  return {
    context,
    page,
    showSettings,
    reads: () => reads,
    writes: () => writes,
  };
}

try {
  const restored = await openCase({ savedSession: true });
  await restored.page.getByText("已绑定身份验证器").waitFor();
  await restored.page.getByRole("button", { name: "更换身份验证器" }).waitFor();
  await restored.page.reload();
  await restored.showSettings();
  await restored.page.getByText("已绑定身份验证器").waitFor();
  assert.ok(restored.reads() >= 2, "refresh reloads the configured method");
  await restored.page.getByRole("button", { name: "改用配对链接" }).click();
  assert.equal(restored.writes(), 0, "disabling requires confirmation");
  await restored.page
    .getByRole("button", { name: "取消", exact: true })
    .click();
  assert.equal(restored.writes(), 0);
  await restored.page.getByRole("button", { name: "改用配对链接" }).click();
  await restored.page
    .getByRole("textbox", { name: "当前身份验证器验证码" })
    .fill("123456");
  await restored.page.getByRole("button", { name: "确认更改" }).click();
  await restored.page.getByText("当前使用一次性配对链接").waitFor();
  assert.equal(restored.writes(), 1);
  await restored.context.close();

  const bootstrap = await openCase({ savedSession: false });
  await bootstrap.page.getByText("已绑定身份验证器").waitFor();
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
  await failed.page.getByText("已绑定身份验证器").waitFor();
  await failed.context.close();

  console.log(
    "Browser authentication UI smoke passed: saved session, bootstrap, refresh, confirmation and failed-load retry.",
  );
} finally {
  await browser.close();
}
