// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// UI-only demo fixture. Real SSH and access controls are tested in Rust.
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  acceptLegalConsent,
  assertNoSeriousAccessibilityViolations,
  launchBrowser,
} from "./browser_test_support.mjs";
const require = createRequire(import.meta.url);
const AxeBuilder = require("@axe-core/playwright").default;
const { browser, name } = await launchBrowser();
try {
  const context = await browser.newContext({
    locale: "zh-CN",
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let resource = null,
    mutations = 0,
    cancelled = 0,
    delay = 0;
  const fingerprint = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
  let observedFingerprint = fingerprint;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    let body = {},
      status = 200;
    if (path.endsWith("/session/methods"))
      body = {
        pin_enabled: true,
        totp_enabled: false,
        pairing_link_enabled: false,
      };
    else if (path.endsWith("/status"))
      body = {
        product: "SecretBridge",
        api_version: "v1",
        mode: "controlled_operations",
        configuration_storage: "sqlite",
        paired: true,
        real_credentials_enabled: true,
      };
    else if (path.endsWith("/session/pair"))
      body = {
        session_token: "demo-session",
        token_type: "Bearer",
        expires_in_seconds: 3600,
      };
    else if (path.endsWith("/session"))
      body = {
        authenticated: true,
        mode: "controlled_operations",
        expires_in_seconds: 3600,
      };
    else if (path.endsWith("/notification-settings"))
      body = { channel: "browser" };
    else if (path.endsWith("/resources") && request.method() === "GET")
      body = { items: resource ? [resource] : [], storage: "sqlite" };
    else if (
      (path.endsWith("/resources") && request.method() === "POST") ||
      (/\/resources\/[^/]+$/.test(path) && request.method() === "PUT")
    ) {
      mutations++;
      resource = {
        ...request.postDataJSON(),
        id: "11111111-1111-4111-8111-111111111111",
        version: mutations,
        created_at_unix_ms: Date.now(),
        updated_at_unix_ms: Date.now(),
        labels: [],
        authentication: {
          kind: "password",
          secret_state: "not_configured",
          secret_version: 1,
        },
      };
      body = resource;
      status = request.method() === "POST" ? 201 : 200;
    } else if (
      /\/ssh-host-key\/[^/]+$/.test(path) &&
      request.method() === "DELETE"
    ) {
      cancelled++;
      status = 204;
    } else if (path.endsWith("/ssh-host-key")) {
      const version = request.postDataJSON().expected_version;
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
      body = {
        resource_id: resource.id,
        resource_version: version,
        code: "observed_unverified",
        fingerprint: observedFingerprint,
        algorithm: "ssh-ed25519",
      };
    } else body = { items: [], execution_enabled: true };
    await route
      .fulfill(status === 204 ? { status } : { status, json: body })
      .catch(() => {});
  });
  await page.goto(
    `${process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799"}/#pair=demo-bootstrap`,
  );
  await acceptLegalConsent(page);
  await page.getByText("已配对", { exact: true }).waitFor();
  await page.getByRole("button", { name: "资源", exact: true }).click();
  await page.getByRole("button", { name: "新建资源", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await page.locator("#resource-name").fill("开发服务器");
  await page.locator("#resource-kind").selectOption("ssh_host");
  await page.locator("#resource-address").fill("example.invalid");
  assert.equal(
    await dialog
      .getByRole("button", { name: "获取公开指纹", exact: true })
      .isDisabled(),
    true,
  );
  await dialog
    .getByRole("button", { name: "保存并核对指纹", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "获取公开指纹", exact: true })
    .click();
  const confirmation = dialog.getByRole("button", {
    name: "确认并填入指纹",
    exact: true,
  });
  await confirmation.waitFor();
  assert.equal(await confirmation.isDisabled(), true);
  assert.equal(await page.locator("#resource-host-key").inputValue(), "");
  assert.equal(mutations, 1);
  assertNoSeriousAccessibilityViolations(
    await new AxeBuilder({ page })
      .include("dialog")
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze(),
    assert,
  );
  await mkdir("dist/ui-ssh", { recursive: true });
  if (name === "chromium")
    await page.screenshot({ path: "dist/ui-ssh/desktop.png" });
  await dialog.getByRole("checkbox", { name: /我已通过可信渠道核对/ }).check();
  await confirmation.click();
  assert.equal(
    await page.locator("#resource-host-key").inputValue(),
    fingerprint,
  );
  assert.equal(
    mutations,
    1,
    "Confirmation fills the draft but must not save it",
  );
  await dialog.getByRole("button", { name: "保存修改", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  assert.equal(resource.connection.host_key_sha256, fingerprint);
  await page.getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#resource-address").fill("changed.example.invalid");
  assert.equal(
    await dialog
      .getByRole("button", { name: "获取公开指纹", exact: true })
      .isDisabled(),
    true,
  );
  await page.locator("#resource-address").fill("example.invalid");
  delay = 300;
  await dialog
    .getByRole("button", { name: "获取公开指纹", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "取消", exact: true })
    .first()
    .click();
  await page.waitForTimeout(400);
  assert.ok(cancelled > 0);
  assert.equal(
    await dialog.getByText("网络获取 · 尚未确认可信", { exact: true }).count(),
    0,
  );
  // Changing endpoint while a request is in flight discards its late response.
  await dialog
    .getByRole("button", { name: "获取公开指纹", exact: true })
    .click();
  await page.locator("#resource-port").fill("2222");
  await page.waitForTimeout(400);
  assert.equal(
    await dialog.getByText("网络获取 · 尚未确认可信", { exact: true }).count(),
    0,
  );
  await page.locator("#resource-port").fill("22");
  delay = 0;
  observedFingerprint = fingerprint.replace("SHA256:a", "SHA256:A");
  await dialog
    .getByRole("button", { name: "获取公开指纹", exact: true })
    .click();
  await confirmation.waitFor();
  assert.equal(await confirmation.isDisabled(), true);
  await dialog
    .getByText("与已保存指纹不同。请先调查密钥变更原因，勿直接替换。", {
      exact: true,
    })
    .waitFor();
  assert.equal(
    await page.locator("#resource-host-key").inputValue(),
    fingerprint,
  );
  await page.setViewportSize({ width: 390, height: 844 });
  const region = dialog.getByRole("region", { name: "公开指纹核对" });
  await region.scrollIntoViewIfNeeded();
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  );
  const bounds = await region.boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 391);
  if (name === "chromium")
    await page.screenshot({ path: "dist/ui-ssh/mobile.png" });
  const checkbox = dialog.getByRole("checkbox", {
    name: /我已通过可信渠道核对/,
  });
  await checkbox.focus();
  await page.keyboard.press("Space");
  assert.equal(await checkbox.isChecked(), true);
  await page.keyboard.press("Tab");
  assert.equal(
    await confirmation.evaluate((node) => document.activeElement === node),
    true,
  );
  assertNoSeriousAccessibilityViolations(
    await new AxeBuilder({ page })
      .include("dialog")
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze(),
    assert,
  );
  assert.deepEqual(errors, []);
  console.log(
    `SSH onboarding UI: explicit trust, save, cancel, endpoint invalidation, responsive layout and accessibility passed (${name}).`,
  );
} finally {
  await browser.close();
}
