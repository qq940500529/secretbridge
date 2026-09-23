// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
// UI-only fixture: no actual service stop, credential writes or login registration.
import assert from "node:assert/strict";
import { acceptLegalConsent, launchBrowser } from "./browser_test_support.mjs";
const { browser } = await launchBrowser();
try {
  for (const width of [1440, 390, 320]) {
    for (const english of [false, true]) {
      const page = await browser.newPage({
        locale: "zh-CN",
        viewport: { width, height: 1000 },
        reducedMotion: "reduce",
      });
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      let attempts = 0;
      await page.route("**/api/v1/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        let body = {};
        if (path === "/api/v1/runtime/stop") {
          assert.equal(route.request().method(), "POST");
          assert.equal(
            route.request().headers().authorization,
            "Bearer synthetic-session",
          );
          attempts++;
          await route.fulfill({ status: attempts === 1 ? 503 : 202 });
          return;
        }
        if (path === "/api/v1/ai-conversations") body = { items: [] };
        else if (path === "/api/v1/notification-settings")
          body = { channel: "browser" };
        else if (path === "/api/v1/status")
          body = {
            product: "SecretBridge",
            api_version: "v1",
            mode: "controlled_operations",
            configuration_storage: "sqlite",
            paired: true,
            real_credentials_enabled: true,
            background_control_enabled: true,
          };
        else if (path === "/api/v1/session/pair")
          body = {
            session_token: "synthetic-session",
            token_type: "Bearer",
            expires_in_seconds: 3600,
          };
        else if (path === "/api/v1/session")
          body = { authenticated: true, expires_in_seconds: 3600 };
        else if (path === "/api/v1/session/methods")
          body = {
            pin_enabled: true,
            totp_enabled: false,
            pairing_link_enabled: false,
          };
        else if (
          /credential-references|targets|action-templates|approvals|runs|events|terminals/.test(
            path,
          )
        )
          body = { items: [], storage: "sqlite" };
        await route.fulfill({ json: body });
      });
      await page.goto(
        `${process.env.SECRETBRIDGE_UI_URL || "http://127.0.0.1:8799"}/?case=${width}-${english}#pair=synthetic-bootstrap`,
      );
      await acceptLegalConsent(page);
      await page.getByText("已配对", { exact: true }).waitFor();
      if (english)
        await page.getByRole("button", { name: "切换到英文" }).click();
      const navigation = page.getByRole("navigation", {
        name: english ? "Primary navigation" : "主导航",
      });
      await navigation
        .getByRole("button", {
          name: english ? "Settings" : "设置",
          exact: true,
        })
        .click();
      const stop = page.getByRole("button", {
        name: english ? "Stop background service" : "停止后台服务",
        exact: true,
      });
      await stop.click();
      const dialog = page.getByRole("dialog");
      await dialog.waitFor();
      await dialog
        .getByRole("button", { name: english ? "Cancel" : "取消", exact: true })
        .click();
      assert.equal(attempts, 0);
      await stop.click();
      const confirm = dialog.getByRole("button", {
        name: english ? "Confirm stop" : "确认停止",
        exact: true,
      });
      await confirm.click();
      await dialog.getByRole("alert").waitFor();
      await confirm.click();
      await page
        .getByRole("status", {
          name: english ? "Connection status" : "连接状态",
        })
        .getByText(english ? /Disconnected/ : /未连接/)
        .waitFor();
      assert.equal(attempts, 2);
      assert.equal(await dialog.count(), 0);
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        true,
      );
      assert.deepEqual(errors, []);
      await page.close();
    }
  }
  console.log(
    "Background UI smoke passed: Chinese/English, confirmation, cancel, failed stop retry, authenticated acknowledgement, offline state and 1440/390/320px layouts.",
  );
} finally {
  await browser.close();
}
