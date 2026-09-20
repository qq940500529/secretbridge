// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { BrowserAuthenticationSettings } from "./BrowserAuthenticationSettings";

describe("browser authentication settings", () => {
  it("explains the AI boundary without rendering the session token", () => {
    const html = renderToStaticMarkup(
      <BrowserAuthenticationSettings
        language="zh-CN"
        sessionToken="synthetic-session-token"
        pinEnabled={false}
        totpEnabled={false}
        onChanged={() => {}}
      />,
    );
    expect(html).toContain("绑定身份验证器");
    expect(html).toContain("请勿向 AI 提供 PIN、二维码或手动密钥");
    expect(html).toContain("当前六位验证码");
    expect(html).not.toContain("synthetic-session-token");
  });

  it("offers replacement and pairing-link recovery when TOTP is active", () => {
    const html = renderToStaticMarkup(
      <BrowserAuthenticationSettings
        language="en"
        sessionToken="token"
        pinEnabled={false}
        totpEnabled
        onChanged={() => {}}
      />,
    );
    expect(html).toContain("Replace authenticator");
    expect(html).toContain("Use pairing links");
  });
});
