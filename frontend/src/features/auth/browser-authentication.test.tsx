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
        authMethodStatus="ready"
        onRetry={() => {}}
        onChanged={() => {}}
      />,
    );
    expect(html).toContain("初始化待完成：请先设置 PIN");
    expect(html).toContain("PIN/口令至少 6 位");
    expect(html).toContain("请勿向 AI 提供 PIN、恢复密钥或身份验证器密钥");
    expect(html).toContain("诊断记录");
    expect(html).not.toContain("synthetic-session-token");
  });

  it("keeps the PIN active when TOTP is configured", () => {
    const html = renderToStaticMarkup(
      <BrowserAuthenticationSettings
        language="en"
        sessionToken="token"
        pinEnabled
        totpEnabled
        authMethodStatus="ready"
        onRetry={() => {}}
        onChanged={() => {}}
      />,
    );
    expect(html).toContain("Replace authenticator");
    expect(html).toContain("PIN set; authenticator configured");
    expect(html).toContain("Remove authenticator");
  });

  it("does not present an unknown method as unconfigured", () => {
    const html = renderToStaticMarkup(
      <BrowserAuthenticationSettings
        language="zh-CN"
        sessionToken="token"
        pinEnabled={false}
        totpEnabled={false}
        authMethodStatus="error"
        onRetry={() => {}}
        onChanged={() => {}}
      />,
    );
    expect(html).toContain("无法读取身份验证配置");
    expect(html).toContain("重试");
    expect(html).not.toContain(">绑定身份验证器</button>");
  });
});
