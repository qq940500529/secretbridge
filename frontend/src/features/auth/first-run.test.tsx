// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { LegalConsent } from "./LegalConsent";

describe("first-run agreement and PIN wizard", () => {
  const props = {
    language: "zh-CN" as const,
    sessionToken: "synthetic-session-token",
    onLanguageChange: () => {},
    onAccept: () => {},
    onClose: () => {},
    onInitialized: async () => {},
  };

  it("starts with the full agreement before PIN setup", () => {
    const html = renderToStaticMarkup(
      <LegalConsent {...props} canClose={false} requiresPinSetup />,
    );
    expect(html).toContain("许可协议与免责协议");
    expect(html).toContain("最终用户许可协议");
    expect(html).not.toContain("设置 PIN 并生成恢复密钥");
    expect(html).not.toContain("synthetic-session-token");
  });

  it("renders the six-character PIN and recovery guidance in the same dialog", () => {
    const html = renderToStaticMarkup(
      <LegalConsent {...props} canClose requiresPinSetup />,
    );
    expect(html).toContain("设置本机 PIN");
    expect(html).toContain("至少 6 位");
    expect(html).toContain("恢复密钥仅显示一次");
    expect(html).toContain("设置 PIN 并生成恢复密钥");
    expect(html).not.toContain("synthetic-session-token");
  });

  it("never presents PIN enrollment without a paired session", () => {
    const html = renderToStaticMarkup(
      <LegalConsent {...props} sessionToken={null} canClose requiresPinSetup />,
    );
    expect(html).toContain("许可协议与免责协议");
    expect(html).not.toContain("设置 PIN 并生成恢复密钥");
  });
});
