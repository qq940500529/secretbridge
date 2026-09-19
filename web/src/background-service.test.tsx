// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BackgroundServiceView } from "./BackgroundServiceView";
import { stopBroker } from "./api";
afterEach(() => vi.unstubAllGlobals());
describe("background service", () => {
  it("explains terminal and task impact without rendering the session token", () => {
    const html = renderToStaticMarkup(
      <BackgroundServiceView
        sessionToken="synthetic-token"
        language="zh-CN"
        onStopped={() => {}}
      />,
    );
    expect(html).toContain("停止后台服务");
    expect(html).toContain("关闭浏览器不会停止服务");
    expect(html).toContain("结束终端");
    expect(html).not.toContain("synthetic-token");
    expect(html).not.toContain("beta.");
    expect(html).not.toContain("确认停止");
  });
  it("renders an English service control", () => {
    const html = renderToStaticMarkup(
      <BackgroundServiceView
        sessionToken="token"
        language="en"
        onStopped={() => {}}
      />,
    );
    expect(html).toContain("Stop background service");
    expect(html).toContain("Saved configuration is retained");
  });
  it("uses an authenticated POST and accepts only an explicit acknowledgement", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal("fetch", fetch);
    await stopBroker("token");
    expect(fetch).toHaveBeenCalledWith("/api/v1/runtime/stop", {
      method: "POST",
      headers: { Authorization: "Bearer token" },
    });
    fetch.mockResolvedValue(new Response(null, { status: 403 }));
    await expect(stopBroker("token")).rejects.toThrow("broker_stop_failed");
  });
});
