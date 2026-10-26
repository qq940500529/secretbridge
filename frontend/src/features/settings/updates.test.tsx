// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, expect, it, vi } from "vitest";
import { UpdateSettings } from "./UpdateSettings";
import { checkUpdates, type UpdateStatus } from "../../api/index";

afterEach(() => vi.unstubAllGlobals());
const available: UpdateStatus = {
  current_version: "0.3.2",
  latest_version: "0.3.3",
  update_available: true,
  checked_at_unix_ms: 1000,
  check_state: "checked",
  release_url:
    "https://github.com/qq940500529/secretbridge/releases/tag/v0.3.3",
  automatic_install: false,
  compatibility_guaranteed: false,
  user_choice_required: true,
  default_action: "keep_current_version",
};
it.each(["zh-CN", "en"] as const)(
  "explains choice and incompatibility without automatic installation (%s)",
  (language) => {
    const html = renderToStaticMarkup(
      <UpdateSettings
        status={available}
        sessionToken="synthetic-token"
        language={language}
      />,
    );
    expect(html).toContain("0.3.3");
    expect(html).toContain(
      language === "zh-CN"
        ? "默认保持当前版本"
        : "Keep the current version by default",
    );
    expect(html).toContain(
      language === "zh-CN"
        ? "不能保证与旧版兼容"
        : "compatibility with earlier versions is not guaranteed",
    );
    expect(html).not.toContain("synthetic-token");
  },
);
it("does not represent offline or unknown checks as up to date", () => {
  for (const status of [
    undefined,
    {
      ...available,
      update_available: false,
      check_state: "unavailable" as const,
    },
  ]) {
    const html = renderToStaticMarkup(
      <UpdateSettings status={status} language="en" />,
    );
    expect(html).not.toContain("No newer release found");
    expect(html).toContain("disabled");
  }
});
it("only requests a bounded authenticated check, not installation", async () => {
  const fetch = vi
    .fn()
    .mockResolvedValue(new Response(JSON.stringify(available)));
  vi.stubGlobal("fetch", fetch);
  expect(await checkUpdates("synthetic-token")).toEqual(available);
  expect(fetch).toHaveBeenCalledWith("/api/v1/updates/check", {
    method: "POST",
    headers: { Authorization: "Bearer synthetic-token" },
    credentials: "omit",
    cache: "no-store",
  });
  expect(fetch).toHaveBeenCalledTimes(1);
});
