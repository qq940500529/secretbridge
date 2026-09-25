// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DataMaintenanceView } from "./DataMaintenanceView";
import {
  downloadBackup,
  exportConfiguration,
  getDiagnostics,
  importConfiguration,
  previewBackup,
  previewConfiguration,
  type ConfigurationBundle,
} from "../../api/index";
afterEach(() => vi.unstubAllGlobals());
const bundle: ConfigurationBundle = {
  format: "secretbridge-configuration",
  format_version: 1,
  exported_at_unix_ms: 1,
  credentials: [],
  connections: [],
  templates: [],
};
describe("data maintenance", () => {
  it("separates workflows and requires a preflight before import", () => {
    const html = renderToStaticMarkup(
      <DataMaintenanceView sessionToken="synthetic-token" language="zh-CN" />,
    );
    expect(html).toContain("数据维护");
    expect(html).toContain("配置迁移");
    expect(html).toContain("不覆盖现有配置");
    expect(html).toContain("检查导入");
    expect(html).not.toContain("确认导入");
    expect(html).not.toContain("synthetic-token");
    expect(html).not.toContain("下载 SQLite 备份");
  });
  it("renders participant-facing English without development labels", () => {
    const html = renderToStaticMarkup(
      <DataMaintenanceView sessionToken="synthetic-token" language="en" />,
    );
    expect(html).toContain("Data maintenance");
    expect(html).toContain("Export configuration");
    expect(html).not.toContain("alpha.");
  });
  it("carries the same configuration and checked digest through confirmation", async () => {
    const fetch = vi
      .fn()
      .mockImplementation(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    await exportConfiguration("token");
    await previewConfiguration("token", bundle);
    await importConfiguration("token", bundle, "verified-digest");
    await getDiagnostics("token");
    expect(fetch.mock.calls.map(([path]) => path)).toEqual([
      "/api/v1/maintenance/configuration",
      "/api/v1/maintenance/configuration/preview",
      "/api/v1/maintenance/configuration/import",
      "/api/v1/maintenance/diagnostics",
    ]);
    expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual(bundle);
    expect(JSON.parse(fetch.mock.calls[2][1].body)).toEqual({
      bundle,
      expected_digest: "verified-digest",
    });
    for (const [, init] of fetch.mock.calls) {
      expect(init.headers.Authorization).toBe("Bearer token");
      expect(init.credentials).toBe("omit");
      expect(init.cache).toBe("no-store");
    }
  });
  it("handles backup as binary without converting it to JSON or text", async () => {
    const file = new Blob(["SQLite format 3\0"], {
      type: "application/vnd.sqlite3",
    });
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response(file))
      .mockResolvedValueOnce(new Response('{"integrity_ok":true}'));
    vi.stubGlobal("fetch", fetch);
    expect((await downloadBackup("token")).size).toBe(file.size);
    expect((await previewBackup("token", file)).integrity_ok).toBe(true);
    expect(fetch.mock.calls[1][1].body).toBe(file);
    expect(fetch.mock.calls[1][1].headers["Content-Type"]).toBe(
      "application/octet-stream",
    );
  });
  it("does not download an unsuccessful backup response", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response('{"code":"unauthorized"}', { status: 401 }),
        ),
    );
    await expect(downloadBackup("expired")).rejects.toMatchObject({
      status: 401,
      code: "unauthorized",
    });
  });
});
