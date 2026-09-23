// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EditorDialog, MasterDetail, SectionTabs } from "./Workbench";
import { revokePageSession } from "./api";
import type { ActionTemplate } from "./api";
import { CommandReview } from "./CommandReview";

afterEach(() => vi.unstubAllGlobals());
describe("workbench surfaces", () => {
  const items = [
    { id: "one", name: "First", detail: "Database" },
    { id: "two", name: "Second", detail: "HTTP" },
  ];
  it("shows one detail rather than expanding every record", () => {
    const html = renderToStaticMarkup(
      <MasterDetail items={items} language="en">
        <article>First details</article>
        <article>Second details</article>
      </MasterDetail>,
    );
    expect(html).toContain("First details");
    expect(html).not.toContain("Second details");
    expect(html).toContain('aria-label="Search records"');
  });
  it("selects an explicit record and falls back after deletion", () => {
    const html = (selectedId: string) =>
      renderToStaticMarkup(
        <MasterDetail items={items} selectedId={selectedId} language="en">
          <p>One detail</p>
          <p>Two detail</p>
        </MasterDetail>,
      );
    expect(html("two")).toContain("Two detail");
    expect(html("removed")).toContain("One detail");
  });
  it("escapes names and renders long labels without truncation", () => {
    const name = "<script>" + "长名称".repeat(40);
    const html = renderToStaticMarkup(
      <MasterDetail items={[{ id: "one", name }]} language="zh-CN">
        <p>Detail</p>
      </MasterDetail>,
    );
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("长名称".repeat(40));
    expect(html).toContain('aria-label="搜索记录"');
  });
  it("uses normal keyboard-focusable buttons for section navigation", () => {
    const html = renderToStaticMarkup(
      <SectionTabs
        items={[
          { id: "tasks", label: "Tasks" },
          { id: "runs", label: "Runs" },
        ]}
        selected="runs"
        onSelect={() => {}}
      />,
    );
    expect(html).toContain('aria-current="page"');
    expect(html).not.toContain('role="tab"');
  });
  it("does not mount closed editor fields or secret inputs", () => {
    const html = renderToStaticMarkup(
      <EditorDialog
        title="新建任务"
        open={false}
        onOpen={() => {}}
        onClose={() => {}}
      >
        <input type="password" value="synthetic-only" readOnly />
      </EditorDialog>,
    );
    expect(html).not.toContain("synthetic-only");
    expect(html).toContain("aria-labelledby=");
    expect(html).toContain('data-presentation="side-drawer"');
  });
  it("keeps errors and fields available in an open editor", () => {
    const html = renderToStaticMarkup(
      <EditorDialog
        title="Edit task"
        open
        onOpen={() => {}}
        onClose={() => {}}
        busy
      >
        <p role="alert">Retry</p>
      </EditorDialog>,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain('disabled=""');
  });
  it("revokes only the current page session using the existing API", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);
    await revokePageSession("synthetic-session");
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/session",
      expect.objectContaining({
        method: "DELETE",
        credentials: "omit",
        headers: { Authorization: "Bearer synthetic-session" },
      }),
    );
  });
  it("reports a rejected session revocation instead of claiming success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 401 })),
    );
    await expect(revokePageSession("synthetic-session")).rejects.toThrow();
  });
  it("shows every byte of a long command argument in the expanded approval review", () => {
    const longArgument = "合成参数".repeat(700);
    const template = {
      id: "draft",
      target_id: "target",
      name: "Long command",
      operation: "command_execution",
      result_scope: "sanitized_output",
      description: null,
      timeout_seconds: 30,
      enabled: true,
      created_at_unix_ms: 1,
      updated_at_unix_ms: 1,
      version: 1,
      command: {
        terminal_id: "terminal",
        program: "/usr/bin/example",
        working_directory: "/tmp",
        arguments: ["{{.Names}}", longArgument],
        slots: [],
      },
    } as ActionTemplate;
    const html = renderToStaticMarkup(
      <CommandReview
        template={template}
        expectedVersion={1}
        language="zh-CN"
        expanded
      />,
    );
    expect(html).toContain(longArgument);
    expect(html).toContain("{{.Names}}");
    expect(html).toContain("terminal");
    expect(html).toContain('open=""');
  });
});
