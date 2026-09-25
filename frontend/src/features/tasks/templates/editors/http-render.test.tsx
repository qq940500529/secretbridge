// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { renderToStaticMarkup } from "react-dom/server";
import { describe, it, expect } from "vitest";
import { CommandEditor } from "./CommandEditor";
import { CommandReview } from "../../shared/CommandReview";
import { emptyHttp } from "./HttpEditor";
import type { CommandConfig, ActionTemplate } from "../../../../api/index";
const config: CommandConfig = {
  http: { ...emptyHttp, url: "https://example.com/v1/status" },
  program: "",
  working_directory: "",
  arguments: [],
  slots: [
    {
      name: "token",
      credential_id: "internal-credential-id",
      injection: "protocol",
      environment_variable: null,
    },
  ],
  parameters: [],
};
describe("HTTP configuration rendering", () => {
  it("renders a protocol editor instead of program-path inputs", () => {
    const html = renderToStaticMarkup(
      <CommandEditor
        value={config}
        onChange={() => {}}
        credentials={[]}
        language="zh-CN"
      />,
    );
    expect(html).toContain("固定请求地址");
    expect(html).toContain("查询参数");
    expect(html).not.toContain("程序绝对路径");
    expect(html).not.toContain("JSON 请求体字段");
  });
  it("renders body configuration for write methods and warns on plaintext HTTP", () => {
    const html = renderToStaticMarkup(
      <CommandEditor
        value={{
          ...config,
          http: {
            ...config.http!,
            method: "POST",
            url: "http://localhost/test",
          },
        }}
        onChange={() => {}}
        credentials={[]}
        language="zh-CN"
      />,
    );
    expect(html).toContain("JSON 请求体字段");
    expect(html).toContain("HTTP 不加密传输");
  });
  it("shows request review without credential IDs or empty program paths", () => {
    const template = { command: config, version: 2 } as ActionTemplate;
    const html = renderToStaticMarkup(
      <CommandReview
        template={template}
        expectedVersion={2}
        language="en"
        parameters={{ company: "100" }}
      />,
    );
    expect(html).toContain("GET https://example.com/v1/status");
    expect(html).toContain("token");
    expect(html).not.toContain("internal-credential-id");
    expect(html).not.toContain("Directory");
  });
  it("rejects stale approval review", () => {
    const html = renderToStaticMarkup(
      <CommandReview
        template={{ command: config, version: 2 } as ActionTemplate}
        expectedVersion={1}
        language="zh-CN"
      />,
    );
    expect(html).toContain("模板已修改");
    expect(html).not.toContain("example.com");
  });
});
