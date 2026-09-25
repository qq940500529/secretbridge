// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { CommandEditor } from "./CommandEditor";
import { CommandReview } from "../../shared/CommandReview";
import { emptyTelnet } from "./TelnetEditor";
import type { ActionTemplate, CommandConfig } from "../../../../api/index";

const config: CommandConfig = {
  telnet: {
    ...emptyTelnet,
    host: "legacy.example.test",
    username: "operator",
    command_prompt: "legacy> ",
    commands: ["show status", "show version"],
  },
  program: "",
  working_directory: "",
  arguments: [],
  slots: [
    {
      name: "password",
      credential_id: "opaque-password-reference",
      injection: "protocol",
      environment_variable: null,
    },
  ],
};

describe("Telnet configuration", () => {
  it("keeps the plaintext risk and protocol limits visible in the editor", () => {
    const html = renderToStaticMarkup(
      <CommandEditor
        value={config}
        onChange={() => {}}
        credentials={[]}
        language="zh-CN"
      />,
    );
    expect(html).toContain("明文协议风险");
    expect(html).toContain("固定登录对话");
    expect(html).toContain("固定命令脚本");
    expect(html).toContain("输出上限");
    expect(html).not.toContain("程序绝对路径");
  });

  it("reviews the exact endpoint, prompts and script without credential IDs", () => {
    const html = renderToStaticMarkup(
      <CommandReview
        template={{ command: config, version: 3 } as ActionTemplate}
        expectedVersion={3}
        language="en"
      />,
    );
    expect(html).toContain("operator@legacy.example.test:23");
    expect(html).toContain("show status");
    expect(html).toContain("show version");
    expect(html).toContain("does not encrypt credentials");
    expect(html).not.toContain("opaque-password-reference");
  });
});
