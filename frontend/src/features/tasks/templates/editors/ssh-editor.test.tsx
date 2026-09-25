// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { emptySsh, sshCommandPreview } from "./SshEditor";
import { CommandEditor } from "./CommandEditor";
import { CommandReview } from "../../shared/CommandReview";
import type {
  CommandConfig,
  ActionTemplate,
  SshConfig,
} from "../../../../api/index";

const ssh: SshConfig = {
  ...emptySsh,
  host: "example.com",
  username: "operator",
  host_key_sha256: "SHA256:confirmed-host",
  remote_program: "/usr/bin/printf",
  arguments: [
    { kind: "literal", value: "%s" },
    { kind: "parameter", name: "message" },
  ],
};
const config: CommandConfig = {
  ssh,
  program: "",
  working_directory: "",
  arguments: [],
  slots: [
    {
      name: "password",
      credential_id: "hidden-reference-id",
      injection: "protocol",
      environment_variable: null,
    },
  ],
};
describe("SSH configuration", () => {
  it("quotes empty values, single quotes and shell metacharacters as single arguments", () => {
    expect(
      sshCommandPreview(ssh, { message: "'; $(touch /tmp/no); {{password}}" }),
    ).toBe("'/usr/bin/printf' '%s' ''\\''; $(touch /tmp/no); {{password}}'");
    expect(sshCommandPreview(ssh, { message: "" })).toBe(
      "'/usr/bin/printf' '%s' ''",
    );
    expect(sshCommandPreview(ssh, { message: false })).toBe(
      "'/usr/bin/printf' '%s' 'false'",
    );
  });
  it("renders native protocol configuration without local program inputs", () => {
    const html = renderToStaticMarkup(
      <CommandEditor
        value={config}
        onChange={() => {}}
        credentials={[]}
        language="zh-CN"
      />,
    );
    expect(html).toContain("可信主机指纹");
    expect(html).toContain("远程程序绝对路径");
    expect(html).toContain("远程工作目录（可选绝对路径）");
    expect(html).not.toContain("程序与凭据插槽");
    expect(html).not.toContain("工作目录（绝对路径）");
  });
  it("renders encrypted key and passphrase references, not raw secrets", () => {
    const html = renderToStaticMarkup(
      <CommandEditor
        value={{
          ...config,
          ssh: {
            ...ssh,
            authentication: {
              kind: "private_key",
              slot: "key",
              passphrase_slot: "passphrase",
            },
          },
        }}
        onChange={() => {}}
        credentials={[]}
        language="zh-CN"
      />,
    );
    expect(html).toContain("解密口令凭据引用");
    expect(html).toContain("Ed25519 / ECDSA");
  });
  it("reviews the frozen resolved command without exposing credential IDs", () => {
    const html = renderToStaticMarkup(
      <CommandReview
        template={{ command: config, version: 1 } as ActionTemplate}
        expectedVersion={1}
        language="en"
        parameters={{ message: "safe value" }}
      />,
    );
    expect(html).toContain("operator@example.com:22");
    expect(html).toContain("confirmed-host");
    expect(html).toContain("safe value");
    expect(html).toContain("cannot guarantee remote rollback");
    expect(html).not.toContain("hidden-reference-id");
  });
  it("quotes the optional remote working directory in the reviewed command", () => {
    const working = { ...ssh, working_directory: "/tmp/a' b" };
    expect(sshCommandPreview(working, { message: "ok" })).toBe(
      "cd '/tmp/a'\\'' b' && exec '/usr/bin/printf' '%s' 'ok'",
    );
    const html = renderToStaticMarkup(
      <CommandReview
        template={
          { command: { ...config, ssh: working }, version: 1 } as ActionTemplate
        }
        expectedVersion={1}
        language="en"
        parameters={{ message: "ok" }}
      />,
    );
    expect(html).toContain("Remote working directory");
    expect(html).toContain("/tmp/a&#x27; b");
  });
});
