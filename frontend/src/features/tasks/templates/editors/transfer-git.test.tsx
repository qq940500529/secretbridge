// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { CommandEditor, emptyCommand } from "./CommandEditor";
import { CommandReview } from "../../shared/CommandReview";
import { emptySsh } from "./SshEditor";
import { emptyGit } from "./GitEditor";
import type { ActionTemplate, CommandConfig } from "../../../../api/index";

function editor(config: CommandConfig, language: "zh-CN" | "en" = "zh-CN") {
  return renderToStaticMarkup(
    <CommandEditor
      value={config}
      onChange={() => {}}
      credentials={[]}
      language={language}
    />,
  );
}
function review(config: CommandConfig) {
  return renderToStaticMarkup(
    <CommandReview
      template={{ command: config, version: 2 } as ActionTemplate}
      expectedVersion={2}
      language="en"
    />,
  );
}
const transfer: CommandConfig = {
  ...emptyCommand,
  ssh: {
    ...emptySsh,
    transfer: {
      direction: "download",
      local_path: "/tmp/output.bin",
      remote_path: "/srv/source.bin",
      max_bytes: 1024,
      overwrite: true,
    },
  },
  slots: [
    {
      name: "password",
      credential_id: "hidden-credential-id",
      injection: "protocol",
      environment_variable: null,
    },
  ],
};
const git: CommandConfig = {
  ...emptyCommand,
  git: {
    ...emptyGit,
    remote_url: "https://example.com/repo.git",
    branch: "feature/one",
    username: "owner",
  },
  slots: [
    {
      name: "token",
      credential_id: "hidden-credential-id",
      injection: "protocol",
      environment_variable: null,
    },
  ],
};
describe("file transfer and Git workflows", () => {
  it("offers dedicated transfer and Git execution modes", () => {
    const html = editor(emptyCommand);
    expect(html).toContain("SFTP 文件传输");
    expect(html).toContain("Git HTTPS");
  });
  it("renders fixed paths, size limit and explicit replacement without command arguments", () => {
    const html = editor(transfer);
    expect(html).toContain("本机文件绝对路径");
    expect(html).toContain("远程文件绝对路径");
    expect(html).toContain("允许替换目标文件");
    expect(html).toContain("文件大小上限");
    expect(html).not.toContain("远程程序绝对路径");
    expect(html).not.toContain("普通参数定义");
  });
  it("shows frozen replacement and paths during transfer approval without credential IDs", () => {
    const html = review(transfer);
    expect(html).toContain("/srv/source.bin");
    expect(html).toContain("/tmp/output.bin");
    expect(html).toContain("Replacement: Allowed");
    expect(html).toContain("1024");
    expect(html).not.toContain("hidden-credential-id");
  });
  it("renders Git-specific fields in both languages without free-form argv or parameters", () => {
    const html = editor(git);
    expect(html).toContain("Git 程序绝对路径");
    expect(html).toContain("固定分支");
    expect(html).toContain("令牌凭据引用");
    expect(html).not.toContain("参数（每行一个");
    expect(editor(git, "en")).toContain("no working-tree merge");
  });
  it("reviews fixed Git operation and branch without raw credentials or hidden references", () => {
    const html = review(git);
    expect(html).toContain("https://example.com/repo.git");
    expect(html).toContain("feature/one");
    expect(html).toContain("inspect");
    expect(html).toContain("cannot roll back");
    expect(html).not.toContain("hidden-credential-id");
  });
});
