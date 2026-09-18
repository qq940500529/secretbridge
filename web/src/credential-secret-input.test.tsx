// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  CredentialSecretInput,
  readPrivateKeyFile,
} from "./CredentialSecretInput";
describe("private-key input", () => {
  it("preserves multiline contents without rendering the key buffer", async () => {
    const value = "synthetic-key\nsecond-line\n";
    expect(
      await readPrivateKeyFile({ size: value.length, text: async () => value }),
    ).toBe(value);
    const html = renderToStaticMarkup(
      <CredentialSecretInput
        id="key"
        kind="ssh_key"
        value={value}
        onChange={() => {}}
        onError={() => {}}
        placeholder=""
        className=""
        zh
      />,
    );
    expect(html).toContain('type="file"');
    expect(html).toContain("私钥已载入");
    expect(html).not.toContain("synthetic-key");
  });
  it("rejects empty, oversized and NUL-containing contents", async () => {
    for (const file of [
      { size: 0, text: async () => "" },
      { size: 8193, text: async () => "x" },
      { size: 3, text: async () => "a\0b" },
      { size: 2, text: async () => "中".repeat(3000) },
    ])
      await expect(readPrivateKeyFile(file)).rejects.toThrow(
        "invalid_key_file",
      );
  });
  it("keeps passwords masked", () => {
    const html = renderToStaticMarkup(
      <CredentialSecretInput
        id="password"
        kind="password"
        value=""
        onChange={() => {}}
        onError={() => {}}
        placeholder=""
        className=""
        zh={false}
      />,
    );
    expect(html).toContain('type="password"');
    expect(html).not.toContain('type="file"');
  });
});
