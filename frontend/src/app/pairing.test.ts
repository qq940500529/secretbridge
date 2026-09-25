// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from "vitest";

import { readPairingToken, urlWithoutFragment } from "./pairing";

describe("browser pairing", () => {
  it("reads an opaque token from the URL fragment", () => {
    expect(readPairingToken("#pair=synthetic-token-123")).toBe(
      "synthetic-token-123",
    );
  });

  it("does not treat unrelated fragments as pairing tokens", () => {
    expect(readPairingToken("#dashboard")).toBeNull();
    expect(readPairingToken("")).toBeNull();
  });

  it("removes the complete fragment from browser history", () => {
    expect(urlWithoutFragment("/console", "?lang=zh-CN")).toBe(
      "/console?lang=zh-CN",
    );
  });
});
