// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from "vitest";

import {
  hasCurrentLegalConsent,
  initialLanguage,
  LEGAL_CONSENT_VERSION,
  storeLanguage,
  storeLegalConsent,
  systemLanguage,
} from "./preferences";

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    values,
  };
}

describe("frontend preferences", () => {
  it("uses the system language until the user chooses a supported language", () => {
    expect(systemLanguage("zh-Hans-CN")).toBe("zh-CN");
    expect(systemLanguage("en-US")).toBe("en");
    expect(systemLanguage("fr-FR")).toBe("en");
    expect(initialLanguage(memoryStorage(), "zh-TW")).toBe("zh-CN");
  });

  it("persists a valid language and ignores an invalid stored value", () => {
    const storage = memoryStorage({ "secretbridge.language.v1": "fr" });
    expect(initialLanguage(storage, "en-US")).toBe("en");
    storeLanguage("zh-CN", storage);
    expect(initialLanguage(storage, "en-US")).toBe("zh-CN");
  });

  it("requires the current version of the legal consent", () => {
    const storage = memoryStorage({
      "secretbridge.legal-consent.v1": "an-older-version",
    });
    expect(hasCurrentLegalConsent(storage)).toBe(false);
    storeLegalConsent(storage);
    expect(storage.values.get("secretbridge.legal-consent.v1")).toBe(
      LEGAL_CONSENT_VERSION,
    );
    expect(hasCurrentLegalConsent(storage)).toBe(true);
  });
});
