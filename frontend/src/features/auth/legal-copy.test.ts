// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from "vitest";

import { legalCopy } from "./legal-copy";

describe("first-run legal copy", () => {
  it("keeps complete parallel Chinese and English agreements", () => {
    const chinese = legalCopy["zh-CN"];
    const english = legalCopy.en;

    expect(chinese.licenseSections).toHaveLength(6);
    expect(english.licenseSections).toHaveLength(6);
    expect(chinese.disclaimerSections).toHaveLength(7);
    expect(english.disclaimerSections).toHaveLength(7);
    expect(
      [...chinese.licenseSections, ...chinese.disclaimerSections].every(
        (section) => section.title && section.paragraphs.every(Boolean),
      ),
    ).toBe(true);
    expect(
      [...english.licenseSections, ...english.disclaimerSections].every(
        (section) => section.title && section.paragraphs.every(Boolean),
      ),
    ).toBe(true);
  });

  it("states the governing license, prerelease risk and non-excludable liability", () => {
    const allText = Object.values(legalCopy)
      .flatMap((copy) => [
        copy.prerelease,
        ...copy.licenseSections.flatMap((section) => section.paragraphs),
        ...copy.disclaimerSections.flatMap((section) => section.paragraphs),
      ])
      .join("\n");

    expect(allText).toContain("AGPL-3.0-or-later");
    expect(allText).toContain("Beta");
    expect(allText).toContain("依法不得排除或限制");
    expect(allText).toContain("does not permit to be excluded or limited");
  });
});
