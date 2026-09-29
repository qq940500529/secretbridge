// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { noteForApproval } from "./decision-note";

describe("approval decision note ownership", () => {
  const draft = {
    approvalId: "first",
    version: 1,
    value: "Use a bounded alternative.",
  };
  it("retains the note when the same approval is refreshed", () => {
    expect(noteForApproval(draft, { id: "first", version: 1 })).toBe(
      draft.value,
    );
  });
  it("never displays a previous item's note for the next approval", () => {
    expect(noteForApproval(draft, { id: "next", version: 1 })).toBe("");
  });
  it("does not reuse a note after a version change or removal", () => {
    expect(noteForApproval(draft, { id: "first", version: 2 })).toBe("");
    expect(noteForApproval(draft, undefined)).toBe("");
    expect(noteForApproval(null, { id: "first", version: 1 })).toBe("");
  });
});
