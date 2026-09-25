// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  authorizationLabel,
  parseParameter,
  retryGuidance,
  nextParameterName,
  setParameterValue,
} from "./parameters";

describe("task parameter inputs", () => {
  it("chooses a free parameter name after deletion", () => {
    expect(nextParameterName(["param_1", "param_3"])).toBe("param_2");
  });
  it("keeps identifier-like object keys as data", () => {
    const values = setParameterValue({}, "__proto__", "ordinary value");
    expect(Object.hasOwn(values, "__proto__")).toBe(true);
    expect(values["__proto__"]).toBe("ordinary value");
    expect(Object.getPrototypeOf(values)).toBe(Object.prototype);
    expect(setParameterValue(values, "__proto__", undefined)).toEqual({});
  });
  it("preserves strings including shell punctuation as ordinary data", () => {
    expect(parseParameter("string", "天津; {{password}} & next")).toBe(
      "天津; {{password}} & next",
    );
  });
  it("accepts only exact types and safe integers", () => {
    expect(parseParameter("integer", "-100")).toBe(-100);
    expect(parseParameter("boolean", "false")).toBe(false);
    for (const text of ["1.5", "1e3", "NaN", "", "9007199254740992"])
      expect(() => parseParameter("integer", text)).toThrow();
    expect(() => parseParameter("boolean", "yes")).toThrow();
  });
  it("describes authorization scope and cautious retries", () => {
    expect(authorizationLabel("time_window", true)).toContain("相同参数");
    expect(retryGuidance("command_ok", true)).toBeNull();
    expect(retryGuidance("timed_out", true)).toContain("已产生效果");
    expect(retryGuidance("command_cleanup_failed", true)).toContain(
      "不要直接重试",
    );
  });
});
