// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { emptyHttp, nextFieldName, parseStatuses } from "./HttpEditor";
describe("HTTP task editing", () => {
  it("defaults to status-only GET without secret literals", () => {
    expect(emptyHttp.method).toBe("GET");
    expect(emptyHttp.response_fields).toEqual([]);
    expect(emptyHttp.headers).toEqual([]);
  });
  it("avoids duplicate names after removing rows", () => {
    expect(nextFieldName(["field_1", "field_3"], "field")).toBe("field_2");
  });
  it("validates status codes without silently discarding input", () => {
    expect(parseStatuses("200, 201 204,200")).toEqual([200, 201, 204]);
    expect(parseStatuses("")).toEqual([]);
    for (const input of [
      "200x",
      "199",
      "600",
      "200,999",
      Array(33).fill("200").join(","),
    ])
      expect(parseStatuses(input)).toBeNull();
  });
});
