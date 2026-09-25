// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from "vitest";
import { RunRequestKeys } from "./run-request";

it("reuses uncertain request keys even across approval switches", () => {
  let count = 0;
  const keys = new RunRequestKeys(() => `request-${++count}`);
  expect(keys.forApproval("first")).toBe("request-1");
  expect(keys.forApproval("first")).toBe("request-1");
  expect(keys.forApproval("second")).toBe("request-2");
  expect(keys.forApproval("first")).toBe("request-1");
  keys.acknowledge("first");
  expect(keys.forApproval("first")).toBe("request-3");
  expect(keys.forApproval("second")).toBe("request-2");
});
