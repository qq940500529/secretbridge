// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ActionTemplate, Approval } from "../../../api/index";
import {
  includeApprovalDrafts,
  operationDisplayName,
} from "./operation-presentation";

afterEach(() => vi.unstubAllGlobals());

const saved = {
  id: "saved",
  name: "Saved operation",
  one_time: false,
} as ActionTemplate;
const draft = {
  id: "draft",
  name: "AI-created request",
  one_time: true,
  command: { ssh: {} },
} as ActionTemplate;
const templates = new Map([saved, draft].map((item) => [item.id, item]));
const reference = (id: string | null) => ({
  action_template_id: id,
  operation: "command_execution" as const,
});

describe.each(["zh-CN", "en"] as const)(
  "operation labels in %s",
  (language) => {
    it("preserves saved-template names", () => {
      expect(
        operationDisplayName(reference("saved"), templates, language),
      ).toBe(saved.name);
    });
    it("identifies an existing one-time SSH draft", () => {
      expect(
        operationDisplayName(reference("draft"), templates, language),
      ).toBe(language === "zh-CN" ? "一次性 SSH 命令" : "One-time SSH command");
    });
    it("uses the operation kind when no template was referenced", () => {
      expect(operationDisplayName(reference(null), templates, language)).toBe(
        language === "zh-CN" ? "凭据任务" : "Credential task",
      );
    });
    it("marks an explicitly referenced but missing template as removed", () => {
      expect(
        operationDisplayName(reference("deleted"), templates, language),
      ).toBe(
        language === "zh-CN"
          ? "已移除的操作模板"
          : "Removed operation template",
      );
    });
    it("labels non-SSH one-time operations without requiring a saved template", () => {
      const command = { ...draft, command: undefined };
      expect(
        operationDisplayName(
          reference("draft"),
          new Map([[command.id, command]]),
          language,
        ),
      ).toBe(
        language === "zh-CN"
          ? "一次性操作 · 凭据任务"
          : "One-time operation · Credential task",
      );
    });
  },
);

it("resolves active draft IDs once without treating the saved catalog as complete", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(draft)));
  vi.stubGlobal("fetch", fetch);
  const active = (id: string | null, state = "approved") =>
    ({
      action_template_id: id,
      state,
    }) as Approval;
  const result = await includeApprovalDrafts(
    "synthetic-session",
    [
      active("saved"),
      active("draft"),
      active("draft", "pending"),
      active(null),
      active("inactive", "denied"),
    ],
    [saved],
  );
  expect(result).toEqual([saved, draft]);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/action-templates/draft");
});

it("keeps existing templates when a referenced template cannot be loaded", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ code: "not_found" }), { status: 404 }),
      ),
  );
  expect(
    await includeApprovalDrafts(
      "synthetic-session",
      [{ action_template_id: "deleted", state: "approved" } as Approval],
      [saved],
    ),
  ).toEqual([saved]);
});
