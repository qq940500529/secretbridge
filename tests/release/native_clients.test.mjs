// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { apply, inject, name } from "../../plugins/deepseek-harness/index.js";
test("Harness guidance registers a scoped, literal prompt through the native service", () => {
  const sections = [];
  const ctx = { systemPrompt: { section: (section) => { sections.push(section); return () => {}; } } };
  apply(ctx);
  assert.equal(name, "secretbridge-guidance");
  assert.deepEqual(inject, ["systemPrompt"]);
  assert.equal(sections.length, 1);
  assert.equal(sections[0].name, "secretbridge:operations");
  assert.equal(sections[0].interpolate, false);
  assert.equal(Number.isFinite(sections[0].order), true);
  for (const word of ["mcp__secretbridge__secretbridge_list_catalog", "ui_language", "decision_note", "idempotency", "pending", "Never request"]) assert.ok(sections[0].text.includes(word));
  assert.ok(!sections[0].complete, "Do not replace the host's system prompt");
});
