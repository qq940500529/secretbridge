// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from "vitest";
import {
  renderSafeLog,
  type SafeLogEntry,
  type SafeLogMetadata,
} from "./safeLogExport";

const metadata: SafeLogMetadata = {
  format: "secretbridge-safe-log",
  schema_version: 2,
  exported_at_unix_ms: 100,
  fetched_event_counts: { authentication: 1, run: 1 },
  truncation: "unknown",
  filters: { source: "all", keyword_applied: false },
};
const entries: SafeLogEntry[] = [
  {
    source: "authentication",
    kind: "verification_succeeded",
    channel: "mcp",
    approval_id: "approval-1",
    run_id: "run-1",
    sequence: null,
    state: null,
    result_status: null,
    created_at_unix_ms: 101,
  },
  {
    source: "run",
    kind: "succeeded",
    channel: null,
    approval_id: "approval-1",
    run_id: "run-1",
    sequence: 1,
    state: "succeeded",
    result_status: "command_ok",
    created_at_unix_ms: 102,
  },
];

describe("safe log export", () => {
  it("keeps one approval correlation and a versioned header across formats", () => {
    const json = JSON.parse(renderSafeLog("json", metadata, entries));
    expect(json.schema_version).toBe(2);
    expect(
      json.entries.map((entry: SafeLogEntry) => entry.approval_id),
    ).toEqual(["approval-1", "approval-1"]);
    const lines = renderSafeLog("jsonl", metadata, entries)
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(lines.map((line) => line.record_type)).toEqual([
      "metadata",
      "event",
      "event",
    ]);
    expect(lines[2].approval_id).toBe("approval-1");
    const csv = renderSafeLog("csv", metadata, entries);
    expect(csv).toContain('# {"format":"secretbridge-safe-log"');
    expect(csv).toContain('"approval-1","run-1"');
  });
});
