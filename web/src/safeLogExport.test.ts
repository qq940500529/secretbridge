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
  schema_version: 3,
  exported_at_unix_ms: 100,
  fetched_event_counts: { authentication: 1, approval: 1, run: 1 },
  truncation: "complete",
  filters: { source: "all", keyword_applied: false },
};
const entries: SafeLogEntry[] = [
  {
    source: "authentication",
    kind: "verification_succeeded",
    channel: "mcp",
    approval_id: "11111111-1111-4111-8111-111111111111",
    run_id: "22222222-2222-4222-8222-222222222222",
    terminal_id: null,
    sequence: null,
    state: null,
    result_status: null,
    authorization_mode: "once",
    created_at_unix_ms: 101,
  },
  {
    source: "approval",
    kind: "denied",
    channel: null,
    approval_id: "33333333-3333-4333-8333-333333333333",
    run_id: null,
    terminal_id: null,
    sequence: null,
    state: "denied",
    result_status: null,
    authorization_mode: "once",
    created_at_unix_ms: 101,
  },
  {
    source: "run",
    kind: "succeeded",
    channel: null,
    approval_id: "11111111-1111-4111-8111-111111111111",
    run_id: "22222222-2222-4222-8222-222222222222",
    terminal_id: "44444444-4444-4444-8444-444444444444",
    sequence: 1,
    state: "succeeded",
    result_status: "command_ok",
    authorization_mode: "once",
    created_at_unix_ms: 102,
  },
];

describe("safe log export", () => {
  it("keeps one approval correlation and a versioned header across formats", () => {
    const json = JSON.parse(renderSafeLog("json", metadata, entries));
    expect(json.schema_version).toBe(3);
    expect(json.entries[2].terminal_id).toBe(
      "44444444-4444-4444-8444-444444444444",
    );
    expect(
      json.entries.map((entry: SafeLogEntry) => entry.approval_id),
    ).toEqual([
      "11111111-1111-4111-8111-111111111111",
      "33333333-3333-4333-8333-333333333333",
      "11111111-1111-4111-8111-111111111111",
    ]);
    const lines = renderSafeLog("jsonl", metadata, entries)
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(lines.map((line) => line.record_type)).toEqual([
      "metadata",
      "event",
      "event",
      "event",
    ]);
    expect(lines[3].approval_id).toBe("11111111-1111-4111-8111-111111111111");
    const csv = renderSafeLog("csv", metadata, entries);
    expect(csv).toContain('# {"format":"secretbridge-safe-log"');
    expect(csv).toContain(
      '"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222"',
    );
  });
  it("removes unexpected personal and credential-like data before every export format", () => {
    const unsafe = [
      {
        ...entries[1],
        kind: "synthetic-password-secret",
        run_id: "/home/synthetic-user",
        result_status: "synthetic-api-token",
        channel: "synthetic-totp-123456",
      },
    ];
    for (const format of ["json", "jsonl", "csv"] as const) {
      const text = renderSafeLog(
        format,
        {
          ...metadata,
          filters: {
            source: "all",
            unsafe_path: "/Users/synthetic-user",
            error_code: "192.0.2.77",
          },
        },
        unsafe,
      );
      for (const marker of [
        "synthetic-password-secret",
        "synthetic-api-token",
        "synthetic-totp-123456",
        "/home/synthetic-user",
        "/Users/synthetic-user",
        "192.0.2.77",
      ]) {
        expect(text).not.toContain(marker);
      }
    }
  });
});
