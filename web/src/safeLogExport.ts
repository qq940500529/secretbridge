// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export type SafeLogFormat = "json" | "jsonl" | "csv";

export interface SafeLogEntry {
  source: "authentication" | "run";
  kind: string;
  channel: string | null;
  approval_id: string | null;
  run_id: string | null;
  sequence: number | null;
  state: string | null;
  result_status: string | null;
  created_at_unix_ms: number;
}

export interface SafeLogMetadata {
  format: "secretbridge-safe-log";
  schema_version: 2;
  exported_at_unix_ms: number;
  fetched_event_counts: { authentication: number; run: number };
  truncation: "unknown";
  filters: Record<string, string | number | boolean | null>;
}

const csvColumns = [
  "source",
  "kind",
  "channel",
  "approval_id",
  "run_id",
  "sequence",
  "state",
  "result_status",
  "created_at_unix_ms",
] as const;

function csvCell(value: unknown): string {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

export function renderSafeLog(
  format: SafeLogFormat,
  metadata: SafeLogMetadata,
  entries: SafeLogEntry[],
): string {
  if (format === "json")
    return JSON.stringify({ ...metadata, entries }, null, 2);
  if (format === "jsonl") {
    return (
      [
        JSON.stringify({ record_type: "metadata", ...metadata }),
        ...entries.map((entry) =>
          JSON.stringify({ record_type: "event", ...entry }),
        ),
      ].join("\n") + "\n"
    );
  }
  return (
    [
      `# ${JSON.stringify(metadata)}`,
      csvColumns.join(","),
      ...entries.map((entry) =>
        csvColumns.map((column) => csvCell(entry[column])).join(","),
      ),
    ].join("\n") + "\n"
  );
}
