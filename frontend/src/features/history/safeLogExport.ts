// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export type SafeLogFormat = "json" | "jsonl" | "csv";

export interface SafeLogEntry {
  source: "authentication" | "approval" | "run";
  kind: string;
  channel: string | null;
  approval_id: string | null;
  run_id: string | null;
  terminal_id: string | null;
  sequence: number | null;
  state: string | null;
  result_status: string | null;
  authorization_mode: string | null;
  created_at_unix_ms: number;
}

export interface SafeLogMetadata {
  format: "secretbridge-safe-log";
  schema_version: 3;
  exported_at_unix_ms: number;
  fetched_event_counts: {
    authentication: number;
    approval: number;
    run: number;
  };
  truncation: "complete" | "authentication_retention_window";
  filters: Record<string, string | number | boolean | null>;
}

const csvColumns = [
  "source",
  "kind",
  "channel",
  "approval_id",
  "run_id",
  "terminal_id",
  "sequence",
  "state",
  "result_status",
  "authorization_mode",
  "created_at_unix_ms",
] as const;

const safeKinds = new Set([
  "authorization_revoked",
  "requested",
  "started",
  "succeeded",
  "failed",
  "cancelled",
  "interrupted",
  "enrollment_started",
  "enrollment_succeeded",
  "verification_succeeded",
  "verification_failed",
  "rate_limited",
  "disabled",
  "pending",
  "approved",
  "denied",
  "revoked",
  "expired",
]);
const safeStates = new Set([
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "pending",
  "approved",
  "denied",
  "revoked",
  "expired",
]);
const safeChannels = new Set(["browser", "mcp", "settings"]);
const safeResultCodes = new Set([
  "authorization_revoked",
  "cancelled",
  "command_cleanup_failed",
  "command_failed",
  "command_ok",
  "credential_unavailable",
  "database_connection_failed",
  "database_query_failed",
  "git_failed",
  "http_request_failed",
  "postgres_configuration_invalid",
  "postgres_connection_failed",
  "postgres_connection_ok",
  "service_restarted",
  "sftp_transfer_failed",
  "ssh_connection_failed",
  "synthetic_ok",
  "timed_out",
]);
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function safeId(value: string | null): string | null {
  return value !== null && uuidPattern.test(value) ? value : null;
}

function safeFilter(
  value: string | number | boolean | null,
): string | number | boolean | null {
  if (typeof value !== "string") return value;
  const fixed = new Set([
    "all",
    "auth",
    "run",
    "approval",
    "once",
    "every_run",
    "time_window",
    "day",
    "week",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "one_time",
  ]);
  return fixed.has(value) ||
    safeKinds.has(value) ||
    safeResultCodes.has(value) ||
    uuidPattern.test(value)
    ? value
    : "redacted";
}

function safeEntry(entry: SafeLogEntry): SafeLogEntry {
  return {
    source:
      entry.source === "authentication"
        ? "authentication"
        : entry.source === "approval"
          ? "approval"
          : "run",
    kind: safeKinds.has(entry.kind) ? entry.kind : "unknown",
    channel:
      entry.channel && safeChannels.has(entry.channel) ? entry.channel : null,
    approval_id: safeId(entry.approval_id),
    run_id: safeId(entry.run_id),
    terminal_id: safeId(entry.terminal_id),
    sequence:
      Number.isSafeInteger(entry.sequence) && (entry.sequence ?? -1) >= 0
        ? entry.sequence
        : null,
    state: entry.state && safeStates.has(entry.state) ? entry.state : null,
    result_status:
      entry.result_status && safeResultCodes.has(entry.result_status)
        ? entry.result_status
        : null,
    authorization_mode:
      entry.authorization_mode &&
      new Set(["once", "every_run", "time_window"]).has(
        entry.authorization_mode,
      )
        ? entry.authorization_mode
        : null,
    created_at_unix_ms:
      Number.isSafeInteger(entry.created_at_unix_ms) &&
      entry.created_at_unix_ms >= 0
        ? entry.created_at_unix_ms
        : 0,
  };
}

function csvCell(value: unknown): string {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

export function renderSafeLog(
  format: SafeLogFormat,
  metadata: SafeLogMetadata,
  entries: SafeLogEntry[],
): string {
  const safeMetadata: SafeLogMetadata = {
    format: "secretbridge-safe-log",
    schema_version: 3,
    exported_at_unix_ms: Number.isSafeInteger(metadata.exported_at_unix_ms)
      ? metadata.exported_at_unix_ms
      : 0,
    fetched_event_counts: metadata.fetched_event_counts,
    truncation:
      metadata.truncation === "authentication_retention_window"
        ? "authentication_retention_window"
        : "complete",
    filters: Object.fromEntries(
      Object.entries(metadata.filters)
        .filter(([key]) =>
          new Set([
            "source",
            "kind",
            "period",
            "result",
            "authorization_mode",
            "error_code",
            "target_id",
            "template_id",
            "keyword_applied",
          ]).has(key),
        )
        .map(([key, value]) => [key, safeFilter(value)]),
    ),
  };
  const safeEntries = entries.map(safeEntry);
  if (format === "json")
    return JSON.stringify({ ...safeMetadata, entries: safeEntries }, null, 2);
  if (format === "jsonl") {
    return (
      [
        JSON.stringify({ record_type: "metadata", ...safeMetadata }),
        ...safeEntries.map((entry) =>
          JSON.stringify({ record_type: "event", ...entry }),
        ),
      ].join("\n") + "\n"
    );
  }
  return (
    [
      `# ${JSON.stringify(safeMetadata)}`,
      csvColumns.join(","),
      ...safeEntries.map((entry) =>
        csvColumns.map((column) => csvCell(entry[column])).join(","),
      ),
    ].join("\n") + "\n"
  );
}
