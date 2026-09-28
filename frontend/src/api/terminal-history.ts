// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { readJson, sessionHeaders, deleteCatalogItem } from "./transport";
export interface TerminalHistoryEntry {
  cursor: number;
  terminal_id: string;
  occurred_at_unix_ms: number;
  kind: "created" | "input" | "output" | "command" | "result" | "closed";
  data: string;
  metadata: Record<string, unknown>;
}
export interface TerminalHistoryPage {
  items: TerminalHistoryEntry[];
  next_cursor: number;
  retention_limit: number;
}
export async function listTerminalHistory(
  token: string,
  after = 0,
  terminalId?: string,
): Promise<TerminalHistoryPage> {
  const query = new URLSearchParams({ after: String(after) });
  if (terminalId) query.set("terminal_id", terminalId);
  return readJson(
    await fetch(`/api/v1/terminal-history?${query}`, {
      headers: sessionHeaders(token),
      credentials: "omit",
      cache: "no-store",
    }),
  );
}
export async function clearTerminalHistory(token: string, id: string) {
  await deleteCatalogItem(token, `/api/v1/terminal-history/${id}`);
}
