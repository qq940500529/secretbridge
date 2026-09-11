// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ServiceStatus {
  product: string;
  api_version: string;
  release_stage: string;
  mode: "synthetic_only";
  identity_boundary: "unverified_same_user";
  paired: boolean;
  real_credentials_enabled: boolean;
}

export interface PairResponse {
  session_token: string;
  token_type: "Bearer";
  expires_in_seconds: number;
}

export interface SessionResponse {
  authenticated: boolean;
  mode: "synthetic_only";
  expires_in_seconds: number;
}

export type TerminalStatus = "running" | "exited" | "terminated" | "failed";

export interface TerminalSummary {
  id: string;
  created_at_unix_ms: number;
  status: TerminalStatus;
  mode: "synthetic_only";
}

interface TerminalListResponse {
  terminals: TerminalSummary[];
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(`SecretBridge API returned ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function getStatus(): Promise<ServiceStatus> {
  return readJson<ServiceStatus>(
    await fetch("/api/v1/status", {
      cache: "no-store",
      credentials: "omit",
    }),
  );
}

export async function pair(bootstrapToken: string): Promise<PairResponse> {
  return readJson<PairResponse>(
    await fetch("/api/v1/session/pair", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: {
        Authorization: `Bearer ${bootstrapToken}`,
      },
    }),
  );
}

export async function getSession(
  sessionToken: string,
): Promise<SessionResponse> {
  return readJson<SessionResponse>(
    await fetch("/api/v1/session", {
      cache: "no-store",
      credentials: "omit",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
    }),
  );
}

function sessionHeaders(sessionToken: string): HeadersInit {
  return { Authorization: `Bearer ${sessionToken}` };
}

export async function listTerminals(
  sessionToken: string,
): Promise<TerminalSummary[]> {
  const response = await readJson<TerminalListResponse>(
    await fetch("/api/v1/terminals", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
  return response.terminals;
}

export async function createTerminal(
  sessionToken: string,
  rows: number,
  cols: number,
): Promise<TerminalSummary> {
  return readJson<TerminalSummary>(
    await fetch("/api/v1/terminals", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: {
        ...sessionHeaders(sessionToken),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ rows, cols }),
    }),
  );
}

export async function deleteTerminal(
  sessionToken: string,
  terminalId: string,
): Promise<void> {
  const response = await fetch(`/api/v1/terminals/${terminalId}`, {
    method: "DELETE",
    cache: "no-store",
    credentials: "omit",
    headers: sessionHeaders(sessionToken),
  });
  if (!response.ok) {
    throw new Error(`SecretBridge API returned ${response.status}`);
  }
}

export function terminalWebSocketUrl(terminalId: string): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/v1/terminals/${terminalId}/attach`;
}
