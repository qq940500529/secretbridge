// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ServiceStatus {
  product: string;
  api_version: string;
  release_stage: string;
  mode: "synthetic_only";
  identity_boundary: "unverified_same_user";
  configuration_storage: "memory_only";
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

export type CredentialKind = "password" | "api_token" | "ssh_key";

export interface CredentialReference {
  id: string;
  name: string;
  kind: CredentialKind;
  purpose: string | null;
  secret_state: "not_configured";
  created_at_unix_ms: number;
}

export interface CreateCredentialReference {
  name: string;
  kind: CredentialKind;
  purpose?: string;
}

export type TargetKind = "database" | "http_service" | "ssh_host";
export type TargetEnvironment = "development" | "test" | "production";

export interface Target {
  id: string;
  name: string;
  kind: TargetKind;
  environment: TargetEnvironment;
  description: string | null;
  credential_reference_id: string | null;
  created_at_unix_ms: number;
}

export interface CreateTarget {
  name: string;
  kind: TargetKind;
  environment: TargetEnvironment;
  description?: string;
  credential_reference_id?: string;
}

interface CatalogListResponse<T> {
  items: T[];
  storage: "memory_only";
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

function sessionJsonHeaders(sessionToken: string): HeadersInit {
  return {
    ...sessionHeaders(sessionToken),
    "Content-Type": "application/json",
  };
}

export async function listCredentialReferences(
  sessionToken: string,
): Promise<CredentialReference[]> {
  const response = await readJson<CatalogListResponse<CredentialReference>>(
    await fetch("/api/v1/credential-references", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
  return response.items;
}

export async function createCredentialReference(
  sessionToken: string,
  request: CreateCredentialReference,
): Promise<CredentialReference> {
  return readJson<CredentialReference>(
    await fetch("/api/v1/credential-references", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}

export async function deleteCredentialReference(
  sessionToken: string,
  id: string,
): Promise<void> {
  return deleteCatalogItem(sessionToken, `/api/v1/credential-references/${id}`);
}

export async function listTargets(sessionToken: string): Promise<Target[]> {
  const response = await readJson<CatalogListResponse<Target>>(
    await fetch("/api/v1/targets", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
  return response.items;
}

export async function createTarget(
  sessionToken: string,
  request: CreateTarget,
): Promise<Target> {
  return readJson<Target>(
    await fetch("/api/v1/targets", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}

export async function deleteTarget(
  sessionToken: string,
  id: string,
): Promise<void> {
  return deleteCatalogItem(sessionToken, `/api/v1/targets/${id}`);
}

async function deleteCatalogItem(
  sessionToken: string,
  path: string,
): Promise<void> {
  const response = await fetch(path, {
    method: "DELETE",
    cache: "no-store",
    credentials: "omit",
    headers: sessionHeaders(sessionToken),
  });
  if (!response.ok) {
    throw new Error(`SecretBridge API returned ${response.status}`);
  }
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
        ...sessionJsonHeaders(sessionToken),
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
