// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ServiceStatus {
  product: string;
  api_version: string;
  release_stage: string;
  mode: "synthetic_only";
  paired: boolean;
  real_credentials_enabled: boolean;
}

export interface PairResponse {
  session_token: string;
  token_type: "Bearer";
}

export interface SessionResponse {
  authenticated: boolean;
  mode: "synthetic_only";
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
