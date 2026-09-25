// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  PairResponse,
  BrowserAuthMethods,
  BrowserAuthEventListResponse,
  TotpSetup,
  CurrentBrowserAuthProof,
  SessionResponse,
} from "./models";
import {
  SecretBridgeApiError,
  requireOk,
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
} from "./transport";

export async function getBrowserAuthMethods(): Promise<BrowserAuthMethods> {
  return readJson<BrowserAuthMethods>(
    await fetch("/api/v1/session/methods", {
      credentials: "omit",
      cache: "no-store",
    }),
  );
}

export async function pairWithPin(pin: string): Promise<PairResponse> {
  return readJson<PairResponse>(
    await fetch("/api/v1/session/pin", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin }),
    }),
  );
}

export async function pairWithTotp(code: string): Promise<PairResponse> {
  return readJson<PairResponse>(
    await fetch("/api/v1/session/totp", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }),
  );
}

export async function startTotpSetup(
  token: string,
  proof: CurrentBrowserAuthProof = {},
): Promise<TotpSetup> {
  return readJson<TotpSetup>(
    await fetch("/api/v1/session/totp/setup", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify(proof),
    }),
  );
}

export async function confirmTotpSetup(
  token: string,
  code: string,
): Promise<void> {
  await requireOk(
    await fetch("/api/v1/session/totp/confirm", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ code }),
    }),
  );
}

export async function listBrowserAuthEvents(
  token: string,
): Promise<BrowserAuthEventListResponse> {
  return readJson<BrowserAuthEventListResponse>(
    await fetch("/api/v1/session/auth-events", {
      credentials: "omit",
      cache: "no-store",
      headers: sessionHeaders(token),
    }),
  );
}

export async function setBrowserAuthMethod(
  token: string,
  method: "pin" | "disable_totp",
  pin?: string,
  proof: CurrentBrowserAuthProof = {},
): Promise<void> {
  await requireOk(
    await fetch("/api/v1/session/method", {
      method: "PUT",
      credentials: "omit",
      cache: "no-store",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ method, ...(pin ? { pin } : {}), ...proof }),
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

export async function revokePageSession(token: string): Promise<void> {
  const response = await fetch("/api/v1/session", {
    method: "DELETE",
    headers: sessionHeaders(token),
    credentials: "omit",
    cache: "no-store",
  });
  if (!response.ok)
    throw new SecretBridgeApiError(response.status, "session_revoke_failed");
}
