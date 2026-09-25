// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export class SecretBridgeApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`SecretBridge API returned ${status} (${code})`);
    this.name = "SecretBridgeApiError";
  }
}

export async function requireOk(response: Response): Promise<void> {
  if (response.ok) return;
  let code = "request_failed";
  try {
    const body = (await response.json()) as { code?: unknown };
    if (typeof body.code === "string") code = body.code;
  } catch {
    // Error responses may be empty or come from an intermediary.
  }
  throw new SecretBridgeApiError(response.status, code);
}

export async function readJson<T>(response: Response): Promise<T> {
  await requireOk(response);
  return (await response.json()) as T;
}

export function sessionHeaders(sessionToken: string): HeadersInit {
  return { Authorization: `Bearer ${sessionToken}` };
}

export function sessionJsonHeaders(sessionToken: string): HeadersInit {
  return {
    ...sessionHeaders(sessionToken),
    "Content-Type": "application/json",
  };
}

export async function updateCatalogItem<T>(
  sessionToken: string,
  path: string,
  request: object,
): Promise<T> {
  return readJson<T>(
    await fetch(path, {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}

export async function deleteCatalogItem(
  sessionToken: string,
  path: string,
): Promise<void> {
  const response = await fetch(path, {
    method: "DELETE",
    cache: "no-store",
    credentials: "omit",
    headers: sessionHeaders(sessionToken),
  });
  await requireOk(response);
}
