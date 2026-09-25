// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { SafeEventListResponse } from "./models";
import { readJson, sessionHeaders } from "./transport";

export async function listRunSafeEvents(
  sessionToken: string,
  id: string,
): Promise<SafeEventListResponse> {
  return readJson<SafeEventListResponse>(
    await fetch(`/api/v1/runs/${id}/events`, {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function listSafeEvents(
  sessionToken: string,
): Promise<SafeEventListResponse> {
  return readJson<SafeEventListResponse>(
    await fetch("/api/v1/safe-events", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}
