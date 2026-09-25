// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  Target,
  CreateTarget,
  UpdateTarget,
  CatalogListResponse,
} from "./models";
import {
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
  updateCatalogItem,
  deleteCatalogItem,
} from "./transport";

export async function listTargets(
  sessionToken: string,
): Promise<CatalogListResponse<Target>> {
  return readJson<CatalogListResponse<Target>>(
    await fetch("/api/v1/targets", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
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

export async function updateTarget(
  sessionToken: string,
  id: string,
  request: UpdateTarget,
): Promise<Target> {
  return updateCatalogItem(sessionToken, `/api/v1/targets/${id}`, request);
}
