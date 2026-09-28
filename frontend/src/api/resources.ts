// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  Resource,
  ResourceRequest,
  CatalogListResponse,
  ConnectionTestResult,
} from "./models";
import {
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
  deleteCatalogItem,
} from "./transport";
export async function listResources(
  token: string,
): Promise<CatalogListResponse<Resource>> {
  return readJson(
    await fetch("/api/v1/resources", {
      headers: sessionHeaders(token),
      credentials: "omit",
      cache: "no-store",
    }),
  );
}
export async function saveResource(
  token: string,
  request: ResourceRequest,
  id?: string,
): Promise<Resource> {
  return readJson(
    await fetch(id ? `/api/v1/resources/${id}` : "/api/v1/resources", {
      method: id ? "PUT" : "POST",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify(request),
      credentials: "omit",
      cache: "no-store",
    }),
  );
}
export async function removeResource(token: string, id: string) {
  await deleteCatalogItem(token, `/api/v1/resources/${id}`);
}
export async function setResourceSecret(
  token: string,
  resource: Resource,
  secret: string,
): Promise<Resource> {
  return readJson(
    await fetch(`/api/v1/resources/${resource.id}/secret`, {
      method: "PUT",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({
        secret,
        expected_version: resource.authentication.secret_version,
      }),
      credentials: "omit",
      cache: "no-store",
    }),
  );
}
export async function clearResourceSecret(
  token: string,
  resource: Resource,
): Promise<Resource> {
  return readJson(
    await fetch(`/api/v1/resources/${resource.id}/secret`, {
      method: "DELETE",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({
        expected_version: resource.authentication.secret_version,
      }),
      credentials: "omit",
      cache: "no-store",
    }),
  );
}
export async function testResource(
  token: string,
  resource: Resource,
): Promise<ConnectionTestResult> {
  return readJson(
    await fetch(`/api/v1/resources/${resource.id}/test`, {
      method: "POST",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ expected_version: resource.version }),
      credentials: "omit",
      cache: "no-store",
    }),
  );
}
