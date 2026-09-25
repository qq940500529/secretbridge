// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  CredentialReference,
  CreateCredentialReference,
  UpdateCredentialReference,
  CatalogListResponse,
} from "./models";
import {
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
  updateCatalogItem,
  deleteCatalogItem,
} from "./transport";

export async function listCredentialReferences(
  sessionToken: string,
): Promise<CatalogListResponse<CredentialReference>> {
  return readJson<CatalogListResponse<CredentialReference>>(
    await fetch("/api/v1/credential-references", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
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

export async function updateCredentialReference(
  sessionToken: string,
  id: string,
  request: UpdateCredentialReference,
): Promise<CredentialReference> {
  return updateCatalogItem(
    sessionToken,
    `/api/v1/credential-references/${id}`,
    request,
  );
}

export async function setCredentialSecret(
  sessionToken: string,
  id: string,
  secret: string,
  expectedVersion: number,
): Promise<CredentialReference> {
  return readJson<CredentialReference>(
    await fetch(`/api/v1/credential-references/${id}/secret`, {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify({ secret, expected_version: expectedVersion }),
    }),
  );
}

export async function clearCredentialSecret(
  sessionToken: string,
  id: string,
  expectedVersion: number,
): Promise<CredentialReference> {
  return readJson<CredentialReference>(
    await fetch(`/api/v1/credential-references/${id}/secret`, {
      method: "DELETE",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify({ expected_version: expectedVersion }),
    }),
  );
}
