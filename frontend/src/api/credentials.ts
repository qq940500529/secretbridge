// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { listResources } from "./resources";
import type { CredentialReference, CatalogListResponse } from "./models";

export async function listCredentialReferences(
  sessionToken: string,
): Promise<CatalogListResponse<CredentialReference>> {
  const response = await listResources(sessionToken);
  return {
    ...response,
    items: response.items.map((item) => ({
      id: item.id,
      name: item.name,
      kind: item.authentication.kind,
      purpose: item.description,
      address: item.address,
      username: item.username,
      version: item.authentication.secret_version,
      secret_state: item.authentication.secret_state,
      secret_updated_at_unix_ms: null,
      created_at_unix_ms: item.created_at_unix_ms,
      updated_at_unix_ms: item.updated_at_unix_ms,
    })),
  };
}
