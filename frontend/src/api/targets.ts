// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { listResources } from "./resources";
import type { Target, CatalogListResponse } from "./models";

export async function listTargets(
  sessionToken: string,
): Promise<CatalogListResponse<Target>> {
  const response = await listResources(sessionToken);
  return {
    ...response,
    items: response.items.map((item) => ({
      ...item,
      credential_reference_id: item.id,
      postgres: null,
      allow_insecure_protocol:
        item.connection.protocol === "telnet" &&
        item.connection.allow_plaintext,
    })),
  };
}
