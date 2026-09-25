// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  ActionTemplate,
  CreateActionTemplate,
  UpdateActionTemplate,
  ActionTemplateListResponse,
  PolicyEvaluation,
} from "./models";
import {
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
  updateCatalogItem,
  deleteCatalogItem,
} from "./transport";

export async function listActionTemplates(
  sessionToken: string,
): Promise<ActionTemplateListResponse> {
  return readJson<ActionTemplateListResponse>(
    await fetch("/api/v1/action-templates", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function getActionTemplate(
  sessionToken: string,
  id: string,
): Promise<ActionTemplate> {
  return readJson<ActionTemplate>(
    await fetch(`/api/v1/action-templates/${encodeURIComponent(id)}`, {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function evaluateActionTemplate(
  sessionToken: string,
  id: string,
): Promise<PolicyEvaluation> {
  return readJson<PolicyEvaluation>(
    await fetch(`/api/v1/action-templates/${id}/policy-evaluation`, {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function createActionTemplate(
  sessionToken: string,
  request: CreateActionTemplate,
): Promise<ActionTemplate> {
  return readJson<ActionTemplate>(
    await fetch("/api/v1/action-templates", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}

export async function updateActionTemplate(
  sessionToken: string,
  id: string,
  request: UpdateActionTemplate,
): Promise<ActionTemplate> {
  return updateCatalogItem(
    sessionToken,
    `/api/v1/action-templates/${id}`,
    request,
  );
}

export async function deleteActionTemplate(
  sessionToken: string,
  id: string,
): Promise<void> {
  return deleteCatalogItem(sessionToken, `/api/v1/action-templates/${id}`);
}
