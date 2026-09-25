// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  Approval,
  CreateApproval,
  DecideApproval,
  ApprovalListResponse,
} from "./models";
import { readJson, sessionHeaders, sessionJsonHeaders } from "./transport";

export async function listApprovals(
  sessionToken: string,
): Promise<ApprovalListResponse> {
  return readJson<ApprovalListResponse>(
    await fetch("/api/v1/approvals", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function createApproval(
  sessionToken: string,
  request: CreateApproval,
): Promise<Approval> {
  return readJson<Approval>(
    await fetch("/api/v1/approvals", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}

export async function decideApproval(
  sessionToken: string,
  id: string,
  decision: "approve" | "deny" | "revoke",
  request: DecideApproval,
): Promise<Approval> {
  return readJson<Approval>(
    await fetch(`/api/v1/approvals/${id}/${decision}`, {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}
