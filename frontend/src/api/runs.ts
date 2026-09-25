// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  RunOutput,
  SyntheticRun,
  SyntheticRunListResponse,
  CreateSyntheticRunResponse,
} from "./models";
import {
  requireOk,
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
} from "./transport";

export async function readRunOutput(
  token: string,
  id: string,
  cursor = 0,
): Promise<RunOutput> {
  return readJson(
    await fetch(`/api/v1/runs/${encodeURIComponent(id)}/output`, {
      method: "POST",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ cursor, wait_ms: 0 }),
    }),
  );
}

export async function deleteRunOutput(
  token: string,
  id: string,
): Promise<void> {
  await requireOk(
    await fetch(`/api/v1/runs/${encodeURIComponent(id)}/output`, {
      method: "DELETE",
      headers: sessionHeaders(token),
    }),
  );
}

export async function listSyntheticRuns(
  sessionToken: string,
): Promise<SyntheticRunListResponse> {
  return readJson<SyntheticRunListResponse>(
    await fetch("/api/v1/runs", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function getSyntheticRun(
  sessionToken: string,
  id: string,
): Promise<SyntheticRun> {
  return readJson<SyntheticRun>(
    await fetch(`/api/v1/runs/${id}`, {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function createSyntheticRun(
  sessionToken: string,
  approvalId: string,
  idempotencyKey: string,
): Promise<CreateSyntheticRunResponse> {
  return readJson<CreateSyntheticRunResponse>(
    await fetch("/api/v1/runs", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify({
        approval_id: approvalId,
        idempotency_key: idempotencyKey,
      }),
    }),
  );
}

export async function cancelSyntheticRun(
  sessionToken: string,
  id: string,
  expectedVersion: number,
): Promise<SyntheticRun> {
  return readJson<SyntheticRun>(
    await fetch(`/api/v1/runs/${id}/cancel`, {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify({ expected_version: expectedVersion }),
    }),
  );
}
