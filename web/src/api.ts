// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ServiceStatus {
  product: string;
  api_version: string;
  release_stage: string;
  mode: "synthetic_only";
  identity_boundary: "unverified_same_user";
  configuration_storage: ConfigurationStorage;
  paired: boolean;
  real_credentials_enabled: boolean;
}

export type ConfigurationStorage = "memory_only" | "sqlite";

export interface PairResponse {
  session_token: string;
  token_type: "Bearer";
  expires_in_seconds: number;
}

export interface SessionResponse {
  authenticated: boolean;
  mode: "synthetic_only";
  expires_in_seconds: number;
}

export type TerminalStatus = "running" | "exited" | "terminated" | "failed";

export interface TerminalSummary {
  id: string;
  created_at_unix_ms: number;
  status: TerminalStatus;
  mode: "synthetic_only";
}

export type CredentialKind = "password" | "api_token" | "ssh_key";

export interface CredentialReference {
  id: string;
  name: string;
  kind: CredentialKind;
  purpose: string | null;
  secret_state: "not_configured";
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  version: number;
}

export interface CreateCredentialReference {
  name: string;
  kind: CredentialKind;
  purpose?: string;
}

export interface UpdateCredentialReference extends CreateCredentialReference {
  expected_version: number;
}

export type TargetKind = "database" | "http_service" | "ssh_host";
export type TargetEnvironment = "development" | "test" | "production";

export interface Target {
  id: string;
  name: string;
  kind: TargetKind;
  environment: TargetEnvironment;
  description: string | null;
  credential_reference_id: string | null;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  version: number;
}

export interface CreateTarget {
  name: string;
  kind: TargetKind;
  environment: TargetEnvironment;
  description?: string;
  credential_reference_id?: string;
}

export interface UpdateTarget extends CreateTarget {
  expected_version: number;
}

export interface CatalogListResponse<T> {
  items: T[];
  storage: ConfigurationStorage;
}

export type ApprovalOperation =
  | "inspect_metadata"
  | "synthetic_health_check";
export type ApprovalResultScope = "status_only" | "metadata_summary";
export type ApprovalState =
  | "pending"
  | "approved"
  | "denied"
  | "revoked"
  | "expired";

export interface ActionTemplate {
  id: string;
  target_id: string;
  name: string;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  description: string | null;
  timeout_seconds: number;
  enabled: boolean;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  version: number;
}

export interface CreateActionTemplate {
  target_id: string;
  name: string;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  description?: string;
  timeout_seconds: number;
}

export interface UpdateActionTemplate extends CreateActionTemplate {
  enabled: boolean;
  expected_version: number;
}

export interface Approval {
  id: string;
  action_template_id: string | null;
  action_template_version: number | null;
  target_id: string;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  reason: string | null;
  state: ApprovalState;
  decision_note: string | null;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  expires_at_unix_ms: number;
  version: number;
}

export interface CreateApproval {
  action_template_id: string;
  reason?: string;
  expires_in_seconds: number;
}

export interface DecideApproval {
  expected_version: number;
  note?: string;
}

export interface ApprovalListResponse extends CatalogListResponse<Approval> {
  execution_enabled: false;
}

export interface ActionTemplateListResponse
  extends CatalogListResponse<ActionTemplate> {
  execution_enabled: false;
}

export type RunState =
  | "queued"
  | "running"
  | "succeeded"
  | "cancelled"
  | "failed";

export interface SyntheticRun {
  id: string;
  approval_id: string;
  action_template_id: string;
  target_id: string;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  state: RunState;
  result_status:
    | "synthetic_ok"
    | "cancelled"
    | "service_restarted"
    | "authorization_revoked"
    | null;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  started_at_unix_ms: number | null;
  finished_at_unix_ms: number | null;
  version: number;
}

export interface SyntheticRunListResponse {
  items: SyntheticRun[];
  execution_mode: "synthetic_simulation";
}

export interface CreateSyntheticRunResponse {
  run: SyntheticRun;
  replayed: boolean;
  execution_mode: "synthetic_simulation";
}

export type SafeEventKind =
  | "authorization_revoked"
  | "requested"
  | "started"
  | "succeeded"
  | "cancelled"
  | "interrupted";

export interface SafeEvent {
  id: number;
  run_id: string;
  sequence: number;
  kind: SafeEventKind;
  state: RunState;
  message: string;
  created_at_unix_ms: number;
}

export interface SafeEventListResponse {
  items: SafeEvent[];
  payload_policy: "fixed_safe_messages_only";
}

interface TerminalListResponse {
  terminals: TerminalSummary[];
}

export class SecretBridgeApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`SecretBridge API returned ${status} (${code})`);
    this.name = "SecretBridgeApiError";
  }
}

async function requireOk(response: Response): Promise<void> {
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

async function readJson<T>(response: Response): Promise<T> {
  await requireOk(response);
  return (await response.json()) as T;
}

export async function getStatus(): Promise<ServiceStatus> {
  return readJson<ServiceStatus>(
    await fetch("/api/v1/status", {
      cache: "no-store",
      credentials: "omit",
    }),
  );
}

export async function pair(bootstrapToken: string): Promise<PairResponse> {
  return readJson<PairResponse>(
    await fetch("/api/v1/session/pair", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: {
        Authorization: `Bearer ${bootstrapToken}`,
      },
    }),
  );
}

export async function getSession(
  sessionToken: string,
): Promise<SessionResponse> {
  return readJson<SessionResponse>(
    await fetch("/api/v1/session", {
      cache: "no-store",
      credentials: "omit",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
    }),
  );
}

function sessionHeaders(sessionToken: string): HeadersInit {
  return { Authorization: `Bearer ${sessionToken}` };
}

function sessionJsonHeaders(sessionToken: string): HeadersInit {
  return {
    ...sessionHeaders(sessionToken),
    "Content-Type": "application/json",
  };
}

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

async function updateCatalogItem<T>(
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

async function deleteCatalogItem(
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

export async function listTerminals(
  sessionToken: string,
): Promise<TerminalSummary[]> {
  const response = await readJson<TerminalListResponse>(
    await fetch("/api/v1/terminals", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
  return response.terminals;
}

export async function createTerminal(
  sessionToken: string,
  rows: number,
  cols: number,
): Promise<TerminalSummary> {
  return readJson<TerminalSummary>(
    await fetch("/api/v1/terminals", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: {
        ...sessionJsonHeaders(sessionToken),
      },
      body: JSON.stringify({ rows, cols }),
    }),
  );
}

export async function deleteTerminal(
  sessionToken: string,
  terminalId: string,
): Promise<void> {
  const response = await fetch(`/api/v1/terminals/${terminalId}`, {
    method: "DELETE",
    cache: "no-store",
    credentials: "omit",
    headers: sessionHeaders(sessionToken),
  });
  if (!response.ok) {
    throw new Error(`SecretBridge API returned ${response.status}`);
  }
}

export function terminalWebSocketUrl(terminalId: string): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/v1/terminals/${terminalId}/attach`;
}
