// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ServiceStatus {
  product: string;
  api_version: string;
  mode: "synthetic_only" | "credential_configuration" | "controlled_operations";
  configuration_storage: ConfigurationStorage;
  paired: boolean;
  real_credentials_enabled: boolean;
  background_control_enabled?: boolean;
}

export async function stopBroker(token: string): Promise<void> {
  const response = await fetch("/api/v1/runtime/stop", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (response.status !== 202) throw new Error("broker_stop_failed");
}

export type ConfigurationStorage = "memory_only" | "sqlite";

export interface ConfigurationBundle {
  format: "secretbridge-configuration";
  format_version: 1;
  exported_at_unix_ms: number;
  credentials: Array<
    Pick<
      CredentialReference,
      "id" | "name" | "kind" | "purpose" | "address" | "username"
    >
  >;
  connections: Array<
    Pick<
      Target,
      | "id"
      | "name"
      | "kind"
      | "environment"
      | "description"
      | "address"
      | "username"
      | "allow_insecure_protocol"
      | "credential_reference_id"
      | "postgres"
    >
  >;
  templates: Array<
    Pick<
      ActionTemplate,
      | "id"
      | "target_id"
      | "name"
      | "operation"
      | "result_scope"
      | "description"
      | "timeout_seconds"
      | "enabled"
      | "command"
    >
  >;
}
export interface ImportReport {
  digest: string;
  credentials: number;
  connections: number;
  templates: number;
  replayed: boolean;
  credentials_need_configuration: boolean;
}
export interface BackupReport {
  schema_version: number;
  restore_schema_version: number;
  integrity_ok: boolean;
  credentials: number;
  connections: number;
  templates: number;
  runs: number;
  requires_secret_reentry: boolean;
  restores_authorizations: boolean;
}
export interface Diagnostics {
  format: string;
  diagnostic_schema_version: number;
  version: string;
  platform: string;
  bridge_schema_version: number;
  authentication_mode: "pairing_link" | "pin" | "totp";
  generated_at_unix_ms: number;
  schema_version: number;
  storage: ConfigurationStorage;
  credentials: number;
  configured_credentials: number;
  connections: number;
  templates: number;
  pending_authorizations: number;
  failed_runs: number;
  terminal_sessions: number;
  error_codes: Record<string, number>;
  run_states: Record<string, number>;
  failure_stages: Record<string, number>;
  run_failures: {
    code: string;
    stage: string;
    occurrences: number;
    first_at_unix_ms: number;
    last_at_unix_ms: number;
  }[];
  mcp_failures: {
    code: string;
    stage: string;
    occurrences: number;
    first_at_unix_ms: number;
    last_at_unix_ms: number;
  }[];
  terminal_states: Record<string, number>;
  stale_terminal_references: number;
}
async function maintenanceJson<T>(
  token: string,
  path: string,
  payload?: unknown,
): Promise<T> {
  return readJson<T>(
    await fetch(`/api/v1/maintenance/${path}`, {
      method: payload === undefined ? "GET" : "POST",
      credentials: "omit",
      cache: "no-store",
      headers:
        payload === undefined
          ? sessionHeaders(token)
          : sessionJsonHeaders(token),
      body: payload === undefined ? undefined : JSON.stringify(payload),
    }),
  );
}
export const exportConfiguration = (token: string) =>
  maintenanceJson<ConfigurationBundle>(token, "configuration");
export const previewConfiguration = (
  token: string,
  bundle: ConfigurationBundle,
) => maintenanceJson<ImportReport>(token, "configuration/preview", bundle);
export const importConfiguration = (
  token: string,
  bundle: ConfigurationBundle,
  digest: string,
) =>
  maintenanceJson<ImportReport>(token, "configuration/import", {
    bundle,
    expected_digest: digest,
  });
export const getDiagnostics = (token: string) =>
  maintenanceJson<Diagnostics>(token, "diagnostics");
export async function downloadBackup(token: string): Promise<Blob> {
  const response = await fetch("/api/v1/maintenance/backup", {
    credentials: "omit",
    cache: "no-store",
    headers: sessionHeaders(token),
  });
  await requireOk(response);
  return response.blob();
}
export async function previewBackup(
  token: string,
  file: Blob,
): Promise<BackupReport> {
  return readJson<BackupReport>(
    await fetch("/api/v1/maintenance/backup/preview", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: {
        ...sessionHeaders(token),
        "Content-Type": "application/octet-stream",
      },
      body: file,
    }),
  );
}

export interface PairResponse {
  session_token: string;
  token_type: "Bearer";
  expires_in_seconds: number;
}

export interface BrowserAuthMethods {
  pin_enabled: boolean;
  totp_enabled: boolean;
  pairing_link_enabled: boolean;
}

export type BrowserAuthEventKind =
  | "enrollment_started"
  | "enrollment_succeeded"
  | "verification_succeeded"
  | "verification_failed"
  | "rate_limited"
  | "disabled";

export interface BrowserAuthEvent {
  id: number;
  kind: BrowserAuthEventKind;
  channel: "browser" | "mcp" | "settings";
  approval_id?: string | null;
  created_at_unix_ms: number;
}

export interface BrowserAuthEventListResponse {
  items: BrowserAuthEvent[];
}

export interface TotpSetup {
  manual_key: string;
  qr_code_data_url: string;
  expires_in_seconds: number;
  accepted_past_steps: number;
}

export async function getBrowserAuthMethods(): Promise<BrowserAuthMethods> {
  return readJson<BrowserAuthMethods>(
    await fetch("/api/v1/session/methods", {
      credentials: "omit",
      cache: "no-store",
    }),
  );
}

export async function pairWithPin(pin: string): Promise<PairResponse> {
  return readJson<PairResponse>(
    await fetch("/api/v1/session/pin", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin }),
    }),
  );
}

export async function pairWithTotp(code: string): Promise<PairResponse> {
  return readJson<PairResponse>(
    await fetch("/api/v1/session/totp", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }),
  );
}

export interface CurrentBrowserAuthProof {
  current_pin?: string;
  current_totp_code?: string;
}

export async function startTotpSetup(
  token: string,
  proof: CurrentBrowserAuthProof = {},
): Promise<TotpSetup> {
  return readJson<TotpSetup>(
    await fetch("/api/v1/session/totp/setup", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify(proof),
    }),
  );
}

export async function confirmTotpSetup(
  token: string,
  code: string,
): Promise<void> {
  await requireOk(
    await fetch("/api/v1/session/totp/confirm", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ code }),
    }),
  );
}

export async function listBrowserAuthEvents(
  token: string,
): Promise<BrowserAuthEventListResponse> {
  return readJson<BrowserAuthEventListResponse>(
    await fetch("/api/v1/session/auth-events", {
      credentials: "omit",
      cache: "no-store",
      headers: sessionHeaders(token),
    }),
  );
}

export async function setBrowserAuthMethod(
  token: string,
  method: "pairing_link" | "pin",
  pin?: string,
  proof: CurrentBrowserAuthProof = {},
): Promise<void> {
  await requireOk(
    await fetch("/api/v1/session/method", {
      method: "PUT",
      credentials: "omit",
      cache: "no-store",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ method, ...(pin ? { pin } : {}), ...proof }),
    }),
  );
}

export interface SessionResponse {
  authenticated: boolean;
  mode: "synthetic_only" | "credential_configuration" | "controlled_operations";
  expires_in_seconds: number;
}

export type TerminalStatus = "running" | "exited" | "terminated" | "failed";
export type TerminalShell = "powershell" | "cmd" | "bash" | "zsh" | "synthetic";

export interface TerminalSummary {
  id: string;
  name: string;
  shell: TerminalShell;
  working_directory: string;
  process_id: number | null;
  environment_variable_count: number;
  created_at_unix_ms: number;
  status: TerminalStatus;
  exit_code: number | null;
  interactive_unverified?: boolean;
}

export interface TerminalCapabilities {
  platform: "windows" | "linux" | "macos" | "unsupported";
  default_shell: TerminalShell | null;
  shells: Array<{
    shell: TerminalShell;
    display_name: string;
  }>;
  max_sessions: number;
  max_environment_variables: number;
}

export interface CreateTerminalRequest {
  rows: number;
  cols: number;
  shell: TerminalShell;
  name?: string;
  working_directory?: string;
  environment: Record<string, string>;
}

export type CredentialKind = "password" | "api_token" | "ssh_key";

export interface CredentialReference {
  id: string;
  name: string;
  kind: CredentialKind;
  purpose: string | null;
  address: string | null;
  username: string | null;
  secret_state: "not_configured" | "available";
  secret_updated_at_unix_ms: number | null;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  version: number;
}

export interface CreateCredentialReference {
  name: string;
  kind: CredentialKind;
  purpose?: string;
  address?: string;
  username?: string;
}

export interface UpdateCredentialReference extends CreateCredentialReference {
  expected_version: number;
}

export type TargetKind =
  "database" | "http_service" | "ssh_host" | "telnet_host";
export type TargetEnvironment = "development" | "test" | "production";
export type PostgresTlsMode = "verify_full";

export interface PostgresTargetConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  tls_mode: PostgresTlsMode;
}

export interface Target {
  id: string;
  name: string;
  kind: TargetKind;
  environment: TargetEnvironment;
  description: string | null;
  address: string | null;
  username: string | null;
  allow_insecure_protocol: boolean;
  credential_reference_id: string | null;
  postgres: PostgresTargetConfig | null;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  version: number;
}

export interface CreateTarget {
  name: string;
  kind: TargetKind;
  environment: TargetEnvironment;
  description?: string;
  address?: string;
  username?: string;
  allow_insecure_protocol?: boolean;
  credential_reference_id?: string;
  postgres?: PostgresTargetConfig;
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
  | "synthetic_health_check"
  | "postgres_connection_check"
  | "command_execution";
export type ApprovalResultScope =
  "status_only" | "metadata_summary" | "sanitized_output";
export type ApprovalState =
  "pending" | "approved" | "denied" | "revoked" | "expired";

export interface ActionTemplate {
  command?: CommandConfig | null;
  one_time?: boolean;
  terminal_available?: boolean;
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
  command?: CommandConfig;
  target_id: string;
  name: string;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  description?: string;
  timeout_seconds: number;
}

export interface CredentialSlot {
  name: string;
  credential_id: string;
  injection: "stdin" | "environment" | "argument" | "file" | "protocol";
  environment_variable: string | null;
}
export interface CommandConfig {
  terminal_id?: string | null;
  database?: DatabaseConfig | null;
  git?: GitConfig | null;
  http?: HttpConfig | null;
  ssh?: SshConfig | null;
  telnet?: TelnetConfig | null;
  parameters?: ParameterDefinition[];
  program: string;
  working_directory: string;
  arguments: string[];
  slots: CredentialSlot[];
}
export interface DatabaseConfig {
  engine: "postgres" | "mysql";
  operation: "check" | "version" | "query";
  host: string;
  port: number;
  database: string;
  username: string;
  password_slot: string;
  tls_mode: "verify_full" | "loopback_plaintext";
  ca_certificate: string | null;
  query: string;
  columns: string[];
  max_rows: number;
}
export type HttpValueSource =
  | { kind: "literal"; value: string }
  | { kind: "parameter"; name: string }
  | { kind: "credential"; name: string; prefix: string };
export interface SshConfig {
  transfer?: TransferConfig | null;
  host: string;
  port: number;
  username: string;
  host_key_sha256: string;
  authentication:
    | { kind: "password"; slot: string }
    | { kind: "private_key"; slot: string; passphrase_slot: string | null };
  remote_program: string;
  arguments: Array<
    { kind: "literal"; value: string } | { kind: "parameter"; name: string }
  >;
}
export interface TelnetConfig {
  host: string;
  port: number;
  username: string;
  password_slot: string;
  login_prompt: string;
  password_prompt: string;
  command_prompt: string;
  authentication_failure_prompt: string | null;
  commands: string[];
  logout_command: string;
  max_output_bytes: number;
}
export interface TransferConfig {
  direction: "upload" | "download";
  local_path: string;
  remote_path: string;
  overwrite: boolean;
  max_bytes: number;
}
export interface GitConfig {
  operation: "inspect" | "fetch" | "push";
  remote_url: string;
  branch: string;
  username: string;
  token_slot: string;
}
export interface HttpField {
  name: string;
  source: HttpValueSource;
}
export interface HttpConfig {
  method: string;
  url: string;
  headers: HttpField[];
  query: HttpField[];
  body: HttpField[];
  response_fields: { name: string; pointer: string }[];
  accepted_statuses: number[];
}
export type AuthorizationMode = "every_run" | "once" | "time_window";
export type ParameterValue = string | number | boolean;
export interface ParameterDefinition {
  name: string;
  label: string;
  kind: "string" | "integer" | "boolean";
  required: boolean;
  default: ParameterValue | null;
  choices: ParameterValue[];
  max_length: number | null;
}
export interface RunOutput {
  items: Array<{
    sequence: number;
    stream: string;
    text: string;
    created_at_unix_ms: number;
  }>;
  next_cursor: number;
  oldest_cursor: number;
  truncated: boolean;
  has_more: boolean;
  exit_code: number | null;
  state: RunState;
}

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

export interface UpdateActionTemplate extends CreateActionTemplate {
  enabled: boolean;
  expected_version: number;
}

export interface Approval {
  conversation_id: string | null;
  preauthorized: boolean;
  authorization_mode: AuthorizationMode;
  parameters: Record<string, ParameterValue>;
  id: string;
  action_template_id: string | null;
  action_template_version: number | null;
  target_id: string;
  target_version: number;
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

export type ConversationApprovalPolicy =
  "every_task" | "same_task_once" | "conversation_once";
export interface AiConversation {
  id: string;
  summary: string;
  approval_policy: ConversationApprovalPolicy;
  grant_expires_at_unix_ms: number | null;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  version: number;
}

export type ApprovalNotificationChannel = "browser" | "system";
export async function getApprovalNotificationSettings(
  token: string,
): Promise<{ channel: ApprovalNotificationChannel }> {
  return readJson(
    await fetch("/api/v1/notification-settings", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(token),
    }),
  );
}
export async function setApprovalNotificationSettings(
  token: string,
  channel: ApprovalNotificationChannel,
): Promise<{ channel: ApprovalNotificationChannel }> {
  return readJson(
    await fetch("/api/v1/notification-settings", {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ channel }),
    }),
  );
}

export async function listAiConversations(
  sessionToken: string,
): Promise<{ items: AiConversation[] }> {
  return readJson(
    await fetch("/api/v1/ai-conversations", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function setAiConversationPolicy(
  sessionToken: string,
  id: string,
  request: {
    expected_version: number;
    approval_policy: ConversationApprovalPolicy;
    risk_acknowledgement?: string;
  },
): Promise<AiConversation> {
  return readJson(
    await fetch(`/api/v1/ai-conversations/${encodeURIComponent(id)}/policy`, {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}

export interface CreateApproval {
  authorization_mode?: AuthorizationMode;
  parameters?: Record<string, ParameterValue>;
  action_template_id: string;
  reason?: string;
  expires_in_seconds: number;
}

export interface DecideApproval {
  expected_version: number;
  note?: string;
}

export interface ApprovalListResponse extends CatalogListResponse<Approval> {
  execution_enabled: true;
}

export interface ActionTemplateListResponse extends CatalogListResponse<ActionTemplate> {
  execution_enabled: true;
}

export type PolicyDecision = "eligible_for_approval" | "denied";
export type PolicyReasonCode =
  | "fixed_synthetic_scope"
  | "fixed_postgres_connection_check"
  | "fixed_command_template"
  | "template_disabled"
  | "target_incompatible"
  | "postgres_configuration_missing"
  | "credential_missing"
  | "credential_not_configured"
  | "credential_kind_unsupported"
  | "result_scope_unsupported";
export type PolicyRequirement =
  | "validated_parameters"
  | "scoped_authorization"
  | "explicit_approval"
  | "no_parameters"
  | "single_use"
  | "synthetic_only"
  | "transition_revalidation"
  | "tls_verify_full"
  | "read_only_transaction"
  | "structured_status_only"
  | "redacted_output";

export interface PolicyEvaluation {
  policy_version:
    | "synthetic-policy-v1"
    | "postgres-readonly-policy-v1"
    | "credential-command-policy-v1";
  decision: PolicyDecision;
  reason_codes: PolicyReasonCode[];
  requirements: PolicyRequirement[];
  action_template_id: string;
  action_template_version: number;
  target_id: string;
  target_version: number;
  target_environment: TargetEnvironment;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  timeout_seconds: number;
  execution_mode:
    "synthetic_simulation" | "controlled_postgres" | "credential_command";
}

export type RunState =
  "queued" | "running" | "succeeded" | "cancelled" | "failed";

export interface SyntheticRun {
  id: string;
  approval_id: string;
  action_template_id: string;
  target_id: string;
  target_version: number;
  operation: ApprovalOperation;
  result_scope: ApprovalResultScope;
  state: RunState;
  result_status:
    | "synthetic_ok"
    | "postgres_connection_ok"
    | "postgres_connection_failed"
    | "postgres_configuration_invalid"
    | "credential_unavailable"
    | "timed_out"
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
  execution_mode: "controlled_operations";
}

export interface CreateSyntheticRunResponse {
  run: SyntheticRun;
  replayed: boolean;
  execution_mode:
    "synthetic_simulation" | "controlled_postgres" | "credential_command";
}

export type SafeEventKind =
  | "authorization_revoked"
  | "requested"
  | "started"
  | "succeeded"
  | "failed"
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

export async function revokePageSession(token: string): Promise<void> {
  const response = await fetch("/api/v1/session", {
    method: "DELETE",
    headers: sessionHeaders(token),
    credentials: "omit",
    cache: "no-store",
  });
  if (!response.ok)
    throw new SecretBridgeApiError(response.status, "session_revoke_failed");
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

export async function getTerminalCapabilities(
  sessionToken: string,
): Promise<TerminalCapabilities> {
  return readJson<TerminalCapabilities>(
    await fetch("/api/v1/terminals/capabilities", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function createTerminal(
  sessionToken: string,
  request: CreateTerminalRequest,
): Promise<TerminalSummary> {
  return readJson<TerminalSummary>(
    await fetch("/api/v1/terminals", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      headers: {
        ...sessionJsonHeaders(sessionToken),
      },
      body: JSON.stringify(request),
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
