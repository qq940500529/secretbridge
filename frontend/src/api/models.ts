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
  encrypted_diagnostics_ready: boolean;
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
    recovery_actions: string[];
    occurrences: number;
    failures_with_later_same_template_success: number;
    first_at_unix_ms: number;
    last_at_unix_ms: number;
  }[];
  mcp_failures: {
    code: string;
    stage: string;
    recovery_actions: string[];
    occurrences: number;
    first_at_unix_ms: number;
    last_at_unix_ms: number;
  }[];
  terminal_states: Record<string, number>;
  stale_terminal_references: number;
  state_consistency: {
    active_runs_missing_start: number;
    finished_runs_missing_finish: number;
    active_runs_missing_template: number;
    active_terminal_runs_missing_terminal: number;
  };
  state_consistency_issues: number;
}

export interface UnlockedDiagnosticRecord {
  category: "command" | "event";
  created_at_unix_ms: number;
  data: unknown;
}

export interface DiagnosticExport {
  format: "secretbridge-encrypted-diagnostics-export";
  format_version: 1;
  records: UnlockedDiagnosticRecord[];
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
  retention_truncated: boolean;
}

export interface TotpSetup {
  manual_key: string;
  qr_code_data_url: string;
  expires_in_seconds: number;
  accepted_past_steps: number;
}

export interface CurrentBrowserAuthProof {
  current_pin?: string;
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
  stdin_content?: string | null;
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
  working_directory?: string | null;
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
  terminal_id: string | null;
}

export interface SafeEventListResponse {
  items: SafeEvent[];
  payload_policy: "fixed_safe_messages_only";
}

export interface TerminalListResponse {
  terminals: TerminalSummary[];
}
