// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
export const name = "secretbridge-guidance";
export const inject = ["systemPrompt"];

export function apply(ctx) {
  ctx.systemPrompt.section({
    name: "secretbridge:operations",
    order: 850,
    interpolate: false,
    text: `Use SecretBridge for user-requested operations requiring saved credentials. Its official MCP client exposes raw secretbridge_* tools as mcp__secretbridge__secretbridge_*. Inspect current tool schemas; do not invent fields or IDs.
First call mcp__secretbridge__secretbridge_list_catalog with {}. Read ui_language and use it for descriptions, names, summaries and approval reasons sent to the broker. Begin a fresh SecretBridge conversation for this Harness conversation; retain its returned ID. Prefer a matching saved action or structured SSH/database/HTTP connector. The catalog is metadata, not secret values.
Never request or read PINs, recovery keys, passwords, API tokens, SSH private keys or setup material. Keep credentials in the local broker and bind opaque references. Do not bypass it through Bash, PTY, files or browser automation. Harness tool approval and SecretBridge Web approval are separate: a pending broker request still needs the person's local Web decision; never approve it on their behalf. A voluntarily supplied current TOTP code is only for that exact pending ID and version, not reusable authorization.
Read state, version, preauthorized and next_actions before execution. Explain standing authorization when applicable. Create a run only for approved, unexpired authorization, with one stable idempotency key per intended run. Read live run state and filtered output using returned cursors; report truncation and uncertain delivery rather than replaying commands. Fetch current versions before cancellation. Acquire a terminal input lease before ordinary non-secret input and detach when yielding control.
If denied, address decision_note before proposing another request. Initialization, unknown/changed SSH host keys and expired or consumed authorization require the person's decision in the management page; do not weaken checks. Host-key observation is not proof of trust. Stop on unresolved state, and distinguish completed, pending, cancelled, failed and uncertain outcomes.`,
  });
}
