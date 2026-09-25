# Changelog

[Home](./README.md) / Changelog

This file records public release behavior rather than preserving a development diary for every internal build. Pull requests and Git history remain the source for implementation history.

## 0.3.0-beta.2 — 2026-09-26

- Introduce a new installation line; earlier installation layouts and databases are not supported as in-place upgrade inputs.
- Reorganize the source tree around `frontend/` and `backend/`, with the primary Rust binary named `secretbridge` and a cross-platform local-access helper package inside the backend.
- Separate Web API requests by resource and Rust code by domain, application, transport, persistence, executor and runtime responsibilities. Move documentation into task-oriented sections and remove deployment prompts from the README.
- Treat builds from this refactor as a new installation line. Compatibility with earlier binaries, installation layouts and databases is not promised; existing local data is neither read nor modified by the refactor work.
- Allow a local PIN/passphrase of 6–64 characters; repeated incorrect PIN or recovery attempts now have persistent exponentially increasing wait times (30 seconds initially, capped at one hour).
- Generate a one-time-display recovery key when the PIN is first set. A correct recovery key can reset a forgotten PIN without losing encrypted diagnostics and is rotated after use; existing users can replace it with their current PIN.
- Place PIN setup immediately after the legal agreement in the same first-run dialog, with explicit recovery-key safekeeping confirmation.
- Require a paired local session before presenting PIN enrollment; keep validation messages within a stable-sized dialog and explain when a fresh one-time pairing link is needed.
- Ship the versioned SecretBridge AI operations Skill with native packages, documenting tool selection and the human approval handoff without granting the Skill new broker privileges.
- Advance the configuration schema to 24. Real-device checks remain tracked separately in community issue #139; automated checks do not stand in for human desktop validation.
- Lead new readers through the AI-assisted deployment prompt; documentation-only commits retain repository checks while bypassing unrelated browser, database, Rust and package suites.
- Validate Windows ACL and ACE structures before inspecting private local-access permissions, addressing the pointer-validation findings reported by Code Scanning.

## 0.2.0-beta.9 — 2026-09-24

- Require a PIN during first-time initialization and keep it when an optional authenticator is bound. Encrypt detailed diagnostic records continuously; the user unlocks and selects export fields with the same PIN. Advance SQLite to schema 23.
- Bound operating-system credential reads and writes, including TOTP enrollment and disablement, so stalled native prompts do not leave a usable late secret; strengthened private Unix IPC metadata checks.
- Verify 4,000 synthetic approvals and runs across persistent catalog processes, with backup and resource trends; pin Linux and macOS native package runners to the Beta validation targets.
- Retain bounded, sanitized run output and safe failure details for later inspection and export, including after a terminal closes.
- Stop probing user-supplied command paths before approval; reject malformed paths and let the approved launch report missing files. Generate database test credentials at runtime and keep synthetic scanner markers off disk.

- Advertise concrete output schemas for every MCP tool and document the response paths used by AI clients. Advance the diagnostic export to format 3 with aggregated, fixed-code non-MCP run failure stages and first/last occurrence times; add a cross-resource state and cleanup contract for approvals, runs, terminals and input leases.
- Advance SQLite to schema 22. Group AI requests and runs by conversation ID and summary; let the human choose per-task, identical-task or one-hour conversation-wide approval in Web. Conversation-wide authorization requires a high-risk acknowledgement, displays a persistent warning and can be revoked. Keep the in-page approval dialog visible regardless of notification setting; offer separate browser and native OS notification channels with generic, non-sensitive messages. Track real-desktop and cross-platform verification in a community backlog without treating it as an implementation-issue closure gate.
- Advance SQLite to schema 21 and diagnostic format 2. Record only fixed MCP failure classes with counts and first/last times, and summarize terminal state, stale terminal references, browser authentication mode and bridge protocol version. Complete the README deployment handoff through opening the local management page and a final health check.
- Correlate safe authentication and run events by approval ID in the history view, and export the selected timeline as versioned JSON, JSONL or CSV.
- Retire one-time drafts after denial, expiry or run completion, reject a second approval for the same draft and remove orphan drafts after restart while retaining referenced audit snapshots.
- Check expanded approval review at 4K and laptop widths with 200% browser zoom in synthetic browser acceptance; add a fixed failed-run error-code filter to the safe event view.
- Show pending approvals in a chronological in-page dialog with a live queue count, automatic next-item review and a defer option; keep the full authorization record. Move task templates, authorization and execution to direct sidebar subnavigation.
- Fail closed when a controlled command tries to reuse a terminal after interactive input, and terminate its terminal on command timeout or cancellation. Preserve bounded sanitized terminal-run output with timestamps for later reading, structured download, and deletion after completion.
- Keep MCP one-time drafts out of reusable template lists and configuration exports; provide explicit saving, structured SSH requests, bilingual approval guidance and field-level command argument errors.
- Restore browser PIN/TOTP settings after session recovery and require the current method before changing or disabling it. Add filtered event export, diagnostic previews and broader approval review layout.
- Advance SQLite to schema 20 for one-time draft lifecycle metadata. Published Beta 7/8 schemas migrate in place; keep an independent backup before upgrade.
- Run native package lifecycle acceptance and Rust tests/lint on separate CI runners in parallel, avoid incremental/debug-symbol overhead for one-shot CI builds, and cache the pinned vulnerability scanner without removing any checks.

## 0.2.0-beta.8 — 2026-09-20

### Product

- Add standard six-digit TOTP enrollment with an in-product QR code and manual setup key.
- Allow TOTP to replace the local browser PIN for session recovery.
- Add `secretbridge_confirm_approval`, which lets an AI relay a user-provided one-time code for one identified, version-matched pending approval without operating the Web console.

### Security and reliability

- Keep the TOTP seed exclusively in the operating-system credential store; SQLite records the selected mode, last accepted time step and fixed non-secret audit metadata only.
- Accept a bounded delayed-code window for AI conversation latency, persist the replay guard across service restarts, and retain the existing five-failure cooldown.
- Record bounded, fixed-shape enrollment, verification, throttling and disablement events without storing codes or setup material.
- Never expose the setup key or QR code through MCP. Fixed tool instructions prohibit requesting, repeating, retaining or reusing a code and continue to prohibit AI control of the Web console.

### Compatibility

- Advance the catalog to schema 19. Public Beta 7 catalogs are upgraded in place; the release remains prerelease software and independent backups are recommended.

## 0.2.0-beta.7 — 2026-09-20

### Product

- Add address and account metadata to every credential and connection type, plus a read-only MCP catalog for planning without exposing secrets.
- Allow MCP clients to request one-time, non-shell command drafts without a pre-created template; the local user still approves the exact frozen request in the Web console.
- Run ordinary and credential-bearing commands in the same broker-owned continuous terminal while exposing only redacted cursor output to AI clients.
- Add optional PIN/passphrase browser authentication, persistent revocable page sessions, explicit Telnet risk opt-in metadata and automatic opening of the human approval console.

### Security and reliability

- Store only Argon2 PIN verifiers in the native credential store, rate-limit failed verification, and exclude browser sessions and PIN mode from backups.
- Keep secrets out of shell history through private temporary files and retain each terminal's redaction set across later commands until the session closes.
- Recover a new installation record after an incompatible-upgrade cleanup leaves a fully verified release directory, while continuing to reject damaged records and symbolic links.
- Tolerate SQLite WAL/SHM files disappearing during uninstall without treating successful cleanup as a failure.

### Validation

- Pass 165 Rust tests, 92 Web tests, 55 Python tests, three browser engines, two real PostgreSQL/MySQL matrices and a 20-iteration Linux stability soak.
- Exercise Ubuntu package installation, incompatible-schema recovery, native Secret Service lifecycle and locked-keyring failure behavior with disposable data.

## 0.2.0-beta.6 — 2026-09-20

### Deployment

- Complete AI-assisted and manual deployment with existing-install discovery, MCP host configuration, read-only bridge verification and upgrade/rollback path refresh guidance.
- Return the active installed binary path from status, repeat installation and rollback results so automation can reuse one installation across AI clients and conversations.

### Reliability

- Increase successful Windows command-fixture limits without changing production timeout behavior, preventing loaded CI runners from misclassifying slow PowerShell startup as a product timeout.

## 0.2.0-beta.5 — 2026-09-20

### Product

- Added a bilingual first-run License Agreement and Disclaimer, versioned local consent, system-language defaults and a persistent language preference.
- Added in-product links for sanitized public issue reports and private vulnerability reports.
- Added local browser pairing, revocable page sessions, a searchable workbench and reconnectable platform terminals.
- Added write-only native credential storage and controlled command, HTTP, SSH, SFTP, Git HTTPS, PostgreSQL and MySQL operations.
- Added explicit approval, frozen parameters, single-use and time-window grants, idempotent execution, cancellation, bounded output and audit events.
- Added non-secret configuration import/export, SQLite backup/restore, concise diagnostics and native package lifecycle commands.

### Security and reliability

- Filter credential-bearing output before decoding, persistence or return; scan APIs, events, exports, diagnostics and backups with synthetic canaries.
- Fail closed when the native credential store is missing, locked, denied or unavailable, and coordinate native-store changes with versioned catalog state.
- Prevent completed or rejected history from exhausting active approval and run capacity.
- Recover interrupted work with fixed states and propagate storage failures instead of reporting false success.
- Verify package manifests, file digests, schema metadata and CycloneDX SBOMs before installation.

### Engineering and delivery

- Pin Rust 1.98, Node.js 24 and pnpm 11; enforce formatting, linting, tests, licenses and vulnerability checks.
- Exercise Chromium, Firefox and WebKit workflows, real PostgreSQL/MySQL fixtures and three-platform package lifecycles in CI.
- Produce deterministic ZIP/tar.gz packages, matching source archives, checksums and SBOMs.
- Separate large inline test suites from production modules and isolate credential coordination from HTTP routing.
- Centralize database schema metadata at schema 16. Earlier unpublished schemas and packages are intentionally unsupported.

### Documentation

- Published the first community Beta with a user-led cross-platform testing guide and direct feedback routes.
- Recommend permission-aware AI-assisted deployment while retaining complete manual commands and stop conditions.
- Reorganize documentation by reader task, remove obsolete prototype wording and replace historical progress logs with current behavior and limitations.

### Known limitations

- Beta packages are unsigned; operating systems may show an unknown-publisher warning.
- Windows, Ubuntu and macOS still need broader community evidence for credential stores, browser pairing, login/reboot recovery and assistive technology across different machine configurations.
- Ordinary terminals are not credential sandboxes. Software running with the same operating-system account may be able to bypass application controls.
- The project does not support arbitrary SQL, arbitrary remote scripts, Git SSH, recursive SFTP or unrestricted credential export.

## Versioning before 1.0

`0.2.0-beta.5` intentionally does not migrate databases or packages from unpublished development builds. Compatibility between public Betas is defined by each Release note until 1.0; keep independent backups and test upgrades with synthetic data. Each public release receives a dated changelog section and immutable tag.
