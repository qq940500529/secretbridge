# Changelog

[Home](README.md) / Changelog

Changes affecting contributors, project scope and future users are recorded here. Entries under **Unreleased** do not represent a stable release.

## Unreleased

### 0.1.0-alpha.12 · controlled PostgreSQL connection check

- Add the first credential-bearing adapter: a fixed PostgreSQL `SELECT 1` connection check using the native protocol, a read-only serializable transaction and mandatory certificate/hostname verification.
- Route every check through explainable policy evaluation, expiring approval, single-use/idempotent run creation, transition revalidation, timeout, cancellation and fixed safe events.
- Keep passwords inside the operating-system credential store and expose only bounded result states; raw database errors, SQL, parameters, business rows and credentials cannot enter API or event payloads.
- Invalidate target versions when a linked secret is rotated or cleared so previously approved snapshots fail closed.
- Advance SQLite to schema version 7 with history-preserving migrations and add catalog, HTTP, migration and Web-client regression coverage.
- Report `m2_development` and `controlled_operations` through the service status API without weakening the explicit `unverified_same_user` identity warning.
- Update the bilingual UI for controlled PostgreSQL templates, policy requirements, run results and audit events. A real low-privilege target pilot remains an M3 validation task.

### 0.1.0-alpha.11 · native credential configuration

- Add write-only password and API-token management backed by the operating-system credential store on Windows, Linux and macOS; there is no secret read or export route.
- Keep secret values out of SQLite, response bodies, URLs, command arguments, process environments and logs; SQLite stores only availability and last-update metadata.
- Serialize credential mutations, require exact Origin plus an authenticated and versioned request, clear transient Rust buffers with `zeroize`, and attempt rollback when cross-store metadata updates fail.
- Add PostgreSQL target configuration for host, port, database and login user with strict validation and a fixed `verify_full` TLS posture; arbitrary connection strings and TLS-disable options remain absent.
- Advance SQLite to schema version 6 with forward migrations, update the bilingual UI, and add catalog, migration, API and no-read-route regression coverage.
- Keep business-system execution disabled until the fixed PostgreSQL operation is wired through the existing policy, approval, single-use run and safe-event chain.

### 0.1.0-alpha.10 · explainable synthetic policy

- Add an authenticated policy-evaluation endpoint that explains eligibility, fixed reason codes, mandatory safeguards, template and target versions, and the synthetic-only execution mode.
- Snapshot target versions in approvals and runs, advance SQLite to schema version 5, and migrate existing records without discarding workflow history.
- Enforce the same fail-closed policy before approval, run creation, run start and run completion; disabled or changed templates and modified targets invalidate stale authorization.
- Safely stop queued or running simulations when policy changes after creation, using the existing fixed authorization event without exposing configuration details.
- Add a bilingual server-policy preflight card to the Approval center, policy-aware conflict guidance, and cross-layer migration, enforcement, API and Web-client tests.

### 0.1.0-alpha.9 · observable synthetic runs

- Connect approved controlled-action templates to a persistent, single-use synthetic run lifecycle with queued, running, succeeded, cancelled and restart-interrupted states.
- Add caller-supplied idempotency keys stored only as SHA-256 digests: an identical retry returns the original run, conflicting reuse is rejected and one approval cannot authorize multiple runs.
- Add optimistic cancellation, automatic short synthetic completion and startup recovery that marks unfinished persisted runs as failed instead of silently resuming or duplicating work.
- Revalidate approval state before both start and completion; a revoked or expired authorization safely stops its queued or running simulation and emits a fixed authorization event.
- Persist server-generated safe events with monotonic per-run sequences and a database-enforced fixed-message allowlist; no terminal output, business payload, argument, endpoint or credential can enter the event stream.
- Add authenticated run/status/cancellation and safe-event APIs, with exact Origin checks on mutations and explicit `synthetic_simulation` and `fixed_safe_messages_only` response markers.
- Add bilingual Runs and Audit pages with active-state polling, per-run event inspection, filters and clear non-execution notices.
- Advance the SQLite schema to version 4 with migrations from versions 1, 2 and 3, plus lifecycle, idempotency, cancellation, recovery, API and Web-client regression tests.

### 0.1.0-alpha.8 · controlled action templates

- Add persistent controlled-action templates that bind an enabled fixed synthetic operation and result scope to one logical target, a 1–300 second planned timeout and versioned descriptive metadata.
- Bind every new approval to an enabled template and preserve the template ID, version, target, operation and result-scope snapshot in the approval record.
- Add authenticated create, list, update and safe-delete APIs plus a bilingual Policies page with editing, disabling and optimistic conflict recovery.
- Preserve referenced templates and targets so approval history cannot silently lose its subject; disabling a template blocks new approval requests without rewriting existing snapshots.
- Advance the SQLite catalog to schema version 3 with forward migrations from the previously implemented version 1 and 2 layouts.
- Keep both templates and approvals non-executable and free of command, script, endpoint, argument and credential fields.

### 0.1.0-alpha.7 · scoped approval records

- Add a persistent synthetic approval workflow bound to one logical target, one fixed operation, one result scope and a mandatory 1–60 minute expiry.
- Support pending-to-approved or pending-to-denied decisions and approved-to-revoked transitions, with automatic expiry and optimistic version checks on every decision.
- Add authenticated approval APIs with exact Origin validation on mutations, relationship-safe target deletion and a schema-v1-to-v2 SQLite migration.
- Add a bilingual approval center for creating, reviewing, approving, denying and revoking records, including visible expiry, scope, state and version information.
- Keep execution explicitly disabled: approval records cannot run commands, connect to a network target, read a real secret or produce an operation result.
- Add state-machine, expiry, migration, authorization and Web-client regression coverage.

### 0.1.0-alpha.6 · persistent metadata

- Persist credential-reference and logical-target metadata in a versioned SQLite schema under the operating system's local application-data directory.
- Add full-record `PUT` updates, optimistic version checks that reject stale writes, monotonically increasing record versions and bilingual edit/cancel controls.
- Run all SQLite work outside async executor threads; retain session authentication, exact Origin checks, field validation, capacity limits and relationship-safe deletion.
- Keep the database schema free of secret values and network endpoints; real credential storage and business connections remain disabled.
- Add database-reopen, update authorization, versioning and Web API-client regression tests.
- Add locked `rusqlite` 0.40.2 with minimized features and updated third-party records; use platform application-data conventions without adding a directory helper dependency.

### 0.1.0-alpha.5 · configuration catalog

- Start M1 development while retaining unresolved M0 platform isolation as a hard gate for real credentials and releases.
- Add authenticated, memory-only credential-reference and logical-target APIs with strict field validation, bounded capacity and relationship-safe deletion.
- Reject secret-bearing fields at the credential-reference API boundary; keep every reference in `not_configured` state.
- Add bilingual Web forms and lists for credential references and logical targets, with persistent warnings that restart clears data and no business address is accepted.
- Report `m1_development` and `memory_only` configuration storage through the service status API.

### 0.1.0-alpha.4 · resilience boundary

- Report the current OS identity posture as `unverified_same_user` through the status API and dashboard instead of implying verified process isolation.
- Bound every server-to-browser WebSocket send to five seconds so a stalled reader cannot hold a terminal attachment indefinitely.
- Add bounded `flood` and `wait` commands to the synthetic terminal for repeatable output-pressure and cancellation tests without exposing a system shell.
- Extend the PTY integration test with a 2 MiB non-reading-client scenario, 64 KiB replay-bound assertions, cursor truncation evidence and cancellation of a sleeping child.
- Improve narrow-viewport and 200% zoom behavior, add a skip link and accessible names, expose connection changes as status updates, and honor reduced-motion preferences.

### 0.1.0-alpha.3 · supervised reconnect

- Add one-writer input leases: the first client receives input control, concurrent clients attach read-only, and reconnecting the same in-memory client safely replaces its earlier connection.
- Replace whole-buffer replay with monotonic byte cursors so a reconnect receives only output not yet observed by that page.
- Report retained-output truncation and live broadcast gaps explicitly; reconnect resumes from the last client cursor within a bounded 64 KiB buffer.
- Extend the end-to-end PTY test to cover cursor replay, read-only enforcement, lease release, cancellation and immediate browser-session revocation.
- Add visible bilingual input-lease and replay-recovery states to the terminal UI.

### 0.1.0-alpha.2 · synthetic terminal lifecycle

- Add an isolated, built-in synthetic PTY with bounded dimensions, input, retained output and concurrent-session capacity.
- Add authenticated WebSocket attachment, automatic reconnect, buffered output replay, resize and explicit termination.
- Keep the PTY alive when the browser transport disconnects; integration tests cover detach, reattach and output replay.
- Store only SHA-256 digests of bootstrap and browser-session tokens in service memory; expire sessions after 30 minutes and support explicit revocation.
- Add xterm.js 6 and `portable-pty` 0.9 with locked dependencies and updated third-party review records.
- Continue to reject system shells, user commands, real credentials and business-system targets.

### Licensing

- Identify 数链创元（天津）信息技术有限责任公司 as the copyright holder of company-owned material.
- License the repository under AGPL-3.0-or-later and provide a separate written commercial licensing route for proprietary commercial use.
- Document contribution relicensing boundaries, third-party exclusions and candidate dependency license risks.

### Documentation

- Add a role-based documentation hub, user orientation, developer setup and glossary.
- Reorganize English and Chinese homepages around product purpose and reading paths.
- Add workflow, architecture, approval and lifecycle diagrams with text explanations.
- Standardize navigation, GitHub alerts, reference tables and expandable detail.
- Clarify repository checks, runtime status and supported contribution workflows.

### M0 Web foundation

- Add a React 19, TypeScript 7, Vite 8 and Tailwind CSS 4 bilingual management console.
- Add a Rust 1.98, Axum 0.8 and Tokio local service bound to loopback only.
- Add one-time URL-fragment bootstrap pairing, exact Origin validation and memory-only browser sessions.
- Keep real credential storage, injection and command execution disabled; tests assert synthetic-only mode.
- Add locked Rust and pnpm dependency graphs plus Web and Rust checks to the three-platform CI workflow.
- Record the permanent browser-based UI decision; no desktop shell is planned.

### Project foundation · 2026-09-10

- Establish credential-use boundaries, persistent terminal semantics and a threat model.
- Define Windows, Linux and macOS as implementation targets.
- Specify platform credential/IPC/supervisor abstractions and UI/accessibility goals.
- Adopt AGPL-3.0-or-later and contribution, security and release policies.
- Add limited repository hygiene checks and three-OS CI for those checks.

> [!NOTE]
> Synthetic paths run in Windows, Linux and macOS CI. Native identity isolation, credential stores and business-system adapters remain unverified and disabled.

---

[Roadmap](ROADMAP.md) · [Documentation](docs/README.md)
