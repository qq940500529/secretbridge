# Changelog

## 0.2.0-beta.1

- Added detached native start/open/status/stop commands using the authenticated local IPC channel. Closing the launcher no longer owns the broker lifetime, and pairing tokens stay out of CLI results.
- Added graceful cancellation, page-session revocation and owned terminal cleanup, rejection of new work during shutdown, Unix termination handling, and a confirmed Web settings stop control.
- Added checksum-verified immutable version installations, matching executable/Web/schema validation, activation failure recovery and previous-release rollback without overwriting configuration data.
- Added explicit per-user login startup controls for Windows, Linux desktop sessions and macOS, ownership-checked startup files and transactional restoration on write failures.
- Added manifest-scoped uninstall with default data retention and an explicit catalog-removal option; operating-system credentials and unknown files remain untouched.
- Added native package generation with corresponding source snapshots, third-party license texts and SHA-256 sidecars, three-platform isolated lifecycle acceptance and an unsigned release-build workflow.
- Desktop login/reboot observation, signing and clean-machine usability acceptance remain separate from process-level CI tests.

## 0.1.0-alpha.32

- Added settings workflows for non-secret configuration export, read-only import preflight and explicit confirmation, remapping imported UUIDs and credential slots without replacing existing records.
- Added persistent digest-based import receipts so retries, lost responses and broker restarts do not create duplicate records; staging failures leave the live catalog unchanged.
- Added bounded native SQLite consistency backups including committed WAL pages, standalone backup downloads and schema/integrity/relationship preflight.
- Added offline inspection and restoration into a new data directory only. Restored references require secret re-entry, pending/approved grants are revoked and unfinished runs are interrupted; existing data directories and credential stores remain untouched.
- Added automatic pre-migration rollback snapshots and database rollback on migration failure, plus concise diagnostics restricted to fixed environment fields, counts and allowlisted error codes.
- Enabled existing rusqlite backup/serialize features, migrated the catalog to schema 15 and added backend, real local credential-command recovery and browser workflow regressions. No new application dependency was added.

## 0.1.0-alpha.31

- Reorganized the console into Credentials, Connections, Tasks, Terminal, History and Settings, with task and history sub-navigation.
- Added searchable master-detail workspaces and native modal creation/editing/authorization/run forms, preserving inputs after retryable failures and restoring keyboard focus.
- Connected connection details to task credentials, available tasks, authorization requests and recent execution output; new runs reveal results automatically.
- Filtered expired and unrelated approvals, added page-session unpairing through the existing API, and introduced narrow-screen bottom navigation.
- Added workbench component and headless browser workflow tests; no new application dependencies or schema migration.

## 0.1.0-alpha.30

- Added native PostgreSQL/MySQL connection checks, version queries and registered read-only SELECT/WITH templates, using driver-bound string/integer/boolean values rather than SQL interpolation.
- Added explicit selected columns, row/byte budgets, truncation reporting, NULL handling and text-based numeric results to preserve long integers and decimal precision in the browser.
- Added bilingual database configuration, frozen approval review and table-shaped run results; reused Web/MCP authorization, idempotency, history and SQLite configuration persistence.
- Added per-template verified TLS and private CA support, with plaintext limited to numeric loopback addresses, native interruption and bounded connection cleanup.
- Added real native database, function-write rejection, TLS, Web/MCP and configuration-reopen tests; added a disposable Docker acceptance script and dedicated CI job with synthetic credentials.
- Locked mysql_async 0.37.1 with minimal Rust/rustls/ring features; recorded runtime licenses, compression/hash dependencies and test-only server distribution boundaries.

## 0.1.0-alpha.29

- Added native single-file SFTP upload/download through the existing pinned SSH password/private-key authentication, fixed paths, explicit replacement, size limits, temporary-file commit and bounded cleanup reporting.
- Preserved existing destinations on transfer failure and cancellation; upload replacement requires the server's POSIX rename extension, and no-overwrite download uses exclusive hard-link commit.
- Added Git HTTPS token tasks for fixed-branch inspection, fetch and non-forced push using a user-installed Git executable. Fetch does not merge the working tree; push cannot be rolled back by cancellation.
- Kept Git authentication out of URLs, argv, credential helpers and temporary files. Auth headers exist only in the task's child-process environment; raw tokens and known encoded authentication representations are filtered before output storage.
- Added dedicated bilingual editors, frozen approval previews, MCP execution-kind summaries, and real local SFTP/Git smart-HTTP, Web API, native MCP/IPC and SQLite reopen regression coverage.
- Added exact russh-sftp 3.0.0 and base64 0.22.1 dependencies with third-party notices. Git over SSH, recursive transfers, clone, merge and force-push are not included.

## 0.1.0-alpha.28

- Added native SSH credential tasks with mandatory SHA256 host-key pinning, password and Ed25519/ECDSA private-key authentication, including separate encrypted-key passphrase references.
- Added fixed remote programs and independently POSIX-quoted literal/ordinary arguments, Web configuration and resolved approval review, MCP execution-kind summaries and cursor-based filtered stdout/stderr.
- Closed the underlying SSH transport on completion, timeout and cancellation; retained actual remote exit codes and fixed failure codes without upstream exception text. Disconnecting does not guarantee remote process termination or rollback.
- Restricted broker logs to application targets even when RUST_LOG enables global trace, keeping upstream raw protocol logs outside the normal diagnostic channel.
- Added a real local SSH service fixture covering host rejection before authentication, key/password authentication, UTF-8/secret fragments, failures, timeout/cancel socket closure, Web/MCP workflows and SQLite reopen.
- Locked the Apache-2.0 russh dependency with its ring-only backend and reviewed the additional fiat-crypto MIT license option. SSH file transfer and Git remain separate follow-up work.

[Home](README.md) / Changelog

Changes affecting contributors, project scope and future users are recorded here. Entries under **Unreleased** do not represent a stable release.

## Unreleased

### 0.1.0-alpha.27 · native HTTP credential tasks

- Add a native HTTP/HTTPS executor and structured Web request editor for fixed methods and destinations, named headers, encoded query parameters and flat JSON bodies. Credential slots are confined to headers and body; ordinary body parameters retain string, integer and boolean types.
- Reuse template versioning, frozen approval parameters, explicit user approval, time-window grants, idempotency, four-task concurrency, cancellation and bounded run output. MCP template summaries identify HTTP execution without returning credentials or credential IDs.
- Default to status-only results; optionally select JSON Pointer fields from responses bounded to 256 KiB. Filter selected output before persistence or return, and expose fixed error codes instead of transport errors or error bodies. HTTP status codes are not process exit codes.
- Verify HTTPS with platform roots; disable redirects, environment proxies and TLS key logging. Add real loopback-server tests and native MCP/IPC acceptance. Private CA files, arbitrary response bodies, nested body templates, uploads and dynamic paths are not included.
- Lock reqwest 0.13.5 under MIT OR Apache-2.0 with minimal features and the existing ring crypto provider; retain SQLite schema v14 and compatibility with existing program tasks.
- Flush terminal WebSocket closing frames after lag or revocation, and make flood acceptance follow explicit lag/reconnect notifications rather than assume a fixed sleep guarantees completion.

### 0.1.0-alpha.26 · parameterized reusable tasks

- Add ordinary text, integer and boolean parameters with required/default/choice/length validation, bounded payloads and whole-argument placeholders. Keep values separate from credential slots and never recursively expand supplied text.
- Freeze resolved values and authorization mode at approval creation. Web and MCP share the same validation, explicit user decision and execution path.
- Support per-run confirmation, current-run-only authorization and time-limited repetition of exactly the same confirmed values. Configuration drift, credential rotation, expiry and revocation continue to invalidate authorization.
- Preserve idempotent retries; repeated time-window runs need distinct keys. Display confirmed values, resolved arguments, live elapsed time, exit status and cautious retry guidance in the Web console.
- Upgrade SQLite to schema v14 while preserving events, retained output, exit codes and existing single-use grants. Add real-process parameter, native MCP, authorization-consumption and migration regression coverage without new application dependencies.
- Commit process exit code and completion state in the same transaction, eliminating a client-visible race observed by the Windows native MCP test.

### 0.1.0-alpha.25 · credential command execution and streaming redaction

- Extend existing templates, single-use approvals and idempotent runs with fixed local program tasks and named credential slots for stdin, child environment, arguments and temporary files.
- Keep credential values out of tool requests and template definitions; add an explicit sanitized-output scope and show program/argument/slot configuration before Web approval.
- Filter raw stdout/stderr bytes across read boundaries before decoding, bounded persistence or return; preserve split UTF-8 text and filter raw, UTF-16, JSON-escaped and common percent-encoded representations.
- Add Web run output and `secretbridge_read_run_output` over native IPC with chunk-sequence cursors, explicit replay gaps and process exit status; preserve retry deduplication without rerunning programs.
- Bound command concurrency, support timeout/cancellation and process-tree termination, clean transient credential files, report cleanup failures and recover managed leftovers on broker startup.
- Upgrade SQLite to schema v13 without removing existing workflows; credential rotation invalidates approvals for linked command templates.
- Add real-program acceptance for all injection methods, native MCP/IPC output, encoding boundaries, retention gaps, credential rotation, cancellation, timeout and recovery cleanup. No dependencies were added; output filtering is not a sandbox or universal secret recognizer.

### 0.1.0-alpha.24 · AI terminal control and live state

- Add ten MCP tools for ordinary terminal capability discovery, list/create, attach, bounded cursor reads, write/resize, Ctrl+C, detach and close through the existing native IPC broker.
- Scope attachments to internally generated MCP-session identities; preserve input leases across calls, release them on orderly disconnect, and expire idle attachments without stopping their processes.
- Provide byte-exact replay alongside a UTF-8 preview, explicit retention gaps, bounded long polling and shell lifecycle/exit status; never retry mutating terminal input automatically.
- Add an Origin-checked, first-frame-authenticated WebSocket invalidation stream that closes on session expiry or revocation and carries no resource values or output.
- Refresh approval, run and terminal views on live changes, reconcile snapshots on reconnection, and replace frequent polling with a slow fallback for expiry and unavailable WebSockets.
- Keep ordinary terminal output separate from credential-backed execution: no secret injection or general streaming redaction is claimed on this path.
- Add real-shell MCP/native-IPC acceptance, client-isolation, expiry, protocol-boundary, realtime-authentication and Web reconnection tests. No dependencies were added.

### 0.1.0-alpha.23 · real persistent terminals

- Replace the production synthetic PTY launcher with platform-aware real shells: PowerShell and CMD on Windows, Bash on Linux, and Zsh on macOS.
- Add authenticated shell-capability discovery and bounded terminal creation settings for session name, existing absolute working directory, and ordinary process environment variables.
- Preserve terminal processes across browser detachment and reconnect from monotonic output cursors while retaining the existing input lease, bounded replay, resize, backpressure, revocation, and force-termination behavior.
- Report session shell, initial working directory, process ID, environment-variable count, lifecycle state, and exit code without exposing process environment values.
- Rework the Web terminal into a task-oriented create form, session list, live terminal surface, explicit detach, reconnect, and terminate/remove actions.
- Order final PTY output before process-exit notifications so fast commands do not lose their trailing output.
- Add cross-platform real-shell integration acceptance for process environment, working directory, browser reconnection, natural exit, long-command termination, plus Windows CMD coverage; retain the synthetic child only for deterministic stress tests.

### 0.1.0-alpha.22 · core product reset

- Remove the security-validation center, platform-evidence workspace, pilot-readiness snapshots and governed pilot campaigns from the Web UI, HTTP API, domain layer and tests.
- Advance SQLite to schema version 12 and remove the eight obsolete governance/evidence tables during upgrade while preserving credentials, targets, templates, approvals, runs and audit events.
- Remove development-stage and same-user-boundary metadata from the runtime status API and operator dashboard; the limitation remains documented without dominating the product workflow.
- Retain the security controls that directly protect credential-assisted execution: loopback binding, pairing/session/Origin checks, write-only secret APIs, OS credential storage, approval/version/idempotency controls, local IPC and verified PostgreSQL TLS.
- Replace the roadmap and architecture documents with a feature-first plan centered on real persistent terminals, immediate AI control, credential injection with streaming redaction, reusable tasks and common connectors.
- Simplify the documentation hub, implementation design and security model so release hardening remains a development responsibility rather than a user-facing product module.

### 0.1.0-alpha.21 · PostgreSQL TLS remediation and live adapter evidence

- Add an opt-in process-level `SECRETBRIDGE_POSTGRES_CA_CERT` trust bundle for private PostgreSQL CAs while retaining certificate-chain and hostname verification.
- Fail closed on relative, missing, empty, symbolic-link, non-file and over-64-KiB CA inputs; configuration failures remain an enumerated result and do not expose parser or filesystem errors.
- Add an opt-in ignored integration test that exercises the production native adapter against an explicitly provisioned TLS PostgreSQL instance.
- Verify a local isolated PostgreSQL 18.6 instance with TLS 1.3 and a restricted test role across success, stale-password rejection after rotation, untrusted CA, hostname mismatch and unavailable-port scenarios.
- Document private-CA operation, the repeatable live-test contract, evidence boundaries and complete cleanup requirements. The evidence is local Windows engineering validation, not a production pilot, cross-platform certification or independent security review.

### 0.1.0-alpha.20 · governed low-privilege pilot workspace

- Add time-bounded PostgreSQL pilot campaign records that bind an exact test target/template version, readiness snapshot, platform snapshot, target-owner authorization reference and least-privilege review reference.
- Enforce the `registered → active → closing → closed` lifecycle with revocation and automatic expiry; activation fails closed on target, template or evidence drift.
- Create an immutable 11-scenario verification matrix for success, authentication rejection, timeout, DNS, TLS, network interruption, credential rotation, authorization revocation, service restart and credential cleanup.
- Require versioned evidence and reviewer references for recorded results. Closure requires every scenario to pass and the linked temporary credential to be cleared.
- Persist bounded campaigns and scenario evidence in SQLite schema version 11, preserve existing platform evidence through migration, and prevent referenced targets or templates from being deleted.
- Add authenticated Web APIs and a bilingual master-detail pilot workspace with collapsible registration, row-based evidence editing, lifecycle actions and Markdown/JSON export.
- Keep the workflow governance-only: it does not automatically contact remote targets, does not verify operator-entered external authority and is intentionally absent from the MCP tool surface.
- Add catalog lifecycle/drift/migration tests, HTTP secrecy and boundary tests, Web API tests, operator documentation and UI-copy regression coverage.

### 0.1.0-alpha.19 · platform identity and IPC evidence candidate

- Add a fixed, non-secret platform probe for runtime-directory, connection-document, native IPC, credential-store selection and installed-identity evidence without returning usernames, operating-system identifiers, hostnames, paths, endpoint names or secrets.
- Verify real directory/file/socket types and private POSIX permission masks on Linux and macOS, and record the existing Unix peer-credential enforcement as a fixed implementation fact.
- Record Windows first-pipe-instance and remote-client rejection controls while keeping directory/file DACL inspection, explicit named-pipe DACL and pipe-client token checks visibly open instead of treating token authentication as identity isolation.
- Persist up to 128 ordered platform-boundary snapshots in SQLite schema version 10 and recompute a canonical SHA-256 digest whenever evidence is read.
- Add authenticated list, create, detail and report APIs. Collection requires exact Origin and an empty body, so callers cannot select paths, omit checks or provide their own conclusion.
- Add a bilingual master-detail Platform evidence workspace with row-based checks and Markdown/JSON export, and incorporate the latest digest-verifiable platform snapshot into pilot-readiness evaluation.
- Keep every product-generated snapshot at `attention` or `blocked` and retain `identity_boundary=unverified_same_user`; independent fresh-install and hostile-subject evidence remains required to finish this package.
- Add catalog tamper detection, schema migration coverage, HTTP-boundary tests, Web-client tests and a platform acceptance guide. The engineering candidate is complete; three-platform installed acceptance remains open.

### 0.1.0-alpha.18 · enterprise workflow UI

- Remove milestone labels, roadmap promotion and implementation-phase copy from the runtime UI so operators see business purpose, state and next action instead of development metadata.
- Replace dashboard feature-card grids with a compact operational status surface and reserve notices for actionable security boundaries.
- Move credential, target, policy, approval and run creation into collapsible task entry areas above their records instead of permanently placing creation cards beside lists.
- Present catalogs, approvals, runs and audit events as continuous row-based collections with restrained borders, hierarchy and inline metadata.
- Use master-detail navigation for validation and pilot-readiness evidence; render checks as ordered rows rather than independent status cards.
- Align terminal sessions with the same master-workspace pattern and retain the terminal itself as the sole high-emphasis work surface.
- Add a source-level regression check that prevents milestone labels and development-stage fields from returning to rendered Web views.

### 0.1.0-alpha.17 · pilot readiness evidence workspace

- Add a paired-Web pilot-readiness workspace that aggregates the complete local test-target configuration chain and the latest security-validation evidence without reading secrets or contacting a remote target.
- Evaluate ten fixed gates covering a dedicated test database, complete PostgreSQL TLS metadata, native credential availability, an enabled status-only template, validation evidence and four explicit external/manual requirements.
- Keep technical eligibility distinct from authorization: missing technical prerequisites produce `blocked`, while a complete local chain remains `attention` until OS identity, target-owner authorization, remote least privilege and independent review have external evidence.
- Persist bounded readiness snapshots and ordered checks in SQLite schema version 9, recompute canonical SHA-256 digests on reads and preserve validation history through the v8-to-v9 migration.
- Add authenticated history, creation, detail and report APIs. Creation requires exact Origin and an empty body so callers cannot select a favorable target, omit checks or supply their own conclusion.
- Add a bilingual Pilot readiness view with history, candidate/eligible counts, gate details and Markdown/JSON downloads; reports contain aggregate counts and fixed evidence, never target names, addresses, usernames, credential references or approval notes.
- Replace the milestone-only roadmap with a complete acceptance-package history and forward plan, and add a mature-state architecture and feature specification for orderly future development.
- Add catalog aggregation, evidence-tamper, migration, HTTP-boundary and Web-client tests plus a dedicated operating and acceptance guide.

### 0.1.0-alpha.16 · security validation and evidence center

- Add a paired-Web security validation center that runs a complete suite without accepting commands, parameters, target identifiers or secret values from the caller.
- Inspect the current SQLite catalog for integrity, foreign-key violations, secret-value-shaped credential columns and persisted safe-event messages outside the fixed allowlist.
- Reuse the production catalog, policy and transition code in disposable in-memory scenarios to verify approval-bypass rejection, single-use/idempotent execution, target-rotation invalidation, approval revocation and interrupted-run recovery.
- Persist server-generated fixed evidence in SQLite schema version 8 with bounded history, stable check codes, application/platform metadata and a canonical SHA-256 evidence digest.
- Add authenticated history/detail/report APIs plus a bilingual Web view with status summaries and Markdown/JSON downloads; report retrieval verifies the stored digest and states that self-validation is not independent certification.
- Keep OS identity isolation as an explicit manual warning and leave real least-privilege targets, hostile same-user tests and independent review as M3 gates.
- Add catalog tamper-detection, schema migration, HTTP boundary and Web-client coverage, and document the operating procedure, report interpretation and acceptance baseline.

### 0.1.0-alpha.15 · native local MCP bridge transport

- Replace the broker-to-stdio-bridge loopback HTTP client and private Web routes with a length-prefixed native IPC protocol: Windows named pipes and Unix domain sockets on Linux/macOS.
- Keep the MCP surface at the same eight fixed operations, require a rotated 256-bit runtime token as defense in depth, reject unknown document/request/response fields and cap requests, responses, concurrent connections and I/O time.
- Create Windows pipes as first instances with remote clients rejected; place Unix sockets inside the private application-data directory, set socket and connection-document permissions to `0600`, and require the peer UID to match the directory owner.
- Reload the version-2 connection document before every request so a detached stdio bridge follows broker endpoint and token rotation without replaying a failed operation.
- Validate the data directory, connection file type, platform endpoint shape and Unix ownership/permissions; remove the connection document and Unix socket only with their owning broker lifecycle.
- Remove Reqwest and the internal MCP HTTP surface from the runtime dependency graph, while retaining the explicit `unverified_same_user` posture until installed ACLs and hostile-client boundaries are independently verified on all three platforms.

### 0.1.0-alpha.14 · detached MCP bridge

- Split the long-lived Web broker from the lightweight `--mcp-stdio` bridge so an MCP disconnect no longer stops the console, controlled runs or persistent terminal sessions.
- Publish an ephemeral, versioned connection document in the private application-data directory; store a random bridge bearer token only in that runtime file and its digest in broker memory, never in SQLite, command arguments or environment variables.
- Restrict the private bridge to exact loopback endpoints for the existing eight fixed tools, disable proxies and redirects, require a valid token and cap response bodies at 512 KiB.
- Reload the connection document before every MCP request so one bridge process can reconnect after broker address and token rotation without replaying an operation automatically.
- Remove the bridge document on orderly broker shutdown only when it still belongs to that broker instance, and reject symlinks, non-loopback addresses, malformed tokens and oversized documents.
- Add lifecycle tests for invalid authentication, MCP disconnect, broker survival and broker replacement; retain the explicit `unverified_same_user` posture because a bearer file and loopback transport are not OS identity isolation.
- Lock Reqwest 0.13.5 with default features disabled and only JSON support for the private HTTP client; record its MIT-or-Apache-2.0 license and transitive dependency impact.

### 0.1.0-alpha.13 · bounded MCP stdio tools

- Add an MCP stdio server using the official Rust SDK, started with `--mcp-stdio` alongside the local Web console in one SecretBridge process.
- Expose eight fixed tools for template discovery, policy evaluation, approval request/status, approved run creation/status/cancellation and fixed safe events.
- Keep approval decisions in the trusted Web console and omit secret access, target addresses, template descriptions, approval notes, SQL, shell commands, connection strings, operation parameters, raw adapter errors and business rows from the MCP surface.
- Reuse the existing policy, expiry, single-use approval, idempotency, transition revalidation, cancellation and database-enforced safe-event boundaries instead of introducing a parallel execution path.
- Reserve MCP stdout for JSON-RPC, route diagnostics to stderr, reject undocumented startup arguments and document the current same-process lifecycle limitation.
- Add protocol-level tests that assert the exact tool and input schema surface, block execution before human approval, start and cancel an approved synthetic run, and verify sensitive markers do not cross the MCP result boundary.
- Lock `rmcp` 3.3.0 and `schemars` 1.2.2 and record their Apache-2.0/MIT obligations and transitive dependency review status.

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
