# Changelog

[Home](README.md) / Changelog

Changes affecting contributors, project scope and future users are recorded here. Entries under **Unreleased** do not represent a stable release.

## Unreleased

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
