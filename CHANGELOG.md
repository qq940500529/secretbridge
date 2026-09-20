# Changelog

[Home](README.md) / Changelog

This file records public release behavior rather than preserving a development diary for every internal build. Pull requests and Git history remain the source for implementation history.

## Unreleased

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
