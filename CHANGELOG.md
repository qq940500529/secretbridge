# Changelog

[Home](README.md) / Changelog

SecretBridge has not published its first GitHub Release. This file records the current prerelease contract instead of preserving a development diary for every internal alpha. Pull requests and Git history remain the source for implementation history.

## Unreleased — 0.2.0-beta.4

### Product

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

- Recommend permission-aware AI-assisted deployment while retaining complete manual commands and stop conditions.
- Reorganize documentation by reader task, remove obsolete prototype wording and replace historical progress logs with current behavior and limitations.

### Known limitations

- No public release or signed package exists yet.
- Windows, Ubuntu and macOS still require release-candidate desktop evidence for credential stores, browser pairing, login/reboot recovery and assistive technology.
- Ordinary terminals are not credential sandboxes. Software running with the same operating-system account may be able to bypass application controls.
- The project does not support arbitrary SQL, arbitrary remote scripts, Git SSH, recursive SFTP or unrestricted credential export.

## Versioning before 1.0

Until the first public release, database and package compatibility may be reset when doing so removes unsafe or unnecessary migration code. Each public release will receive a conventional dated changelog section and immutable tag.
