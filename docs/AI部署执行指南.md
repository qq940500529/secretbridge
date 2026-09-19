# SecretBridge AI deployment runbook

This file is an execution contract for local automation agents. User-facing context and copyable prompts are in [AI辅助部署.md](AI辅助部署.md).

## Scope

Build, verify, install, start, inspect, stop, roll back and uninstall a SecretBridge development candidate on the current user account. Never publish, merge, create a release, modify network security, or delete pre-existing user data unless the user separately requests that action.

## Non-negotiable rules

1. Read `AGENTS.md`, this file, `docs/后台运行与安装交付.md`, `docs/发行物验证与SBOM.md` and `SECURITY.md` before changing state.
2. Never put passwords, tokens, private keys or credential values in argv, environment variables, scripts, files, logs, reports or chat. Use interactive secure input where the tested product requires a value.
3. Use synthetic one-time credentials and loopback/disposable services only. Do not inspect existing credential-store entries.
4. Preserve unrelated working-tree changes. Stop on dirty-file overlap, verification failure, unknown schema, permission error or unexpected external target.
5. Do not bypass tests, signatures/checksums, browser warnings, OS credential-store controls or file permissions.
6. Redact account names, host names, private addresses and personal paths from any shared report.

## Required phases

### 1. Preflight

- Record `git status --short`, current branch and `git rev-parse HEAD`.
- Confirm the intended commit with the user if it is not a clean trusted checkout.
- Record OS/version, architecture and the versions pinned by `rust-toolchain.toml`, `.node-version`, `package.json` and `tools/requirements-dev.txt`.
- Inspect existing SecretBridge status without stopping or replacing it.
- Present planned install/data directories and whether login autostart will be changed.

### 2. Quality gates

Run every command listed in the manual section of `docs/AI辅助部署.md`, plus the locked vulnerability policy when its scanners are available. A failure blocks packaging. Report the failing command and a sanitized excerpt; diagnose before proposing a code change.

### 3. Package

- Build with `cargo build --release --locked`.
- Create two independent output directories with `tools/package_release.py`.
- Require `tools/verify_reproducible_packages.py` to pass.
- Require `tools/test_packaged_delivery.py` to pass for the produced archive.
- Retain the manifest, SHA-256, CycloneDX SBOM, corresponding source and toolchain metadata together.

### 4. Install and verify

- Extract to a new temporary directory; reject path traversal and symlinks outside it.
- Run the packaged executable's `verify-package` before `install`.
- Install only to the user-approved absolute directory.
- Check `status`, loopback-only listening, `open`, browser pairing, stop/start and the documented login-start descriptor.
- Do not claim desktop, credential-store, reboot or accessibility acceptance unless actually observed on that platform.

### 5. Upgrade or rollback

- Never treat rollback as a database downgrade.
- This unreleased beta accepts only the current schema. Do not migrate or reuse an older unpublished beta database; use a new data directory after preserving the old directory for manual recovery.
- On activation failure, verify the old pointer and old process were restored. If recovery also fails, stop and report the fixed public error code.

### 6. Cleanup and report

- Remove only temporary directories, disposable services and synthetic credentials created by this run.
- Stop test processes and confirm no test listener remains.
- State whether the installed application and user data were intentionally retained.
- Report commit, package version, platform, checks passed/failed/limited, rollback path and exact uninstall command. Never include secret values or identity-bearing machine details.

## Success condition

Success means all applicable quality gates and package verification passed, the installed broker starts on loopback, status and stop/start work, and cleanup is accounted for. Anything not executed is **limited**, not passed.
