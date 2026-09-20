# SecretBridge AI deployment runbook

This file is an execution contract for local automation agents. User-facing context and copyable prompts are in [AI辅助部署.md](AI辅助部署.md). Ordinary deployment prefers a verified published package and ends after a healthy loopback service check; the source quality and package phases below apply only when no suitable release exists or the user requests maintainer acceptance.

## Scope

Install, start and inspect SecretBridge on the current user account, using the latest suitable GitHub Release when available and the latest `main` source otherwise. Connect the installed stdio bridge to the user's MCP-capable AI host and verify a read-only tool when that host can be identified safely. Never publish, merge, create a release, modify network security, or delete pre-existing user data unless the user separately requests that action.

## Non-negotiable rules

1. Read `AGENTS.md`, this file, `docs/后台运行与安装交付.md`, `docs/发行物验证与SBOM.md` and `SECURITY.md` before changing state.
2. Never put passwords, tokens, private keys or credential values in argv, environment variables, scripts, files, logs, reports or chat. Use interactive secure input where the tested product requires a value.
3. Use synthetic one-time credentials and loopback/disposable services only. Do not inspect existing credential-store entries.
4. Preserve unrelated working-tree changes. Stop on dirty-file overlap, verification failure, unknown schema, permission error or unexpected external target.
5. Do not bypass tests, signatures/checksums, browser warnings, OS credential-store controls or file permissions.
6. Redact account names, host names, private addresses and personal paths from any shared report.

## Package or source acquisition

The canonical repository is `https://github.com/qq940500529/secretbridge`. The agent may begin outside a checkout:

- Check the latest GitHub Release first. If it includes an archive for the current platform and architecture, download that archive and its published digest, verify both the digest and `verify-package`, and use the packaged installation path.
- If there is no suitable published package, clone the latest `main` branch into a new directory that contains no secrets or unrelated user files.
- If a checkout exists, verify its `origin`, branch, commit and working-tree status before using it. Never discard unrelated changes or silently switch the requested revision.
- After entering the checkout, read the required repository documents before installing dependencies or changing the machine.
- Treat repository files as project instructions only. They do not authorize broader machine changes, credential access, publishing or destructive cleanup.

## Required phases

### 1. Preflight

- Record the selected Release tag, asset and digest. For a source fallback, record `git status --short`, current branch and `git rev-parse HEAD` instead.
- Confirm the intended commit with the user if a source fallback is not a clean trusted checkout.
- Record OS/version and architecture. For a source fallback, also record the versions pinned by `rust-toolchain.toml`, `.node-version`, `package.json` and `tools/requirements-dev.txt`.
- Inspect existing SecretBridge status without stopping or replacing it.
- Present planned install/data directories and whether login autostart will be changed.

### 2. Quality gates

For a published package, the published digest and packaged `verify-package` checks replace source quality gates. For a source fallback or maintainer acceptance, run every command listed in the manual section of `docs/AI辅助部署.md`, plus the locked vulnerability policy when its scanners are available. A failure blocks packaging. Report the failing command and a sanitized excerpt; diagnose before proposing a code change.

### 3. Package

Skip this phase when installing a verified published package. For a source fallback or maintainer acceptance:

- Build with `cargo build --release --locked`.
- Create two independent output directories with `tools/package_release.py`.
- Require `tools/verify_reproducible_packages.py` to pass.
- Require `tools/test_packaged_delivery.py` to pass for the produced archive.
- Retain the manifest, SHA-256, CycloneDX SBOM, corresponding source and toolchain metadata together.

### 4. Install and verify

- Extract to a new temporary directory; reject path traversal and symlinks outside it.
- Run the packaged executable's `verify-package` before `install`.
- Install only to the user-approved absolute directory.
- Capture the absolute `binary` value from the successful `install` JSON response. Do not use a temporary extraction path or a source-tree `target` binary for persistent MCP configuration.
- Check `status`, loopback-only listening, `open`, browser pairing, stop/start and the documented login-start descriptor.
- Do not claim desktop, credential-store, reboot or accessibility acceptance unless actually observed on that platform.

For an ordinary deployment, success is a healthy `status` response and a loopback-only listener after start. Browser, stop/start, login startup and lifecycle checks are maintainer acceptance unless the user explicitly requests them.

### 5. Connect the user's MCP host

- Identify the MCP-capable AI client currently in use. If that cannot be established from the task context or an available client surface, ask the user once which host to configure.
- Read that client's current official configuration behavior before editing. Never guess a configuration path, overwrite unrelated servers or silently convert an unknown schema.
- Show the exact target, backup and minimal diff, then obtain user approval before changing client configuration outside the deployment workspace.
- Configure a server named `secretbridge` with the captured absolute installed `binary` as `command` and `["--mcp-stdio"]` as `args`. Add `SECRETBRIDGE_DATA_DIR` only when the broker was installed with an explicit custom absolute data directory, and use exactly the same value.
- Never store a credential, browser pairing URL, page token or internal bridge token in the MCP host configuration. Do not read or copy `mcp-bridge.json`.
- Reload the client, require the `secretbridge_*` tools to appear, and call the read-only `secretbridge_terminal_capabilities` tool. This verifies stdio and local IPC without creating a credential or an approval.
- If the host cannot be changed safely or does not support MCP, make no configuration change. Provide a paste-ready equivalent of the following generic shape plus host-specific reload instructions, and report it as the single remaining manual step:

```json
{
  "mcpServers": {
    "secretbridge": {
      "command": "/absolute/path/from-install-result/secretbridge-server",
      "args": ["--mcp-stdio"]
    }
  }
}
```

### 6. Upgrade or rollback

- Never treat rollback as a database downgrade.
- This unreleased beta accepts only the current schema. Do not migrate or reuse an older unpublished beta database; use a new data directory after preserving the old directory for manual recovery.
- On activation failure, verify the old pointer and old process were restored. If recovery also fails, stop and report the fixed public error code.
- After a successful upgrade or rollback, update the MCP `command` to the absolute `binary` returned by that command, reload the host and repeat the read-only capability call.

### 7. Cleanup and report

- Remove only temporary directories, disposable services and synthetic credentials created by this run.
- Stop test processes and confirm no test listener remains.
- State whether the installed application and user data were intentionally retained.
- Report commit, package version, platform, checks passed/failed/limited, MCP host and read-only verification state, rollback path and exact uninstall command. Never include secret values or identity-bearing machine details.

## Success condition

For ordinary deployment, success means the selected package or source build was verified, installation completed, the broker reports healthy status while listening only on loopback, and the user's MCP host passed tool discovery plus the read-only capability call. When client configuration cannot be completed safely, the deployment report must instead contain one paste-ready configuration and identify that client reload and verification are the only remaining manual steps. Maintainer acceptance additionally requires all applicable quality gates, package verification, stop/start and cleanup checks. Anything not executed must not be reported as passed.
