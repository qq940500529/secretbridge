# SecretBridge · 密桥

**A local credential-use broker for AI-assisted operations — designed for Windows, Linux and macOS.**

[简体中文](README.zh-CN.md) · [Architecture](docs/开发设计.md) · [Security](SECURITY.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md)

## Status: design-stage, not a usable credential manager

This initial repository contains design documents, contribution policies and repository hygiene checks. **There is no application, working UI, credential broker or installer yet. Do not use real credentials.** Cross-platform support and the UI experience below are implementation targets, not verified product capabilities. Repository CI does not test an application.

## The goal

Let an AI request an approved operation without receiving the underlying password. A trusted local broker would retrieve credentials, execute a narrowly scoped operation, and release only reviewed results. Ordinary persistent terminals and credential-bearing operations are separate trust domains.

Planned capabilities:

- A polished, accessible desktop UI with Chinese and English localization.
- Local credential configuration, target binding, approvals, revocation and audit.
- Persistent terminal sessions independent of the UI and AI connection lifecycle.
- Structured MCP tools that never offer a secret-reading API.
- Platform-specific credential, IPC, process supervision and isolation backends.

Proposed stack: Tauri 2, Rust, React/TypeScript and xterm.js; Windows ConPTY and POSIX PTYs on Linux/macOS. Libraries are proposals, not bundled dependencies.

## Security is more than masking

Passing secrets to arbitrary commands and filtering their output cannot reliably stop exfiltration. OS credential stores alone do not isolate an AI with unrestricted execution under the credential owner's account. Production use requires validated identity/process isolation, narrow adapters, authenticated targets and controlled output. See the [threat model](docs/安全模型与验收.md).

## Platform targets

| Platform | Initial validation target | Current status |
|---|---|---|
| Windows | Windows 11 x64 | Planned; application not implemented |
| Linux | Ubuntu 24.04 x64, GNOME and KDE sessions | Planned; application not implemented |
| macOS | macOS 14+ arm64 and x64 | Planned; application not implemented |

Exact supported versions will be published only after testing. Windows/Linux arm64 and other Linux distributions require separate validation. Details: [platform and UI specification](docs/跨平台与UI规范.md).

## Check this repository

Python 3.11+ is sufficient; no package installation or secrets required:

```sh
python tools/check_repository.py
python -m unittest discover -s tests -v
```

Checks cover required files, local document links, selected leak patterns and forbidden artifacts. They are intentionally limited, not a substitute for a mature secret scanner, dependency audit or security review.

## License and responsible contribution

Project-owned material is offered under **GNU Affero General Public License v3.0 only**, SPDX `AGPL-3.0-only`, unless explicitly marked otherwise. See [LICENSE](LICENSE) and [licensing guidance](docs/开源治理与发布.md). Third-party material retains its own license. No warranty is provided; this repository is not security certification.

Do not submit credentials, private infrastructure, business exports, personal information or unlicensed assets. Report vulnerabilities privately through the process in [SECURITY.md](SECURITY.md).
