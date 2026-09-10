<div align="center">

# SecretBridge · 密桥

**Controlled credential use for AI-assisted operations.**

Windows · Linux · macOS &nbsp; | &nbsp; AGPL-3.0-only + separate commercial licensing

[简体中文](README.zh-CN.md) · [Documentation](docs/README.md) · [Contribute](CONTRIBUTING.md) · [Security](SECURITY.md)

![Repository checks](https://github.com/qq940500529/secretbridge/actions/workflows/repository-checks.yml/badge.svg?branch=main)

</div>

> [!IMPORTANT]
> **Design-stage project.** Documentation and repository checks are available; the desktop application, credential broker and installers are not. Platform support is a development target. Do not use real credentials.

## Why SecretBridge?

Giving an assistant a password also exposes that password to its surrounding context and tools. SecretBridge is designed to keep credential use behind a local, explicit authorization boundary: an assistant requests an operation; a trusted broker performs it; reviewed results return to the assistant.

| Capability | Intended experience |
| :--- | :--- |
| Credential-use delegation | Configure credentials locally; expose approved operations, not a secret-reading API. |
| Explicit approvals | Review the target, parameters, permissions and output scope before an operation starts. |
| Persistent terminals | Reconnect to sessions without tying their lifetime to a window or one assistant request. |
| Controlled results | Release approved fields and filtered output; retain an attributable audit trail. |
| Cross-platform desktop | Consistent workflows with native credential, IPC and process backends. |

All capabilities above are planned. See [milestone acceptance criteria](ROADMAP.md) for implementation progress.

## How it works

```mermaid
flowchart LR
    A["Assistant<br/>Operation request"] --> B["Policy and approval"]
    U["User"] -->|"Approve scope"| B
    B --> C["Local broker"]
    K["Credential store"] -->|"Private use"| C
    C --> D["Approved target"]
    D --> E["Review output"]
    E -->|"Allowed results only"| A
```

The assistant does not receive the stored secret. Ordinary terminals and credential-bearing operations use separate execution paths; a credentialed session is not an unrestricted shell.

> [!WARNING]
> Masking is not isolation. An assistant with unrestricted access under the credential owner's OS account may bypass application controls. A secure deployment requires a tested identity/process boundary and narrowly scoped adapters. Read the [security model](docs/安全模型与验收.md) before evaluating real-world use.

## Choose a starting point

| Your goal | Start here |
| :--- | :--- |
| Understand the workflow and limitations | [User orientation](docs/使用指南.md) — Chinese |
| Find the right technical document | [Documentation hub](docs/README.md) |
| Contribute code, design or tests | [Contributor guide](CONTRIBUTING.md) and [development setup](docs/开发者入门.md) |
| Review architecture and platform behavior | [Architecture](docs/开发设计.md) and [platform/UI specification](docs/跨平台与UI规范.md) |
| Report a vulnerability privately | [Security policy](SECURITY.md) |

The English and Chinese homepages cover the same product scope. Detailed engineering documents are currently in Simplified Chinese; English translations are welcome.

## Platform targets

| Platform | First validation baseline | Runtime status |
| :--- | :--- | :--- |
| Windows | Windows 11 · x64 | Not implemented |
| Linux | Ubuntu 24.04 · x64 · GNOME/KDE | Not implemented |
| macOS | macOS 14+ · arm64/x64 | Not implemented |

Other OS versions and architectures require their own validation. The CI badge covers repository checks on three runner families, **not application compatibility**.

## Work with this repository

Python 3.11+ and Git are sufficient for the current contribution workflow:

```sh
git clone https://github.com/qq940500529/secretbridge.git
cd secretbridge
python tools/check_repository.py
python -m unittest discover -s tests -v
```

These commands validate documentation and repository hygiene. There is no application launch command yet. See [development setup](docs/开发者入门.md) for expected results, limitations and troubleshooting.

## License and community

Copyright (c) 2026 **数链创元（天津）信息技术有限责任公司**. Company-owned material is offered under **AGPL-3.0-only** or a **separate written commercial license**. Commercial authorization may permit proprietary use within its agreed scope; this repository does not automatically grant such authorization. See [licensing options](LICENSING.md), [commercial licensing](COMMERCIAL_LICENSE.md) and [copyright](COPYRIGHT.md).

AGPL permits commercial use subject to its terms. [Third-party obligations](THIRD_PARTY_NOTICES.md) remain applicable under either route; see the [candidate dependency assessment](docs/依赖许可风险评估.md).

Contributions follow the [contribution guide](CONTRIBUTING.md) and [community standards](CODE_OF_CONDUCT.md). Report ordinary issues through [GitHub Issues](https://github.com/qq940500529/secretbridge/issues); report vulnerabilities through the private channel in [SECURITY.md](SECURITY.md).

---

[Documentation](docs/README.md) · [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md)
