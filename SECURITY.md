# Security policy

[Home](README.md) / Security

> [!WARNING]
> No supported application release is available. Do not use real credentials with this design-stage project. No independent security audit has been completed.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/qq940500529/secretbridge/security/advisories/new). Do not post exploit details or live credentials in a public issue.

| Include | Leave out |
| :--- | :--- |
| Affected commit or version | Passwords, tokens, private keys and session cookies |
| Platform and relevant configuration, sanitized | Production endpoints, personal paths and business exports |
| Minimal synthetic reproduction | Screenshots or logs containing unreviewed sensitive data |
| Expected/actual behavior and security impact | Unauthorized tests against third-party systems |

If private reporting is unavailable, open an issue requesting a private channel **without vulnerability details**, then wait for that channel before sharing evidence.

## Handling a report

1. **Triage:** confirm the affected scope, reproduction and impact.
2. **Contain:** prevent further exposure where possible and identify affected credentials or sessions.
3. **Remediate:** develop a fix and a regression test using synthetic data.
4. **Validate:** review the original attack path and adjacent failure modes.
5. **Disclose:** coordinate a public advisory and version guidance without exposing private information.

Reports are handled as maintainer capacity permits; no response-time SLA is promised. Coordinate disclosure while the issue is assessed and a remediation plan is established.

## If a live secret has been exposed

Revoke or rotate it at its source first. Stop affected sessions, review access and retain sanitized incident evidence. Deleting a file, issue or commit does not guarantee removal from clones, caches or logs.

## Security boundaries

SecretBridge's intended secure mode requires a tested OS/process/identity boundary and narrowly scoped operation adapters. Output masking is not a sandbox, and an assistant with unrestricted access under the credential owner's account can bypass application-level controls.

For implementation review, use the [threat model and acceptance tests](docs/安全模型与验收.md). For contribution data handling, use [CONTRIBUTING.md](CONTRIBUTING.md).

---

[Documentation](docs/README.md) · [Threat model](docs/安全模型与验收.md)
