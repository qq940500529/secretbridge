# Roadmap

[Home](README.md) / Roadmap

Milestones describe acceptance gates rather than promised dates. The current phase is **design and repository tooling**; application implementation has not started.

## Progress at a glance

| Milestone | Outcome | Status |
| :--- | :--- | :--- |
| Foundation | Architecture, threat model, platform/UI targets and repository governance | Available |
| M0 · Feasibility | Synthetic credential and isolation experiments | Planned |
| M1 · Desktop workflow | UI, approvals, session supervision and reconnection | Planned |
| M2 · Controlled operations | Scoped adapter and MCP integration | Planned |
| M3 · Security pilot | Approved low-privilege testing and independent review | Planned |
| M4 · Distribution | Validated packages, source correspondence and recovery | Planned |

```mermaid
flowchart LR
    A["Foundation"] --> B["M0<br/>Prove boundaries"]
    B --> C["M1<br/>Build workflows"]
    C --> D["M2<br/>Integrate operations"]
    D --> E["M3<br/>Validate security"]
    E --> F["M4<br/>Distribute"]
```

A later milestone cannot bypass an unresolved security prerequisite.

## Acceptance criteria

<details open>
<summary>M0 — Feasibility and isolation</summary>

- [ ] Use only synthetic credentials and targets.
- [ ] Verify the intended identity boundary on Windows, Linux and macOS.
- [ ] Demonstrate authenticated local IPC and rejection of unauthorized clients.
- [ ] Demonstrate PTY lifetime independent of UI and assistant connections.
- [ ] Record unsupported environments and remaining risks.

</details>

<details>
<summary>M1 — Desktop workflow</summary>

- [ ] Implement credential-reference and target configuration.
- [ ] Implement scoped approval and revocation.
- [ ] Provide accessible bilingual navigation and clear task states.
- [ ] Verify reconnect, input leases, output backpressure and cancellation.
- [ ] Keep ordinary terminals separate from credential-bearing operations.

</details>

<details>
<summary>M2 — Controlled operations</summary>

- [ ] Implement one scoped database adapter with least-privilege access.
- [ ] Implement MCP request, status, cancellation and safe-event tools.
- [ ] Validate idempotency and unknown-result handling.
- [ ] Reject arbitrary credentialed shell input and output bypasses.

</details>

<details>
<summary>M3 — Security pilot</summary>

- [ ] Complete attack and leakage tests in the threat model.
- [ ] Resolve high-risk findings before connecting real test credentials.
- [ ] Obtain explicit approval for a dedicated low-privilege test environment.
- [ ] Validate rotation, revocation and failure recovery.
- [ ] Complete independent review of security-sensitive implementation.

</details>

<details>
<summary>M4 — Distribution</summary>

- [ ] Build and test each supported OS/architecture.
- [ ] Validate native UI, keychain, IPC, install and uninstall behavior.
- [ ] Publish signed packages with corresponding source, SBOM and hashes.
- [ ] Validate upgrade, rollback and configuration recovery.
- [ ] Publish compatibility, known limitations and release notes.

</details>

## Release policy

> [!IMPORTANT]
> Stable status requires documented safety, usability and compatibility evidence. A successful build or repository CI run is not sufficient.

Additional platforms, adapters, remote operation and team features require separate scope and maintenance review. See [release governance](docs/开源治理与发布.md) for distribution requirements.

---

[Architecture](docs/开发设计.md) · [Security gates](docs/安全模型与验收.md) · [Changelog](CHANGELOG.md)
