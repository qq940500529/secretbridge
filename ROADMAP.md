# Roadmap

[Home](README.md) / Roadmap

Milestones describe acceptance gates rather than promised dates. The current phase is **M0 security foundation**: a synthetic-only Web console and loopback Rust service are implemented, while credential handling and command execution remain disabled.

## Progress at a glance

| Milestone | Outcome | Status |
| :--- | :--- | :--- |
| Foundation | Architecture, threat model, platform/UI targets and repository governance | Available |
| M0 · Feasibility | Synthetic credential and isolation experiments | In progress |
| M1 · Local Web workflow | UI, approvals, session supervision and reconnection | Planned |
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

- [x] Enforce synthetic-only mode; real credential and execution paths are absent.
- [ ] Verify the intended identity boundary on Windows, Linux and macOS.
- [x] Demonstrate one-time browser pairing, exact Origin checks and rejection of invalid tokens on a loopback-only service.
- [x] Demonstrate synthetic PTY lifetime independent of WebSocket/UI attachment, including output replay after reconnection.
- [x] Record unsupported environments, verified evidence and remaining risks in the [M0 validation record](docs/M0验证记录.md).

</details>

<details>
<summary>M1 — Local Web workflow</summary>

- [ ] Implement credential-reference and target configuration.
- [ ] Implement scoped approval and revocation.
- [x] Provide bilingual navigation and clear task states; full accessibility verification remains a release gate.
- [ ] Verify reconnect, input leases, output backpressure and cancellation.
  - Implemented in synthetic mode: cursor-based reconnect, single-writer leases, bounded replay with explicit gap/truncation signals, and cancellation; slow-consumer stress limits remain to be measured.
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
- [ ] Validate browser UI, native keychain/process backends, local transport, install and uninstall behavior.
- [ ] Publish signed service packages with corresponding source, SBOM and hashes.
- [ ] Validate upgrade, rollback and configuration recovery.
- [ ] Publish compatibility, known limitations and release notes.

</details>

## Release policy

> [!IMPORTANT]
> Stable status requires documented safety, usability and compatibility evidence. A successful build or repository CI run is not sufficient.

Additional platforms, adapters, remote operation and team features require separate scope and maintenance review. See [release governance](docs/开源治理与发布.md) for distribution requirements.

---

[Architecture](docs/开发设计.md) · [Security gates](docs/安全模型与验收.md) · [Changelog](CHANGELOG.md)
