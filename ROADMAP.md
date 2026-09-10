# Roadmap

Status: design-stage, 2026-09-10. Milestones are acceptance gates, not delivery dates.

- [x] Initial architecture, threat model, cross-platform and UI targets.
- [x] AGPL-3.0-only licensing, contribution/security policies and repository checks.
- [ ] M0: synthetic credentials, three-platform identity/IPC/PTY feasibility evidence.
- [ ] M1: accessible bilingual UI, approval workflow, independent supervisor and reconnection.
- [ ] M2: one scoped database adapter, MCP tools, cancellation, idempotency and safe events.
- [ ] M3: user-approved low-privilege test environment, attack cases, rotation/revocation and independent security review.
- [ ] M4: Windows/Linux/macOS build and native testing, signed packages, source correspondence, SBOM, upgrade and recovery tests.
- [ ] Stable release only after documented safety, usability and compatibility gates pass.

No real credentials before the isolation and safety gates pass. No stable label solely because a build succeeds. Additional platforms, adapters and remote/team features need their own security and maintenance review.
