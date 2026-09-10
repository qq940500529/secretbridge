# Changelog

[Home](README.md) / Changelog

Changes affecting contributors, project scope and future users are recorded here. Entries under **Unreleased** do not represent a stable release.

## Unreleased

### Licensing

- Identify 数链创元（天津）信息技术有限责任公司 as the copyright holder of company-owned material.
- License the repository under AGPL-3.0-or-later and provide a separate written commercial licensing route for proprietary commercial use.
- Document contribution relicensing boundaries, third-party exclusions and candidate dependency license risks.

### Documentation

- Add a role-based documentation hub, user orientation, developer setup and glossary.
- Reorganize English and Chinese homepages around product purpose and reading paths.
- Add workflow, architecture, approval and lifecycle diagrams with text explanations.
- Standardize navigation, GitHub alerts, reference tables and expandable detail.
- Clarify repository checks, runtime status and supported contribution workflows.

### M0 Web foundation

- Add a React 19, TypeScript 7, Vite 8 and Tailwind CSS 4 bilingual management console.
- Add a Rust 1.98, Axum 0.8 and Tokio local service bound to loopback only.
- Add one-time URL-fragment bootstrap pairing, exact Origin validation and memory-only browser sessions.
- Keep real credential storage, injection and command execution disabled; tests assert synthetic-only mode.
- Add locked Rust and pnpm dependency graphs plus Web and Rust checks to the three-platform CI workflow.
- Record the permanent browser-based UI decision; no desktop shell is planned.

### Project foundation · 2026-09-10

- Establish credential-use boundaries, persistent terminal semantics and a threat model.
- Define Windows, Linux and macOS as implementation targets.
- Specify platform credential/IPC/supervisor abstractions and UI/accessibility goals.
- Adopt AGPL-3.0-or-later and contribution, security and release policies.
- Add limited repository hygiene checks and three-OS CI for those checks.

> [!NOTE]
> The M0 prototype has only been run locally on Windows. Linux/macOS CI and native platform functions remain unverified until their checks complete.

---

[Roadmap](ROADMAP.md) · [Documentation](docs/README.md)
