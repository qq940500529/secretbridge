# Contributing

[Home](README.md) / Contributing

Thank you for helping build SecretBridge. Contributions to documentation, accessibility, platform validation, security design and repository tooling are welcome.

> [!IMPORTANT]
> The project is in the design stage. Discuss changes to credential access, authorization or isolation before implementation. Never include real credentials or private infrastructure in a contribution.

## Find a contribution

| Area | Useful contributions | Include in the proposal |
| :--- | :--- | :--- |
| Documentation | Clear examples, navigation, terminology, translations | Reader problem and affected pages |
| Product design | Approval clarity, keyboard flow, accessibility | Annotated design and test criteria |
| Platform research | Credential, IPC and PTY behavior | OS/version, synthetic reproduction and limits |
| Security | Threat-model review and safe regression cases | Private report if exploitable; no live targets |
| Repository tooling | Focused checks and tests | Failure case, expected behavior and limitations |

Start with an [issue](https://github.com/qq940500529/secretbridge/issues) for substantial work. Small corrections can go directly to a PR.

## Prepare a change

1. Read the [development guide](docs/开发者入门.md) and relevant design specification.
2. Create a focused branch; avoid mixing unrelated cleanup with behavior changes.
3. Update documentation and tests alongside the change.
4. Run the local checks:

   ```sh
   python tools/check_repository.py
   python -m unittest discover -s tests -v
   git diff --check
   ```
5. Inspect the complete diff for private data, unlicensed material and inaccurate status claims.
6. Open a PR against `main` using the repository template.

These commands validate repository content, not the desktop application.

## What reviewers need

| Item | Review evidence |
| :--- | :--- |
| Scope | Problem, intended behavior, alternatives and affected components |
| Correctness | Reproduction or tests; actual results rather than only a success assertion |
| Safety | Authorization, credential lifecycle, output and target changes |
| Compatibility | Platforms checked and platforms still untested |
| Documentation | Updated examples, links, diagrams and status |
| Provenance | Source/license of imported material; review of generated portions |

Declare the scope of AI-assisted contributions and the review performed. Generated content remains subject to the same provenance, licensing and testing requirements as other work.

## License and sign-off

Contribute only material you have the right to submit under `AGPL-3.0-only` or documented compatible third-party terms. Read the [Developer Certificate of Origin 1.1](https://developercertificate.org/) before using `git commit -s`. Sign-off is a contributor assertion, not a copyright transfer; never sign for another person without authority.

SecretBridge also offers [separate commercial licensing](COMMERCIAL_LICENSE.md) for rights controlled by 数链创元（天津）信息技术有限责任公司. A DCO sign-off or PR merge **does not grant proprietary relicensing rights or transfer copyright**. Commercial inclusion of externally owned contributions requires sufficient separate written authorization; see the [contribution and relicensing policy](docs/贡献与再许可.md). No such agreement is implied by submitting a contribution.

Use an appropriate public or noreply email. Do not submit employer-owned or client material without the necessary rights. Dependency and asset obligations are described in [the maintenance policy](docs/开源治理与发布.md).

## Review and merge

PRs must satisfy required repository checks and resolve review discussions. A maintainer may request a smaller change, additional evidence or a design decision before accepting implementation. Security-sensitive code requires independent review before a stable release; repository checks alone are insufficient.

## Need help?

- Setup and check failures: [development guide](docs/开发者入门.md).
- Terminology: [glossary](docs/术语表.md).
- Vulnerabilities: [private security reporting](SECURITY.md).
- Community expectations: [code of conduct](CODE_OF_CONDUCT.md).

---

[Documentation](docs/README.md) · [Roadmap](ROADMAP.md) · [Security](SECURITY.md)
