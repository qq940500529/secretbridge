# Third-party notices

[Home](README.md) / Third-party notices

This inventory describes material included in the repository. Technologies discussed in design documents are not automatically bundled dependencies.

## Included or referenced material

| Material | Relationship | Notice |
| :--- | :--- | :--- |
| GNU AGPL v3 license text | Included as [LICENSE](LICENSE) | License-document copyright and terms retained verbatim |
| Developer Certificate of Origin | Linked from [CONTRIBUTING.md](CONTRIBUTING.md) | Not copied or relicensed |
| actions/checkout | CI reference pinned to a commit | Retrieved by GitHub Actions; not vendored |
| Application libraries, fonts and images | None currently bundled | Inventory required before introduction |

Company-owned material is offered under `AGPL-3.0-only` or a separate written commercial license; see [LICENSING.md](LICENSING.md). An upstream component retains its own terms; this file does not override those terms.

## Adding a dependency or asset

Record the following before merge:

| Field | Required information |
| :--- | :--- |
| Identity | Component/asset name and exact version or commit |
| Source | Upstream repository or distribution location |
| License | SPDX identifier and license-file evidence |
| Use | Runtime, build, test, CI or documentation |
| Changes | Whether upstream content was modified |
| Distribution | Bundled files, notices, source and attribution obligations |

Generated inventories must be reviewed against actual release contents. A dependency list is not itself a license or vulnerability audit.

## Provenance

AI-assisted contributions are subject to the same source, license and review requirements as other work. Contribution records should identify generated portions and their review; generation does not establish ownership, originality or safety.

For maintainer decisions, see [open-source governance](docs/开源治理与发布.md) and the [candidate dependency license assessment](docs/依赖许可风险评估.md). The latter is a design-stage review, not an audit of a resolved dependency graph or release binaries.

---

[License](LICENSE) · [Contribution guide](CONTRIBUTING.md)
