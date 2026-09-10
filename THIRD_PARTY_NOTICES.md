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

The repository is licensed under `AGPL-3.0-or-later`. Proprietary commercial use requires a separate written license for the rights controlled by the copyright holder; see [LICENSING.md](LICENSING.md). Upstream components retain their own terms, which this project cannot override.

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

For maintainer decisions, see [open-source governance](docs/开源治理与发布.md) and the [candidate dependency license assessment](docs/依赖许可风险评估.md). The latter is a design-stage review, not an audit of a resolved dependency graph or release binaries.

---

[License](LICENSE) · [Contribution guide](CONTRIBUTING.md)
