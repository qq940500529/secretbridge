# Third-party notices

[Home](README.md) / Third-party notices

This inventory describes material included in the repository. Technologies discussed in design documents are not automatically bundled dependencies.

## Included or referenced material

| Material | Relationship | Notice |
| :--- | :--- | :--- |
| GNU AGPL v3 license text | Included as [LICENSE](LICENSE) | License-document copyright and terms retained verbatim |
| Developer Certificate of Origin | Linked from [CONTRIBUTING.md](CONTRIBUTING.md) | Not copied or relicensed |
| actions/checkout | CI reference pinned to a commit | Retrieved by GitHub Actions; not vendored |
| actions/setup-node | CI reference pinned to a commit | Retrieved by GitHub Actions; not vendored |
| Rust dependencies | Exact versions resolved in [Cargo.lock](Cargo.lock) | Source dependencies are downloaded for builds; applicable notices must accompany distributed service packages |
| Web dependencies | Exact versions resolved in [pnpm-lock.yaml](pnpm-lock.yaml) | Runtime portions are bundled into generated Web assets; applicable notices must accompany distribution |
| React / React DOM 19.3.0 | Web runtime, MIT | Copyright and MIT terms must be retained |
| Radix Tooltip 1.2.16 / Tailwind CSS 4.3.3 / Vite 8.3.0 | Web UI and build tooling, MIT | Copyright and MIT terms must be retained where applicable |
| Lucide React 1.44.0 | Web icons, ISC | Copyright and ISC terms must be retained |
| TypeScript 7.0.2 | Build tooling, Apache-2.0 | Preserve the license and any applicable notices when distributing covered material |
| lightningcss 1.32 / 1.33 and platform packages | Transitive CSS build tooling, MPL-2.0 | Not part of the current browser runtime bundle; preserve MPL-covered files, notices and corresponding-source rights if those files are distributed |

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

For maintainer decisions, see [open-source governance](docs/开源治理与发布.md) and the [dependency license assessment](docs/依赖许可风险评估.md). The latter reviews the M0 direct dependencies and future candidates; it is not a legal opinion or an audit of every transitive dependency and release binary.

---

[License](LICENSE) · [Contribution guide](CONTRIBUTING.md)
