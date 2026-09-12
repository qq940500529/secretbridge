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
| xterm.js 6.0.0 / Fit addon 0.11.0 | Browser terminal runtime, MIT | Copyright and MIT terms must be retained with distributed Web assets |
| portable-pty 0.9.0 | Cross-platform PTY runtime, MIT | Preserve the crate license and upstream copyright notice with distributed service packages |
| SHA-2 0.10.9 | In-memory token digest runtime, MIT OR Apache-2.0 | Record the chosen license path and preserve applicable terms and notices |
| rusqlite 0.40.2 / libsqlite3-sys 0.38.2 | SQLite binding and bundled native build, MIT | Preserve upstream MIT notices; only the `bundled` feature is enabled |
| SQLite 3.53.2 | Bundled non-secret metadata database, public domain per upstream | Record the exact bundled source version and upstream provenance in release materials |
| keyring 4.2.0 and selected native platform stores | Operating-system credential-store integration, MIT OR Apache-2.0 | Preserve the selected license and platform-backend notices; review each target platform's resolved dependency graph |
| zeroize 1.9.0 | Transient secret-buffer clearing, MIT OR Apache-2.0 | Record the selected license path and preserve applicable terms and notices |
| tokio-postgres 0.7.18 | PostgreSQL wire-protocol client, MIT OR Apache-2.0 | Preserve the selected license and upstream notices with distributed service packages |
| rustls-tokio-postgres 0.5.1 | TLS connector for the PostgreSQL client, Apache-2.0 | Preserve the Apache-2.0 terms and applicable notices |
| tokio-util 0.7.19 | Runtime cancellation support, MIT | Preserve the MIT license and upstream copyright notice |
| rmcp 3.3.0 / rmcp-macros 3.3.0 | MCP stdio server SDK and macros, Apache-2.0 | Preserve the Apache-2.0 license, copyright and any applicable NOTICE content with distributed service packages |
| schemars 1.2.2 / schemars_derive 1.2.2 | MCP JSON Schema generation, MIT | Preserve the upstream MIT terms and copyright notice with distributed service packages |
| darling 0.24.1, dyn-clone 1.0.20, pastey 0.2.3, ref-cast 1.0.27, tokio-stream 0.1.19 and related packages | Transitive MCP/schema build or runtime dependencies, MIT and/or Apache-2.0 | Resolved versions and exact expressions are locked in `Cargo.lock`; preserve applicable terms in each platform's generated notice inventory |
| rustls 0.23.44 / rustls-platform-verifier 0.7.0 / ring 0.17.14 | Transitive TLS, platform trust and cryptography runtime | Preserve each resolved component's applicable Apache-2.0, ISC or MIT terms; review each platform-specific distribution graph |
| webpki-root-certs 1.0.9 | Transitive root-certificate data, CDLA-Permissive-2.0 | Preserve the data license, provenance and applicable notices if the data is included in a distributed package |
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
