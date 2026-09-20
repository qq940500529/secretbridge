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
| reqwest 0.13.5 | Native HTTP runtime, MIT OR Apache-2.0; upstream source https://github.com/seanmonstar/reqwest | Exact version and minimal TLS feature locked; no vendored source modifications. Preserve the selected license and applicable upstream notices in service distributions |
| russh 0.63.2 / russh-cryptovec 0.62.0 / russh-util 0.52.0 / pageant 0.2.3 | Native SSH runtime, Apache-2.0; upstream https://github.com/Eugeny/russh | Only the ring backend is enabled; no vendored changes. Preserve Apache-2.0 terms and applicable upstream notices. The Windows-specific pageant dependency is resolved upstream but this application does not use SSH-agent authentication |
| russh-sftp 3.0.0 | Native SFTP runtime, Apache-2.0; upstream commit c2776c64c27e554dda0e0304925f890833fea5b1 at https://github.com/AspectUnk/russh-sftp | No vendored changes. Preserve the Apache-2.0 license and applicable upstream notices in service distributions |
| base64 0.22.1 | Git authentication-header encoding, MIT OR Apache-2.0; upstream https://github.com/marshallpierce/rust-base64 | Exact direct dependency; preserve the selected license and applicable copyright notices |
| dashmap 6.2.1 / hashbrown 0.14.5 / serde_bytes 0.11.19 / gloo-timers 0.4.0 | SFTP transitive dependencies, MIT and/or Apache-2.0 | Review target-specific inclusion; preserve applicable upstream terms and notices. The lockfile includes WebAssembly dependencies that are not necessarily part of native service packages |
| Git executable | User-installed external program, not linked, copied or bundled by this repository; Git upstream https://github.com/git/git | Git's GPL-2.0 terms and the actual platform distribution's third-party components must be reviewed if a future package redistributes Git. This project's commercial permission does not relicense Git |
| ssh-key 0.7.0-rc.11 and SSH cryptographic dependencies | Key decoding and protocol cryptography; predominantly MIT OR Apache-2.0 | The prerelease key library is transitively pinned by russh. Record it in the release inventory and recheck on upgrades; no RSA/DSA or legacy 3DES feature is enabled in russh |
| fiat-crypto 0.3.0 | Transitive cryptographic arithmetic, MIT OR Apache-2.0 OR BSD-1-Clause; upstream commit 67316f05d771f7f2db62beede59e9b56406a9efd | The MIT option is reviewed and selected for this dependency; preserve LICENSE-MIT, copyright, AUTHORS and upstream provenance in applicable distributions |
| hyper-rustls 0.27.9, base64 0.23.1, ipnet 2.12.2, tower-http 0.6.11, try-lock 0.2.5, want 0.3.1 and wasm-bindgen-futures 0.4.78 | Additional HTTP dependency graph, MIT and/or Apache-2.0 | Review target-specific inclusion and preserve applicable terms; exact expressions remain in the locked dependency inventory |
| SHA-2 0.10.9 | In-memory token digest runtime, MIT OR Apache-2.0 | Record the chosen license path and preserve applicable terms and notices |
| rusqlite 0.40.2 / libsqlite3-sys 0.38.2 | SQLite binding and bundled native build, MIT | Preserve upstream MIT notices; only the `bundled` feature is enabled |
| SQLite 3.53.2 | Bundled non-secret metadata database, public domain per upstream | Record the exact bundled source version and upstream provenance in release materials |
| keyring 4.2.0 and selected native platform stores | Operating-system credential-store integration, MIT OR Apache-2.0 | Preserve the selected license and platform-backend notices; review each target platform's resolved dependency graph |
| zeroize 1.9.0 | Transient secret-buffer clearing, MIT OR Apache-2.0 | Record the selected license path and preserve applicable terms and notices |
| totp-rs 6.0.0, qrcodegen 1.8.0 and png 0.18.1 | RFC 6238 TOTP generation, validation and enrollment QR rendering; MIT, plus png under MIT OR Apache-2.0 | Preserve applicable license texts and include the resolved components in release SBOMs; the QR image is rendered directly without the `qrcodegen-image` wrapper, whose published package does not include a license text |
| tokio-postgres 0.7.18 | PostgreSQL wire-protocol client, MIT OR Apache-2.0 | Preserve the selected license and upstream notices with distributed service packages |
| mysql_async 0.37.1 / mysql_common 0.37.3 | Native MySQL client, MIT OR Apache-2.0; mysql_async upstream commit ce4b27698c50fb945d8c9ff8c40a2a646be50b12 at https://github.com/blackbeam/mysql_async | MIT option reviewed. No vendored changes; minimal Rust compression and rustls/ring/TLS 1.2 features only, without derive/binlog/tracing. Preserve MIT copyright and terms in service distributions |
| foldhash 0.2.0 | MySQL transitive hashing, Zlib; upstream https://github.com/orlp/foldhash | Retain origin and license notice; mark altered versions if any. This project makes no vendored changes |
| adler2 2.0.1 / miniz_oxide 0.9.1 / flate2 1.1.10 / crc32fast 1.5.2 / simd-adler32 0.3.10 | MySQL transitive compression/checksums, MIT and/or Apache-2.0 with other optional license paths | MIT option reviewed where available; preserve applicable copyright and terms. Exact expressions, including alternative ordering and adler2's 0BSD option, are retained in the lockfile inventory |
| webpki-roots 1.0.9 | MySQL TLS root data, CDLA-Permissive-2.0 | Preserve the data agreement and provenance if included in service distributions; this trust source differs from PostgreSQL's OS platform verifier |
| PostgreSQL / MySQL container images and native servers | Optional external test fixtures only; not linked or bundled; upstream https://hub.docker.com/_/postgres and https://hub.docker.com/_/mysql | Test downloads retain their upstream and server distribution terms. A future package that redistributes database server binaries/images requires a separate review; this project's commercial permission does not relicense those components |
| rustls-tokio-postgres 0.5.1 | TLS connector for the PostgreSQL client, Apache-2.0 | Preserve the Apache-2.0 terms and applicable notices |
| Tokio 1.53.1 | Async runtime, Windows named pipes and Unix domain sockets, MIT | Preserve the MIT license and upstream copyright notice with distributed service packages |
| tokio-util 0.7.19 | Runtime cancellation support, MIT | Preserve the MIT license and upstream copyright notice |
| rmcp 3.3.0 / rmcp-macros 3.3.0 | MCP stdio server SDK and macros, Apache-2.0 | Preserve the Apache-2.0 license, copyright and any applicable NOTICE content with distributed service packages |
| schemars 1.2.2 / schemars_derive 1.2.2 | MCP JSON Schema generation, MIT | Preserve the upstream MIT terms and copyright notice with distributed service packages |
| darling 0.24.1, dyn-clone 1.0.20, pastey 0.2.3, ref-cast 1.0.27, tokio-stream 0.1.19 and related packages | Transitive MCP/schema build or runtime dependencies, MIT and/or Apache-2.0 | Resolved versions and exact expressions are locked in `Cargo.lock`; preserve applicable terms in each platform's generated notice inventory |
| rustls 0.23.45 / rustls-platform-verifier 0.7.0 / ring 0.17.14 | Transitive TLS, platform trust and cryptography runtime | Preserve each resolved component's applicable Apache-2.0, ISC or MIT terms; review each platform-specific distribution graph |
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

For maintainer decisions, see [open-source governance](docs/开源治理与发布.md) and the [dependency license assessment](docs/依赖许可风险评估.md). The latter reviews current direct dependencies and future candidates; it is not a legal opinion or an audit of every transitive dependency and release binary.

---

[License](LICENSE) · [Contribution guide](CONTRIBUTING.md)
