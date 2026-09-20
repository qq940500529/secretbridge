# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check duplicated release metadata against the repository's authoritative manifests."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise ValueError(message)


def check(root: Path) -> str:
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text(encoding="utf-8"))
    root_package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    web_package = json.loads((root / "web" / "package.json").read_text(encoding="utf-8"))
    version = cargo["workspace"]["package"]["version"]
    if root_package["version"] != version or web_package["version"] != version:
        fail("Cargo, root package and Web package versions must match")
    rust_minimum = cargo["workspace"]["package"]["rust-version"]
    rust_pinned = toolchain["toolchain"]["channel"]
    if not rust_pinned.startswith(f"{rust_minimum}."):
        fail("the RC Rust toolchain must be a patch release of workspace rust-version")
    node_version = (root / ".node-version").read_text(encoding="utf-8").strip()
    if not node_version.startswith("24."):
        fail("the RC Node.js toolchain must stay within the declared Node.js 24 engine")
    core = (root / "crates/secretbridge-core/src/lib.rs").read_text(encoding="utf-8")
    match = re.search(r"SCHEMA_VERSION: i64 = (\d+);", core)
    if match is None:
        fail("SCHEMA_VERSION was not found")
    schema = int(match.group(1))
    package_tool = (root / "tools/package_release.py").read_text(encoding="utf-8")
    if f'"schema_version": {schema}' not in package_tool:
        fail("package_release.py schema metadata is out of date")
    current_documents = (
        root / "docs/README.md",
        root / "docs/开发设计.md",
        root / "docs/后台运行与安装交付.md",
        root / "docs/配置迁移与备份恢复.md",
    )
    for document in current_documents:
        content = document.read_text(encoding="utf-8")
        for stale_schema in range(1, schema):
            if re.search(
                rf"(?:当前|current)[^\n]{{0,40}}(?:接受|使用|恢复到|为|uses?|accepts?)"
                rf"[^\n]{{0,20}}schema (?:v)?{stale_schema}\b",
                content,
                re.IGNORECASE,
            ):
                fail(f"{document.name} describes stale schema {stale_schema} as current")
    return (
        f"Project metadata aligned: version {version}, schema {schema}, "
        f"Rust {rust_pinned}, Node.js {node_version}."
    )


def main() -> int:
    print(check(ROOT))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"Project metadata check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
