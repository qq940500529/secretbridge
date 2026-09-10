# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail when locked dependencies introduce an unreviewed license expression."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

REVIEWED_RUST_LICENSES = {
    "(MIT OR Apache-2.0) AND Unicode-3.0",
    "Apache-2.0",
    "Apache-2.0/MIT",
    "Apache-2.0 OR BSL-1.0",
    "Apache-2.0 OR MIT",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
    "BSD-3-Clause",
    "BSD-2-Clause OR Apache-2.0",
    "BSD-2-Clause OR Apache-2.0 OR MIT",
    "MIT",
    "MIT AND BSD-3-Clause",
    "MIT OR Apache-2.0",
    "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
    "MIT/Apache-2.0",
    "Unicode-3.0",
    "Unlicense OR MIT",
    "Unlicense/MIT",
    "Zlib OR Apache-2.0 OR MIT",
}

REVIEWED_NPM_LICENSES = {
    "Apache-2.0",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "MPL-2.0",
}


def unreviewed(observed: set[str], reviewed: set[str]) -> list[str]:
    """Return stable identifiers only; package paths are intentionally omitted."""
    return sorted(observed - reviewed)


def command_json(command: list[str]) -> object:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise RuntimeError(f"dependency metadata command failed: {command[0]}") from error


def main() -> int:
    cargo = shutil.which("cargo")
    pnpm = shutil.which("pnpm")
    if cargo is None or pnpm is None:
        print("Dependency license check requires cargo and pnpm.")
        return 1

    cargo_metadata = command_json(
        [cargo, "metadata", "--format-version", "1", "--locked"]
    )
    rust_packages = [
        package
        for package in cargo_metadata["packages"]
        if package.get("source") is not None
    ]
    missing_rust = sorted(
        package["name"] for package in rust_packages if not package.get("license")
    )
    rust_licenses = {
        package["license"] for package in rust_packages if package.get("license")
    }

    npm_metadata = command_json([pnpm, "licenses", "list", "--json"])
    npm_licenses = set(npm_metadata)

    errors = []
    if missing_rust:
        errors.append("Rust packages without license metadata: " + ", ".join(missing_rust))
    if unexpected := unreviewed(rust_licenses, REVIEWED_RUST_LICENSES):
        errors.append("Unreviewed Rust license expressions: " + ", ".join(unexpected))
    if unexpected := unreviewed(npm_licenses, REVIEWED_NPM_LICENSES):
        errors.append("Unreviewed npm license identifiers: " + ", ".join(unexpected))

    if errors:
        print("Dependency license policy failed:")
        print("\n".join(errors))
        return 1

    print(
        "Dependency license policy passed "
        f"({len(rust_packages)} Rust packages; {len(npm_licenses)} npm license groups)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
