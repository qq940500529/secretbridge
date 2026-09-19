# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare two independently created SecretBridge package directories byte for byte."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package_files(directory: Path) -> dict[str, Path]:
    if not directory.is_dir():
        raise ValueError("Package comparison input must be a directory")
    files = {
        path.name: path
        for path in directory.iterdir()
        if path.is_file() and (path.name.endswith(".zip") or path.name.endswith(".tar.gz"))
    }
    if len(files) != 1:
        raise ValueError("Each directory must contain exactly one native package")
    return files


def compare(first: Path, second: Path) -> tuple[str, str]:
    left, right = package_files(first), package_files(second)
    if left.keys() != right.keys():
        raise ValueError("Package names differ between builds")
    name = next(iter(left))
    first_digest, second_digest = digest(left[name]), digest(right[name])
    if first_digest != second_digest:
        raise ValueError("Package bytes differ between builds")
    for directory, expected in ((first, first_digest), (second, second_digest)):
        sidecar = directory / f"{name}.sha256"
        if not sidecar.is_file() or sidecar.read_text(encoding="ascii").strip() != f"{expected}  {name}":
            raise ValueError("Package checksum sidecar is missing or inconsistent")
    return name, first_digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    try:
        name, checksum = compare(args.first.resolve(), args.second.resolve())
    except (OSError, ValueError) as error:
        print(f"Reproducibility check failed: {error}")
        return 1
    print(f"Reproducible package verified: {name} sha256:{checksum}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
