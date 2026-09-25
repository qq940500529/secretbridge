# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write a small, secret-free record of the toolchain used by a CI job."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path


def version(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return result.stdout.strip().splitlines()[0][:160]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "format": "secretbridge-ci-metadata",
        "format_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "commit": os.environ.get("GITHUB_SHA", "local")[:40],
        "platform": platform.system().lower(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "node": version(["node", "--version"]),
        "pnpm": version(["pnpm", "--version"]),
        "rustc": version(["rustc", "--version"]),
        "cargo": version(["cargo", "--version"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"CI metadata written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
