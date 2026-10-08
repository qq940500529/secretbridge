# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Select real Rust tests before running a named acceptance suite; fail on missing tests."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SUITES = {
    "database": ("adapters::executors::database::tests::real_", 11, True, False),
    "database-mcp": ("native_mcp_executes_real_databases", 1, True, False),
    "parallel": (
        "stability_acceptance::parallel_cancellation_releases_capacity_and_follow_up_work_succeeds",
        1,
        False,
        True,
    ),
    "history": (
        "adapters::persistence::tests::same_directory_soak_records_resource_trend_and_restores_history",
        1,
        True,
        True,
    ),
}


def suite_command(name: str) -> tuple[str, ...]:
    pattern, _, ignored, exact = SUITES[name]
    harness = ["--nocapture"]
    if ignored:
        harness.append("--ignored")
    if exact:
        harness.append("--exact")
    return ("cargo", "test", "--locked", "-p", "secretbridge", "--lib", pattern, "--", *harness)


def select_suite(name: str) -> int:
    completed = subprocess.run(
        (*suite_command(name), "--list"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=1_200,
    )
    if completed.returncode:
        raise ValueError("test_list_failed")
    count = sum(line.endswith(": test") for line in completed.stdout.splitlines())
    if count < SUITES[name][1]:
        raise ValueError("test_selection_incomplete")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=(*SUITES, "all"))
    parser.add_argument("--list-only", action="store_true")
    args = parser.parse_args()
    if args.suite == "all" and not args.list_only:
        parser.error("all requires --list-only; database execution needs disposable fixtures")
    names = SUITES if args.suite == "all" else (args.suite,)
    for name in names:
        try:
            count = select_suite(name)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            print(f"Rust acceptance selection failed: {name}", flush=True)
            return 1
        print(f"Rust acceptance selected: {name}: {count} tests", flush=True)
        if not args.list_only:
            result = subprocess.run(suite_command(name), cwd=ROOT, check=False)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
