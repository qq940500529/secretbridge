# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the bounded connector, terminal and concurrency stability acceptance suite."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "dist" / "stability-acceptance.json"
PARALLEL_FILTER = (
    "stability_acceptance::"
    "parallel_cancellation_releases_capacity_and_follow_up_work_succeeds"
)


@dataclass(frozen=True)
class Check:
    name: str
    command: tuple[str, ...]


@dataclass
class CheckResult:
    name: str
    command: list[str]
    duration_seconds: float
    exit_code: int
    passed: bool


def build_plan(profile: str, iterations: int, with_databases: bool) -> list[Check]:
    if profile not in {"quick", "soak"}:
        raise ValueError("profile must be quick or soak")
    if not 1 <= iterations <= 100:
        raise ValueError("iterations must be between 1 and 100")
    plan = [
        Check(
            "connector failure and resource cleanup contracts",
            ("cargo", "test", "-p", "secretbridge-server", "--lib"),
        ),
        Check(
            "terminal output flood, reconnect and cancellation",
            ("cargo", "test", "-p", "secretbridge-server", "--test", "synthetic_terminal"),
        ),
        Check(
            "native persistent terminal lifecycle",
            ("cargo", "test", "-p", "secretbridge-server", "--test", "real_terminal"),
        ),
    ]
    if profile == "soak":
        plan.extend(
            Check(
                f"parallel cancellation soak {attempt + 1}/{iterations}",
                (
                    "cargo",
                    "test",
                    "-p",
                    "secretbridge-server",
                    PARALLEL_FILTER,
                    "--",
                    "--exact",
                ),
            )
            for attempt in range(iterations)
        )
    if with_databases:
        plan.append(
            Check(
                "disposable PostgreSQL and MySQL failures and service restarts",
                ("bash", "tools/test_database_connectors.sh"),
            )
        )
    return plan


def run_plan(plan: list[Check]) -> tuple[list[CheckResult], bool]:
    results: list[CheckResult] = []
    environment = os.environ.copy()
    environment.setdefault("RUST_TEST_THREADS", "2")
    for index, check in enumerate(plan, 1):
        print(f"[{index}/{len(plan)}] {check.name}", flush=True)
        started = time.monotonic()
        completed = subprocess.run(
            check.command,
            cwd=ROOT,
            env=environment,
            check=False,
        )
        result = CheckResult(
            name=check.name,
            command=list(check.command),
            duration_seconds=round(time.monotonic() - started, 3),
            exit_code=completed.returncode,
            passed=completed.returncode == 0,
        )
        results.append(result)
        if not result.passed:
            return results, False
    return results, True


def write_report(
    path: Path,
    profile: str,
    iterations: int,
    with_databases: bool,
    started_at: str,
    duration: float,
    results: list[CheckResult],
    passed: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "format": "secretbridge-stability-acceptance",
        "format_version": 1,
        "profile": profile,
        "iterations": iterations if profile == "soak" else 1,
        "with_databases": with_databases,
        "started_at": started_at,
        "duration_seconds": round(duration, 3),
        "platform": platform.system().lower(),
        "architecture": platform.machine(),
        "passed": passed,
        "checks": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("quick", "soak"), default="quick")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--with-databases", action="store_true")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    try:
        plan = build_plan(args.profile, args.iterations, args.with_databases)
    except ValueError as error:
        parser.error(str(error))
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    results, passed = run_plan(plan)
    report = args.report.resolve()
    write_report(
        report,
        args.profile,
        args.iterations,
        args.with_databases,
        started_at,
        time.monotonic() - started,
        results,
        passed,
    )
    print(
        f"Stability acceptance {'passed' if passed else 'failed'}; report: {report}",
        flush=True,
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
