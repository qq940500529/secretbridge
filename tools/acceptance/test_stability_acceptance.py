# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the bounded connector, terminal and concurrency stability acceptance suite."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT = ROOT / "dist" / "stability-acceptance.json"
PARALLEL_FILTER = (
    "stability_acceptance::parallel_cancellation_releases_capacity_and_follow_up_work_succeeds"
)


@dataclass(frozen=True)
class Check:
    name: str
    command: tuple[str, ...]
    capture_metrics: bool = False


@dataclass
class CheckResult:
    name: str
    command: list[str]
    duration_seconds: float
    exit_code: int
    passed: bool
    error_code: str | None
    metrics: list[dict[str, int | float | str | None]]


SOAK_MARKER = "SOAK_METRIC "
SOAK_FIELDS = {
    "phase",
    "authorizations",
    "runs",
    "duration_seconds",
    "catalog_bytes",
    "resident_pages",
    "backup_bytes",
}


def parse_soak_metrics(output: str) -> list[dict[str, int | float | str | None]]:
    metrics = []
    for line in output.splitlines():
        if SOAK_MARKER not in line:
            continue
        value = json.loads(line.split(SOAK_MARKER, 1)[1])
        if not isinstance(value, dict) or set(value) - SOAK_FIELDS:
            raise ValueError("unexpected soak metric fields")
        if value.get("phase") not in (1, 2, 3, 4, "backup_restore"):
            raise ValueError("unexpected soak metric phase")
        if not all(
            isinstance(item, (int, float)) or item is None or item == "backup_restore"
            for item in value.values()
        ):
            raise ValueError("unexpected soak metric value")
        metrics.append(value)
    return metrics


def build_plan(profile: str, iterations: int, with_databases: bool) -> list[Check]:
    if profile not in {"quick", "soak"}:
        raise ValueError("profile must be quick or soak")
    if not 1 <= iterations <= 100:
        raise ValueError("iterations must be between 1 and 100")
    plan = [
        Check(
            "connector failure and resource cleanup contracts",
            ("cargo", "test", "-p", "secretbridge", "--lib"),
        ),
        Check(
            "terminal output flood, reconnect and cancellation",
            ("cargo", "test", "-p", "secretbridge", "--test", "synthetic_terminal"),
        ),
        Check(
            "native persistent terminal lifecycle",
            ("cargo", "test", "-p", "secretbridge", "--test", "real_terminal"),
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
                    "secretbridge",
                    PARALLEL_FILTER,
                    "--",
                    "--exact",
                ),
            )
            for attempt in range(iterations)
        )
        plan.append(
            Check(
                "same-directory 2000 approval/run history, restart and backup restore",
                (
                    "cargo",
                    "test",
                    "-p",
                    "secretbridge",
                    "--lib",
                    "catalog::tests::same_directory_soak_records_resource_trend_and_restores_history",
                    "--",
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ),
                capture_metrics=True,
            )
        )
    if with_databases:
        plan.append(
            Check(
                "disposable PostgreSQL and MySQL failures and service restarts",
                ("bash", "tools/acceptance/test_database_connectors.sh"),
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
        metrics: list[dict[str, int | float | str | None]] = []
        exit_code = 0
        error_code = None
        try:
            directory = (
                tempfile.TemporaryDirectory(prefix="secretbridge-soak-")
                if check.capture_metrics
                else contextlib.nullcontext(None)
            )
            with directory as owned_directory:
                check_environment = environment.copy()
                if owned_directory is not None:
                    Path(owned_directory, ".secretbridge-soak-owned").write_text(
                        "secretbridge-owned-soak\n", encoding="utf-8"
                    )
                    check_environment["SECRETBRIDGE_SOAK_OWNED_DIR"] = owned_directory
                for _ in range(2 if check.capture_metrics else 1):
                    completed = subprocess.run(
                        check.command,
                        cwd=ROOT,
                        env=check_environment,
                        check=False,
                        capture_output=check.capture_metrics,
                        text=check.capture_metrics,
                        timeout=1_200,
                    )
                    if check.capture_metrics:
                        metrics.extend(parse_soak_metrics(completed.stdout or ""))
                    exit_code = completed.returncode
                    if exit_code != 0:
                        error_code = "check_failed"
                        break
                if check.capture_metrics and error_code is None and len(metrics) != 6:
                    error_code = "metrics_incomplete"
        except subprocess.TimeoutExpired:
            exit_code = -1
            error_code = "check_timed_out"
        except ValueError:
            exit_code = -1
            error_code = "metrics_invalid"
        except OSError:
            exit_code = -1
            error_code = "check_unavailable"
        result = CheckResult(
            name=check.name,
            command=list(check.command),
            duration_seconds=round(time.monotonic() - started, 3),
            exit_code=exit_code,
            passed=exit_code == 0 and error_code is None,
            error_code=error_code,
            metrics=metrics,
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
        "format_version": 2,
        "profile": profile,
        "iterations": iterations if profile == "soak" else 1,
        "planned_same_directory_approvals": 4_000 if profile == "soak" else 0,
        "planned_same_directory_runs": 4_000 if profile == "soak" else 0,
        "data_directory_reuse": (
            "one_owned_directory_across_two_test_processes" if profile == "soak" else None
        ),
        "remaining_limits": (
            ["synthetic_catalog_operations_only", "no_multiday_desktop_residency"]
            if profile == "soak"
            else []
        ),
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
    started_at = datetime.now(UTC).isoformat()
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
