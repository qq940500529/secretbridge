# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Measure bounded startup, local API latency, and idle memory for one user."""

from __future__ import annotations

import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LIMITS = {
    "startup_p95_ms": 5000.0,
    "status_p95_ms": 250.0,
    "idle_rss_mib": 256.0,
}


def percentile(samples: list[float], fraction: float) -> float:
    if not samples:
        raise ValueError("samples must not be empty")
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def available_port() -> int:
    with closing(socket.socket()) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def rss_mib(process_id: int) -> float:
    if sys.platform == "win32":
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-Process -Id {process_id}).WorkingSet64",
        ]
        raw = subprocess.check_output(command, text=True, timeout=10).strip()
        return int(raw) / 1024 / 1024
    if sys.platform.startswith("linux"):
        status = Path(f"/proc/{process_id}/status").read_text(encoding="utf-8")
        line = next(item for item in status.splitlines() if item.startswith("VmRSS:"))
        return int(line.split()[1]) / 1024
    raw = subprocess.check_output(
        ["ps", "-o", "rss=", "-p", str(process_id)], text=True, timeout=10
    ).strip()
    return int(raw) / 1024


def wait_ready(opener, url: str, process: subprocess.Popen[bytes]) -> float:
    started = time.perf_counter()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("broker exited during startup")
        try:
            with opener.open(url + "/api/v1/status", timeout=1) as response:
                if response.status == 200:
                    return (time.perf_counter() - started) * 1000
        except OSError:
            time.sleep(0.025)
    raise TimeoutError("broker startup exceeded 10 seconds")


def measure(binary: Path, web_root: Path, rounds: int) -> dict[str, object]:
    opener = build_opener(ProxyHandler({}))
    startups: list[float] = []
    latencies: list[float] = []
    memories: list[float] = []
    for _ in range(rounds):
        with tempfile.TemporaryDirectory(prefix="sb-scale-") as temporary:
            port = available_port()
            url = f"http://127.0.0.1:{port}"
            env = dict(
                os.environ,
                SECRETBRIDGE_BIND=f"127.0.0.1:{port}",
                SECRETBRIDGE_DATA_DIR=str(Path(temporary).resolve()),
                SECRETBRIDGE_WEB_ROOT=str(web_root.resolve()),
            )
            process = subprocess.Popen(
                [str(binary), "--serve"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                startups.append(wait_ready(opener, url, process))
                for _request in range(20):
                    started = time.perf_counter()
                    with opener.open(url + "/api/v1/status", timeout=2) as response:
                        response.read()
                    latencies.append((time.perf_counter() - started) * 1000)
                time.sleep(0.5)
                memories.append(rss_mib(process.pid))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return {
        "startup_p50_ms": round(statistics.median(startups), 2),
        "startup_p95_ms": round(percentile(startups, 0.95), 2),
        "status_p50_ms": round(statistics.median(latencies), 2),
        "status_p95_ms": round(percentile(latencies, 0.95), 2),
        "idle_rss_mib": round(max(memories), 2),
        "rounds": rounds,
        "status_requests": len(latencies),
    }


def evaluate(metrics: dict[str, object], limits: dict[str, float]) -> list[str]:
    return [key for key, limit in limits.items() if float(metrics[key]) > limit]


def main() -> int:
    default_binary = (
        ROOT
        / "target"
        / "debug"
        / ("secretbridge-server.exe" if os.name == "nt" else "secretbridge-server")
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=default_binary)
    parser.add_argument("--web-root", type=Path, default=ROOT / "web" / "dist")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "personal-scale.json")
    args = parser.parse_args()
    if not args.binary.is_file() or not (args.web_root / "index.html").is_file():
        print("Build the broker and Web application before measuring.", file=sys.stderr)
        return 2
    if not 1 <= args.rounds <= 20:
        print("Rounds must be between 1 and 20.", file=sys.stderr)
        return 2
    try:
        metrics = measure(args.binary.resolve(), args.web_root.resolve(), args.rounds)
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        print(f"Personal-scale acceptance failed: {error}", file=sys.stderr)
        return 1
    failures = evaluate(metrics, DEFAULT_LIMITS)
    report = {
        "format": "secretbridge-personal-scale",
        "format_version": 1,
        "profile": "single-user-local",
        "platform": sys.platform,
        "limits": DEFAULT_LIMITS,
        "metrics": metrics,
        "passed": not failures,
        "failed_limits": failures,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failures:
        print("Personal-scale limits exceeded: " + ", ".join(failures), file=sys.stderr)
        return 1
    print(
        "Personal-scale acceptance passed: "
        f"startup p95 {metrics['startup_p95_ms']} ms, "
        f"status p95 {metrics['status_p95_ms']} ms, "
        f"idle RSS {metrics['idle_rss_mib']} MiB."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
