# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run synthetic browser compatibility and accessibility acceptance."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
BROWSERS = ("chromium", "firefox", "webkit")
CHROMIUM_SCRIPTS = (
    "smoke_connector_ui.mjs",
    "smoke_maintenance_ui.mjs",
    "smoke_background_ui.mjs",
)


def available_port() -> int:
    with closing(socket.socket()) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def acceptance_plan(browsers: list[str]) -> list[tuple[str, str]]:
    plan = [(browser, "smoke_workbench_ui.mjs") for browser in browsers]
    if "chromium" in browsers:
        plan.extend(("chromium", script) for script in CHROMIUM_SCRIPTS)
    return plan


def wait_for_preview(url: str, process: subprocess.Popen[bytes]) -> None:
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Web preview exited before it became ready")
        try:
            with opener.open(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Web preview did not become ready")


def run_acceptance(browsers: list[str], output: Path) -> dict[str, object]:
    node = shutil.which("node")
    vite = ROOT / "web" / "node_modules" / "vite" / "bin" / "vite.js"
    if node is None or not vite.is_file():
        raise RuntimeError("Run pnpm install before browser acceptance")
    port = available_port()
    url = f"http://127.0.0.1:{port}"
    preview = subprocess.Popen(
        [node, str(vite), "--host", "127.0.0.1", "--port", str(port), "--strictPort"],
        cwd=ROOT / "web",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    results: list[dict[str, object]] = []
    try:
        wait_for_preview(url, preview)
        for browser, script in acceptance_plan(browsers):
            env = dict(
                os.environ,
                SECRETBRIDGE_UI_URL=url,
                SECRETBRIDGE_BROWSER=browser,
            )
            started = time.monotonic()
            subprocess.run(
                [node, str(ROOT / "tools" / script)],
                cwd=ROOT,
                env=env,
                check=True,
                timeout=120,
            )
            results.append(
                {
                    "browser": browser,
                    "script": script,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                }
            )
    finally:
        preview.terminate()
        try:
            preview.wait(timeout=5)
        except subprocess.TimeoutExpired:
            preview.kill()
            preview.wait(timeout=5)
    report = {
        "format": "secretbridge-browser-acceptance",
        "format_version": 1,
        "browsers": browsers,
        "checks": results,
        "passed": len(results) == len(acceptance_plan(browsers)),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--browser",
        action="append",
        choices=BROWSERS,
        dest="browsers",
        help="browser engine to run; repeat for multiple engines",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "browser-acceptance.json",
    )
    args = parser.parse_args()
    browsers = list(dict.fromkeys(args.browsers or BROWSERS))
    try:
        report = run_acceptance(browsers, args.output)
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"Browser acceptance failed: {error}", file=sys.stderr)
        return 1
    print(
        "Browser acceptance passed: "
        + ", ".join(report["browsers"])
        + f" ({len(report['checks'])} workflows)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
