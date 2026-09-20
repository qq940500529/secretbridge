# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the repeatable macOS native acceptance against a built package."""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import tarfile
import tempfile
import threading
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sanitized(text: str) -> str:
    replacements = sorted(
        ((str(ROOT), "$REPOSITORY"), (str(Path.home()), "$HOME")),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    for original, replacement in replacements:
        text = text.replace(original, replacement)
    return text


def run(label: str, command: list[str], *, env: dict[str, str] | None = None) -> str:
    print(f"\n== {label} ==", flush=True)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=900,
    )
    output = sanitized(result.stdout + result.stderr)
    if output:
        print(output.rstrip(), flush=True)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")
    return result.stdout


def extract_archive(archive: Path, destination: Path) -> Path:
    destination.mkdir()
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                candidate = (destination / member.filename).resolve()
                if (
                    destination.resolve() not in candidate.parents
                    and candidate != destination.resolve()
                ):
                    raise RuntimeError("package archive contains an unsafe path")
            bundle.extractall(destination)
    elif archive.name.endswith(".tar.gz"):
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter="data")
    else:
        raise RuntimeError("expected a .tar.gz or .zip native package")
    packages = [item for item in destination.iterdir() if item.is_dir()]
    if len(packages) != 1:
        raise RuntimeError("native package must contain exactly one top-level directory")
    return packages[0]


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass


def browser_acceptance(package: Path, environment: dict[str, str]) -> None:
    web = package / "web"
    if not (web / "index.html").is_file():
        raise RuntimeError("packaged Web assets are missing")
    handler = partial(QuietHandler, directory=str(web))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        browser_environment = dict(
            environment,
            SECRETBRIDGE_UI_URL=f"http://127.0.0.1:{server.server_port}",
            PLAYWRIGHT_CHANNEL=environment.get("PLAYWRIGHT_CHANNEL", "chrome"),
        )
        run(
            "Packaged Web workbench navigation and synthetic workflow",
            ["node", "tools/smoke_workbench_ui.mjs"],
            env=browser_environment,
        )
        run(
            "Packaged Web background-service interaction",
            ["node", "tools/smoke_background_ui.mjs"],
            env=browser_environment,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def accept(archive: Path) -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("this acceptance entry is intentionally limited to macOS")
    archive = archive.resolve(strict=True)
    environment = dict(os.environ)

    print(
        f"macOS {platform.mac_ver()[0]} ({platform.machine()}); disposable data only",
        flush=True,
    )
    run(
        "Apple Keychain write/read/overwrite/delete/failure cleanup",
        [
            "cargo",
            "test",
            "-p",
            "secretbridge-server",
            "native_store_round_trip_uses_a_disposable_entry",
            "--",
            "--ignored",
            "--nocapture",
        ],
        env=environment,
    )
    run(
        "Persistent zsh create/input/reconnect/cursor/close",
        [
            "cargo",
            "test",
            "-p",
            "secretbridge-server",
            "--test",
            "real_terminal",
            "platform_shell_preserves_state_across_browser_reconnection",
            "--",
            "--nocapture",
        ],
        env=environment,
    )
    run(
        "Unpacked verification and isolated install lifecycle",
        ["python3", "tools/test_packaged_delivery.py", str(archive)],
        env=environment,
    )

    with tempfile.TemporaryDirectory(prefix="sb-macos-ui-") as temporary:
        package = extract_archive(archive, Path(temporary) / "package")
        browser_acceptance(package, environment)

    print(
        "\nmacOS native acceptance passed; temporary package, browser profile, "
        "installation fixtures, test credentials and terminal sessions were cleaned.",
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="newly built native .tar.gz package")
    accept(parser.parse_args().archive)
