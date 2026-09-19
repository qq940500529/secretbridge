# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run native package lifecycle acceptance in an isolated user/data directory."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from urllib.request import urlopen
import uuid
import zipfile
from contextlib import closing


def rehash(package: Path) -> None:
    path = package / "secretbridge-package.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for file in manifest["files"]:
        raw = (package / file["path"]).read_bytes()
        file["bytes"], file["sha256"] = len(raw), hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def accept(archive: Path) -> None:
    archive = archive.resolve()
    # macOS Unix sockets have a 104-byte pathname limit; keep the fixture root short.
    with tempfile.TemporaryDirectory(prefix="sb-p-") as temporary:
        workspace = Path(temporary)
        extracted = workspace / "download"
        extracted.mkdir()
        # This script accepts only our own newly-built CI archives, not user uploads.
        if archive.name.endswith(".zip"):
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(extracted)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
        package = next(extracted.iterdir())
        binary = package / "bin" / ("secretbridge-server.exe" if os.name == "nt" else "secretbridge-server")
        data, install = workspace / "data", workspace / "installed"
        env = dict(os.environ, SECRETBRIDGE_DATA_DIR=str(data), SECRETBRIDGE_INSTALL_DIR=str(install),
                   SECRETBRIDGE_BIND="127.0.0.1:0", SECRETBRIDGE_WEB_ROOT=str(package / "web"),
                   APPDATA=str(workspace / "appdata"), HOME=str(workspace / "home"),
                   XDG_CONFIG_HOME=str(workspace / "xdg"))

        def run(*args: str | Path, success: bool = True) -> dict:
            result = subprocess.run([str(binary), *(str(arg) for arg in args)], env=env, capture_output=True, timeout=45)
            assert result.returncode == 0 if success else result.returncode != 0, result.stderr.decode(errors="replace")
            return json.loads(result.stdout) if success and result.stdout else {}

        def web_text() -> str:
            origin = run("status")["runtime"]["origin"]
            with urlopen(origin, timeout=5) as response:
                return response.read().decode("utf-8")

        def wait_stopped() -> None:
            deadline = time.monotonic() + 10
            while (data / "mcp-bridge.json").exists():
                assert time.monotonic() < deadline, "Bridge did not stop"
                time.sleep(0.05)

        try:
            # Detached launch survives return of the command, reuses its broker and persists data.
            first = run("start", "--no-open")
            assert first["version"] == json.loads((package / "secretbridge-package.json").read_text())["version"]
            assert run("start", "--no-open")["process_id"] == first["process_id"]
            status = run("status")
            assert status["running"] and not any(key in status["runtime"] for key in ("token", "bootstrap", "session_token"))
            run("stop")
            wait_stopped()
            assert not run("status")["running"]
            print("Detached launch, broker reuse and graceful stop passed.", flush=True)
            # A plain configuration reference is not a vault secret and can be seeded offline.
            database = data / "secretbridge.sqlite3"
            reference = str(uuid.uuid4())
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("INSERT INTO credential_references (id,name,kind,purpose,secret_state,secret_configured,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?,?,?,NULL,'not_configured',0,1,1,1)", (reference, "delivery acceptance", "password"))

            run("install", package)
            assert run("install", package)["replayed"]
            run("stop")
            assert run("install", package)["replayed"]
            assert run("status")["running"]
            original = run("status")["installation"]["active_release"]
            run("autostart", "on")
            pointer = json.loads((install / "installation.json").read_text(encoding="utf-8"))
            assert pointer["startup_files"]
            print("Versioned installation and isolated login-startup registration passed.", flush=True)
            saved_startup = {item["path"]: Path(item["path"]).read_bytes() for item in pointer["startup_files"]}
            if os.name == "nt":
                assert any(path.endswith(".lnk") for path in saved_startup)
            elif os.uname().sysname == "Darwin":
                import plistlib
                for raw in saved_startup.values():
                    assert plistlib.loads(raw)["RunAtLoad"] is True
            else:
                assert any(b"Terminal=false" in raw for raw in saved_startup.values())

            # Ownership protection must reject modified startup files without deleting them.
            original_path, original_contents = next(iter(saved_startup.items()))
            modified = Path(original_path)
            modified.write_bytes(original_contents + b"\nmodified by user\n")
            run("autostart", "off", success=False)
            assert modified.read_bytes().endswith(b"modified by user\n")
            assert json.loads((install / "installation.json").read_text())["startup_files"] == pointer["startup_files"]
            modified.write_bytes(original_contents)

            # Bad checksums are rejected before stopping the active process.
            bad = workspace / "bad-checksum"
            shutil.copytree(package, bad)
            (bad / "web" / "index.html").write_text("tampered", encoding="utf-8")
            pid = run("status")["runtime"]["process_id"]
            run("install", bad, success=False)
            assert run("status")["runtime"]["process_id"] == pid

            traversal = workspace / "traversal"
            shutil.copytree(package, traversal)
            traversal_manifest = traversal / "secretbridge-package.json"
            malformed = json.loads(traversal_manifest.read_text())
            malformed["files"][0]["path"] = "web/../../outside"
            traversal_manifest.write_text(json.dumps(malformed), encoding="utf-8")
            run("install", traversal, success=False)
            assert run("status")["runtime"]["process_id"] == pid

            # A checksum-valid package with mismatching Web version fails activation and restarts old release.
            broken = workspace / "broken-build"
            shutil.copytree(package, broken)
            build = broken / "web" / "secretbridge-build.json"
            build.write_text('{"format_version":1,"version":"0.0.0-invalid"}', encoding="utf-8")
            rehash(broken)
            run("install", broken, success=False)
            assert run("status")["installation"]["active_release"] == original
            for path, contents in saved_startup.items():
                assert Path(path).read_bytes() == contents
            print("Checksum rejection and activation failure recovery passed.", flush=True)

            upgraded = workspace / "upgrade"
            shutil.copytree(package, upgraded)
            index = upgraded / "web" / "index.html"
            index.write_text(index.read_text(encoding="utf-8") + "\n<!-- delivery upgrade -->\n", encoding="utf-8")
            rehash(upgraded)
            run("install", upgraded)
            assert "delivery upgrade" in web_text()
            assert run("status")["installation"]["previous_release"] == original
            run("rollback")
            assert run("status")["installation"]["active_release"] == original
            assert "delivery upgrade" not in web_text()
            run("stop")
            run("start", "--no-open")
            assert run("status")["installation"]["active_release"] == original
            with closing(sqlite3.connect(database)) as connection:
                assert connection.execute("SELECT name FROM credential_references WHERE id=?", (reference,)).fetchone() == ("delivery acceptance",)
                assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            print("Upgrade, rollback and configuration-preserving restart passed.", flush=True)

            run("autostart", "off")
            assert all(not Path(path).exists() for path in saved_startup)
            run("autostart", "on")
            (install / "keep-me.txt").write_text("unknown user file", encoding="utf-8")
            run("uninstall")
            assert database.exists() and (install / "keep-me.txt").exists()
            assert not (install / "installation.json").exists()
            assert all(not Path(path).exists() for path in saved_startup)
            # A second clean installation exercises the explicit configuration-removal option.
            env["SECRETBRIDGE_INSTALL_DIR"] = str(workspace / "second-install")
            run("install", package)
            (data / "user-note.txt").write_text("retain", encoding="utf-8")
            result = run("uninstall", "--remove-configuration")
            assert result["system_credentials_retained"] and not result["data_retained"]
            assert not database.exists() and (data / "user-note.txt").exists()
            print("Package acceptance passed: detached lifecycle, repeat install, checksum rejection, upgrade failure recovery, startup descriptors, upgrade/rollback, restart, retained data, explicit catalog removal.")
        finally:
            # Never target another user profile or terminate a process using a recorded PID.
            subprocess.run([str(binary), "stop"], env=env, capture_output=True, timeout=30)
            wait_stopped()
            time.sleep(0.2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    accept(parser.parse_args().archive)
