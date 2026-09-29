# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build and verify portable, version-matched client downloads without compiling."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
SPECS = (
    ("codex-plugin", "plugins/secretbridge", "secretbridge", ".zip"),
    ("workbuddy-connector", "connectors/workbuddy", "secretbridge-workbuddy", ".zip"),
    ("workbuddy-skill", "connectors/workbuddy/skills/secretbridge-workbuddy", "", ".zip"),
    ("deepseek-harness", "plugins/deepseek-harness", "package", ".tgz"),
    ("operations-skill", "skills/secretbridge-operations", "secretbridge-operations", ".zip"),
)
MAX_BYTES = 32 * 1024 * 1024


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=root, text=True, encoding="utf-8", timeout=30
    )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in name.split("/"))
        and "\\" not in name
        and ":" not in name
    )


def write_archive(path: Path, files: dict[str, bytes], epoch: int) -> None:
    if path.suffix == ".zip":
        stamp = datetime.fromtimestamp(max(epoch, 315532800), UTC)
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(name, stamp.timetuple()[:6])
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                bundle.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    else:
        with (
            path.open("xb") as stream,
            gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=epoch) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle,
        ):
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(data), epoch, 0o644
                bundle.addfile(info, io.BytesIO(data))


def build(output: Path, root: Path = ROOT) -> list[Path]:
    if git(root, "status", "--porcelain").strip():
        raise ValueError("Client release packaging requires a clean source checkout")
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"][
        "package"
    ]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("Invalid release version")
    commit = git(root, "rev-parse", "HEAD").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid source commit")
    epoch = int(git(root, "log", "-1", "--format=%ct").strip())
    tracked = git(root, "ls-files", "-z").split("\0")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Client output directory must be empty; existing files are not replaced")
    archives = []
    for kind, source, prefix, extension in SPECS:
        files = {}
        for name in tracked:
            if not name.startswith(source + "/"):
                continue
            relative = name[len(source) + 1 :]
            path = root / name
            if (
                not safe_name(relative)
                or path.is_symlink()
                or not path.is_file()
                or not path.resolve().is_relative_to(root.resolve())
            ):
                raise ValueError("Unsupported client source entry")
            files[relative] = path.read_bytes()
        if not files:
            raise ValueError(f"Client source is empty: {kind}")
        manifests = {
            "codex-plugin": (".codex-plugin/plugin.json", "version"),
            "workbuddy-connector": ("connector-meta.json", "version"),
            "deepseek-harness": ("package.json", "version"),
            "operations-skill": ("references/compatibility.json", "broker_version"),
        }
        if kind in manifests:
            manifest, key = manifests[kind]
            if json.loads(files[manifest])[key] != version:
                raise ValueError(f"Client version does not match broker: {kind}")
        if kind in {"workbuddy-skill", "workbuddy-connector"}:
            skill = (
                "SKILL.md"
                if kind == "workbuddy-skill"
                else "skills/secretbridge-workbuddy/SKILL.md"
            )
            if f"\nversion: {version}\n" not in files[skill].decode("utf-8"):
                raise ValueError("WorkBuddy Skill version does not match broker")
        for document in ("LICENSE", "COPYRIGHT.md"):
            files[document] = (root / document).read_bytes()
        files["INSTALL.md"] = (root / "docs/release/客户端集成下载.md").read_bytes()
        if sum(map(len, files.values())) > MAX_BYTES:
            raise ValueError("Client contents exceed the release size limit")
        metadata = {
            "format": "secretbridge-client-integration",
            "format_version": 1,
            "integration": kind,
            "version": version,
            "broker_version": version,
            "api_version": "v1",
            "source_commit": commit,
            "source_url": f"https://github.com/qq940500529/secretbridge/tree/{commit}",
            "files": [
                {"path": name, "bytes": len(data), "sha256": digest(data)}
                for name, data in sorted(files.items())
            ],
        }
        files["INTEGRATION.json"] = (
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n"
        ).encode()
        files = {f"{prefix}/{name}" if prefix else name: data for name, data in files.items()}
        archive = output / f"secretbridge-{version}-{kind}{extension}"
        write_archive(archive, files, epoch)
        checksum = digest(archive.read_bytes())
        archive.with_name(archive.name + ".sha256").write_text(
            f"{checksum}  {archive.name}\n", encoding="ascii"
        )
        archives.append(archive)
    verify(output)
    return archives


def read_archive(path: Path) -> dict[str, bytes]:
    entries = {}
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("Client archive exceeds the release size limit")
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as bundle:
            records = bundle.infolist()
            if sum(record.file_size for record in records) > MAX_BYTES:
                raise ValueError("Expanded client archive exceeds the size limit")
            for record in records:
                if record.is_dir() or record.external_attr >> 28 == 0xA:
                    raise ValueError("Client archives must contain regular files only")
                if not safe_name(record.filename) or record.filename in entries:
                    raise ValueError("Unsafe or duplicate archive path")
                entries[record.filename] = bundle.read(record)
    else:
        with tarfile.open(path, "r:gz") as bundle:
            records = bundle.getmembers()
            if sum(record.size for record in records) > MAX_BYTES:
                raise ValueError("Expanded client archive exceeds the size limit")
            for record in records:
                if not record.isfile() or not safe_name(record.name) or record.name in entries:
                    raise ValueError("Unsafe or duplicate archive entry")
                entries[record.name] = bundle.extractfile(record).read()
    return entries


def verify(directory: Path) -> list[str]:
    archives = sorted(path for path in directory.iterdir() if path.name.endswith((".zip", ".tgz")))
    if len(archives) != len(SPECS) or len(list(directory.iterdir())) != 2 * len(SPECS):
        raise ValueError("Expected exactly five client archives and five SHA-256 sidecars")
    seen, versions, commits = set(), set(), set()
    for archive in archives:
        if archive.stat().st_size > MAX_BYTES:
            raise ValueError("Client archive exceeds the release size limit")
        checksum = digest(archive.read_bytes())
        if archive.with_name(archive.name + ".sha256").read_text(encoding="ascii").strip() != (
            f"{checksum}  {archive.name}"
        ):
            raise ValueError("Client archive checksum mismatch")
        files = read_archive(archive)
        manifest_names = [name for name in files if name.endswith("INTEGRATION.json")]
        if len(manifest_names) != 1:
            raise ValueError("Expected one integration manifest")
        manifest_name = manifest_names[0]
        meta = json.loads(files.pop(manifest_name))
        spec = next((spec for spec in SPECS if spec[0] == meta.get("integration")), None)
        if spec is None or spec[0] in seen:
            raise ValueError("Unknown or duplicate integration")
        kind, _, prefix, extension = spec
        if (
            meta.get("format") != "secretbridge-client-integration"
            or meta.get("format_version") != 1
            or meta.get("api_version") != "v1"
            or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", meta.get("version", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", meta.get("source_commit", ""))
            or meta.get("source_url")
            != f"https://github.com/qq940500529/secretbridge/tree/{meta.get('source_commit')}"
            or meta.get("version") != meta.get("broker_version")
            or archive.name != f"secretbridge-{meta['version']}-{kind}{extension}"
            or manifest_name != (f"{prefix}/INTEGRATION.json" if prefix else "INTEGRATION.json")
        ):
            raise ValueError("Inconsistent integration metadata")
        expected = {
            f"{prefix}/{entry['path']}" if prefix else entry["path"]: entry
            for entry in meta["files"]
        }
        if len(expected) != len(meta["files"]) or expected.keys() != files.keys():
            raise ValueError("Client archive inventory mismatch")
        for name, data in files.items():
            if expected[name]["bytes"] != len(data) or expected[name]["sha256"] != digest(data):
                raise ValueError("Client file checksum mismatch")
        seen.add(kind)
        versions.add(meta["version"])
        commits.add(meta["source_commit"])
    if len(versions) != 1 or len(commits) != 1:
        raise ValueError("Client archives must share one version and source commit")
    return [path.name for path in archives]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    if args.output:
        if args.compare:
            parser.error("--compare requires --verify")
        for archive in build(args.output):
            print(archive.name)
    else:
        names = verify(args.verify)
        if args.compare and (
            names != verify(args.compare)
            or any(
                (args.verify / name).read_bytes() != (args.compare / name).read_bytes()
                for name in names
            )
        ):
            raise ValueError("Client archives differ between independent packaging runs")
        print(
            "Five client integration archives verified" + ("; reproducible" if args.compare else "")
        )


if __name__ == "__main__":
    main()
