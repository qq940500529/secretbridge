# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Create a native portable package with matching assets, source and notices."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
import base64
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import re
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = ("LICENSE", "LICENSING.md", "COPYRIGHT.md", "THIRD_PARTY_NOTICES.md",
             "COMMERCIAL_LICENSE.md", "README.md")
NATIVE_PLATFORMS = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}
ARCHITECTURES = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def command(args: list[str]) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, encoding="utf-8", timeout=120)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def release_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH") or command(["git", "log", "-1", "--format=%ct"]).strip()
    try:
        epoch = int(raw)
    except ValueError as error:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from error
    # ZIP's DOS timestamp cannot represent dates after 2107.
    if not 0 <= epoch <= 4_354_819_198:
        raise ValueError("SOURCE_DATE_EPOCH is outside the supported range")
    return epoch


def _tar_info(name: str, size: int, epoch: int, mode: int = 0o644) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = epoch
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def source_snapshot(target: Path, allow_dirty: bool, epoch: int | None = None) -> dict:
    dirty = bool(command(["git", "status", "--porcelain"]).strip())
    if dirty and not allow_dirty:
        raise ValueError("Release packaging requires a clean source checkout")
    commit = command(["git", "rev-parse", "HEAD"]).strip()
    names = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    epoch = release_epoch() if epoch is None else epoch
    with target.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name in sorted(set(names.split("\0")) - {""}):
                    path = ROOT / name
                    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()):
                        raise ValueError("Source snapshot contains a missing or unsupported file")
                    content = path.read_bytes()
                    archive.addfile(_tar_info(f"secretbridge-source/{name}", len(content), epoch), io.BytesIO(content))
    return {"repository": "https://github.com/qq940500529/secretbridge", "base_commit": commit,
            "dirty": dirty, "corresponding_source": "SOURCE.tar.gz",
            "source_sha256": sha256(target), "source_date_epoch": epoch}


def software_bill_of_materials(version: str, native: str, arch: str, source: dict, epoch: int) -> dict:
    """Create a deterministic CycloneDX inventory for the resolved native and Web runtime graph."""
    host = re.search(r"^host: (.+)$", command(["rustc", "-vV"]), re.MULTILINE)[1]
    metadata = json.loads(command(["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", host]))
    resolved = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    components: dict[str, dict] = {}
    dependency_edges: dict[str, set[str]] = {}
    cargo_refs: dict[str, str] = {}
    for package in metadata["packages"]:
        if package["id"] not in resolved:
            continue
        ref = f"pkg:cargo/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}"
        cargo_refs[package["id"]] = ref
        component = {"type": "library", "bom-ref": ref, "name": package["name"],
                     "version": package["version"], "purl": ref}
        if package.get("license"):
            component["licenses"] = [{"license": {"name": package["license"]}}]
        if package.get("repository"):
            component["externalReferences"] = [{"type": "vcs", "url": package["repository"]}]
        components[ref] = component
    for package_id, node in resolved.items():
        if package_id not in cargo_refs:
            continue
        dependency_edges[cargo_refs[package_id]] = {
            cargo_refs[item["pkg"]] for item in node.get("deps", []) if item["pkg"] in cargo_refs
        }

    graph = json.loads(command([shutil.which("pnpm") or "pnpm", "--dir", "web", "list", "--prod", "--depth", "Infinity", "--json"]))
    npm_root_refs: set[str] = set()

    def visit_npm(name: str, node: dict) -> str | None:
        version_value = node.get("version")
        if not version_value:
            return None
        ref = f"pkg:npm/{quote(name, safe='/')}@{quote(str(version_value), safe='')}"
        component = {"type": "library", "bom-ref": ref, "name": name,
                     "version": str(version_value), "purl": ref}
        manifest_path = Path(node["path"]) / "package.json" if node.get("path") else None
        if manifest_path and manifest_path.is_file():
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest_data.get("license"):
                component["licenses"] = [{"license": {"name": str(manifest_data["license"])}}]
        components[ref] = component
        children = set()
        for group in ("dependencies", "optionalDependencies"):
            for child_name, child in node.get(group, {}).items():
                if child_ref := visit_npm(child_name, child):
                    children.add(child_ref)
        dependency_edges.setdefault(ref, set()).update(children)
        return ref

    for workspace in graph:
        for group in ("dependencies", "optionalDependencies"):
            for dependency_name, dependency in workspace.get(group, {}).items():
                if dependency_ref := visit_npm(dependency_name, dependency):
                    npm_root_refs.add(dependency_ref)

    application_ref = f"pkg:generic/secretbridge@{quote(version, safe='')}?arch={quote(arch, safe='')}&platform={quote(native, safe='')}"
    workspace_refs = {
        ref
        for package_id, ref in cargo_refs.items()
        if packages_by_id[package_id].get("source") is None
    }
    dependency_edges[application_ref] = workspace_refs | npm_root_refs
    timestamp = datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{source['repository']}@{source['base_commit']}:{native}:{arch}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {"type": "application", "bom-ref": application_ref,
                          "name": "SecretBridge", "version": version,
                          "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}]},
            "properties": [
                {"name": "secretbridge:platform", "value": native},
                {"name": "secretbridge:architecture", "value": arch},
                {"name": "secretbridge:source-commit", "value": source["base_commit"]},
            ],
        },
        "components": [components[ref] for ref in sorted(components)],
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(dependencies)}
            for ref, dependencies in sorted(dependency_edges.items())
        ],
    }


def _write_deterministic_archive(package: Path, archive: Path, name: str, native: str, epoch: int) -> None:
    paths = [path for path in sorted(package.rglob("*")) if path.is_file()]
    if native == "windows":
        stamp = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc)
        date_time = (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second)
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for path in paths:
                relative = path.relative_to(package).as_posix()
                info = zipfile.ZipInfo(f"{name}/{relative}", date_time=date_time)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ((0o755 if relative.startswith("bin/") else 0o644) & 0xFFFF) << 16
                bundle.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        return
    with archive.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
                root = _tar_info(name, 0, epoch, 0o755)
                root.type = tarfile.DIRTYPE
                bundle.addfile(root)
                for path in paths:
                    relative = path.relative_to(package).as_posix()
                    content = path.read_bytes()
                    mode = 0o755 if relative.startswith("bin/") else 0o644
                    bundle.addfile(_tar_info(f"{name}/{relative}", len(content), epoch, mode), io.BytesIO(content))


@lru_cache(maxsize=128)
def upstream_license(repository: str, commit: str) -> str:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)", repository)
    if match is None or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Missing license cannot be resolved from pinned upstream source")
    owner, repo = match[1], match[2].removesuffix(".git")
    # Older published russh manifests retain the repository's former owner.
    if (owner, repo) == ("warp-tech", "russh"):
        owner = "Eugeny"
    for name in ("LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "LICENSE.txt", "LICENSE.md", "LICENSE-MIT.txt", "LICENSE-APACHE.txt", "LICENSE-2.0.txt"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{name}"
        if shutil.which("gh"):
            result = subprocess.run(["gh", "api", f"repos/{owner}/{repo}/contents/{name}?ref={commit}"],
                                    capture_output=True, text=True, encoding="utf-8", timeout=30)
            if result.returncode != 0:
                if "HTTP 404" in result.stderr:
                    continue
                raise ValueError(f"Pinned license fetch failed: {owner}/{repo}/{name}")
            content = json.loads(result.stdout)
            if content.get("encoding") != "base64":
                raise ValueError("Unsupported upstream license encoding")
            raw = base64.b64decode(content["content"])
        else:
            try:
                with urlopen(url, timeout=20) as response:
                    raw = response.read(1024 * 1024 + 1)
            except HTTPError as error:
                if error.code == 404:
                    continue
                raise
        if len(raw) > 1024 * 1024:
            raise ValueError("Upstream license file exceeds size limit")
        text = raw.decode("utf-8")
        return f"\n--- {url} (SHA-256 {hashlib.sha256(raw).hexdigest()}) ---\n{text}\n"
    raise ValueError(f"Pinned upstream license unavailable: {owner}/{repo}@{commit}")


def third_party_notices() -> str:
    host = re.search(r"^host: (.+)$", command(["rustc", "-vV"]), re.MULTILINE)[1]
    metadata = json.loads(command(["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", host]))
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    packages = sorted((item for item in metadata["packages"] if item.get("source") and item["id"] in resolved),
                      key=lambda item: (item["name"], item["version"]))

    def rust_notice(package: dict) -> str:
        sections = [f"\n=== Rust: {package['name']} {package['version']} ({package.get('license')}) ===\n"]
        directory = Path(package["manifest_path"]).parent
        files = [path for path in directory.iterdir() if path.is_file() and
                 path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"))]
        if package.get("license_file"):
            files.append(directory / package["license_file"])
        # Some crates retain license files in a dedicated license directory.
        for folder in ("LICENSES", "licenses"):
            if (directory / folder).is_dir():
                files.extend(path for path in (directory / folder).rglob("*") if path.is_file())
        if not files:
            vcs = json.loads((directory / ".cargo_vcs_info.json").read_text(encoding="utf-8"))
            sections.append(upstream_license(package["repository"], vcs["git"]["sha1"]))
        for path in sorted(set(files)):
            sections.append(f"\n--- {path.relative_to(directory).as_posix()} ---\n")
            sections.append(path.read_text(encoding="utf-8", errors="replace"))
        return "\n".join(sections)

    sections = ["SecretBridge third-party license texts\nGenerated from locked build sources and pinned upstream commits.\n"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        sections.extend(pool.map(rust_notice, packages))
    graph = json.loads(command([shutil.which("pnpm") or "pnpm", "--dir", "web", "list", "--prod", "--depth", "Infinity", "--json"]))
    manifests = set()
    def visit(node: dict) -> None:
        for group in ("dependencies", "optionalDependencies"):
            for dependency in node.get(group, {}).values():
                if dependency.get("path"):
                    manifests.add(Path(dependency["path"]) / "package.json")
                visit(dependency)
    for workspace in graph:
        visit(workspace)
    seen = set()
    for manifest in sorted(manifests):
        package = json.loads(manifest.read_text(encoding="utf-8"))
        key = (package.get("name"), package.get("version"))
        if key in seen:
            continue
        seen.add(key)
        files = [path for path in manifest.parent.iterdir() if path.is_file() and
                 path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"))]
        if not files:
            raise ValueError(f"License text missing for npm package {key}")
        sections.append(f"\n=== npm: {key[0]} {key[1]} ({package.get('license')}) ===\n")
        for path in sorted(files):
            sections.append(f"\n--- {path.name} ---\n{path.read_text(encoding='utf-8', errors='replace')}\n")
    if not seen:
        raise ValueError("Web dependency sources are unavailable; run pnpm install first")
    return "\n".join(sections)


def build_package(binary: Path, output: Path, allow_dirty: bool = False) -> Path:
    binary, output = binary.resolve(), output.resolve()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    web = ROOT / "web" / "dist"
    build = json.loads((web / "secretbridge-build.json").read_text(encoding="utf-8"))
    actual = subprocess.check_output([str(binary), "--version"], text=True, timeout=20).strip()
    if build != {"format_version": 1, "version": version} or actual != version:
        raise ValueError("Executable, source and Web versions must match")
    native = NATIVE_PLATFORMS[platform.system()]
    arch = ARCHITECTURES[platform.machine()]
    name = f"secretbridge-{version}-{native}-{arch}"
    epoch = release_epoch()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secretbridge-package-") as temporary:
        package = Path(temporary) / name
        (package / "bin").mkdir(parents=True)
        executable = package / "bin" / ("secretbridge-server.exe" if native == "windows" else "secretbridge-server")
        shutil.copy2(binary, executable)
        if os.name != "nt":
            executable.chmod(0o755)
        shutil.copytree(web, package / "web")
        for document in DOCUMENTS:
            shutil.copy2(ROOT / document, package / document)
        source = source_snapshot(package / "SOURCE.tar.gz", allow_dirty, epoch)
        (package / "SOURCE.json").write_text(json.dumps(source, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (package / "THIRD_PARTY_LICENSES.txt").write_text(third_party_notices(), encoding="utf-8")
        sbom = software_bill_of_materials(version, native, arch, source, epoch)
        (package / "SBOM.cdx.json").write_text(
            json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        files = []
        for path in sorted(package.rglob("*")):
            if path.is_file():
                if path.is_symlink():
                    raise ValueError("Package symlinks are not supported")
                files.append({"path": path.relative_to(package).as_posix(), "bytes": path.stat().st_size, "sha256": sha256(path)})
        manifest = {"format": "secretbridge-package", "format_version": 1, "version": version,
                    "platform": native, "architecture": arch, "schema_version": 15, "files": files}
        (package / "secretbridge-package.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        archive = output / (name + (".zip" if native == "windows" else ".tar.gz"))
        if archive.exists():
            raise ValueError("Output package already exists; use a new output directory")
        _write_deterministic_archive(package, archive, name, native, epoch)
        archive.with_name(archive.name + ".sha256").write_text(f"{sha256(archive)}  {archive.name}\n", encoding="ascii")
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true", help="Local development only; source snapshot is marked dirty")
    args = parser.parse_args()
    print(build_package(args.binary, args.output, args.allow_dirty))


if __name__ == "__main__":
    main()
