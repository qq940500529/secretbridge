# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conservatively select CI checks affected by a commit range."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

CHECKS = frozenset({"dependency", "database", "python", "web", "rust", "browser", "package"})
ROOT_DOCUMENTS = frozenset(
    {
        "README.md",
        "README.zh-CN.md",
        "CHANGELOG.md",
        "ROADMAP.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
    }
)
DOCUMENT_EXTENSIONS = frozenset(
    {".md", ".mdx", ".txt", ".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".pdf"}
)
VERSION_MANIFESTS = frozenset({"Cargo.toml", "Cargo.lock", "package.json", "frontend/package.json"})
WEB_MANIFESTS = frozenset({"pnpm-lock.yaml", "pnpm-workspace.yaml", ".node-version"})
RELEASE_MATERIALS = frozenset(
    {"LICENSE", "LICENSING.md", "COMMERCIAL_LICENSE.md", "COPYRIGHT.md", "THIRD_PARTY_NOTICES.md"}
)


def checks_for_path(path: str) -> frozenset[str]:
    """Unknown paths deliberately cause every check to run."""
    if path in ROOT_DOCUMENTS or (
        path.startswith("docs/")
        and not path.startswith("docs/.")
        and Path(path).suffix.lower() in DOCUMENT_EXTENSIONS
    ):
        return frozenset()
    if path.startswith(".github/") or path == "tools/checks/change_scope.py":
        return CHECKS
    if path in VERSION_MANIFESTS or path.startswith("security/"):
        return CHECKS
    if path in WEB_MANIFESTS:
        return frozenset({"dependency", "web", "browser", "package"})
    if path in RELEASE_MATERIALS:
        return frozenset({"dependency", "python", "package"})
    if path.startswith("backend/"):
        if path.endswith(("Cargo.toml", "build.rs")):
            return CHECKS
        if path.startswith("backend/local-access/"):
            return frozenset({"rust", "package"})
        if path.startswith("backend/src/adapters/executors/database/") or path == (
            "backend/src/adapters/executors/postgres.rs"
        ):
            return frozenset({"rust", "database", "browser", "package"})
        if path.startswith("backend/src/adapters/http/"):
            return frozenset({"rust", "python", "browser", "package"})
        if path == "backend/src/adapters/persistence/schema.rs":
            return frozenset({"rust", "python", "database", "package"})
        return frozenset({"rust", "browser", "package"})
    if path.startswith("frontend/"):
        return frozenset({"web", "browser", "package"})
    if path.startswith("skills/"):
        return frozenset({"python", "package"})
    if path.startswith("tools/release/"):
        return frozenset({"dependency", "python", "package"})
    if path.startswith("tools/checks/"):
        if "dependency" in path:
            return frozenset({"dependency", "python", "package"})
        return frozenset({"python"})
    if path == "tools/requirements-dev.txt":
        return frozenset({"python"})
    if path.startswith("tools/acceptance/"):
        if path.endswith(".mjs") or "browser" in path:
            return frozenset({"python", "browser"})
        if "database" in path:
            return frozenset({"database"})
        return frozenset({"python", "package"})
    if path.startswith("tests/"):
        if path.startswith("tests/release/"):
            return frozenset({"python", "package"})
        if path.startswith("tests/acceptance/"):
            return frozenset({"python", "browser", "package"})
        if "dependency" in path:
            return frozenset({"dependency", "python"})
        return frozenset({"python"})
    return CHECKS


def affected_checks(paths: list[str]) -> frozenset[str]:
    if not paths:
        return CHECKS
    affected: set[str] = set()
    for path in paths:
        affected.update(checks_for_path(path))
    return frozenset(affected)


def changed_paths(base: str, head: str, root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            base,
            head,
            "--",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [path.decode("utf-8") for path in result.stdout.split(b"\0") if path]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    # Scheduled/manual runs and a repository's initial push always run the full suite.
    affected = CHECKS
    if args.base and args.base.strip("0"):
        try:
            affected = affected_checks(changed_paths(args.base, args.head, root))
        except subprocess.CalledProcessError:
            print("Commit range unavailable; running the full suite")
    with args.github_output.open("a", encoding="utf-8") as output:
        output.write(f"docs_only={'true' if not affected else 'false'}\n")
        for check in sorted(CHECKS):
            output.write(f"{check}={'true' if check in affected else 'false'}\n")
    print("Selected checks: " + (", ".join(sorted(affected)) or "documentation only"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
