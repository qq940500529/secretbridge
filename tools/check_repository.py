# SPDX-License-Identifier: AGPL-3.0-only
"""Limited public-repository hygiene checks; not a full secret scanner."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

REQUIRED = (
    "README.md", "README.zh-CN.md", "LICENSE", "SECURITY.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "ROADMAP.md",
    "CHANGELOG.md", "THIRD_PARTY_NOTICES.md",
    ".github/workflows/repository-checks.yml",
)
SPECIAL_NAMES = {"LICENSE", ".gitignore", ".gitattributes", ".editorconfig", "CODEOWNERS"}
TEXT_SUFFIXES = {".md", ".py", ".yml", ".yaml"}
SKIP_PARTS = {".git", "__pycache__"}
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "aws-access-key": re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    "credential-url": re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.I),
    "personal-path": re.compile(r"[A-Za-z]:[\\/](?:Users|文档)[\\/]|/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    "private-ip": re.compile(r"(?<![\d.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"),
}


def inspect_file(root: Path, path: Path) -> list[str]:
    """Return rule IDs and relative paths only; never print matching values."""
    relative = path.relative_to(root)
    label = relative.as_posix()
    if path.is_symlink():
        return [f"{label}: symlink-not-allowed"]
    if path.name not in SPECIAL_NAMES and path.suffix not in TEXT_SUFFIXES:
        return [f"{label}: unexpected-artifact"]
    if path.name.startswith(".env") or path.stat().st_size > 1_000_000:
        return [f"{label}: forbidden-or-oversize-file"]
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        return [f"{label}: unreadable-text"]
    errors = [f"{label}: {name}" for name, pattern in PATTERNS.items() if pattern.search(content)]
    if path.suffix == ".md":
        for match in re.finditer(r"\]\(([^)]+)\)", content):
            link = match.group(1).strip().strip("<>")
            parsed = urlsplit(link)
            if parsed.scheme or not parsed.path:
                continue
            target = (path.parent / unquote(parsed.path)).resolve()
            if not target.is_relative_to(root.resolve()):
                errors.append(f"{label}: link-outside-repository")
            elif not target.exists():
                errors.append(f"{label}: missing-local-link")
    return errors


def check_repository(root: Path) -> list[str]:
    errors = [f"{name}: required-file-missing" for name in REQUIRED if not (root / name).is_file()]
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or path.is_file():
            errors.extend(inspect_file(root, path))
    readme = root / "README.md"
    if readme.exists() and "AGPL-3.0-only" not in readme.read_text(encoding="utf-8"):
        errors.append("README.md: license-identifier-missing")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = check_repository(args.root.resolve())
    if errors:
        print("Repository checks failed (matching content intentionally omitted):")
        print("\n".join(errors))
        return 1
    print("Repository checks passed. Limited hygiene checks only; not a security audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
