# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Limited public-repository hygiene checks; not a full secret scanner."""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

REQUIRED = (
    "README.md",
    "README.zh-CN.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "ROADMAP.md",
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
    "COPYRIGHT.md",
    "LICENSING.md",
    "COMMERCIAL_LICENSE.md",
    "docs/README.md",
    "docs/使用指南.md",
    "docs/开发者入门.md",
    "docs/依赖许可风险评估.md",
    "docs/贡献与再许可.md",
    "docs/发行物验证与SBOM.md",
    "docs/依赖漏洞与发行门槛.md",
    "docs/自动化安全验收.md",
    "security/dependency-vulnerability-policy.json",
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "rust-toolchain.toml",
    "tools/check_dependency_licenses.py",
    "tools/verify_reproducible_packages.py",
    ".github/workflows/repository-checks.yml",
)
SPECIAL_NAMES = {
    "LICENSE",
    "Cargo.lock",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".node-version",
    ".prettierignore",
    "CODEOWNERS",
}
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".json",
    ".md",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".mjs",
    ".yml",
    ".yaml",
    ".ps1",
    ".sh",
}
SKIP_PARTS = {".git", ".ruff_cache", "__pycache__", "dist", "node_modules", "target"}
MAX_RUST_SOURCE_LINES = 2_500
MAX_MARKDOWN_LINES = 240
PUBLIC_REPOSITORY_URL = "https://github.com/qq940500529/secretbridge"
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "aws-access-key": re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    "credential-url": re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
    "personal-path": re.compile(
        r"[A-Za-z]:[\\/](?:Users|文档)[\\/]|/(?:Users|home)/[A-Za-z0-9_.-]+/"
    ),
    "private-ip": re.compile(
        r"(?<![\d.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"
    ),
}


def markdown_structure(content: str) -> tuple[str, list[str]]:
    """Check our Markdown subset; omit fenced examples from link/HTML checks."""
    visible = []
    fence = None
    for line in content.splitlines():
        if fence is not None:
            if re.fullmatch(
                r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*", line
            ):
                fence = None
            continue
        opening = re.match(r" {0,3}(`{3,}|~{3,})(.*)$", line)
        if opening and not (opening[1][0] == "`" and "`" in opening[2]):
            fence = opening[1]
        else:
            visible.append(line)
    errors = ["unclosed-fence"] if fence is not None else []
    body = "\n".join(visible)
    depth = 0
    for match in re.finditer(r"<(/?)details\b[^>]*>", body, re.IGNORECASE):
        depth += -1 if match[1] else 1
        if depth < 0:
            errors.append("unbalanced-details")
            depth = 0
    if depth:
        errors.append("unbalanced-details")
    return body, errors


def markdown_anchors(content: str) -> set[str]:
    """Support explicit anchors and plain ATX headings used by this repository.

    This is not a complete GitHub slug renderer; rich heading syntax needs
    an explicit anchor and a rendering review.
    """
    body, _ = markdown_structure(content)
    anchors = set(re.findall(r'<a\s+(?:name|id)=["\x27]([^"\x27]+)["\x27]', body, re.IGNORECASE))
    generated = set()
    for heading in re.findall(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", body, re.MULTILINE):
        plain = re.sub(r"<[^>]+>", "", heading).replace("`", "")
        slug = "".join(
            c for c in plain.lower() if c in "-_ " or unicodedata.category(c)[0] in "LNM"
        )
        slug = slug.replace(" ", "-")
        candidate, suffix = slug, 0
        while candidate in generated:
            suffix += 1
            candidate = f"{slug}-{suffix}"
        generated.add(candidate)
    return anchors | generated


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
    line_count = len(content.splitlines())
    if path.suffix == ".rs" and line_count > MAX_RUST_SOURCE_LINES:
        errors.append(f"{label}: oversized-rust-module")
    if path.suffix == ".md" and line_count > MAX_MARKDOWN_LINES:
        errors.append(f"{label}: oversized-document")
    if path.suffix == ".md":
        body, structure_errors = markdown_structure(content)
        errors.extend(f"{label}: {rule}" for rule in structure_errors)
        for match in re.finditer(r"\]\(([^)]+)\)", body):
            link = match.group(1).strip().strip("<>")
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue
            target = (
                (path.parent / unquote(parsed.path)).resolve() if parsed.path else path.resolve()
            )
            if not target.is_relative_to(root.resolve()):
                errors.append(f"{label}: link-outside-repository")
            elif not target.exists():
                errors.append(f"{label}: missing-local-link")
            elif parsed.fragment and target.is_file() and target.suffix == ".md":
                try:
                    target_text = target.read_text(encoding="utf-8")
                except (UnicodeError, OSError):
                    errors.append(f"{label}: unreadable-link-target")
                    continue
                if unquote(parsed.fragment) not in markdown_anchors(target_text):
                    errors.append(f"{label}: missing-fragment")
    return errors


def check_repository(root: Path) -> list[str]:
    errors = [f"{name}: required-file-missing" for name in REQUIRED if not (root / name).is_file()]
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or path.is_file():
            errors.extend(inspect_file(root, path))
    readme = root / "README.md"
    if readme.exists() and "AGPL-3.0-or-later" not in readme.read_text(encoding="utf-8"):
        errors.append("README.md: license-identifier-missing")
    errors.extend(check_ai_deployment_entrypoints(root))
    return errors


def check_ai_deployment_entrypoints(root: Path) -> list[str]:
    """Keep the public, checkout-independent deployment entry points discoverable."""
    errors = []
    contracts = {
        "README.md": (PUBLIC_REPOSITORY_URL, "You may start from any directory"),
        "README.zh-CN.md": (PUBLIC_REPOSITORY_URL, "任意目录"),
        "docs/AI辅助部署.md": (PUBLIC_REPOSITORY_URL, "不需要预先克隆仓库"),
    }
    for name, required_text in contracts.items():
        path = root / name
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        if any(text not in content for text in required_text):
            errors.append(f"{name}: ai-deployment-entrypoint-missing")
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
