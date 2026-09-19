# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail closed on known Rust and production Web dependency vulnerabilities."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "security" / "dependency-vulnerability-policy.json"
ADVISORY_PATTERNS = {
    "cargo": re.compile(r"^RUSTSEC-\d{4}-\d{4}$"),
    "npm": re.compile(
        r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$",
        re.IGNORECASE,
    ),
}
PACKAGE_PATTERN = re.compile(r"[A-Za-z0-9@._/+:-]{1,160}")


@dataclass(frozen=True, order=True)
class Finding:
    ecosystem: str
    advisory_id: str
    package: str
    severity: str
    title: str

    @property
    def key(self) -> tuple[str, str, str]:
        return self.ecosystem, self.advisory_id.upper(), self.package


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read valid JSON: {path.name}") from error


def report_text(value: Any, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = " ".join(value.split())[:160]
    return normalized or fallback


def command_text(command: list[str], accepted_codes: set[int] | None = None) -> str:
    accepted_codes = {0} if accepted_codes is None else accepted_codes
    command_name = Path(command[0]).name
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"scanner command failed to run: {command_name}") from error
    if result.returncode not in accepted_codes:
        raise RuntimeError(f"scanner command failed: {command_name} (exit {result.returncode})")
    return result.stdout


def command_json(command: list[str]) -> Any:
    output = command_text(command, {0, 1})
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"scanner returned no valid JSON report: {Path(command[0]).name}"
        ) from error


def load_policy(path: Path, today: date) -> dict[str, Any]:
    policy = read_json(path)
    if not isinstance(policy, dict) or policy.get("schemaVersion") != 1:
        raise ValueError("dependency policy schemaVersion must be 1")
    scanners = policy.get("scanners")
    if not isinstance(scanners, dict) or set(scanners) != {"cargo-audit", "pnpm"}:
        raise ValueError("dependency policy must pin cargo-audit and pnpm")
    for name, version in scanners.items():
        if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError(f"invalid scanner version: {name}")

    exceptions = policy.get("exceptions")
    if not isinstance(exceptions, list):
        raise TypeError("dependency policy exceptions must be a list")
    seen: set[tuple[str, str, str]] = set()
    required = {
        "ecosystem",
        "advisoryId",
        "package",
        "decision",
        "scope",
        "reason",
        "reviewedOn",
        "expiresOn",
    }
    for index, exception in enumerate(exceptions):
        label = f"exception {index + 1}"
        if not isinstance(exception, dict) or set(exception) != required:
            raise ValueError(f"{label} has missing or unexpected fields")
        ecosystem = exception["ecosystem"]
        advisory_id = exception["advisoryId"]
        package = exception["package"]
        if ecosystem not in ADVISORY_PATTERNS:
            raise ValueError(f"{label} has an unsupported ecosystem")
        if not isinstance(advisory_id, str) or not ADVISORY_PATTERNS[ecosystem].fullmatch(
            advisory_id
        ):
            raise ValueError(f"{label} has an invalid advisoryId")
        if not isinstance(package, str) or not PACKAGE_PATTERN.fullmatch(package):
            raise ValueError(f"{label} has an invalid package")
        if exception["decision"] not in {"accepted-risk", "false-positive"}:
            raise ValueError(f"{label} has an invalid decision")
        for field in ("scope", "reason"):
            if not isinstance(exception[field], str) or len(exception[field].strip()) < 20:
                raise ValueError(f"{label} {field} must explain the bounded decision")
        try:
            reviewed = date.fromisoformat(exception["reviewedOn"])
            expires = date.fromisoformat(exception["expiresOn"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"{label} dates must use YYYY-MM-DD") from error
        if reviewed > today:
            raise ValueError(f"{label} reviewedOn is in the future")
        if expires < reviewed or (expires - reviewed).days > 90:
            raise ValueError(f"{label} must expire within 90 days of review")
        if expires < today:
            raise ValueError(f"{label} expired on {expires.isoformat()}")
        key = ecosystem, advisory_id.upper(), package
        if key in seen:
            raise ValueError(f"duplicate exception: {ecosystem} {advisory_id} {package}")
        seen.add(key)
    return policy


def rust_findings(report: Any) -> list[Finding]:
    if not isinstance(report, dict) or not isinstance(report.get("vulnerabilities"), dict):
        raise TypeError("cargo-audit report is missing vulnerabilities")
    entries = report["vulnerabilities"].get("list")
    if not isinstance(entries, list):
        raise TypeError("cargo-audit vulnerability list is invalid")
    findings = []
    for entry in entries:
        advisory = entry.get("advisory", {}) if isinstance(entry, dict) else {}
        package = entry.get("package", {}) if isinstance(entry, dict) else {}
        advisory_id = advisory.get("id")
        package_name = package.get("name") or advisory.get("package")
        if (
            not isinstance(advisory_id, str)
            or not ADVISORY_PATTERNS["cargo"].fullmatch(advisory_id)
            or not isinstance(package_name, str)
            or not PACKAGE_PATTERN.fullmatch(package_name)
        ):
            raise ValueError("cargo-audit vulnerability identity is invalid")
        severity = report_text(advisory.get("cvss"), "unspecified")
        title = report_text(advisory.get("title"), "RustSec advisory")
        findings.append(Finding("cargo", advisory_id.upper(), package_name, severity, title))
    return sorted(set(findings))


def _ghsa_id(key: str, advisory: dict[str, Any]) -> str | None:
    for candidate in (
        advisory.get("github_advisory_id"),
        advisory.get("id"),
        key,
        str(advisory.get("url", "")).rstrip("/").rsplit("/", 1)[-1],
    ):
        if isinstance(candidate, str) and ADVISORY_PATTERNS["npm"].fullmatch(candidate):
            return candidate.upper()
    return None


def npm_findings(report: Any) -> list[Finding]:
    if not isinstance(report, dict) or not isinstance(report.get("advisories"), dict):
        raise TypeError("pnpm audit report is missing advisories")
    if not isinstance(report.get("metadata"), dict):
        raise TypeError("pnpm audit report is missing metadata")
    findings = []
    for key, value in report["advisories"].items():
        if not isinstance(value, dict):
            raise TypeError("pnpm advisory entry is invalid")
        advisory_id = _ghsa_id(str(key), value)
        package = (
            value.get("module_name")
            or value.get("moduleName")
            or value.get("package_name")
            or value.get("name")
        )
        if (
            advisory_id is None
            or not isinstance(package, str)
            or not PACKAGE_PATTERN.fullmatch(package)
        ):
            raise ValueError("pnpm advisory identity is invalid")
        severity = report_text(value.get("severity"), "unspecified")
        title = report_text(value.get("title"), "npm advisory")
        findings.append(Finding("npm", advisory_id, package, severity, title))
    return sorted(set(findings))


def scanner_versions(policy: dict[str, Any]) -> tuple[str, str]:
    cargo = shutil.which("cargo")
    pnpm = shutil.which("pnpm")
    if cargo is None or pnpm is None:
        raise RuntimeError("dependency scan requires cargo and pnpm")
    cargo_output = command_text([cargo, "audit", "--version"]).strip()
    pnpm_output = command_text([pnpm, "--version"]).strip()
    cargo_match = re.fullmatch(r"cargo-audit(?:-audit)? (\d+\.\d+\.\d+)", cargo_output)
    if cargo_match is None or cargo_match.group(1) != policy["scanners"]["cargo-audit"]:
        raise RuntimeError(f"cargo-audit must be exactly {policy['scanners']['cargo-audit']}")
    if pnpm_output != policy["scanners"]["pnpm"]:
        raise RuntimeError(f"pnpm must be exactly {policy['scanners']['pnpm']}")
    package_manager = json.loads((ROOT / "package.json").read_text(encoding="utf-8")).get(
        "packageManager"
    )
    if package_manager != f"pnpm@{policy['scanners']['pnpm']}":
        raise ValueError("package.json and vulnerability policy pin different pnpm versions")
    return cargo, pnpm


def current_rustsec_report(cargo: str) -> Any:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("dependency scan requires git to retrieve the RustSec database")
    with tempfile.TemporaryDirectory(prefix="secretbridge-rustsec-") as temporary:
        database = Path(temporary) / "advisory-db"
        command_text(
            [
                git,
                "clone",
                "--quiet",
                "--depth",
                "1",
                "https://github.com/RustSec/advisory-db.git",
                str(database),
            ]
        )
        return command_json(
            [
                cargo,
                "audit",
                "--db",
                str(database),
                "--no-fetch",
                "--json",
            ]
        )


def evaluate(
    findings: list[Finding], policy: dict[str, Any]
) -> tuple[list[Finding], list[tuple[Finding, dict[str, Any]]], list[dict[str, Any]]]:
    observed = {finding.key: finding for finding in findings}
    exceptions = {
        (item["ecosystem"], item["advisoryId"].upper(), item["package"]): item
        for item in policy["exceptions"]
    }
    blocked = [finding for key, finding in observed.items() if key not in exceptions]
    accepted = [
        (finding, exceptions[key]) for key, finding in observed.items() if key in exceptions
    ]
    unused = [item for key, item in exceptions.items() if key not in observed]
    return sorted(blocked), sorted(accepted, key=lambda item: item[0]), unused


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--cargo-report", type=Path)
    parser.add_argument("--npm-report", type=Path)
    parser.add_argument(
        "--today",
        type=date.fromisoformat,
        default=datetime.now(UTC).date(),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--print-scanner-version", choices=("cargo-audit", "pnpm"))
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy.resolve(), args.today)
        if args.print_scanner_version:
            print(policy["scanners"][args.print_scanner_version])
            return 0
        cargo, pnpm = scanner_versions(policy)
        rust_report = (
            read_json(args.cargo_report.resolve())
            if args.cargo_report
            else current_rustsec_report(cargo)
        )
        npm_report = (
            read_json(args.npm_report.resolve())
            if args.npm_report
            else command_json([pnpm, "audit", "--prod", "--json"])
        )
        findings = rust_findings(rust_report) + npm_findings(npm_report)
        blocked, accepted, unused = evaluate(findings, policy)
        if unused:
            for item in unused:
                print(
                    f"Stale exception: {item['ecosystem']} {item['advisoryId']} {item['package']}"
                )
            return 1
        for finding, exception in accepted:
            print(
                f"Accepted {exception['decision']}: {finding.ecosystem} "
                f"{finding.advisory_id} {finding.package} until {exception['expiresOn']}"
            )
        if blocked:
            print("Dependency vulnerability policy failed:")
            for finding in blocked:
                print(
                    f"- {finding.ecosystem} {finding.advisory_id} {finding.package} [{finding.severity}] {finding.title}"
                )
            return 1
        print(
            "Dependency vulnerability policy passed "
            f"({len(rust_findings(rust_report))} RustSec; {len(npm_findings(npm_report))} npm; "
            f"{len(accepted)} time-bounded exceptions)."
        )
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"Dependency vulnerability policy failed: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
