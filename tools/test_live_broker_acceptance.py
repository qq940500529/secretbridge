# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise an already-running broker through a one-time pairing URL.

This helper is intended for native acceptance. It never writes or prints the pairing token,
session token, or generated credential value. Point ``BROWSER`` at this script before starting
the broker, call ``open``, and wait for the sanitized report path.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(
    os.environ.get(
        "SECRETBRIDGE_ACCEPTANCE_REPORT",
        ROOT / "dist" / "live-broker-acceptance.json",
    )
)


class AcceptanceFailure(RuntimeError):
    """A sanitized live acceptance assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceFailure(message)


def main(pairing_url: str) -> dict[str, object]:
    parsed = urlsplit(pairing_url)
    bootstrap = parse_qs(parsed.fragment).get("pair", [None])[0]
    require(bool(bootstrap), "pairing URL is missing its one-time token")
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    require(origin.startswith("http://127.0.0.1:"), "broker is not using IPv4 loopback")
    opener = build_opener(ProxyHandler({}))
    session: str | None = None
    credential_id: str | None = None
    credential_version: int | None = None
    terminal_id: str | None = None
    generated_secret = secrets.token_urlsafe(32)
    observed: list[object] = []

    def call(
        method: str,
        path: str,
        *,
        bearer: str | None = None,
        payload: object | None = None,
        expected: int | tuple[int, ...] = 200,
    ) -> tuple[int, object | None, dict[str, str]]:
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Accept": "application/json", "Origin": origin}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        request = Request(origin + path, data=data, headers=headers, method=method)
        try:
            response = opener.open(request, timeout=15)
            status, raw, response_headers = (
                response.status,
                response.read(),
                {key.lower(): value for key, value in response.headers.items()},
            )
        except HTTPError as error:
            status, raw, response_headers = (
                error.code,
                error.read(),
                {key.lower(): value for key, value in error.headers.items()},
            )
        expected_codes = (expected,) if isinstance(expected, int) else expected
        require(status in expected_codes, f"{method} {path} returned unexpected status {status}")
        require(generated_secret.encode() not in raw, "a non-JSON response exposed the credential")
        body = (
            json.loads(raw)
            if raw and "application/json" in response_headers.get("content-type", "")
            else None
        )
        if body is not None:
            observed.append(body)
            require(
                generated_secret not in json.dumps(body), "an API response exposed the credential"
            )
        return status, body, response_headers

    checks: list[str] = []
    try:
        _, status, headers = call("GET", "/api/v1/status")
        require(status["mode"] == "controlled_operations", "unexpected broker mode")
        require(status["configuration_storage"] == "sqlite", "broker is not using SQLite")
        require(headers.get("x-frame-options") == "DENY", "security headers are incomplete")
        checks.append("loopback page and safe status")

        call(
            "POST",
            "/api/v1/session/pair",
            bearer="invalid-one-time-token",
            expected=401,
        )
        _, paired, _ = call("POST", "/api/v1/session/pair", bearer=bootstrap)
        session = paired["session_token"]
        call("POST", "/api/v1/session/pair", bearer=bootstrap, expected=401)
        checks.append("one-time browser pairing and replay rejection")

        _, credential, _ = call(
            "POST",
            "/api/v1/credential-references",
            bearer=session,
            payload={"name": "Native acceptance credential", "kind": "password"},
            expected=201,
        )
        credential_id = credential["id"]
        _, configured, _ = call(
            "PUT",
            f"/api/v1/credential-references/{credential_id}/secret",
            bearer=session,
            payload={"secret": generated_secret, "expected_version": credential["version"]},
        )
        credential_version = configured["version"]
        require(configured["secret_state"] == "available", "credential was not configured")
        call(
            "POST",
            "/api/v1/credential-references",
            bearer=session,
            payload={"name": "Rejected secret field", "kind": "password", "secret": "forbidden"},
            expected=422,
        )

        _, target, _ = call(
            "POST",
            "/api/v1/targets",
            bearer=session,
            payload={
                "name": "Local acceptance target",
                "kind": "http_service",
                "environment": "test",
            },
            expected=201,
        )
        command = {
            "program": "/bin/sh",
            "working_directory": "/tmp",
            "arguments": [
                "-c",
                "printf 'stdout-marker:%s\\n' \"$SB_LIVE_SECRET\"; printf 'stderr-marker:%s\\n' \"$SB_LIVE_SECRET\" >&2",
            ],
            "slots": [
                {
                    "name": "password",
                    "credential_id": credential_id,
                    "injection": "environment",
                    "environment_variable": "SB_LIVE_SECRET",
                }
            ],
            "parameters": [],
        }
        _, template, _ = call(
            "POST",
            "/api/v1/action-templates",
            bearer=session,
            payload={
                "target_id": target["id"],
                "name": "Credential redaction acceptance",
                "operation": "command_execution",
                "result_scope": "sanitized_output",
                "timeout_seconds": 10,
                "command": command,
            },
            expected=201,
        )
        _, approval, _ = call(
            "POST",
            "/api/v1/approvals",
            bearer=session,
            payload={"action_template_id": template["id"], "expires_in_seconds": 300},
            expected=201,
        )
        _, approved, _ = call(
            "POST",
            f"/api/v1/approvals/{approval['id']}/approve",
            bearer=session,
            payload={"expected_version": approval["version"], "note": "Native acceptance"},
        )
        require(approved["state"] == "approved", "approval did not become active")
        key = secrets.token_hex(16)
        _, run_result, _ = call(
            "POST",
            "/api/v1/runs",
            bearer=session,
            payload={"approval_id": approval["id"], "idempotency_key": key},
            expected=201,
        )
        run_id = run_result["run"]["id"]
        deadline = time.monotonic() + 20
        output = None
        while time.monotonic() < deadline:
            _, output, _ = call(
                "POST",
                f"/api/v1/runs/{run_id}/output",
                bearer=session,
                payload={"cursor": 0, "wait_ms": 500},
            )
            if output["state"] not in ("queued", "running"):
                break
        require(output is not None and output["state"] == "succeeded", "command did not succeed")
        rendered = "".join(item["text"] for item in output["items"])
        require("stdout-marker:[REDACTED]" in rendered, "stdout was not redacted")
        require("stderr-marker:[REDACTED]" in rendered, "stderr was not redacted")
        require(generated_secret not in rendered, "command output exposed the credential")
        _, replay, _ = call(
            "POST",
            "/api/v1/runs",
            bearer=session,
            payload={"approval_id": approval["id"], "idempotency_key": key},
        )
        require(replay["replayed"] is True, "run replay was not idempotent")
        _, events, _ = call("GET", f"/api/v1/runs/{run_id}/events", bearer=session)
        require(events["items"], "run audit events are missing")
        checks.append("credential proxy, approval, execution, redaction and audit")

        _, denied, _ = call(
            "POST",
            "/api/v1/approvals",
            bearer=session,
            payload={"action_template_id": template["id"], "expires_in_seconds": 300},
            expected=201,
        )
        call(
            "POST",
            f"/api/v1/approvals/{denied['id']}/deny",
            bearer=session,
            payload={"expected_version": denied["version"], "note": "Denied by acceptance"},
        )
        call(
            "POST",
            "/api/v1/runs",
            bearer=session,
            payload={"approval_id": denied["id"], "idempotency_key": secrets.token_hex(16)},
            expected=409,
        )
        checks.append("denied and invalid requests fail closed")

        _, terminal, _ = call(
            "POST",
            "/api/v1/terminals",
            bearer=session,
            payload={"rows": 24, "cols": 80, "shell": "bash", "name": "Acceptance terminal"},
            expected=201,
        )
        terminal_id = terminal["id"]
        _, terminals, _ = call("GET", "/api/v1/terminals", bearer=session)
        require(
            any(item["id"] == terminal_id for item in terminals["terminals"]),
            "terminal did not survive HTTP reconnection",
        )
        call("DELETE", f"/api/v1/terminals/{terminal_id}", bearer=session, expected=204)
        terminal_id = None
        checks.append("persistent terminal creation, reconnect listing and cleanup")

        require(
            generated_secret not in json.dumps(observed),
            "observed responses exposed the credential",
        )
        return {"format": "secretbridge-live-broker-acceptance", "passed": True, "checks": checks}
    finally:
        if session and terminal_id:
            call("DELETE", f"/api/v1/terminals/{terminal_id}", bearer=session, expected=(204, 404))
        if session and credential_id and credential_version is not None:
            _, cleared, _ = call(
                "DELETE",
                f"/api/v1/credential-references/{credential_id}/secret",
                bearer=session,
                payload={"expected_version": credential_version},
                expected=(200, 404, 409),
            )
            if isinstance(cleared, dict):
                require(
                    cleared.get("secret_state") == "not_configured", "credential cleanup failed"
                )
        if session:
            call("DELETE", "/api/v1/session", bearer=session, expected=(204, 401))


def run() -> int:
    report: dict[str, object]
    try:
        require(len(sys.argv) == 2, "exactly one pairing URL is required")
        report = main(sys.argv[1])
    except (
        AcceptanceFailure,
        HTTPError,
        json.JSONDecodeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as error:  # The report deliberately excludes exception text and secrets.
        report = {
            "format": "secretbridge-live-broker-acceptance",
            "passed": False,
            "failure_type": type(error).__name__,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(run())
