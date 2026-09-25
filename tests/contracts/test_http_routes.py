# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Freeze the public route inventory while HTTP handlers move between modules."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTER = ROOT / "backend/src/adapters/http/mod.rs"

EXPECTED_ROUTES = {
    "/api/v1/status",
    "/api/v1/runtime/stop",
    "/api/v1/session/pair",
    "/api/v1/session/pin",
    "/api/v1/session/recover",
    "/api/v1/session/recovery-key",
    "/api/v1/session/totp",
    "/api/v1/session/totp/setup",
    "/api/v1/session/totp/confirm",
    "/api/v1/session/methods",
    "/api/v1/session/auth-events",
    "/api/v1/session/method",
    "/api/v1/session",
    "/api/v1/credential-references",
    "/api/v1/credential-references/{id}",
    "/api/v1/credential-references/{id}/secret",
    "/api/v1/targets",
    "/api/v1/targets/{id}",
    "/api/v1/action-templates",
    "/api/v1/action-templates/{id}",
    "/api/v1/action-templates/{id}/policy-evaluation",
    "/api/v1/approvals",
    "/api/v1/approvals/{id}/approve",
    "/api/v1/approvals/{id}/deny",
    "/api/v1/approvals/{id}/revoke",
    "/api/v1/runs",
    "/api/v1/runs/{id}",
    "/api/v1/runs/{id}/cancel",
    "/api/v1/runs/{id}/events",
    "/api/v1/runs/{id}/output",
    "/api/v1/safe-events",
    "/api/v1/terminals",
    "/api/v1/terminals/capabilities",
    "/api/v1/terminals/{id}",
    "/api/v1/terminals/{id}/attach",
    "/api/v1/events",
}


class HttpRouteContractTests(unittest.TestCase):
    def test_router_declares_exact_public_paths_once(self):
        source = ROUTER.read_text(encoding="utf-8")
        paths = re.findall(r'\.route\(\s*"([^"]+)"', source)
        self.assertEqual(len(paths), len(set(paths)), "duplicate HTTP route declaration")
        self.assertEqual(set(paths), EXPECTED_ROUTES)


if __name__ == "__main__":
    unittest.main()
