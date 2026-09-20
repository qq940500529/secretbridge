# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "browser_acceptance", ROOT / "tools" / "test_browser_acceptance.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BrowserAcceptanceTests(unittest.TestCase):
    def test_full_plan_runs_all_engines_and_chromium_only_surfaces(self):
        plan = MODULE.acceptance_plan(list(MODULE.BROWSERS))
        self.assertEqual(
            plan[:3],
            [
                ("chromium", "smoke_workbench_ui.mjs"),
                ("firefox", "smoke_workbench_ui.mjs"),
                ("webkit", "smoke_workbench_ui.mjs"),
            ],
        )
        self.assertEqual(len(plan), 6)

    def test_restricted_plan_does_not_claim_chromium_coverage(self):
        self.assertEqual(
            MODULE.acceptance_plan(["firefox"]),
            [("firefox", "smoke_workbench_ui.mjs")],
        )

    def test_available_port_is_loopback_bindable(self):
        self.assertGreater(MODULE.available_port(), 0)


if __name__ == "__main__":
    unittest.main()
