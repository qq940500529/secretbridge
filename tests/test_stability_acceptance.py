# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "test_stability_acceptance_tool",
    Path(__file__).parents[1] / "tools/test_stability_acceptance.py",
)
stability = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stability
SPEC.loader.exec_module(stability)


class StabilityAcceptanceToolTests(unittest.TestCase):
    def test_quick_plan_covers_connectors_and_both_terminal_layers(self):
        plan = stability.build_plan("quick", 20, False)
        self.assertEqual(len(plan), 3)
        commands = [" ".join(item.command) for item in plan]
        self.assertTrue(any("--lib" in command for command in commands))
        self.assertTrue(any("synthetic_terminal" in command for command in commands))
        self.assertTrue(any("real_terminal" in command for command in commands))

    def test_soak_iterations_and_database_fixture_are_explicit(self):
        plan = stability.build_plan("soak", 4, True)
        repeated = [item for item in plan if stability.PARALLEL_FILTER in item.command]
        self.assertEqual(len(repeated), 4)
        self.assertEqual(plan[-1].command, ("bash", "tools/test_database_connectors.sh"))

    def test_invalid_iteration_budget_is_rejected(self):
        for count in (0, 101):
            with self.assertRaisesRegex(ValueError, "between 1 and 100"):
                stability.build_plan("soak", count, False)


if __name__ == "__main__":
    unittest.main()
