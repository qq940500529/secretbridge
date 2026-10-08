# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "test_stability_acceptance_tool",
    Path(__file__).parents[2] / "tools/acceptance/test_stability_acceptance.py",
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
        repeated = [item for item in plan if item.command[-1] == "parallel"]
        self.assertEqual(len(repeated), 4)
        self.assertEqual(plan[-1].command, ("bash", "tools/acceptance/test_database_connectors.sh"))

    def test_history_metrics_require_two_processes_and_4000_records(self):
        check = stability.Check("history", ("fixture",), capture_metrics=True)
        complete = [
            {"phase": 1, "runs": 1000, "authorizations": 1000},
            {"phase": 2, "runs": 2000, "authorizations": 2000},
            {"phase": "backup_restore", "runs": 2000},
            {"phase": 3, "runs": 3000, "authorizations": 3000},
            {"phase": 4, "runs": 4000, "authorizations": 4000},
            {"phase": "backup_restore", "runs": 4000},
        ]
        for metrics, expected_passed in ((complete, True), (complete[:3] * 2, False), ([], False)):
            outputs = [metrics[:3], metrics[3:]]
            responses = [
                subprocess.CompletedProcess(
                    ["fixture"],
                    0,
                    stdout="\n".join("SOAK_METRIC " + json.dumps(item) for item in batch),
                )
                for batch in outputs
            ]
            with (
                self.subTest(metrics=metrics),
                patch.object(stability.subprocess, "run", side_effect=responses),
            ):
                results, passed = stability.run_plan([check])
            self.assertEqual(passed, expected_passed)
            self.assertEqual(
                results[0].error_code, None if expected_passed else "metrics_incomplete"
            )

    def test_invalid_iteration_budget_is_rejected(self):
        for count in (0, 101):
            with self.assertRaisesRegex(ValueError, "between 1 and 100"):
                stability.build_plan("soak", count, False)


if __name__ == "__main__":
    unittest.main()
