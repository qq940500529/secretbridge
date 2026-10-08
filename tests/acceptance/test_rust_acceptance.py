# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "rust_acceptance", Path(__file__).parents[2] / "tools/acceptance/run_rust_acceptance.py"
)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class RustAcceptanceTests(unittest.TestCase):
    def test_zero_tests_cannot_pass_even_when_cargo_succeeds(self):
        response = subprocess.CompletedProcess([], 0, stdout="0 tests, 0 benchmarks\n")
        with patch.object(acceptance.subprocess, "run", return_value=response):
            for suite in acceptance.SUITES:
                with (
                    self.subTest(suite=suite),
                    self.assertRaisesRegex(ValueError, "test_selection_incomplete"),
                ):
                    acceptance.select_suite(suite)

    def test_database_requires_all_eleven_tests_not_only_the_mcp_test(self):
        for count in (1, 10, 11, 12):
            response = subprocess.CompletedProcess(
                [], 0, stdout="\n".join(f"test_{i}: test" for i in range(count))
            )
            with (
                self.subTest(count=count),
                patch.object(acceptance.subprocess, "run", return_value=response) as run,
            ):
                if count < 11:
                    with self.assertRaises(ValueError):
                        acceptance.select_suite("database")
                else:
                    self.assertEqual(acceptance.select_suite("database"), count)
                self.assertIn("--ignored", run.call_args.args[0])
                self.assertEqual(run.call_args.args[0][-1], "--list")

    def test_failed_test_listing_is_rejected_without_exposing_compiler_output(self):
        response = subprocess.CompletedProcess([], 101, stdout="test_a: test\n")
        with (
            patch.object(acceptance.subprocess, "run", return_value=response),
            self.assertRaisesRegex(ValueError, "test_list_failed"),
        ):
            acceptance.select_suite("parallel")

    def test_execution_never_starts_after_empty_selection(self):
        response = subprocess.CompletedProcess([], 0, stdout="0 tests, 0 benchmarks\n")
        with (
            patch.object(sys, "argv", ["acceptance", "database"]),
            patch.object(acceptance.subprocess, "run", return_value=response) as run,
        ):
            self.assertEqual(acceptance.main(), 1)
            self.assertEqual(run.call_count, 1)

    def test_execution_uses_the_same_command_as_inventory(self):
        response = subprocess.CompletedProcess([], 0, stdout="test_a: test\n")
        with (
            patch.object(sys, "argv", ["acceptance", "history"]),
            patch.object(acceptance.subprocess, "run", return_value=response) as run,
        ):
            self.assertEqual(acceptance.main(), 0)
            listed, executed = [call.args[0] for call in run.call_args_list]
            self.assertEqual(listed[:-1], executed)
