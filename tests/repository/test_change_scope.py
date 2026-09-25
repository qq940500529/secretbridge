# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "change_scope", ROOT / "tools" / "checks" / "change_scope.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ChangeScopeTests(unittest.TestCase):
    def test_documentation_only_paths_skip_heavy_checks(self):
        self.assertEqual(
            MODULE.affected_checks(["README.md", "docs/指南/安装.md", "docs/assets/flow.svg"]),
            frozenset(),
        )

    def test_known_changes_select_related_suites(self):
        cases = {
            "frontend/src/app/App.tsx": {"web", "browser", "package"},
            "backend/src/lib.rs": {"rust", "browser", "package"},
            "backend/local-access/src/windows.rs": {"rust", "package"},
            "backend/src/adapters/executors/database/mod.rs": {
                "rust",
                "database",
                "browser",
                "package",
            },
            "backend/src/adapters/http/mod.rs": {"rust", "python", "browser", "package"},
            "tools/acceptance/smoke_workbench_ui.mjs": {"python", "browser"},
            "tools/acceptance/test_database_connectors.sh": {"database"},
            "tools/release/package_release.py": {"dependency", "python", "package"},
            "skills/secretbridge-operations/SKILL.md": {"python", "package"},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(MODULE.affected_checks([path]), expected)

    def test_manifests_workflows_and_unknown_paths_run_full_suite(self):
        for path in (
            "Cargo.toml",
            "frontend/package.json",
            ".github/workflows/repository-checks.yml",
            "tools/checks/change_scope.py",
            "unexpected/new-kind.dat",
            "docs/generated/config.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(MODULE.affected_checks(["README.md", path]), MODULE.CHECKS)

    def test_empty_diff_does_not_skip_checks(self):
        self.assertEqual(MODULE.affected_checks([]), MODULE.CHECKS)
