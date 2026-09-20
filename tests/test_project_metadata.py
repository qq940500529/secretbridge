# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "project_metadata", ROOT / "tools" / "check_project_metadata.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProjectMetadataTests(unittest.TestCase):
    def fixture(
        self,
        root: Path,
        *,
        web_version: str = "1.2.3",
        node_types: str = "24.13.6",
        schema: int = 16,
    ) -> None:
        (root / "web").mkdir()
        (root / "tools").mkdir()
        (root / "docs").mkdir()
        (root / "crates/secretbridge-core/src").mkdir(parents=True)
        (root / "crates/secretbridge-server/src").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "1.2.3"\nrust-version = "1.98"\n', encoding="utf-8"
        )
        (root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.98.0"\n', encoding="utf-8"
        )
        (root / ".node-version").write_text("24.21.0\n", encoding="utf-8")
        (root / "package.json").write_text(
            json.dumps({"version": "1.2.3", "engines": {"node": ">=24 <25"}}),
            encoding="utf-8",
        )
        (root / "web/package.json").write_text(
            json.dumps(
                {
                    "version": web_version,
                    "devDependencies": {"@types/node": node_types},
                }
            ),
            encoding="utf-8",
        )
        (root / "crates/secretbridge-core/src/lib.rs").write_text(
            f"pub const SCHEMA_VERSION: i64 = {schema};\n", encoding="utf-8"
        )
        (root / "crates/secretbridge-server/src/catalog.rs").write_text(
            "pub const SCHEMA_VERSION: i64 = secretbridge_core::SCHEMA_VERSION;\n",
            encoding="utf-8",
        )
        (root / "tools/package_release.py").write_text(
            f'{{"schema_version": {schema}}}\n', encoding="utf-8"
        )
        for name in ("README.md", "开发设计.md", "后台运行与安装交付.md", "配置迁移与备份恢复.md"):
            (root / "docs" / name).write_text(f"当前 schema v{schema}\n", encoding="utf-8")

    def test_aligned_metadata_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            self.assertIn("schema 16", MODULE.check(root))

    def test_version_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, web_version="1.2.2")
            with self.assertRaisesRegex(ValueError, "versions must match"):
                MODULE.check(root)

    def test_node_type_major_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, node_types="26.6.1")
            with self.assertRaisesRegex(ValueError, "must match"):
                MODULE.check(root)

    def test_node_runtime_engine_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / ".node-version").write_text("26.6.0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "engine range"):
                MODULE.check(root)

    def test_stale_current_schema_claim_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "docs/开发设计.md").write_text("当前实现使用 schema v15。\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stale schema 15"):
                MODULE.check(root)


if __name__ == "__main__":
    unittest.main()
