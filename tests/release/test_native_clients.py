# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate native client artifacts without loading profiles or credential stores."""

import json
import re
import shutil
import subprocess
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class NativeClientTests(unittest.TestCase):
    def test_workbuddy_connector_and_skill_follow_official_fields(self):
        folder = ROOT / "connectors/workbuddy"
        meta = json.loads((folder / "connector-meta.json").read_text(encoding="utf-8"))
        version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"][
            "package"
        ]["version"]
        self.assertEqual(meta["version"], version)
        self.assertEqual(meta["type"], "mcp")
        self.assertEqual(meta["minWorkbuddyVersion"], "4.24.0")
        self.assertRegex(meta["source"], r"^[a-z0-9-]+$")
        for field in ("name", "name_en", "description", "description_zh", "description_en"):
            self.assertTrue(meta[field])
        for language in ("zh", "en"):
            self.assertGreaterEqual(len(meta[f"examples_{language}"]), 2)
        self.assertNotIn("auth_mode", meta)
        config = json.loads((folder / "mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(list(config["mcpServers"]), ["secretbridge"])
        self.assertEqual(config["mcpServers"]["secretbridge"]["type"], "stdio")
        self.assertEqual(config["mcpServers"]["secretbridge"]["args"], ["--mcp-stdio"])
        self.assertEqual(
            (folder / "icon.svg").read_bytes(), (ROOT / "brand/secretbridge-mark.svg").read_bytes()
        )
        skill = (folder / "skills/secretbridge-workbuddy/SKILL.md").read_text(encoding="utf-8")
        frontmatter = skill.split("---", 2)[1]
        for field in (
            "name",
            "description",
            "description_zh",
            "description_en",
            "version",
            "author",
        ):
            self.assertRegex(frontmatter, rf"(?m)^{field}: .+$")
        self.assertIn(f"version: {version}", frontmatter)
        self.assertIn("ui_language", skill)
        self.assertIn("decision_note", skill)

    def test_harness_bundle_is_prebuilt_with_host_compatibility(self):
        folder = ROOT / "plugins/deepseek-harness"
        meta = json.loads((folder / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["dsh"]["bundle"]["patch"], "./cordis.patch.yml")
        self.assertNotIn("scripts", meta)
        self.assertNotIn("dependencies", meta)
        self.assertEqual(meta["peerDependencies"]["@deepseek-ai/dsh"], ">=0.2.0-rc.1 <0.3.0")
        self.assertTrue(meta["peerDependenciesMeta"]["@deepseek-ai/dsh"]["optional"])
        self.assertEqual(meta["license"], "AGPL-3.0-or-later")
        self.assertEqual((folder / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())
        self.assertTrue((folder / meta["main"]).is_file())
        patch = (folder / "cordis.patch.yml").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"(?m)^- insert:", patch)), 1)
        self.assertIn("@deepseek-ai/dsh-mcp-client", patch)
        self.assertIn("failOnStartupError: true", patch)
        self.assertIn("name: dsh-secretbridge", patch)

    def test_guidance_uses_native_prompt_registration_without_side_effects(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js is required for native plugin contract tests")
        subprocess.run(
            [node, "--test", "tests/release/native_clients.test.mjs"],
            cwd=ROOT,
            check=True,
            timeout=30,
        )


if __name__ == "__main__":
    unittest.main()
