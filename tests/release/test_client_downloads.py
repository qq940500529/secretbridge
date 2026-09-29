# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise release attachments using copied public sources, not user configuration."""

import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.release import package_client_integrations as downloads


class ClientDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        for _, source, _, _ in downloads.SPECS:
            target = self.root / source
            if not target.exists():
                shutil.copytree(downloads.ROOT / source, target)
        for name in ("Cargo.toml", "LICENSE", "COPYRIGHT.md", "docs/release/客户端集成下载.md"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(downloads.ROOT / name, target)
        self.tracked = (
            "\0".join(
                file.relative_to(self.root).as_posix()
                for file in self.root.rglob("*")
                if file.is_file()
            )
            + "\0"
        )
        self.git_patch = patch.object(downloads, "git", side_effect=self.git)
        self.git_patch.start()
        self.addCleanup(self.git_patch.stop)
        self.output = self.root.parent / "first"

    def git(self, root, *args):
        self.assertEqual(root, self.root)
        return {
            ("status", "--porcelain"): "",
            ("rev-parse", "HEAD"): "a" * 40,
            ("log", "-1", "--format=%ct"): "1700000000",
            ("ls-files", "-z"): self.tracked,
        }[args]

    def test_five_versioned_archives_have_licenses_inventory_and_expected_layouts(self):
        archives = downloads.build(self.output, self.root)
        self.assertEqual(len(archives), 5)
        self.assertEqual(len(downloads.verify(self.output)), 5)
        for archive in archives:
            files = downloads.read_archive(archive)
            manifest_name = next(name for name in files if name.endswith("INTEGRATION.json"))
            meta = json.loads(files[manifest_name])
            self.assertEqual(meta["version"], meta["broker_version"])
            self.assertEqual(meta["source_commit"], "a" * 40)
            self.assertTrue(any(name.endswith("LICENSE") for name in files))
            self.assertTrue(any(name.endswith("INSTALL.md") for name in files))
            self.assertFalse(
                any("node_modules" in name or "application/" in name for name in files)
            )
            if meta["integration"] == "codex-plugin":
                self.assertIn("secretbridge/.codex-plugin/plugin.json", files)
                config = json.loads(files["secretbridge/.mcp.json"])
                self.assertEqual(config["mcpServers"]["secretbridge"]["command"], "secretbridge")
                self.assertNotIn("env", config["mcpServers"]["secretbridge"])
            if meta["integration"] == "workbuddy-skill":
                self.assertIn("SKILL.md", files)
            if meta["integration"] == "deepseek-harness":
                manifest = json.loads(files["package/package.json"])
                self.assertEqual(manifest["name"], "dsh-secretbridge")
                self.assertNotIn("scripts", manifest)

    def test_independent_runs_are_byte_identical_and_ignore_untracked_files(self):
        untracked = self.root / "plugins/secretbridge/not-for-distribution.txt"
        untracked.write_text("not distributed", encoding="utf-8")
        first = downloads.build(self.output, self.root)
        second_dir = self.root.parent / "second"
        second = downloads.build(second_dir, self.root)
        self.assertEqual([item.name for item in first], [item.name for item in second])
        for left, right in zip(first, second, strict=True):
            self.assertEqual(left.read_bytes(), right.read_bytes())
            self.assertFalse(
                any("not-for-distribution" in name for name in downloads.read_archive(left))
            )

    def test_dirty_checkout_and_existing_output_are_rejected_without_overwrite(self):
        with (
            patch.object(downloads, "git", return_value=" M Cargo.toml"),
            self.assertRaisesRegex(ValueError, "clean source"),
        ):
            downloads.build(self.output, self.root)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        retained = self.output / "retained.txt"
        retained.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "empty"):
            downloads.build(self.output, self.root)
        self.assertEqual(retained.read_text(encoding="utf-8"), "keep")

    def test_stale_client_versions_are_rejected(self):
        path = self.root / "connectors/workbuddy/connector-meta.json"
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta["version"] = "0.0.0"
        path.write_text(json.dumps(meta), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "version does not match"):
            downloads.build(self.output, self.root)

    def test_archive_and_inner_file_tampering_are_detected(self):
        archives = downloads.build(self.output, self.root)
        archive = archives[0]
        files = downloads.read_archive(archive)
        config = next(name for name in files if name.endswith(".mcp.json"))
        files[config] = b"{}"
        archive.unlink()
        downloads.write_archive(archive, files, 1700000000)
        with self.assertRaisesRegex(ValueError, "archive checksum"):
            downloads.verify(self.output)
        checksum = downloads.digest(archive.read_bytes())
        archive.with_name(archive.name + ".sha256").write_text(
            f"{checksum}  {archive.name}\n", encoding="ascii"
        )
        with self.assertRaisesRegex(ValueError, "file checksum"):
            downloads.verify(self.output)

    def test_missing_artifact_or_sidecar_is_rejected(self):
        archives = downloads.build(self.output, self.root)
        archives[0].with_name(archives[0].name + ".sha256").unlink()
        with self.assertRaisesRegex(ValueError, "exactly five"):
            downloads.verify(self.output)

    def test_tar_traversal_and_links_are_rejected_without_extraction(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("package/link", tarfile.SYMTYPE)):
            path = self.root.parent / (
                "bad-link.tgz" if kind == tarfile.SYMTYPE else "bad-path.tgz"
            )
            with tarfile.open(path, "w:gz") as bundle:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = 1 if kind == tarfile.REGTYPE else 0
                info.linkname = "../escape" if kind == tarfile.SYMTYPE else ""
                bundle.addfile(info, io.BytesIO(b"x") if info.size else None)
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                downloads.read_archive(path)
        self.assertFalse((self.root.parent / "escape").exists())


if __name__ == "__main__":
    unittest.main()
