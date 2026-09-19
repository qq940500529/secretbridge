# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Package format/version/source regressions without network access."""
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("package_release", Path(__file__).parents[1] / "tools/package_release.py")
package_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_release)


class PackageReleaseTests(unittest.TestCase):
    def test_dirty_checkout_is_rejected_for_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(package_release, "command", return_value=" M README.md\n"):
                with self.assertRaisesRegex(ValueError, "clean source"):
                    package_release.source_snapshot(Path(temporary) / "source.tar.gz", False)

    def test_development_snapshot_records_dirty_state_and_embeds_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text("example", encoding="utf-8")
            with patch.object(package_release, "ROOT", root), patch.object(package_release, "command", side_effect=[" M Cargo.toml", "a" * 40, "Cargo.toml\0"]):
                result = package_release.source_snapshot(root / "source.tar.gz", True)
            self.assertTrue(result["dirty"])
            self.assertEqual(result["base_commit"], "a" * 40)
            self.assertEqual(len(result["source_sha256"]), 64)
            with tarfile.open(root / "source.tar.gz") as bundle:
                self.assertEqual(bundle.getnames(), ["secretbridge-source/Cargo.toml"])

    def test_unpinned_license_download_is_rejected(self):
        with self.assertRaises(ValueError):
            package_release.upstream_license("https://github.com/example/project", "main")
        with self.assertRaises(ValueError):
            package_release.upstream_license("https://untrusted.invalid/example/project", "a" * 40)

    def fixture(self, root):
        (root / "Cargo.toml").write_text('[workspace.package]\nversion="0.2.0-beta.1"\n', encoding="utf-8")
        web = root / "web/dist"
        web.mkdir(parents=True)
        (web / "index.html").write_text("<main>test</main>", encoding="utf-8")
        (web / "secretbridge-build.json").write_text(json.dumps({"format_version": 1, "version": "0.2.0-beta.1"}), encoding="utf-8")
        for document in package_release.DOCUMENTS:
            (root / document).write_text("test notice", encoding="utf-8")
        binary = root / "app"
        binary.write_bytes(b"fixture executable")
        return binary

    def test_binary_web_version_mismatch_fails_before_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self.fixture(root)
            with patch.object(package_release, "ROOT", root), patch.object(package_release.subprocess, "check_output", return_value="0.0.0"):
                with self.assertRaisesRegex(ValueError, "must match"):
                    package_release.build_package(binary, root / "output")

    def test_manifest_covers_payload_source_notices_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self.fixture(root)
            def snapshot(target, _):
                target.write_bytes(b"source fixture")
                return {"dirty": False, "corresponding_source": "SOURCE.tar.gz"}
            with patch.object(package_release, "ROOT", root), patch.object(package_release.subprocess, "check_output", return_value="0.2.0-beta.1"), patch.object(package_release, "source_snapshot", side_effect=snapshot), patch.object(package_release, "third_party_notices", return_value="license fixture"):
                archive = package_release.build_package(binary, root / "output")
                with self.assertRaisesRegex(ValueError, "already exists"):
                    package_release.build_package(binary, root / "output")
            self.assertTrue(archive.with_name(archive.name + ".sha256").is_file())
            extracted = root / "extracted"
            if archive.name.endswith(".zip"):
                with zipfile.ZipFile(archive) as bundle:
                    bundle.extractall(extracted)
            else:
                with tarfile.open(archive) as bundle:
                    bundle.extractall(extracted, filter="data")
            application = next(extracted.iterdir())
            manifest = json.loads((application / "secretbridge-package.json").read_text())
            paths = {file["path"] for file in manifest["files"]}
            self.assertTrue({"SOURCE.tar.gz", "SOURCE.json", "THIRD_PARTY_LICENSES.txt", "LICENSE", "web/index.html"} <= paths)
            for file in manifest["files"]:
                path = application / file["path"]
                self.assertEqual(file["sha256"], package_release.sha256(path))
                self.assertEqual(file["bytes"], path.stat().st_size)


if __name__ == "__main__":
    unittest.main()
