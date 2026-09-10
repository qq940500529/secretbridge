# SPDX-License-Identifier: AGPL-3.0-only
"""Use generated synthetic strings, never real credentials."""

from pathlib import Path
import tempfile
import unittest

from tools.check_repository import PATTERNS, check_repository, inspect_file


class RepositoryChecks(unittest.TestCase):
    def test_detects_synthetic_token_without_returning_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "ghp_" + "x" * 36
            path = root / "sample.md"
            path.write_text(secret, encoding="utf-8")
            errors = inspect_file(root, path)
            self.assertTrue(any("github-token" in item for item in errors))
            self.assertNotIn(secret, "\n".join(errors))

    def test_missing_document_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample.md"
            path.write_text("[missing](missing.md)", encoding="utf-8")
            self.assertIn("sample.md: missing-local-link", inspect_file(root, path))

    def test_link_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample.md"
            path.write_text("[escape](../outside.md)", encoding="utf-8")
            self.assertIn("sample.md: link-outside-repository", inspect_file(root, path))

    def test_unicode_local_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "说明.md").write_text("demo", encoding="utf-8")
            path = root / "sample.md"
            path.write_text("[ok](说明.md)", encoding="utf-8")
            self.assertEqual([], inspect_file(root, path))

    def test_binary_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "export.zip"
            path.write_bytes(b"synthetic")
            self.assertIn("export.zip: unexpected-artifact", inspect_file(root, path))

    def test_required_files(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(check_repository(Path(directory)))

    def test_private_ip_and_path_patterns(self):
        self.assertIsNotNone(PATTERNS["private-ip"].search("10." + "20.30.40"))
        self.assertIsNotNone(PATTERNS["personal-path"].search("C:" + "/Users/" + "demo/"))
        self.assertIsNone(PATTERNS["private-ip"].search("version 0.1.0"))


if __name__ == "__main__":
    unittest.main()
