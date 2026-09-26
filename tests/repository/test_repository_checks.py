# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Use generated synthetic strings, never real credentials."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.checks.check_repository import (
    PATTERNS,
    PUBLIC_REPOSITORY_URL,
    check_ai_deployment_entrypoints,
    check_repository,
    inspect_file,
    markdown_anchors,
    markdown_structure,
)


class RepositoryChecks(unittest.TestCase):
    def check_markdown(self, content):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample.md"
            path.write_text(content, encoding="utf-8")
            return inspect_file(root, path)

    def test_explicit_local_anchor(self):
        self.assertEqual([], self.check_markdown('<a name="overview"></a>\n[ok](#overview)'))

    def test_missing_local_fragment(self):
        self.assertIn("sample.md: missing-fragment", self.check_markdown("[no](#missing)"))

    def test_unicode_heading_and_duplicate_slugs(self):
        self.assertEqual(
            {"开始", "开始-1", "a", "a-1", "a-1-1"},
            markdown_anchors("# 开始\n## 开始\n## A\n## A\n## A-1"),
        )

    def test_cross_document_fragment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "目标.md").write_text("# 中文标题", encoding="utf-8")
            path = root / "sample.md"
            path.write_text("[ok](目标.md#中文标题)", encoding="utf-8")
            self.assertEqual([], inspect_file(root, path))

    def test_fenced_examples_do_not_create_links_or_anchors(self):
        sample = "```md\n# Fake\n[x](missing.md)\n<details>\n```"
        self.assertEqual([], self.check_markdown(sample))
        self.assertEqual(set(), markdown_anchors(sample))

    def test_unclosed_fence(self):
        self.assertIn("sample.md: unclosed-fence", self.check_markdown("```text\nx"))

    def test_shorter_fence_does_not_close(self):
        self.assertIn("unclosed-fence", markdown_structure("````md\n```\n")[1])

    def test_tilde_fence_and_nested_details(self):
        sample = "<details><details></details></details>\n~~~md\n<details>\n~~~"
        self.assertEqual([], markdown_structure(sample)[1])

    def test_unbalanced_details(self):
        for sample in ("<details>", "</details>", "</details><details>"):
            with self.subTest(sample=sample):
                self.assertIn("unbalanced-details", markdown_structure(sample)[1])

    def test_sensitive_patterns_still_check_fenced_examples(self):
        token = "ghp_" + "x" * 36
        self.assertIn("sample.md: github-token", self.check_markdown("```\n" + token + "\n```"))

    def test_detects_synthetic_token_without_returning_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            synthetic_token = "ghp_" + "x" * 36
            path = root / "sample.md"
            path.touch()
            with patch.object(Path, "read_text", return_value=synthetic_token):
                errors = inspect_file(root, path)
            self.assertTrue(any("github-token" in item for item in errors))
            self.assertNotIn(synthetic_token, "\n".join(errors))

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

    def test_only_named_brand_png_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            brand = root / "brand"
            brand.mkdir()
            logo = brand / "secretbridge-logo.png"
            logo.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
            self.assertEqual([], inspect_file(root, logo))
            other = brand / "unused.png"
            other.write_bytes(logo.read_bytes())
            self.assertIn("brand/unused.png: unexpected-artifact", inspect_file(root, other))
            logo.write_bytes(b"not a png")
            self.assertIn(
                "brand/secretbridge-logo.png: invalid-binary-asset", inspect_file(root, logo)
            )

    def test_social_preview_is_the_only_other_allowed_png(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / ".github" / "assets"
            assets.mkdir(parents=True)
            preview = assets / "social-preview.png"
            preview.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
            self.assertEqual([], inspect_file(root, preview))
            preview.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 1_000_000)
            self.assertIn(
                ".github/assets/social-preview.png: forbidden-or-oversize-file",
                inspect_file(root, preview),
            )

    def test_application_source_types_are_checked_as_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                "main.rs",
                "App.tsx",
                "styles.css",
                "Cargo.toml",
                "fixture.ps1",
                "fixture.sh",
                "fixture.mjs",
            ):
                with self.subTest(name=name):
                    path = root / name
                    path.write_text("synthetic", encoding="utf-8")
                    self.assertEqual([], inspect_file(root, path))

    def test_oversized_modules_and_documents_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rust = root / "large.rs"
            rust.write_text("// line\n" * 2501, encoding="utf-8")
            self.assertIn("large.rs: oversized-rust-module", inspect_file(root, rust))
            document = root / "large.md"
            document.write_text("text\n" * 241, encoding="utf-8")
            self.assertIn("large.md: oversized-document", inspect_file(root, document))

    def test_required_files(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(check_repository(Path(directory)))

    def test_ai_deployment_entrypoints_require_url_and_any_directory_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "./docs/getting-started/安装与服务管理.md\n./docs/getting-started/AI辅助部署.md",
                encoding="utf-8",
            )
            (root / "README.zh-CN.md").write_text(
                "./docs/getting-started/安装与服务管理.md\n./docs/getting-started/AI辅助部署.md",
                encoding="utf-8",
            )
            docs = root / "docs"
            docs.mkdir()
            getting_started = docs / "getting-started"
            getting_started.mkdir()
            guide = getting_started / "AI辅助部署.md"
            guide.write_text(
                f"{PUBLIC_REPOSITORY_URL}\n不需要预先克隆仓库\n直接复用\n"
                "client-config CLIENT\nCLIENT_INTEGRATIONS.md\nsecretbridge_terminal_capabilities",
                encoding="utf-8",
            )
            (getting_started / "自动化部署运行手册.md").write_text(
                "Existing installation discovery\nclient-config CLIENT\n"
                "CLIENT_INTEGRATIONS.md\nsecretbridge_terminal_capabilities",
                encoding="utf-8",
            )
            self.assertEqual([], check_ai_deployment_entrypoints(root))
            guide.write_text("只假设已有工作区", encoding="utf-8")
            self.assertEqual(
                ["docs/getting-started/AI辅助部署.md: ai-deployment-entrypoint-missing"],
                check_ai_deployment_entrypoints(root),
            )

    def test_private_ip_and_path_patterns(self):
        self.assertIsNotNone(PATTERNS["private-ip"].search("10." + "20.30.40"))
        self.assertIsNotNone(PATTERNS["personal-path"].search("C:" + "/Users/" + "demo/"))
        self.assertIsNone(PATTERNS["private-ip"].search("version 0.1.0"))


if __name__ == "__main__":
    unittest.main()
