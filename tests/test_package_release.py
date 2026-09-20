# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Package format/version/source regressions without network access."""

import importlib.util
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

SPEC = importlib.util.spec_from_file_location(
    "package_release", Path(__file__).parents[1] / "tools/package_release.py"
)
package_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_release)


class PackageReleaseTests(unittest.TestCase):
    def test_embedded_mit_readme_is_accepted_as_packaged_license_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            readme = directory / "Readme.markdown"
            readme.write_text(
                "MIT License\nPermission is hereby granted, free of charge\n"
                'THE SOFTWARE IS PROVIDED "AS IS"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                package_release.local_rust_license_files({"readme": "Readme.markdown"}, directory),
                [readme],
            )

    def test_dirty_checkout_is_rejected_for_release(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(package_release, "command", return_value=" M README.md\n"),
            self.assertRaisesRegex(ValueError, "clean source"),
        ):
            package_release.source_snapshot(Path(temporary) / "source.tar.gz", False)

    def test_development_snapshot_records_dirty_state_and_embeds_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text("example", encoding="utf-8")
            with (
                patch.object(package_release, "ROOT", root),
                patch.object(
                    package_release,
                    "command",
                    side_effect=[" M Cargo.toml", "a" * 40, "Cargo.toml\0"],
                ),
            ):
                result = package_release.source_snapshot(
                    root / "source.tar.gz", True, 1_700_000_000
                )
            self.assertTrue(result["dirty"])
            self.assertEqual(result["base_commit"], "a" * 40)
            self.assertEqual(result["source_date_epoch"], 1_700_000_000)
            self.assertEqual(len(result["source_sha256"]), 64)
            with tarfile.open(root / "source.tar.gz") as bundle:
                self.assertEqual(bundle.getnames(), ["secretbridge-source/Cargo.toml"])

    def test_unpinned_license_download_is_rejected(self):
        with self.assertRaises(ValueError):
            package_release.upstream_license("https://github.com/example/project", "main")
        with self.assertRaises(ValueError):
            package_release.upstream_license("https://untrusted.invalid/example/project", "a" * 40)

    def test_upstream_license_download_retries_transient_transport_failure(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def read(_limit):
                return b"license fixture"

        package_release.upstream_license.cache_clear()
        with (
            patch.object(package_release.shutil, "which", return_value=None),
            patch.object(
                package_release,
                "urlopen",
                side_effect=[URLError("temporary reset"), Response()],
            ) as request,
            patch.object(package_release.time, "sleep") as sleep,
            patch.object(
                Response,
                "read",
                return_value=json.dumps(
                    {
                        "encoding": "base64",
                        "content": "bGljZW5zZSBmaXh0dXJl",
                    }
                ).encode(),
            ),
        ):
            notice = package_release.upstream_license(
                "https://github.com/example/project", "a" * 40
            )
        self.assertIn("license fixture", notice)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(0.25)
        package_release.upstream_license.cache_clear()

    def test_nayuki_license_falls_back_to_pinned_readme(self):
        package_release.upstream_license.cache_clear()
        payload = json.dumps({"encoding": "base64", "content": "bGljZW5zZSBmaXh0dXJl"}).encode()
        with (
            patch.object(package_release.shutil, "which", return_value=None),
            patch.object(
                package_release,
                "download_upstream_license",
                side_effect=[None] * 8 + [payload],
            ) as download,
        ):
            notice = package_release.upstream_license(
                "https://github.com/nayuki/QR-Code-generator", "a" * 40
            )
        self.assertIn("license fixture", notice)
        self.assertIn("Readme.markdown", download.call_args.args[0])
        package_release.upstream_license.cache_clear()

    def test_sbom_contains_native_and_web_runtime_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            dependency = Path(temporary) / "react"
            dependency.mkdir()
            (dependency / "package.json").write_text(
                json.dumps({"name": "react", "version": "19.3.0", "license": "MIT"}),
                encoding="utf-8",
            )
            cargo = {
                "packages": [
                    {
                        "id": "app",
                        "name": "secretbridge-server",
                        "version": "0.2.0-beta.2",
                        "source": None,
                        "license": "AGPL-3.0-or-later",
                        "manifest_path": "Cargo.toml",
                    },
                    {
                        "id": "serde",
                        "name": "serde",
                        "version": "1.0.229",
                        "source": "registry",
                        "license": "MIT OR Apache-2.0",
                        "manifest_path": "serde/Cargo.toml",
                    },
                ],
                "resolve": {
                    "nodes": [
                        {"id": "app", "deps": [{"pkg": "serde"}]},
                        {"id": "serde", "deps": []},
                    ]
                },
            }
            web = [{"dependencies": {"react": {"version": "19.3.0", "path": str(dependency)}}}]

            def metadata(args):
                if args[:2] == ["rustc", "-vV"]:
                    return "host: x86_64-pc-windows-msvc\n"
                if args[:2] == ["cargo", "metadata"]:
                    return json.dumps(cargo)
                if "list" in args:
                    return json.dumps(web)
                raise AssertionError(args)

            source = {"repository": "https://example.invalid/repository", "base_commit": "c" * 40}
            with patch.object(package_release, "command", side_effect=metadata):
                first = package_release.software_bill_of_materials(
                    "0.2.0-beta.2", "windows", "x86_64", source, 1_700_000_000
                )
                second = package_release.software_bill_of_materials(
                    "0.2.0-beta.2", "windows", "x86_64", source, 1_700_000_000
                )
            self.assertEqual(first, second)
            self.assertEqual(first["bomFormat"], "CycloneDX")
            self.assertEqual(first["metadata"]["component"]["version"], "0.2.0-beta.2")
            names = {component["name"] for component in first["components"]}
            self.assertTrue({"secretbridge-server", "serde", "react"} <= names)

    def fixture(self, root):
        (root / "Cargo.toml").write_text(
            '[workspace.package]\nversion="0.2.0-beta.2"\n', encoding="utf-8"
        )
        web = root / "web/dist"
        web.mkdir(parents=True)
        (web / "index.html").write_text("<main>test</main>", encoding="utf-8")
        (web / "secretbridge-build.json").write_text(
            json.dumps({"format_version": 1, "version": "0.2.0-beta.2"}), encoding="utf-8"
        )
        for document in package_release.DOCUMENTS:
            (root / document).write_text("test notice", encoding="utf-8")
        binary = root / "app"
        binary.write_bytes(b"fixture executable")
        return binary

    def test_binary_web_version_mismatch_fails_before_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self.fixture(root)
            with (
                patch.object(package_release, "ROOT", root),
                patch.object(package_release.subprocess, "check_output", return_value="0.0.0"),
                self.assertRaisesRegex(ValueError, "must match"),
            ):
                package_release.build_package(binary, root / "output")

    def test_manifest_covers_payload_source_notices_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self.fixture(root)

            def snapshot(target, _, epoch):
                target.write_bytes(b"source fixture")
                return {
                    "dirty": False,
                    "corresponding_source": "SOURCE.tar.gz",
                    "repository": "https://example.invalid/repository",
                    "base_commit": "a" * 40,
                    "source_date_epoch": epoch,
                }

            sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
            with (
                patch.object(package_release, "ROOT", root),
                patch.object(
                    package_release.subprocess, "check_output", return_value="0.2.0-beta.2"
                ),
                patch.object(package_release, "release_epoch", return_value=1_700_000_000),
                patch.object(package_release, "source_snapshot", side_effect=snapshot),
                patch.object(
                    package_release, "third_party_notices", return_value="license fixture"
                ),
                patch.object(package_release, "software_bill_of_materials", return_value=sbom),
            ):
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
            self.assertTrue(
                {
                    "SOURCE.tar.gz",
                    "SOURCE.json",
                    "SBOM.cdx.json",
                    "THIRD_PARTY_LICENSES.txt",
                    "LICENSE",
                    "web/index.html",
                }
                <= paths
            )
            for file in manifest["files"]:
                path = application / file["path"]
                self.assertEqual(file["sha256"], package_release.sha256(path))
                self.assertEqual(file["bytes"], path.stat().st_size)

    def test_two_builds_with_the_same_inputs_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self.fixture(root)

            def snapshot(target, _, epoch):
                target.write_bytes(b"stable source fixture")
                return {
                    "dirty": False,
                    "repository": "https://example.invalid/repository",
                    "base_commit": "b" * 40,
                    "source_date_epoch": epoch,
                }

            sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
            with (
                patch.object(package_release, "ROOT", root),
                patch.object(
                    package_release.subprocess, "check_output", return_value="0.2.0-beta.2"
                ),
                patch.object(package_release, "release_epoch", return_value=1_700_000_000),
                patch.object(package_release, "source_snapshot", side_effect=snapshot),
                patch.object(
                    package_release, "third_party_notices", return_value="license fixture"
                ),
                patch.object(package_release, "software_bill_of_materials", return_value=sbom),
            ):
                first = package_release.build_package(binary, root / "first")
                second = package_release.build_package(binary, root / "second")
            self.assertEqual(package_release.sha256(first), package_release.sha256(second))


if __name__ == "__main__":
    unittest.main()
