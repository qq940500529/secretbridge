# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_reproducible_packages",
    Path(__file__).parents[1] / "tools/verify_reproducible_packages.py",
)
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class ReproduciblePackageTests(unittest.TestCase):
    def directories(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        first, second = root / "first", root / "second"
        first.mkdir()
        second.mkdir()
        return temporary, first, second

    def test_equal_package_and_sidecars_pass(self):
        temporary, first, second = self.directories()
        with temporary:
            name = "secretbridge-test.zip"
            for directory in (first, second):
                archive = directory / name
                archive.write_bytes(b"stable package")
                checksum = verify.digest(archive)
                (directory / f"{name}.sha256").write_text(
                    f"{checksum}  {name}\n", encoding="ascii"
                )
            self.assertEqual(verify.compare(first, second)[0], name)

    def test_changed_bytes_or_sidecar_fail(self):
        temporary, first, second = self.directories()
        with temporary:
            for directory, content in ((first, b"first"), (second, b"second")):
                archive = directory / "secretbridge-test.tar.gz"
                archive.write_bytes(content)
                (directory / f"{archive.name}.sha256").write_text(
                    f"{verify.digest(archive)}  {archive.name}\n", encoding="ascii"
                )
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                verify.compare(first, second)


if __name__ == "__main__":
    unittest.main()
