# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from tools.check_dependency_licenses import unreviewed


class DependencyLicensePolicyTests(unittest.TestCase):
    def test_reviewed_identifiers_pass(self):
        self.assertEqual([], unreviewed({"MIT", "ISC"}, {"MIT", "ISC"}))

    def test_new_identifier_requires_review(self):
        self.assertEqual(
            ["Example-1.0"],
            unreviewed({"MIT", "Example-1.0"}, {"MIT"}),
        )


if __name__ == "__main__":
    unittest.main()
