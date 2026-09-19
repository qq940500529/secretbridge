# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "personal_scale", ROOT / "tools" / "test_personal_scale.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PersonalScaleTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(MODULE.percentile([1, 2, 3, 4], 0.5), 2)
        self.assertEqual(MODULE.percentile([1, 2, 3, 4], 0.95), 4)

    def test_empty_percentile_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.percentile([], 0.95)

    def test_limits_name_only_failed_metrics(self):
        metrics = {"startup_p95_ms": 12, "status_p95_ms": 3, "idle_rss_mib": 20}
        limits = {"startup_p95_ms": 10, "status_p95_ms": 5, "idle_rss_mib": 20}
        self.assertEqual(MODULE.evaluate(metrics, limits), ["startup_p95_ms"])


if __name__ == "__main__":
    unittest.main()
