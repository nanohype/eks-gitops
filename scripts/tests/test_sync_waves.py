"""Unit tests for the sync-wave gate's category resolution.

`_category` decides which band an Application is checked against. If it returns
None for something it should classify, that Application is silently unchecked —
the gate reports success having examined nothing about it.
"""

import unittest

from gateloader import load

sw = load("check-sync-waves")


class CategoryFromPath(unittest.TestCase):
    def test_derived_from_addons_path(self):
        self.assertEqual(sw._category("anything.yaml", "addons/networking/cilium"), "networking")

    def test_path_wins_over_file_mapping(self):
        # An appset listed in FILE_CATEGORY still classifies per-element by path,
        # which is what lets one ApplicationSet span two categories safely.
        self.assertEqual(
            sw._category("addons-agent-operator.yaml", "addons/operations/goldilocks-resources"),
            "operations",
        )

    def test_falls_back_to_file_mapping(self):
        self.assertEqual(sw._category("kyverno-policies.yaml", None), "policies")

    def test_unknown_file_without_path_is_none(self):
        self.assertIsNone(sw._category("not-a-known-appset.yaml", None))


class BandsAreCoherent(unittest.TestCase):
    def test_every_primary_category_has_a_band(self):
        for category, _ in sw.PRIMARY_ORDER:
            self.assertIn(category, sw.BANDS, f"{category} is ordered but unbanded")

    def test_bands_are_lo_le_hi(self):
        for name, (lo, hi) in sw.BANDS.items():
            self.assertLessEqual(lo, hi, f"{name} band is inverted")

    def test_file_category_targets_are_real_bands(self):
        for f, category in sw.FILE_CATEGORY.items():
            self.assertIn(category, sw.BANDS, f"{f} maps to unbanded {category!r}")


if __name__ == "__main__":
    unittest.main()
