"""Unit tests for the sync-wave gate's category resolution.

`_category` decides which band an Application is checked against. If it returns
None for something it should classify, that Application is silently unchecked —
the gate reports success having examined nothing about it.
"""

import pathlib
import unittest

import yaml
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



class PolicyCRDsPrecedeThePolicies(unittest.TestCase):
    """Every kind the kyverno-policies Applications render comes from the
    kyverno chart, so its group must be an edge the gate orders."""

    def test_every_rendered_policy_group_is_an_ordered_edge(self):
        root = pathlib.Path(__file__).resolve().parent.parent.parent / "policies" / "kyverno"
        groups = set()
        for path in root.glob("*/base/*.yaml"):
            for doc in yaml.safe_load_all(path.read_text()):
                if isinstance(doc, dict) and "/" in str(doc.get("apiVersion", "")):
                    group = doc["apiVersion"].split("/")[0]
                    if group != "kustomize.config.k8s.io":
                        groups.add(group)
        self.assertTrue(groups, "no policy manifest was read")
        ordered = {edge["group"] for edge in sw.CRD_PRECEDENCE.values()
                   if "kyverno-policies.yaml" in edge["consumers"]}
        self.assertEqual(groups - ordered, set())


if __name__ == "__main__":
    unittest.main()


class ChartLocks(unittest.TestCase):
    """A controller chart and its CRD-only chart are one release."""

    def appset_dir(self, controller_version, crds_version, crds_chart="gateway-crds-helm"):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        doc = {"kind": "ApplicationSet", "spec": {
            "template": {"spec": {"sources": [{"chart": "{{ .chart }}"}]}},
            "generators": [{"list": {"elements": [
                {"chart": "gateway-helm", "chartVersion": controller_version},
                {"chart": crds_chart, "chartVersion": crds_version}]}}]}}
        (root / "a.yaml").write_text(yaml.safe_dump(doc))
        return root

    def locks(self, root):
        from unittest import mock
        with mock.patch.object(sw, "APPSET_DIR", root), \
                mock.patch.object(sw, "CHART_LOCKS",
                                  [("a.yaml", "gateway-helm", "gateway-crds-helm")]):
            return sw.chart_locks()

    def test_a_pair_at_one_version_holds(self):
        self.assertEqual(self.locks(self.appset_dir("1.10.0", "1.10.0")), [])

    def test_a_pair_bumped_on_one_side_is_a_finding(self):
        problems = self.locks(self.appset_dir("1.11.0", "1.10.0"))
        self.assertEqual(len(problems), 1)
        self.assertIn("gateway-helm 1.11.0 but gateway-crds-helm 1.10.0", problems[0])

    def test_a_pair_missing_one_side_cannot_be_evaluated(self):
        problems = self.locks(self.appset_dir("1.10.0", "1.10.0", crds_chart="other"))
        self.assertEqual(len(problems), 1)
        self.assertIn("gateway-crds-helm not pinned", problems[0])

    def test_every_lock_names_charts_the_catalog_pins(self):
        self.assertEqual(sw.chart_locks(), [])
