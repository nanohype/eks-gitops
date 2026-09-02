"""Every gate that enumerates a corpus refuses to pass over an empty one.

A gate reports on the population it read. Nothing in an exit code distinguishes
"this catalog holds no violation" from "this run held no catalog", and the second
is what a renamed directory, a wrong `--root`, a narrowed glob or a filter that
stopped matching all look like. The fork-safety gate printed
`Scanned 0 applied ApplicationSet(s)` followed by its success line and exited 0
under `--blocking`.

So each of those gates carries a floor on what it EXAMINED, and each floor has
two ways to be wrong. Set to zero it grants exactly the vacuous pass it exists to
stop. Set above the real corpus it fails every run, and a gate that is always red
is a gate people route around — which ends in the same place by a longer road.

These assert both bounds against the tree rather than against a number written
here, so the floors stay meaningful as the catalog grows.
"""

from __future__ import annotations

import pathlib
import unittest

import yaml
from gateloader import load

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

fork_safety = load("check-hardcoded-org")
platform_crs = load("check-platform-crs")
policy_admission = load("check-policy-admission")
image_vulns = load("check-image-vulnerabilities")


class EveryFloorIsAboveZero(unittest.TestCase):
    """A floor of zero is the vacuous pass with a constant in front of it."""

    def test_each_gate_declares_one(self):
        for label, floor in (
            ("check-hardcoded-org MIN_APPSETS", fork_safety.MIN_APPSETS),
            ("check-platform-crs MIN_CRS", platform_crs.MIN_CRS),
            ("check-policy-admission MIN_RENDERED", policy_admission.MIN_RENDERED),
            ("check-image-vulnerabilities MIN_IMAGES", image_vulns.MIN_IMAGES),
        ):
            with self.subTest(floor=label):
                self.assertGreater(floor, 0)


class EveryFloorIsBelowTheCorpusItGuards(unittest.TestCase):
    """Measured off the tree. A floor above the real population is always red."""

    def test_the_applied_appsets_clear_the_fork_safety_floor(self):
        applied = [p for p in (ROOT / "applicationsets").glob("*.y*ml") if p.is_file()]
        self.assertGreater(len(applied), fork_safety.MIN_APPSETS,
                           "MIN_APPSETS is at or above the number of applied "
                           "ApplicationSets, so the fork-safety gate cannot pass")

    def test_the_platform_crs_clear_their_floor(self):
        """Counted with the gate's own filters: chart source is Go-template text,
        which the walk identifies structurally rather than by what breaks a parser."""
        found = 0
        for path in platform_crs.manifests():
            if platform_crs.gatelib.is_helm_template(path):
                continue
            for doc in yaml.safe_load_all(path.read_text()):
                if not isinstance(doc, dict):
                    continue
                if str(doc.get("apiVersion", "")).endswith(
                        "/" + platform_crs.CRD_VERSION):
                    found += 1
        self.assertGreater(found, platform_crs.MIN_CRS,
                           "MIN_CRS is at or above the number of platform CRs in the "
                           "tree, so check-platform-crs.py cannot pass")

    def test_the_discovered_addons_clear_the_policy_admission_floor(self):
        """One unit renders at least one manifest, so units bound the render below."""
        units = policy_admission.discover()
        self.assertGreater(len(units), 0)
        self.assertGreaterEqual(
            policy_admission.MIN_RENDERED, len(units),
            "MIN_RENDERED sits below the number of addon units discovered, so it "
            "would pass a render that produced one manifest per unit and nothing "
            "for the environments — which is the shape it exists to catch")


class TheFloorsGuardTheRightQuantity(unittest.TestCase):
    """A floor on findings is not a floor on the corpus.

    Counting what was FOUND cannot separate a clean catalog from an unexamined
    one; only counting what was READ can.
    """

    def test_the_fork_safety_floor_is_read_off_the_file_list(self):
        source = (ROOT / "scripts" / "check-hardcoded-org.py").read_text()
        self.assertIn("if len(files) < MIN_APPSETS:", source)

    def test_the_platform_crs_floor_is_read_off_the_walk_count(self):
        source = (ROOT / "scripts" / "check-platform-crs.py").read_text()
        self.assertIn("if walked < MIN_CRS:", source)

    def test_the_policy_admission_floor_is_read_off_the_render_count(self):
        source = (ROOT / "scripts" / "check-policy-admission.py").read_text()
        self.assertIn("if count < MIN_RENDERED:", source)

    def test_the_image_floor_is_read_off_the_inventory(self):
        source = (ROOT / "scripts" / "check-image-vulnerabilities.py").read_text()
        self.assertIn("if len(images) < MIN_IMAGES:", source)


if __name__ == "__main__":
    unittest.main()
