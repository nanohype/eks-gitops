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

# The API-group suffix the operator chart's CRDs share. The gate filters on the
# schema set the chart ships, which needs the chart; this is the part of that
# filter available offline, and it is what separates a platform CR from an
# ApplicationSet that happens to share a version suffix.
OPERATOR_API_SUFFIX = ".nanohype.dev"

render_addons = load("render-addons")
fork_safety = load("check-hardcoded-org")
platform_crs = load("check-platform-crs")
policy_admission = load("check-policy-admission")
image_pins = load("check-image-pins")
image_vulns = load("check-image-vulnerabilities")


class EveryFloorIsAboveZero(unittest.TestCase):
    """A floor of zero is the vacuous pass with a constant in front of it."""

    def test_each_gate_declares_one(self):
        for label, floor in (
            ("check-hardcoded-org MIN_APPSETS", fork_safety.MIN_APPSETS),
            ("check-platform-crs MIN_CRS", platform_crs.MIN_CRS),
            ("check-policy-admission MIN_RENDERED", policy_admission.MIN_RENDERED),
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
        """The gate keeps documents whose KIND is in the operator chart's schema
        set; a version suffix alone is not that filter.

        Matching `/v1alpha1` counts every ApplicationSet (argoproj.io/v1alpha1)
        and every Kyverno test fixture in the tree — 44 documents against the 8
        the gate walks — so the assertion held for any floor up to 43 and could
        not see an always-red one, which is the only thing it was added to see.
        The operator's own API groups are the discriminator available offline;
        the schema set itself needs the chart.
        """
        found = 0
        for path in platform_crs.manifests():
            if platform_crs.gatelib.is_helm_template(path):
                continue
            for doc in yaml.safe_load_all(path.read_text()):
                if not isinstance(doc, dict):
                    continue
                api = str(doc.get("apiVersion", ""))
                if not api.endswith("/" + platform_crs.CRD_VERSION):
                    continue
                if not api.split("/", 1)[0].endswith(OPERATOR_API_SUFFIX):
                    continue
                found += 1
        self.assertGreater(found, platform_crs.MIN_CRS,
                           f"MIN_CRS is {platform_crs.MIN_CRS} and this tree holds "
                           f"{found} platform CR(s), so check-platform-crs.py exits 2 "
                           f"on every run")

    def test_the_discovered_addons_clear_the_policy_admission_floor(self):
        """The render is one manifest per unit per environment it reaches, so the
        unit count times the environments bounds it above — and a floor above
        THAT is one no render can clear."""
        units = policy_admission.discover()
        self.assertGreater(len(units), 0)
        # ENFORCE_ENVS, not ENVIRONMENTS: check-policy-admission renders the
        # Enforce overlay only. Bounding against all four doubles the ceiling and
        # lets any floor in 66..127 pass here while making the gate red on every
        # run — the failure this test exists to catch.
        reachable = len(units) * len(policy_admission.ENFORCE_ENVS)
        self.assertLess(
            policy_admission.MIN_RENDERED, reachable,
            "MIN_RENDERED is at or above the largest render this catalog can "
            "produce, so check-policy-admission.py is red on every run and the "
            "gate gets routed around")

    def test_the_policy_admission_floor_exceeds_a_degenerate_render(self):
        """A different property, and the reason the floor is not merely > 0: a
        render producing one manifest per unit and nothing per environment is
        the shape the floor exists to catch, so it must sit above that."""
        units = policy_admission.discover()
        self.assertGreaterEqual(policy_admission.MIN_RENDERED, len(units))

    def test_the_imageless_charts_are_charts_the_fleet_renders(self):
        """The image floor is per chart, so its exemption is where it can rot.

        A chart declared imageless that the catalog no longer pins is an entry
        excusing nothing, and the per-chart floor is exactly as strong as that
        list is short.
        """
        charts = {u.chart for u in render_addons.discover()}
        for chart in image_pins.IMAGELESS_CHARTS:
            with self.subTest(chart=chart):
                self.assertIn(chart, charts,
                              f"{chart} is declared to render no image but the fleet "
                              f"does not pin it — the entry outlived its chart")


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

    def test_the_image_floor_is_derived_per_chart(self):
        """Not a constant: every chart the render covers must contribute an image,
        which is the shape a total cannot see."""
        source = (ROOT / "scripts" / "check-image-vulnerabilities.py").read_text()
        self.assertIn("coverage = image_pins.chart_coverage(images, units, seen)", source)
        self.assertIn("if len(images) < len(units):", source)
        self.assertNotIn("MIN_IMAGES", source,
                         "the picked constant is back; the per-chart derivation is "
                         "what catches an extractor that stopped seeing a shape")


if __name__ == "__main__":
    unittest.main()
