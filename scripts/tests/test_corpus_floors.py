"""Every floor sits above zero and below the corpus it guards.

A gate reports on the population it read. Nothing in an exit code distinguishes
"this catalog holds no violation" from "this run held no catalog", and the second
is what a renamed directory, a wrong `--root`, a narrowed glob or a filter that
stopped matching all look like. The fork-safety gate printed
`Scanned 0 applied ApplicationSet(s)` followed by its success line and exited 0
under `--blocking`.

A floor of zero is that vacuous pass with a constant in front of it. A floor
above the real corpus makes the gate red on every run, and a gate that is always
red is one people route around — the same destination by a longer road.

The floors are constants rather than derivations, and the reason is recorded at
each one: every quantity available to derive a floor from comes out of the same
walk over the same files, so a corpus that shrinks shrinks the derivation with
it. Both circular forms were written and rejected. What can be asserted is the
pair of bounds, against the tree — and, where a second enumerator does exist,
the derivation instead of a number.
"""

from __future__ import annotations

import pathlib
import unittest

import yaml
from gateloader import load

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

render_addons = load("render-addons")
fork_safety = load("check-hardcoded-org")
platform_crs = load("check-platform-crs")
policy_admission = load("check-policy-admission")
dashboards = load("validate-dashboards")
image_pins = load("check-image-pins")


class EveryFloorIsAboveZero(unittest.TestCase):
    """Zero grants exactly the vacuous pass the floor exists to stop."""

    def test_each_gate_declares_one(self):
        for label, floor in (
            ("check-hardcoded-org MIN_APPSETS", fork_safety.MIN_APPSETS),
            ("check-platform-crs MIN_CRS", platform_crs.MIN_CRS),
            ("check-policy-admission MIN_RENDERED", policy_admission.MIN_RENDERED),
            ("validate-dashboards MIN_DASHBOARD_REFS", dashboards.MIN_DASHBOARD_REFS),
        ):
            with self.subTest(floor=label):
                self.assertGreater(floor, 0)


class EveryFloorIsBelowTheCorpusItGuards(unittest.TestCase):
    """Measured off the tree. A floor above the real population is always red."""

    def test_the_applied_appsets_clear_the_fork_safety_floor(self):
        applied = [p for p in (ROOT / "applicationsets").glob("*.y*ml") if p.is_file()]
        self.assertGreater(len(applied), fork_safety.MIN_APPSETS)

    def test_the_platform_crs_clear_their_floor(self):
        """Counted the way the gate counts candidates: the operator's API groups.

        Matching a `/v1alpha1` suffix alone counts every ApplicationSet in the
        tree — 44 documents against the 8 the gate walks — so the bound would
        hold for any floor up to 43 and could not see the always-red case.
        """
        found = 0
        for path in platform_crs.manifests():
            if platform_crs.gatelib.is_helm_template(path):
                continue
            for doc in yaml.safe_load_all(path.read_text()):
                if not isinstance(doc, dict):
                    continue
                api = str(doc.get("apiVersion", ""))
                if (api.endswith("/" + platform_crs.CRD_VERSION)
                        and api.split("/", 1)[0].endswith(
                            platform_crs.OPERATOR_API_SUFFIX)):
                    found += 1
        self.assertGreater(found, platform_crs.MIN_CRS,
                           f"MIN_CRS is {platform_crs.MIN_CRS} and this tree holds "
                           f"{found} platform CR(s), so the gate exits 2 on every run")

    def test_the_render_clears_the_policy_admission_floor(self):
        """Bounded by units times the ENFORCE environments — staging and
        production, not all four: doubling the ceiling lets any floor in 66..127
        pass here while making the gate red on every run."""
        units = [u for u in policy_admission.discover()
                 if u.chart not in policy_admission.SKIP_CHARTS]
        self.assertGreater(len(units), 0)
        self.assertLess(policy_admission.MIN_RENDERED,
                        len(units) * len(policy_admission.ENFORCE_ENVS))

    def test_the_policy_admission_floor_exceeds_a_degenerate_render(self):
        """The other bound, and the reason the floor is not merely > 0.

        A render producing one manifest per unit and nothing per environment is
        the exact shape the floor exists to catch, so the floor has to sit above
        it — between the degenerate render and the largest one, not merely
        somewhere above zero.
        """
        units = [u for u in policy_admission.discover()
                 if u.chart not in policy_admission.SKIP_CHARTS]
        self.assertGreaterEqual(policy_admission.MIN_RENDERED, len(units))

    def test_the_dashboards_clear_their_floor(self):
        refs = dashboards.discover(ROOT)
        self.assertGreater(len(refs), dashboards.MIN_DASHBOARD_REFS)

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

    def test_each_floor_is_compared_against_a_count_of_what_was_read(self):
        for rel, expr in (
            ("scripts/check-hardcoded-org.py", "if len(files) < MIN_APPSETS:"),
            ("scripts/check-platform-crs.py", "if len(candidates) < MIN_CRS:"),
            ("scripts/check-policy-admission.py", "if count < MIN_RENDERED:"),
            ("scripts/validate-dashboards.py",
             "if 0 < len(refs) < MIN_DASHBOARD_REFS:"),
        ):
            with self.subTest(gate=rel):
                self.assertIn(expr, (ROOT / rel).read_text())

    def test_the_image_floor_is_derived_per_chart(self):
        """Not a constant, because here a second enumerator exists: every chart
        the render covers must contribute an image, which is the shape a total
        cannot see."""
        source = (ROOT / "scripts" / "check-image-vulnerabilities.py").read_text()
        self.assertIn("coverage = image_pins.chart_coverage(images, units, seen)", source)
        self.assertIn("if len(images) < len(units):", source)
        self.assertNotIn("MIN_IMAGES", source,
                         "the picked constant is back; the per-chart derivation is "
                         "what catches an extractor that stopped seeing a shape")


if __name__ == "__main__":
    unittest.main()
