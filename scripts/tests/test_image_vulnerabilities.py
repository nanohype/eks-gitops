"""Unit tests for the image-vulnerability gate's verdict.

The gate pulls and scans every image the pinned charts render, so it reaches a
registry and the positive-control sweep exempts it. What that leaves untested is
the part that decides the outcome: whether a finding is acknowledged, and whether
an acknowledgement still describes the scan.

Both directions matter and they fail for opposite reasons. Too strict and the
gate reports decisions that were already taken; too loose and
`image-advisories.yaml` becomes a permanent waiver, which is the one outcome that
would make a green run worse than no gate at all.

Everything here is offline. The trivy invocation and the canary are exercised by
running the gate, not from here.
"""

from __future__ import annotations

import pathlib
import unittest

import yaml
from gateloader import load

gate = load("check-image-vulnerabilities")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def finding(image="quay.io/argoproj/argo-events:v1.9.11", cve="CVE-2026-33815",
            package="github.com/jackc/pgx/v5", installed="v5.7.5", fixed="5.9.0",
            severity="CRITICAL"):
    return gate.Finding(image, gate.bare(image), cve, package, installed, fixed,
                        severity)


def advisory(cve="CVE-2026-33815", package="github.com/jackc/pgx/v5",
             reason="upstream rebuild", images=("quay.io/argoproj/argo-events",)):
    return {"id": cve, "package": package, "reason": reason, "images": list(images)}


class TheImageAnAdvisoryNames(unittest.TestCase):
    """An acknowledgement is about the image; the tag moves with every bump."""

    def test_a_tag_is_dropped(self):
        self.assertEqual(gate.bare("quay.io/argoproj/argo-events:v1.9.11"),
                         "quay.io/argoproj/argo-events")

    def test_a_digest_is_dropped(self):
        self.assertEqual(gate.bare("quay.io/cilium/cilium@sha256:" + "0" * 64),
                         "quay.io/cilium/cilium")

    def test_a_tag_and_a_digest_together_are_dropped(self):
        self.assertEqual(
            gate.bare("ghcr.io/opencost/opencost:1.121.1@sha256:" + "5" * 64),
            "ghcr.io/opencost/opencost")

    def test_an_untagged_reference_is_its_own_name(self):
        self.assertEqual(gate.bare("otel/opentelemetry-collector-contrib"),
                         "otel/opentelemetry-collector-contrib")

    def test_a_registry_port_is_not_read_as_a_tag(self):
        """Cutting there produces a key no advisory can match."""
        self.assertEqual(gate.bare("registry:5000/nanohype/agent"),
                         "registry:5000/nanohype/agent")
        self.assertEqual(gate.bare("registry:5000/nanohype/agent:1.2.3"),
                         "registry:5000/nanohype/agent")


class AnUnacknowledgedFinding(unittest.TestCase):
    """The question the gate is named for."""

    def test_a_critical_with_no_entry_blocks(self):
        problems = gate.verdict([finding()], [])
        self.assertEqual(len(problems), 1)
        self.assertIn("no entry in image-advisories.yaml names it", problems[0])
        self.assertIn("CVE-2026-33815", problems[0])
        self.assertIn("fixed in 5.9.0", problems[0])

    def test_an_acknowledged_critical_passes(self):
        self.assertEqual(gate.verdict([finding()], [advisory()]), [])

    def test_a_high_is_not_blocking(self):
        """Counted and printed; gating it would gate on upstream's advisory rate."""
        self.assertEqual(gate.verdict([finding(severity="HIGH")], []), [])

    def test_an_entry_matching_only_the_cve_does_not_cover_another_package(self):
        """One CVE id can be filed against several packages with different fixes."""
        problems = gate.verdict([finding(package="golang.org/x/crypto")],
                                [advisory(package="github.com/jackc/pgx/v5")])
        self.assertIn("no entry in image-advisories.yaml names it", problems[0])

    def test_the_same_finding_reported_twice_is_one_problem(self):
        """One image carries an advisory in the binary and in the layer around it."""
        problems = gate.verdict([finding(), finding()], [])
        self.assertEqual(len(problems), 1)


class AnAcknowledgementCoversTheImagesItNames(unittest.TestCase):
    """A new image acquiring a known CRITICAL is a decision, not an inheritance."""

    def test_a_finding_on_an_unlisted_image_blocks(self):
        """The listed image is covered; the one beside it on the same CVE is not."""
        problems = gate.verdict(
            [finding(image="quay.io/cilium/cilium:v1.19.6"),
             finding(image="quay.io/argoproj/argo-events:v1.9.11")],
            [advisory(images=("quay.io/argoproj/argo-events",))])
        self.assertEqual(len(problems), 1)
        self.assertIn("the entry does not list quay.io/cilium/cilium", problems[0])

    def test_a_tag_bump_on_a_listed_image_still_passes(self):
        self.assertEqual(
            gate.verdict([finding(image="quay.io/argoproj/argo-events:v1.9.12")],
                         [advisory()]), [])


class AnAcknowledgementThatStoppedDescribingTheScan(unittest.TestCase):
    """A list nobody re-checks only ever widens, and it widens permissively."""

    def test_an_entry_no_image_carries_blocks(self):
        problems = gate.verdict([], [advisory()])
        self.assertEqual(len(problems), 1)
        self.assertIn("outlived its reason", problems[0])

    def test_an_entry_listing_an_image_without_the_finding_blocks(self):
        """The shape a chart bump leaves behind when it fixes one image of many."""
        problems = gate.verdict(
            [finding(image="quay.io/argoproj/argo-events:v1.9.11")],
            [advisory(images=("quay.io/argoproj/argo-events", "quay.io/cilium/cilium"))])
        self.assertEqual(len(problems), 1)
        self.assertIn("lists quay.io/cilium/cilium, which no longer carries it",
                      problems[0])

    def test_an_entry_with_no_images_acknowledges_nothing(self):
        problems = gate.verdict([finding()], [advisory(images=())])
        joined = " ".join(problems)
        self.assertIn("lists no images", joined)

    def test_an_entry_with_no_reason_blocks(self):
        problems = gate.verdict([finding()], [advisory(reason="   ")])
        self.assertIn("acknowledged with no reason recorded", problems[0])

    def test_a_high_only_finding_does_not_keep_a_critical_entry_alive(self):
        """The entry is about the blocking severity; a HIGH match is not a match."""
        problems = gate.verdict([finding(severity="HIGH")], [advisory()])
        self.assertEqual(len(problems), 1)
        self.assertIn("outlived its reason", problems[0])


class TheShippedAdvisoryFile(unittest.TestCase):
    """It is read on every run, so its shape is part of the gate."""

    @classmethod
    def setUpClass(cls):
        doc = yaml.safe_load((ROOT / "image-advisories.yaml").read_text())
        cls.entries = doc["advisories"]

    def test_every_entry_carries_the_four_keys_the_verdict_reads(self):
        for entry in self.entries:
            with self.subTest(entry=entry.get("id")):
                for key in ("id", "package", "reason", "images"):
                    self.assertIn(key, entry)

    def test_every_entry_records_a_reason(self):
        for entry in self.entries:
            with self.subTest(entry=entry.get("id")):
                self.assertTrue(str(entry["reason"]).strip())

    def test_every_listed_image_is_named_without_a_tag_or_digest(self):
        """A tagged entry would stop matching at the next chart bump."""
        for entry in self.entries:
            for image in entry["images"]:
                with self.subTest(image=image):
                    self.assertEqual(gate.bare(image), image)

    def test_no_two_entries_share_an_id_and_package(self):
        """The verdict keys on that pair, so a duplicate silently shadows one."""
        keys = [(e["id"], e["package"]) for e in self.entries]
        self.assertEqual(len(keys), len(set(keys)))

    def test_the_file_acknowledges_something(self):
        """An empty list makes every rule below hold over nothing."""
        self.assertTrue(self.entries)


class TheFloorsThatStopAVacuousPass(unittest.TestCase):
    """A scan over almost nothing reports the same as a scan over a clean fleet."""

    def test_a_floor_on_images_scanned_exists(self):
        """Zero is the vacuous pass with a constant in front of it.

        Whether it sits below the catalog's real render is asserted against the
        tree in test_corpus_floors.py, not against a number written here.
        """
        self.assertGreater(gate.MIN_IMAGES, 0)

    def test_the_canary_is_pinned_by_digest(self):
        """A tag can be repointed at a rebuilt, clean image, and then the canary
        stops proving the scanner reports anything."""
        self.assertIn("@sha256:", gate.CANARY)

    def test_the_blocking_severity_is_among_the_ones_scanned_for(self):
        self.assertIn(gate.BLOCKING_SEVERITY, gate.REPORTED_SEVERITIES)


if __name__ == "__main__":
    unittest.main()
