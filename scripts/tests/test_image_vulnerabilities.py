"""Unit tests for the image-vulnerability gate's verdict.

The gate pulls and scans every image the pinned charts render, so it reaches a
registry and the positive-control sweep exempts it. What that leaves untested is
the part that decides the outcome: whether a finding is acknowledged, and whether
an acknowledgement still describes the scan.

Both directions matter and they fail for opposite reasons. Too strict and the
gate reports decisions that were already taken; too loose and
`image-advisories.yaml` becomes a permanent waiver, which is the one outcome that
would make a green run worse than no gate at all.

Everything here is offline. trivy is replaced by a stand-in that answers each
invocation with a status and what trivy writes, so what the gate does with a
registry refusing it for now, with any other failure, and with what trivy said
about either is decided here; a real scan is exercised by running the gate.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import json
import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest import mock

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


class AnAcknowledgementWithAReviewDate(unittest.TestCase):
    """A finding upstream never fixes would otherwise keep its entry alive unread."""

    DUE = datetime.date(2027, 1, 31)

    def dated(self, review_by):
        return [{**advisory(), "review_by": review_by}]

    def test_an_entry_before_its_date_passes(self):
        self.assertEqual(
            gate.verdict([finding()], self.dated(self.DUE),
                         today=self.DUE - datetime.timedelta(days=1)), [])

    def test_an_entry_on_its_date_passes(self):
        self.assertEqual(gate.verdict([finding()], self.dated(self.DUE), today=self.DUE),
                         [])

    def test_an_entry_past_its_date_blocks(self):
        problems = gate.verdict([finding()], self.dated(self.DUE),
                                today=self.DUE + datetime.timedelta(days=1))
        self.assertEqual(len(problems), 1)
        self.assertIn("was due for review on 2027-01-31", problems[0])

    def test_a_quoted_date_reads_the_same_as_an_unquoted_one(self):
        later = self.DUE + datetime.timedelta(days=1)
        self.assertEqual(gate.verdict([finding()], self.dated("2027-01-31"), today=later),
                         gate.verdict([finding()], self.dated(self.DUE), today=later))

    def test_a_value_that_is_not_a_day_blocks(self):
        for value in ("soon", "", None, 20270131,
                      datetime.datetime(2027, 1, 31, 12, 0)):
            with self.subTest(value=value):
                problems = gate.verdict([finding()], self.dated(value), today=self.DUE)
                self.assertEqual(len(problems), 1)
                self.assertIn("not a YYYY-MM-DD date", problems[0])

    def test_an_entry_without_a_date_never_falls_due(self):
        self.assertEqual(gate.verdict([finding()], [advisory()],
                                      today=datetime.date(9999, 12, 31)), [])

    def test_a_due_entry_still_acknowledges_its_finding(self):
        """The due date is its own problem; the finding is not reported twice."""
        problems = gate.verdict([finding()], self.dated(self.DUE),
                                today=self.DUE + datetime.timedelta(days=1))
        self.assertFalse(any("no entry in image-advisories.yaml" in p for p in problems))


# 00:30 UTC on 1 February 2027, which is still 31 January west of Greenwich.
UTC_NOW = datetime.datetime(2027, 2, 1, 0, 30, tzinfo=datetime.UTC)
LOCAL_NOW = datetime.datetime(2027, 1, 31, 18, 30)


class _FrozenDatetime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return UTC_NOW.astimezone(tz) if tz is not None else LOCAL_NOW


class _FrozenDate(datetime.date):
    @classmethod
    def today(cls):
        return LOCAL_NOW.date()


class TheDefaultDayIsTheUtcDay(unittest.TestCase):
    """With no `today` passed, an entry falls due on the UTC calendar.

    The clock is frozen at a moment where the UTC date and a runner's local date
    differ, so a default read from the local clock reaches the other answer.
    """

    def setUp(self):
        frozen = types.SimpleNamespace(datetime=_FrozenDatetime, date=_FrozenDate,
                                       UTC=datetime.UTC, timezone=datetime.timezone)
        real, gate.datetime = gate.datetime, frozen
        self.addCleanup(setattr, gate, "datetime", real)

    def test_an_entry_dated_the_local_day_is_due_on_the_utc_day(self):
        # A string, because review_date's isinstance checks read the frozen
        # classes and refuse a real date object.
        problems = gate.verdict([finding()], [{**advisory(), "review_by": "2027-01-31"}])
        self.assertEqual(len(problems), 1)
        self.assertIn("was due for review on 2027-01-31", problems[0])


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

    def test_every_review_date_is_a_day(self):
        """Read as the gate reads it, so a typo fails here before it fails a run."""
        for entry in self.entries:
            if "review_by" in entry:
                with self.subTest(entry=entry["id"], package=entry["package"]):
                    self.assertIsNotNone(gate.review_date(entry["review_by"]))

    def test_no_two_entries_share_an_id_and_package(self):
        """The verdict keys on that pair, so a duplicate silently shadows one."""
        keys = [(e["id"], e["package"]) for e in self.entries]
        self.assertEqual(len(keys), len(set(keys)))

    def test_the_file_acknowledges_something(self):
        """An empty list makes every rule below hold over nothing."""
        self.assertTrue(self.entries)


class TheFloorsThatStopAVacuousPass(unittest.TestCase):
    """A scan over almost nothing reports the same as a scan over a clean fleet."""

    def test_the_floor_on_images_scanned_is_derived_per_chart(self):
        """A constant can be set above the render and make the gate always red,
        or below it and let a shrunken walk through. One image per chart the
        render covers is neither: it moves with the catalog."""
        self.assertFalse(hasattr(gate, "MIN_IMAGES"))

    def test_the_canary_is_pinned_by_digest(self):
        """A tag can be repointed at a rebuilt, clean image, and then the canary
        stops proving the scanner reports anything."""
        self.assertIn("@sha256:", gate.CANARY)

    def test_the_blocking_severity_is_among_the_ones_scanned_for(self):
        self.assertIn(gate.BLOCKING_SEVERITY, gate.REPORTED_SEVERITIES)


class ReadingTheAdvisories(unittest.TestCase):
    """With no advisories to read, every finding would be reported as
    unacknowledged, so an absent or keyless file is a gate that cannot run."""

    def read(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "image-advisories.yaml"
            if text is not None:
                path.write_text(text)
            out = io.StringIO()
            with mock.patch.object(gate, "ADVISORIES", path), contextlib.redirect_stdout(out):
                try:
                    return gate.read_advisories(), out.getvalue()
                except SystemExit as exc:
                    return exc.code, out.getvalue()

    def test_the_entries_are_returned(self):
        entries, _ = self.read("advisories:\n  - id: CVE-1\n    image: x\n")
        self.assertEqual(entries, [{"id": "CVE-1", "image": "x"}])

    def test_an_empty_list_is_no_advisories(self):
        self.assertEqual(self.read("advisories: []\n")[0], [])

    def test_an_absent_file_cannot_run(self):
        rc, out = self.read(None)
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("image-advisories.yaml does not exist", out)
        self.assertIn("examined nothing", out)

    def test_a_file_with_no_advisories_key_cannot_run(self):
        rc, out = self.read("entries: []\n")
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("declares no `advisories` key", out)


# What trivy writes to stderr when the registry it reads refuses it. Each line is
# the shape go-containerregistry gives the refusal, after the chain of contexts
# trivy prefixes it with.
def trivy_said(refusal: str) -> str:
    return ("2026-10-28T17:24:40Z\tFATAL\tFatal error\trun error: image scan error: "
            "scan error: unable to initialize a scan service: unable to find the "
            "specified image \"public.ecr.aws/karpenter/controller:1.15.1\" in "
            "[\"remote\"]: 1 error occurred:\n"
            f"\t* remote error: GET https://public.ecr.aws/v2/karpenter/controller/"
            f"manifests/1.15.1: {refusal}\n")


THROTTLED = trivy_said("TOOMANYREQUESTS: Rate exceeded")

REPORT = json.dumps({"Results": [{"Vulnerabilities": [{
    "VulnerabilityID": "CVE-2026-1", "PkgName": "musl", "InstalledVersion": "1.1",
    "FixedVersion": "1.2", "Severity": "CRITICAL"}]}]})


class Trivy:
    """A stand-in for subprocess.run that answers each trivy invocation in turn.

    A step is a CompletedProcess's (returncode, stdout, stderr), or an exception
    to raise. Every wait the scan takes is recorded rather than slept.
    """

    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls: list[list[str]] = []
        self.waits: list[float] = []

    def run(self, cmd, **kwargs):
        self.calls.append(cmd)
        self.timeout = kwargs.get("timeout")
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        rc, out, err = step
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def scan(self, ref="public.ecr.aws/karpenter/controller:1.15.1", jitter=0.0):
        with contextlib.redirect_stderr(io.StringIO()) as said:
            try:
                with mock.patch.object(gate.subprocess, "run", self.run):
                    return gate.scan(ref, sleep=self.waits.append, jitter=lambda: jitter)
            finally:
                self.said = said.getvalue()


class ScanningThroughARegistryThatRefusesForNow(unittest.TestCase):
    """A 429, a 5xx or a transfer cut off says nothing about the image, so the
    scan is run again.

    ECR Public refuses an anonymous client over its quota, and the quota belongs
    to the runner's address rather than to this job. Reported at once, an image
    the registry refused for a second is an image the gate examined nothing of.
    Retried without bound, it is a job that runs into its timeout naming no image.
    """

    def test_a_refused_scan_is_run_again_and_its_findings_are_the_result(self):
        trivy = Trivy((1, "", THROTTLED), (0, REPORT, ""))
        found = trivy.scan()
        self.assertEqual([f.id for f in found], ["CVE-2026-1"])
        self.assertEqual(len(trivy.calls), 2)
        self.assertEqual(trivy.waits, [gate.SCAN_BACKOFF_SECONDS])
        self.assertIn("attempt 1 of", trivy.said)
        self.assertIn("ended with 'TOOMANYREQUESTS'", trivy.said)

    def test_each_way_trivy_names_a_refusal_that_clears_is_retried(self):
        """The distribution codes a body carries, and the status when it carries none."""
        for refusal in ("TOOMANYREQUESTS: Rate exceeded",
                        "UNAVAILABLE: service unavailable",
                        "unexpected status code 429 Too Many Requests",
                        "unexpected status code 500 Internal Server Error",
                        "unexpected status code 502 Bad Gateway: <html>bad gateway</html>",
                        "unexpected status code 503 Service Unavailable",
                        "unexpected status code 504 Gateway Timeout"):
            with self.subTest(refusal=refusal):
                trivy = Trivy((1, "", trivy_said(refusal)), (0, REPORT, ""))
                trivy.scan()
                self.assertEqual(len(trivy.calls), 2)

    def test_a_transfer_cut_off_mid_layer_is_run_again(self):
        """A layer whose stream ended short says nothing about the image: the
        connection dropped, and the next scan is a new transfer."""
        cut_off = ("2026-10-29T23:32:16Z\tFATAL\tFatal error\trun error: image scan error: "
                   "scan error: scan failed: failed analysis: analyze error: pipeline error: "
                   "failed to analyze layer (sha256:5eb2f3940bf1): walk error: failed to "
                   "process the file: failed to analyze file: failed to analyze "
                   "bin/rollouts-controller: unable to open bin/rollouts-controller: failed "
                   "to open: failed to copy: unexpected EOF\n")
        trivy = Trivy((1, "", cut_off), (0, REPORT, ""))
        found = trivy.scan("quay.io/argoproj/argo-rollouts:v1.9.1")
        self.assertEqual([f.id for f in found], ["CVE-2026-1"])
        self.assertEqual(len(trivy.calls), 2)
        self.assertEqual(trivy.waits, [gate.SCAN_BACKOFF_SECONDS])
        self.assertIn("ended with 'unexpected EOF'", trivy.said)

    def test_a_failure_a_wait_cannot_clear_is_reported_at_once(self):
        """A missing image, a denied pull, a missing tool: asking again gets the
        same answer, after a wait that delays the report and changes nothing."""
        for refusal in ("DENIED: requested access to the resource is denied",
                        "MANIFEST_UNKNOWN: manifest unknown",
                        "unexpected status code 401 Unauthorized",
                        "unexpected status code 404 Not Found",
                        "failed to parse the image config: EOF"):
            with self.subTest(refusal=refusal):
                trivy = Trivy((1, "", trivy_said(refusal)), (0, REPORT, ""))
                with self.assertRaises(gate.Unscannable) as caught:
                    trivy.scan()
                self.assertEqual(len(trivy.calls), 1)
                self.assertEqual(trivy.waits, [])
                self.assertIn(refusal, caught.exception.stderr)

    def test_each_retry_waits_twice_the_last_and_the_attempts_are_bounded(self):
        trivy = Trivy(*[(1, "", THROTTLED)] * gate.SCAN_ATTEMPTS)
        with self.assertRaises(gate.Unscannable) as caught:
            trivy.scan()
        self.assertEqual(len(trivy.calls), gate.SCAN_ATTEMPTS)
        base = gate.SCAN_BACKOFF_SECONDS
        self.assertEqual(trivy.waits, [base * 2 ** i for i in range(gate.SCAN_ATTEMPTS - 1)])
        self.assertIn(f"on each of {gate.SCAN_ATTEMPTS} attempts", str(caught.exception))
        self.assertIn("TOOMANYREQUESTS: Rate exceeded", caught.exception.stderr)

    def test_jitter_stretches_a_wait_and_never_shortens_one(self):
        trivy = Trivy((1, "", THROTTLED), (0, REPORT, ""))
        trivy.scan(jitter=1.0)
        self.assertEqual(trivy.waits, [gate.SCAN_BACKOFF_SECONDS * (1 + gate.SCAN_JITTER)])

    def test_a_scan_past_its_timeout_is_reported_with_what_trivy_had_said(self):
        """subprocess hands back what the child wrote as bytes, whatever `text` asked."""
        trivy = Trivy(subprocess.TimeoutExpired(["trivy"], gate.SCAN_TIMEOUT,
                                                stderr=b"pulling layer 3 of 9\n"))
        with self.assertRaises(gate.Unscannable) as caught:
            trivy.scan()
        self.assertIn(f"past the {gate.SCAN_TIMEOUT}s", str(caught.exception))
        self.assertEqual(caught.exception.stderr, "pulling layer 3 of 9")
        self.assertEqual(trivy.timeout, gate.SCAN_TIMEOUT)

    def test_a_run_that_wrote_no_report_is_not_a_clean_one(self):
        for out in ("", "not json", "[]"):
            with self.subTest(stdout=out):
                trivy = Trivy((0, out, "warning: something"))
                with self.assertRaises(gate.Unscannable) as caught:
                    trivy.scan()
                self.assertIn("exited 0", str(caught.exception))


class SayingWhyAnImageWasNotScanned(unittest.TestCase):
    """An image named as unscannable with nothing else sends the reader to rerun
    the scan by hand to learn whether the image is missing, private or throttled.
    What trivy said is the answer, so the report carries it."""

    IMAGES = {"public.ecr.aws/eks/aws-load-balancer-controller:v3.5.0":
              {"aws-load-balancer-controller"},
              "quay.io/argoproj/argocd:v3.1.0": {"argo-cd"}}

    def run_gate(self, call, trivy: Trivy):
        out = io.StringIO()
        with mock.patch.object(gate.subprocess, "run", trivy.run), \
                mock.patch.dict(gate.scan.__kwdefaults__, {"sleep": trivy.waits.append}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            try:
                result = call()
            except SystemExit as exc:
                return exc.code, out.getvalue()
        return result, out.getvalue()

    def test_each_image_that_did_not_scan_is_named_with_trivys_stderr(self):
        denied = trivy_said("DENIED: requested access to the resource is denied")
        trivy = Trivy((1, "", denied), (0, REPORT, ""))
        rc, out = self.run_gate(lambda: gate.scan_all(self.IMAGES), trivy)
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("public.ecr.aws/eks/aws-load-balancer-controller:v3.5.0  "
                      "(via aws-load-balancer-controller)", out)
        self.assertIn("trivy exited 1; trivy's stderr ends:", out)
        self.assertIn("DENIED: requested access to the resource is denied", out)
        self.assertNotIn("quay.io/argoproj/argocd", out)

    def test_every_image_that_scanned_contributes_its_findings(self):
        trivy = Trivy((0, REPORT, ""), (0, REPORT, ""))
        found, _ = self.run_gate(lambda: gate.scan_all(self.IMAGES), trivy)
        self.assertEqual(sorted(f.image for f in found), sorted(self.IMAGES))

    def test_a_canary_that_did_not_scan_says_what_trivy_said(self):
        trivy = Trivy(*[(1, "", THROTTLED)] * gate.SCAN_ATTEMPTS)
        rc, out = self.run_gate(gate.run_canary, trivy)
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("the canary image could not be scanned", out)
        self.assertIn("TOOMANYREQUESTS: Rate exceeded", out)

    def test_silence_on_stderr_is_said_rather_than_left_blank(self):
        lines = gate.Unscannable("trivy exited 1", "").lines("  ")
        self.assertEqual(lines, ["  trivy exited 1; trivy wrote nothing to stderr"])

    def test_only_the_end_of_a_long_stderr_is_quoted(self):
        """trivy writes the error that stopped it last."""
        said = "\n".join(f"line {i}" for i in range(gate.STDERR_LINES + 5))
        lines = gate.Unscannable("trivy exited 1", said).lines("")
        self.assertEqual(len(lines), gate.STDERR_LINES + 1)
        self.assertEqual(lines[-1], f"  line {gate.STDERR_LINES + 4}")


if __name__ == "__main__":
    unittest.main()
