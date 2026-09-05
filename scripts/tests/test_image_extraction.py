"""Unit tests for how the fleet's image population is derived from a render.

Both gates that ask anything about images read this one inventory, so an
extractor that misses a spelling removes those images from every question at
once — and the count that remains stays large enough to look healthy. That
happened: the pattern was anchored on `image:` preceded only by whitespace, the
ordinary list-item form `- image: <ref>` never matched, and two charts'
entire workloads were absent from a scan reporting fifty-five images.

So the walk is structural and the pattern is kept under it as an independent
floor. A parser and a regex fail on different inputs; each is planted against
here, and so is the per-chart floor that catches a chart contributing nothing.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import re
import sys
import tempfile
import unittest

from gateloader import load

gate = load("check-image-pins")


class Unit:
    """The fields chart_coverage reads off a render unit."""

    def __init__(self, chart: str):
        self.chart = chart


def render(*docs: str) -> str:
    return "\n---\n".join(docs)


DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/example/app:1.0.0
"""


class ExtractingFromARender(unittest.TestCase):
    def images(self, rendered, chart="c"):
        """(population, references the classifier could not place).

        The two out-parameters are separate because they are separate verdicts:
        a render that will not parse leaves the fleet unknown, a reference that
        will not classify is a question this gate owes an answer to. Every case
        below that asserts `problems == []` is also asserting the render parsed,
        so the two are checked apart.
        """
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        found = gate.extract_images(rendered, chart, unrendered, unclassified)
        self.assertEqual(unrendered, [], "the fixture render did not parse")
        return found, unclassified

    def both(self, rendered, chart="c"):
        """(population, not-rendered, not-placed), for the cases that plant one."""
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        found = gate.extract_images(rendered, chart, unrendered, unclassified)
        return found, unrendered, unclassified

    def test_the_list_item_spelling_is_found(self):
        """The shape the pattern never matched, and the whole defect.

        `- image:` under a `containers:` list is the ordinary Kubernetes form.
        Anchored on whitespace-then-`image:`, a pattern sees nothing here.
        """
        found, problems = self.images(DEPLOYMENT)
        self.assertEqual(found, {"ghcr.io/example/app:1.0.0"})
        self.assertEqual(problems, [])

    def test_every_container_list_is_walked(self):
        rendered = """
apiVersion: apps/v1
kind: DaemonSet
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: init:1
      containers:
        - name: main
          image: main:2
      ephemeralContainers:
        - name: debug
          image: debug:3
"""
        found, _ = self.images(rendered)
        self.assertEqual(found, {"init:1", "main:2", "debug:3"})

    def test_a_cronjob_pod_template_is_reached(self):
        """Nesting depth is not a case the walk has to know about."""
        rendered = """
apiVersion: batch/v1
kind: CronJob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: rotate
              image: aws-cli:2
"""
        found, _ = self.images(rendered)
        self.assertEqual(found, {"aws-cli:2"})

    def test_an_image_key_outside_a_pod_template_is_found(self):
        """A custom resource can name an image its operator then runs."""
        rendered = """
apiVersion: agents.nanohype.dev/v1alpha1
kind: AgentFleet
spec:
  agents:
    - name: a
      image: ghcr.io/example/runner:0.1.0
"""
        found, _ = self.images(rendered)
        self.assertEqual(found, {"ghcr.io/example/runner:0.1.0"})

    def test_an_image_only_the_text_scan_finds_is_reported(self):
        """The extraction-drift assertion: a structural walk that stopped seeing
        a shape looks identical to a controller reading a string payload, so the
        second must be declared and the first is reported."""
        rendered = """
apiVersion: v1
kind: ConfigMap
data:
  envoy-gateway.yaml: |
    rateLimitDeployment:
      container:
        image: docker.io/example/undeclared:1.0
"""
        found, problems = self.images(rendered)
        self.assertIn("docker.io/example/undeclared:1.0", found)
        self.assertEqual(len(problems), 1)
        self.assertIn("stopped seeing a shape", problems[0][1])

    def test_a_declared_controller_image_is_not_reported(self):
        """A controller is handed the reference and creates the pod later, so no
        pod template in this render declares it."""
        declared = next(iter(gate.CONTROLLER_IMAGES))
        rendered = f"""
apiVersion: v1
kind: ConfigMap
data:
  cfg: |
    image: {declared}:abc123
"""
        found, problems = self.images(rendered)
        self.assertIn(f"{declared}:abc123", found)
        self.assertEqual(problems, [])

    def test_an_image_in_a_controller_flag_is_a_candidate(self):
        """The shape neither the key walk nor the line-anchored pattern can see.

        A controller handed `--worker-image=<ref>` creates the pod later; the
        reference is an argument, not a key, and it is not at line start.
        """
        rendered = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: ghcr.io/example/app:1.0.0
          args: ["--worker-image=ghcr.io/example/undeclared-worker:2.0"]
"""
        found, problems = self.images(rendered)
        self.assertEqual(len(problems), 1)
        self.assertIn("ghcr.io/example/undeclared-worker:2.0", problems[0][1])
        self.assertIn("a controller is handed it", problems[0][1])

    def test_a_single_segment_official_image_is_a_candidate(self):
        """`nats:2.10.10` is the whole reference — no registry, no organisation.

        The argo-events event-bus controller declares exactly this beside the two
        natsio/* sidecars it starts in the same StatefulSet, so requiring a path
        separator scanned the helpers and left the main container silent.
        """
        rendered = """
apiVersion: v1
kind: ConfigMap
data:
  controller-config.yaml: |
    nats:
      versions:
        - natsImage: nats:2.10.10
        - natsImage: undeclared-single-segment:9.9.9
"""
        found, problems = self.images(rendered)
        # `nats` is declared in CONTROLLER_IMAGES, so it enters the population.
        self.assertIn("nats:2.10.10", found)
        # An undeclared one is reported rather than silently absent.
        self.assertEqual(len(problems), 1)
        self.assertIn("undeclared-single-segment:9.9.9", problems[0][1])

    def test_an_rbac_name_is_not_an_image(self):
        """`kyverno:admission-controller` has the shape and is a role name; the
        tag is the discriminator."""
        rendered = ("apiVersion: v1\nkind: ConfigMap\ndata:\n"
                    "  x: |\n    role: kyverno:admission-controller\n"
                    "    other: system:auth-delegator\n")
        found, problems = self.images(rendered)
        self.assertEqual(problems, [])

    def test_a_hostname_does_not_yield_its_last_label(self):
        """Without an anchor the alternative starts after a dot and
        `vault.example.com:8200` yields `com:8200`."""
        rendered = ("apiVersion: v1\nkind: ConfigMap\ndata:\n"
                    "  x: |\n    server: vault.example.com:8200\n")
        found, problems = self.images(rendered)
        self.assertEqual(problems, [])

    def test_a_host_and_port_is_not_an_image(self):
        """A rendered config is full of addresses; a grammar admitting them
        cannot be read, and every one would demand a declaration."""
        rendered = """
apiVersion: v1
kind: ConfigMap
data:
  cfg: |
    endpoint: loki.monitoring.svc.cluster.local:3100
    bind: 127.0.0.1:8080
"""
        found, problems = self.images(rendered)
        self.assertEqual(problems, [])

    def test_a_render_that_will_not_parse_is_reported_not_dropped(self):
        """A chart silently absent from the inventory is the whole failure mode."""
        found, unrendered, unclassified = self.both("kind: Deployment\n  bad: [unclosed\n")
        self.assertEqual(found, set())
        self.assertEqual(len(unrendered), 1)
        self.assertIn("could not parse", unrendered[0][1])
        self.assertEqual(unclassified, [],
                         "a render that did not parse cannot also have produced a "
                         "reference the classifier could not place")

    def test_the_helm_value_sentinel_does_not_lose_the_chart(self):
        """Charts emit `- =` inside ConfigMap payloads; PyYAML has no constructor
        for it, and raising there would drop the whole render."""
        rendered = DEPLOYMENT + "\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  a: |\n    - =\n"
        found, problems = self.images(rendered)
        self.assertEqual(found, {"ghcr.io/example/app:1.0.0"})
        self.assertEqual(problems, [])


class EveryChartContributesAnImage(unittest.TestCase):
    """A per-chart floor, because a total cannot see two charts falling out."""

    def coverage(self, images, charts, seen=None):
        """Every declared imageless chart is rendered, and every declared image
        is seen, unless a case says otherwise — so a fixture does not trip a rot
        rule it is not about.
        """
        units = [Unit(c) for c in charts] + [
            Unit(c) for c in gate.IMAGELESS_CHARTS if c not in charts]
        if seen is None:
            seen = set(gate.CONTROLLER_IMAGES) | set(gate.NOT_A_CONTAINER)
        return gate.chart_coverage(images, units, seen)

    def test_declaration_rot_reaches_the_verdict(self):
        """chart_coverage is where the rot rule is consulted, so gutting the call
        must fail here and not only where the rule itself is tested."""
        problems = self.coverage({"x:1": {"a"}}, ["a"], seen=set())
        self.assertTrue(any("outlived its image" in p for p in problems))

    def test_a_chart_contributing_nothing_is_reported(self):
        problems = self.coverage({"x:1": {"a"}}, ["a", "b"])
        self.assertEqual(len(problems), 1)
        self.assertIn("b rendered and contributed no image", problems[0])

    def test_every_chart_contributing_passes(self):
        self.assertEqual(
            self.coverage({"x:1": {"a"}, "y:2": {"b"}}, ["a", "b"]), [])

    def test_a_declared_imageless_chart_is_not_reported(self):
        declared = next(iter(gate.IMAGELESS_CHARTS))
        self.assertEqual(self.coverage({"x:1": {"a"}}, ["a", declared]), [])

    def test_a_declared_chart_the_fleet_stopped_rendering_is_reported(self):
        """The exemption is where a per-chart floor rots: an entry excusing a
        chart nobody pins excuses nothing and reads as considered."""
        seen = set(gate.CONTROLLER_IMAGES) | set(gate.NOT_A_CONTAINER)
        problems = gate.chart_coverage({"x:1": {"a"}}, [Unit("a")], seen)
        self.assertEqual(len(problems), len(gate.IMAGELESS_CHARTS))
        self.assertIn("outlived its chart", problems[0])

    def test_a_declared_chart_that_starts_shipping_a_workload_is_reported(self):
        declared = next(iter(gate.IMAGELESS_CHARTS))
        problems = self.coverage({"x:1": {declared}}, [declared])
        self.assertTrue(any("now contributes an image" in p for p in problems))

    def test_an_empty_inventory_reports_every_chart(self):
        """The vacuous case: no images at all is not a fleet with no images."""
        problems = self.coverage({}, ["a", "b"])
        self.assertEqual(len(problems), 2)


if __name__ == "__main__":
    unittest.main()


class DeclarationsMatchTheRender(unittest.TestCase):
    """Both declaration tables say something about images this catalog renders.

    An entry for one it does not is an excuse for nothing, and an exemption list
    nobody re-reads only ever widens. This is the reverse direction the
    controller-image comment claims and did not have.
    """

    def test_a_controller_image_the_render_dropped_is_reported(self):
        declared = next(iter(gate.CONTROLLER_IMAGES))
        problems = gate.declaration_rot(
            (set(gate.CONTROLLER_IMAGES) | set(gate.NOT_A_CONTAINER)) - {declared})
        self.assertEqual(len(problems), 1)
        self.assertIn(declared, problems[0])
        self.assertIn("outlived its image", problems[0])

    def test_a_non_container_declaration_the_render_dropped_is_reported(self):
        declared = next(iter(gate.NOT_A_CONTAINER))
        problems = gate.declaration_rot(
            (set(gate.CONTROLLER_IMAGES) | set(gate.NOT_A_CONTAINER)) - {declared})
        self.assertEqual(len(problems), 1)
        self.assertIn(declared, problems[0])

    def test_every_declaration_matched_passes(self):
        self.assertEqual(
            gate.declaration_rot(set(gate.CONTROLLER_IMAGES) | set(gate.NOT_A_CONTAINER)),
            [])

    def test_an_empty_render_reports_every_declaration(self):
        problems = gate.declaration_rot(set())
        self.assertEqual(len(problems),
                         len(gate.CONTROLLER_IMAGES) + len(gate.NOT_A_CONTAINER))


DIGEST = "sha256:" + "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"


class ADigestPinnedReferenceIsInThePopulation(unittest.TestCase):
    """`<repo>@sha256:<hex>` is a reference this gate recommends and could not read.

    The pattern under the structural walk had two alternatives and both required
    a tag, so a digest-pinned reference in a controller flag or a config value
    yielded nothing but its `sha256:<hex>` tail — a single-segment shape whose
    bare name is `sha256`, and an entry by that name passed over it. The gate's
    own remediation tells an operator to pin to a digest, so the one spelling it
    recommends was the one its completeness floor could not see.
    """

    def candidates(self, s: str) -> list[str]:
        return [c for groups in gate.IMAGE_REF.findall(s) for c in groups if c]

    def test_a_digest_only_reference_is_matched_whole(self):
        self.assertEqual(self.candidates(f"ghcr.io/example/thing@{DIGEST}"),
                         [f"ghcr.io/example/thing@{DIGEST}"])

    def test_a_tag_and_digest_reference_is_matched_whole(self):
        """Not as its `repo:tag` head: what a container runs is the digest, and
        the head alone reaches the classifier as a tag."""
        ref = f"ghcr.io/example/thing:1.2.3@{DIGEST}"
        self.assertEqual(self.candidates(ref), [ref])
        self.assertEqual(gate.classify(ref), "digest")

    def test_a_single_segment_official_image_carries_a_digest(self):
        """`nats@sha256:...` — no registry, no organisation, and the shape the
        event-bus controller declares."""
        self.assertEqual(self.candidates(f"nats@{DIGEST}"), [f"nats@{DIGEST}"])

    def test_the_bare_name_drops_both_tag_and_digest(self):
        for ref in (f"ghcr.io/example/thing@{DIGEST}",
                    f"ghcr.io/example/thing:1.2.3@{DIGEST}",
                    "ghcr.io/example/thing:1.2.3"):
            with self.subTest(ref=ref):
                self.assertEqual(gate.bare_name(ref), "ghcr.io/example/thing")

    def test_a_digest_with_no_repository_before_it_is_not_a_reference(self):
        """A `digest:` field carries one, and it names no image.

        Excluded by shape, not by a declaration, because the two rules this
        repository already has cannot both hold over it. A NOT_A_CONTAINER entry
        excuses whatever carries its bare name, so an entry for `sha256` would
        excuse every reference whose only matched token is a digest — and
        `declaration_rot` deletes an entry the render does not support, which is
        every tree that happens not to carry a bare digest that day. One rule
        demands the entry and the other deletes it.

        There is nothing lost: a digest that belongs to a repository is matched
        with that repository, whole, by the alternative above.
        """
        self.assertEqual(self.candidates(DIGEST), [])
        self.assertNotIn("sha256", gate.NOT_A_CONTAINER,
                         "a declaration matching nothing in the render is an "
                         "exemption that only ever widens")

    def test_a_repository_digest_is_unaffected_by_that_exclusion(self):
        """The exclusion is anchored at the start of a token, so it removes the
        bare form and nothing else."""
        for ref in (f"ghcr.io/example/app@{DIGEST}",
                    f"ghcr.io/example/app:1.0.0@{DIGEST}"):
            with self.subTest(ref=ref):
                self.assertEqual(self.candidates(ref), [ref])

    def test_a_digest_in_a_rendered_field_contributes_nothing(self):
        """End to end: a `digest:` value is not an unplaceable reference, so it
        does not put a gate that reads this population into a refusal."""
        rendered = f"""
apiVersion: v1
kind: ConfigMap
data:
  provenance.yaml: |
    chart: example
    digest: {DIGEST}
"""
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        found = gate.extract_images(rendered, "c", unrendered, unclassified)
        self.assertEqual((found, unrendered, unclassified), (set(), [], []))

    def test_a_digest_shaped_string_that_is_not_a_digest_is_not_matched(self):
        """64 lowercase hex, because the suffix is the only discriminator the
        digest alternative has — it drops the path separator and the tag rules
        the others need."""
        for s in (f"ghcr.io/example/thing@sha256:{'a' * 63}",
                  "ghcr.io/example/thing@sha256:not-a-digest",
                  f"ghcr.io/example/thing@sha512:{'a' * 64}"):
            with self.subTest(s=s):
                self.assertNotIn(f"ghcr.io/example/thing@{s.split('@')[1]}",
                                 self.candidates(s))

    def test_a_digest_pinned_controller_reference_is_reported_when_undeclared(self):
        """The finding, end to end. A controller is handed a digest-pinned
        reference; no pod template declares it, no list names it, and before the
        digest alternative the whole string produced nothing to report."""
        rendered = f"""
apiVersion: v1
kind: ConfigMap
data:
  controller.yaml: |
    workerImage: ghcr.io/example/undeclared-worker@{DIGEST}
"""
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        gate.extract_images(rendered, "c", unrendered, unclassified)
        self.assertEqual(unrendered, [])
        self.assertEqual(len(unclassified), 1)
        self.assertIn(f"ghcr.io/example/undeclared-worker@{DIGEST}", unclassified[0][1])

    def test_a_digest_pinned_declared_controller_reference_is_in_the_population(self):
        declared = next(iter(gate.CONTROLLER_IMAGES))
        rendered = f"""
apiVersion: v1
kind: ConfigMap
data:
  controller.yaml: |
    image: {declared}@{DIGEST}
"""
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        found = gate.extract_images(rendered, "c", unrendered, unclassified)
        self.assertEqual((unrendered, unclassified), ([], []))
        self.assertIn(f"{declared}@{DIGEST}", found)
        self.assertEqual(gate.classify(f"{declared}@{DIGEST}"), "digest")

    def test_a_digest_pinned_container_is_read_by_the_structural_walk(self):
        rendered = f"""
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/example/app@{DIGEST}
"""
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        found = gate.extract_images(rendered, "c", unrendered, unclassified)
        self.assertEqual(found, {f"ghcr.io/example/app@{DIGEST}"})
        self.assertEqual((unrendered, unclassified), ([], []))

    def test_every_form_the_remediation_recommends_is_one_this_reads(self):
        """The sentence and the pattern, checked against each other.

        Read out of the gate's own remediation string rather than retyped here,
        so rewording the advice to name a spelling the pattern does not read
        fails — which is the defect this closes, one revision later.
        """
        recommended = re.findall(r"`([^`]+)`", gate.MUTABLE_REMEDIATION)
        self.assertTrue(recommended,
                        f"the remediation names no reference form: "
                        f"{gate.MUTABLE_REMEDIATION}")
        for form in recommended:
            with self.subTest(form=form):
                concrete = (form.replace("<repo>", "ghcr.io/example/app")
                                .replace("<hex>", DIGEST.split(":", 1)[1]))
                self.assertEqual(self.candidates(concrete), [concrete],
                                 f"the remediation recommends {form}, which the "
                                 f"pattern under the structural walk does not read")


class WhatCannotBeReadReachesAVerdict(unittest.TestCase):
    """Neither silence, and not the same verdict.

    A chart that did not render leaves the fleet's image set unknown; a
    reference the classifier cannot place is a chart that rendered and a
    question this gate owes an answer to. Held in one list, the second printed
    under the first's heading and reached no verdict at all — the run exited 0,
    and CI blocked only because a sibling gate read the same list as a refusal.
    """

    IMAGES = {"ghcr.io/example/app:1.0.0": {"c"}}
    MUTABLE = {"ghcr.io/example/app:latest": {"c"}}

    def verdict(self, images, unrendered=(), unclassified=()):
        """main() over a planted inventory.

        chart_coverage and ALLOWED_MUTABLE are neutralised because both assert
        against the real fleet: a fixture of two images would trip every
        per-chart floor and every exemption-rot check, and the case would then
        pass for a reason it did not plant. Each has its own tests elsewhere in
        this file.
        """
        saved = (gate.inventory, gate.chart_coverage, dict(gate.ALLOWED_MUTABLE),
                 sys.argv)
        gate.inventory = lambda env, seen=None: (images, list(unrendered),
                                                 list(unclassified))
        gate.chart_coverage = lambda *a, **k: []
        gate.ALLOWED_MUTABLE.clear()
        sys.argv = ["check-image-pins.py"]
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = gate.main()
        finally:
            gate.inventory, gate.chart_coverage, argv = saved[0], saved[1], saved[3]
            gate.ALLOWED_MUTABLE.update(saved[2])
            sys.argv = argv
        return rc, out.getvalue()

    def test_a_clean_fleet_passes(self):
        """The control: without it every case below could be failing for a
        reason the case did not introduce."""
        rc, out = self.verdict(self.IMAGES)
        self.assertEqual(rc, 0, out)

    def test_a_reference_that_cannot_be_placed_fails(self):
        rc, out = self.verdict(self.IMAGES, unclassified=[
            ("c", "ghcr.io/example/mystery:1.0 is image-shaped and reaches no pod "
                  "template or `image:` key.")])
        self.assertEqual(rc, 1)
        self.assertIn("ghcr.io/example/mystery:1.0", out)

    def test_a_reference_that_cannot_be_placed_is_not_a_scope_caveat(self):
        """It is printed as a problem, not under a heading about charts that did
        not render — the chart rendered."""
        _, out = self.verdict(self.IMAGES, unclassified=[("c", "mystery")])
        self.assertNotIn("could not be rendered", out)
        self.assertIn("image-pin problem", out)

    def test_a_chart_that_did_not_render_cannot_report_a_clean_fleet(self):
        """Every image that DID render is immutable, and that is a result over
        part of the fleet rather than over the fleet."""
        rc, out = self.verdict(self.IMAGES, unrendered=[("addons/x", "helm failed")])
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("Cannot run", out)
        self.assertIn("addons/x", out)

    def test_a_chart_that_did_not_render_is_named_alongside_a_real_failure(self):
        """The failure is the verdict, and the unrendered chart still bounds what
        the verdict covers — dropping either one loses something a reader needs."""
        rc, out = self.verdict(self.MUTABLE, unrendered=[("addons/x", "helm failed")])
        self.assertEqual(rc, 1)
        self.assertIn("addons/x", out)
        self.assertIn("subset of the fleet", out)
        self.assertIn("moving target", out)

    def test_an_empty_population_cannot_run(self):
        rc, out = self.verdict({}, unrendered=[("addons/x", "helm failed")])
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("rendered no images at all", out)


class WhatHelmReportsPulling(unittest.TestCase):
    """An OCI registry serves charts and container images through one grammar.

    `public.ecr.aws/karpenter/karpenter:1.14.0` is indistinguishable from an
    image by shape, and it is the chart — the container beside it is
    `public.ecr.aws/karpenter/controller`. Nothing in the reference says which,
    and no walk over the render can, because a chart coordinate reaches no pod
    template by construction.

    helm answers it, about this run: it prints what it fetched as a chart. That
    is an observation rather than a name somebody wrote down, which matters
    because a declaration here could not survive. `declaration_rot` removes an
    entry the render does not support, and the render carries these only under
    the helm builds that print the report to stdout — so one rule would demand
    the entry and the other remove it.
    """

    REPORT = ("Pulled: public.ecr.aws/karpenter/karpenter:1.14.0\n"
              "Digest: sha256:" + "4c1e" + "a" * 60 + "\n")

    def test_the_report_names_the_artifact(self):
        self.assertEqual(gate.chart_artifacts(self.REPORT),
                         {"public.ecr.aws/karpenter/karpenter:1.14.0"})

    def test_a_render_with_no_report_names_nothing(self):
        self.assertEqual(gate.chart_artifacts(DEPLOYMENT), set())

    def test_the_digest_line_is_not_an_artifact(self):
        """It names the artifact above it, not another one."""
        self.assertNotIn("sha256:" + "4c1e" + "a" * 60,
                         gate.chart_artifacts(self.REPORT))

    def test_a_pulled_chart_is_not_an_unplaceable_reference(self):
        """The whole finding, end to end. The report leads the manifests, so on
        the helm builds that print it to stdout every OCI-sourced chart puts its
        own coordinates into the stream this parses."""
        rendered = self.REPORT + DEPLOYMENT
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        found = gate.extract_images(rendered, "karpenter", unrendered, unclassified,
                                    None, gate.chart_artifacts(rendered))
        self.assertEqual((unrendered, unclassified), ([], []))
        self.assertEqual(found, {"ghcr.io/example/app:1.0.0"})

    def test_without_the_report_the_same_stream_is_unplaceable(self):
        """The control on the case above: it passes because the report was read,
        not because the reference stopped being image-shaped."""
        rendered = self.REPORT + DEPLOYMENT
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        gate.extract_images(rendered, "karpenter", unrendered, unclassified)
        self.assertEqual(len(unclassified), 1)
        self.assertIn("public.ecr.aws/karpenter/karpenter:1.14.0", unclassified[0][1])

    def test_a_container_sharing_the_repository_path_is_not_passed_over(self):
        """Compared whole, not on the bare name.

        A registry can serve a chart and an image from one path, and passing
        over every reference sharing a pulled chart's name would take the image
        with it — the one direction this gate must never fail in.
        """
        rendered = ("Pulled: ghcr.io/example/thing:1.0.0\n"
                    "Digest: sha256:" + "b" * 64 + "\n"
                    "apiVersion: v1\nkind: ConfigMap\ndata:\n"
                    "  cfg: |\n    image: ghcr.io/example/thing:9.9.9\n")
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        gate.extract_images(rendered, "thing", unrendered, unclassified,
                            None, gate.chart_artifacts(rendered))
        self.assertEqual(len(unclassified), 1)
        self.assertIn("ghcr.io/example/thing:9.9.9", unclassified[0][1])

    def test_the_same_artifact_carrying_a_digest_is_recognised(self):
        """`<ref>@sha256:<hex>` and `<ref>` are one artifact; the report names
        the second and the render can carry either."""
        ref = "ghcr.io/example/chart:1.0.0"
        rendered = (f"Pulled: {ref}\n"
                    "apiVersion: v1\nkind: ConfigMap\ndata:\n"
                    f"  cfg: |\n    chart: {ref}@sha256:{'c' * 64}\n")
        unrendered: list[tuple[str, str]] = []
        unclassified: list[tuple[str, str]] = []
        gate.extract_images(rendered, "chart", unrendered, unclassified,
                            None, gate.chart_artifacts(rendered))
        self.assertEqual(unclassified, [])

    def test_a_pulled_artifact_still_reaches_the_declaration_record(self):
        """`seen` is what the render CONTAINED, so declaration_rot keeps reading
        the same corpus whether or not a reference was passed over."""
        rendered = self.REPORT + DEPLOYMENT
        seen: set[str] = set()
        gate.extract_images(rendered, "karpenter", [], [], seen,
                            gate.chart_artifacts(rendered))
        self.assertIn("public.ecr.aws/karpenter/karpenter", seen)


class TheReportIsReadFromEitherStream(unittest.TestCase):
    """Which stream carries it is a property of the helm build, not of this repo.

    Some helm builds write the OCI pull report to stdout, where it lands in the
    manifest stream this gate parses; some write it to stderr, where nothing sees
    it. Reading one only makes the gate's answer depend on which helm ran it —
    green on the machine that renders, red in the job that installs a different
    build, with the same tree.

    So `inventory` is exercised here against both stream shapes, with helm itself
    stubbed: the tool is the external input, and what varies is the input.
    """

    REPORT = ("Pulled: public.ecr.aws/karpenter/karpenter:1.14.0\n"
              "Digest: sha256:" + "4c1e" + "a" * 60 + "\n")

    class Unit:
        chart = "karpenter"
        path = "addons/operations/karpenter"
        repo = "https://example.com"
        version = "1.14.0"
        namespace = "kube-system"
        params: tuple = ()
        is_oci = True

        def oci_ref(self):
            return "oci://public.ecr.aws/karpenter/karpenter"

    def inventory_with(self, stdout, stderr):
        """inventory() over one unit whose helm run produced these two streams."""
        root = pathlib.Path(tempfile.mkdtemp())
        (root / self.Unit.path).mkdir(parents=True)

        class Completed:
            returncode = 0

            def __init__(self, out, err):
                self.stdout, self.stderr = out, err

        saved = (gate.ROOT, gate.render_addons.discover, gate.render_addons.add_repos,
                 gate.subprocess.run, gate.gatelib.require)
        gate.ROOT = root
        gate.render_addons.discover = lambda *a, **k: [self.Unit()]
        gate.render_addons.add_repos = lambda *a, **k: {}
        gate.subprocess.run = lambda *a, **k: Completed(stdout, stderr)
        gate.gatelib.require = lambda *a, **k: None
        try:
            return gate.inventory("production")
        finally:
            (gate.ROOT, gate.render_addons.discover, gate.render_addons.add_repos,
             gate.subprocess.run, gate.gatelib.require) = saved

    def test_a_report_on_stdout_is_read(self):
        """The shape that fails: the report is in the manifest stream, so the
        chart's own coordinates are a reference the classifier must place."""
        _, unrendered, unclassified = self.inventory_with(self.REPORT + DEPLOYMENT, "")
        self.assertEqual((unrendered, unclassified), ([], []))

    # A chart carrying its own OCI coordinate in its rendered content. Whether
    # the pull report reaches the gate then decides the verdict on the SAME
    # render, which is what makes the stream choice observable at all.
    SELF_REFERENCING = ("apiVersion: v1\nkind: ConfigMap\ndata:\n"
                        "  cfg: |\n"
                        "    chart: public.ecr.aws/karpenter/karpenter:1.14.0\n")

    def test_a_report_on_stderr_is_read(self):
        """The render carries the coordinate and the report does not, so a gate
        reading stdout alone has no evidence and reports the chart's own
        reference as one it cannot place."""
        _, unrendered, unclassified = self.inventory_with(
            DEPLOYMENT + "---\n" + self.SELF_REFERENCING, self.REPORT)
        self.assertEqual((unrendered, unclassified), ([], []))

    def test_both_stream_shapes_produce_the_same_verdict(self):
        """The property, stated directly: one tree, two helm builds, one answer."""
        body = DEPLOYMENT + "---\n" + self.SELF_REFERENCING
        on_out = self.inventory_with(self.REPORT + body, "")
        on_err = self.inventory_with(body, self.REPORT)
        self.assertEqual(on_out[0], on_err[0])
        self.assertEqual((on_out[1], on_out[2]), (on_err[1], on_err[2]))
        self.assertEqual(on_err[2], [])

    def test_no_report_at_all_leaves_the_render_unchanged(self):
        images, unrendered, unclassified = self.inventory_with(DEPLOYMENT, "")
        self.assertEqual((unrendered, unclassified), ([], []))
        self.assertEqual(images, {"ghcr.io/example/app:1.0.0": {"karpenter"}})
