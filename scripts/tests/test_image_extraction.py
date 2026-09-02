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
        unscannable: list[tuple[str, str]] = []
        return gate.extract_images(rendered, chart, unscannable), unscannable

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
        """Its podSpec sits two levels deeper than every other owner's."""
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

    def test_every_pod_owner_kind_is_walked(self):
        for kind in sorted(gate.POD_OWNERS):
            with self.subTest(kind=kind):
                path = gate.POD_OWNERS[kind]
                spec: dict = {"containers": [{"name": "c", "image": "x:1"}]}
                for key in reversed(path[1:]):
                    spec = {key: spec}
                import yaml
                doc = yaml.safe_dump({"apiVersion": "v1", "kind": kind, "spec": spec})
                found, _ = self.images(doc)
                self.assertEqual(found, {"x:1"})

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

    def test_a_declared_text_only_image_is_not_reported(self):
        declared = next(iter(gate.TEXT_ONLY_IMAGES))
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

    def test_a_render_that_will_not_parse_is_reported_not_dropped(self):
        """A chart silently absent from the inventory is the whole failure mode."""
        found, problems = self.images("kind: Deployment\n  bad: [unclosed\n")
        self.assertEqual(found, set())
        self.assertEqual(len(problems), 1)
        self.assertIn("could not parse", problems[0][1])

    def test_the_helm_value_sentinel_does_not_lose_the_chart(self):
        """Charts emit `- =` inside ConfigMap payloads; PyYAML has no constructor
        for it, and raising there would drop the whole render."""
        rendered = DEPLOYMENT + "\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  a: |\n    - =\n"
        found, problems = self.images(rendered)
        self.assertEqual(found, {"ghcr.io/example/app:1.0.0"})
        self.assertEqual(problems, [])


class EveryChartContributesAnImage(unittest.TestCase):
    """A per-chart floor, because a total cannot see two charts falling out."""

    def coverage(self, images, charts):
        """Every declared imageless chart is rendered unless a case says otherwise,
        so a fixture does not trip the exemption's own rot rule by omission."""
        units = [Unit(c) for c in charts] + [
            Unit(c) for c in gate.IMAGELESS_CHARTS if c not in charts]
        return gate.chart_coverage(images, units)

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
        problems = gate.chart_coverage({"x:1": {"a"}}, [Unit("a")])
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
