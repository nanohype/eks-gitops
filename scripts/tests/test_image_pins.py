"""Unit tests for the image-pin gate's classification and verdict.

The gate renders every chart the catalog pins to learn which images actually
reach a cluster, so it reaches a chart registry and the positive-control sweep
exempts it. What that leaves untested is the rule that decides the outcome:
whether a reference resolves to a moving target.

The rule is where the interesting inputs are. A reference can carry a digest, a
version tag, a mutable tag, a registry port that looks like a tag, or no tag at
all — and the fleet contains one example of some of those and none of others.
These supply all of them.
"""

from __future__ import annotations

import unittest

from gateloader import load

gate = load("check-image-pins")


class ClassifyingAReference(unittest.TestCase):
    """'digest', 'tag' or 'mutable'. Only the third fails the gate."""

    def test_a_digest_is_immutable(self):
        self.assertEqual(
            gate.classify("ghcr.io/opencost/opencost:1.121.1@sha256:" + "5" * 64),
            "digest")

    def test_a_digest_without_a_tag_is_immutable(self):
        self.assertEqual(gate.classify("quay.io/cilium/cilium@sha256:" + "0" * 64),
                         "digest")

    def test_a_version_tag_is_accepted(self):
        for ref in ("quay.io/jetstack/cert-manager-controller:v1.21.1",
                    "memcached:1.6.45-alpine",
                    "docker.io/envoyproxy/ratelimit:1e50889b"):
            with self.subTest(ref=ref):
                self.assertEqual(gate.classify(ref), "tag")

    def test_an_untagged_reference_is_mutable(self):
        """No tag resolves to :latest, which is the defect wearing no clothes."""
        self.assertEqual(gate.classify("ghcr.io/kyverno/readiness-checker"), "mutable")
        self.assertEqual(gate.classify("alpine"), "mutable")

    def test_every_moving_tag_is_mutable(self):
        for tag in sorted(gate.MUTABLE_TAGS):
            with self.subTest(tag=tag):
                self.assertEqual(gate.classify(f"docker.io/library/nginx:{tag}"),
                                 "mutable")

    def test_a_moving_tag_is_recognised_whatever_its_case(self):
        self.assertEqual(gate.classify("docker.io/library/nginx:LATEST"), "mutable")

    def test_a_registry_port_is_not_read_as_a_tag(self):
        """`registry:5000/x/y` carries a colon that is not a tag separator.

        Read as one, an untagged image behind a private registry would be
        classified as pinned — the gate would pass exactly the reference it
        exists to catch.
        """
        self.assertEqual(gate.classify("registry:5000/nanohype/agent"), "mutable")
        self.assertEqual(gate.classify("registry:5000/nanohype/agent:1.2.3"), "tag")

    def test_a_tag_containing_a_moving_word_is_not_itself_moving(self):
        self.assertEqual(gate.classify("docker.io/x/y:v1-stable-2"), "tag")


class TheBareNameAnExemptionMatches(unittest.TestCase):
    """An exemption names the image, not the tag it happened to carry."""

    def test_the_tag_is_dropped(self):
        self.assertEqual(gate.bare_name("docker.io/library/nginx:latest"),
                         "docker.io/library/nginx")

    def test_an_untagged_reference_is_its_own_bare_name(self):
        self.assertEqual(gate.bare_name("ghcr.io/kyverno/readiness-checker"),
                         "ghcr.io/kyverno/readiness-checker")

    def test_a_registry_port_survives(self):
        self.assertEqual(gate.bare_name("registry:5000/nanohype/agent"),
                         "registry:5000/nanohype/agent")


class TheVerdict(unittest.TestCase):
    """Both directions fail: an unpinned image, and an exemption that rotted."""

    def test_an_all_pinned_fleet_has_no_problems(self):
        images = {"quay.io/cilium/cilium@sha256:" + "0" * 64: {"cilium"},
                  "registry.k8s.io/metrics-server/metrics-server:v0.8.1": {"metrics-server"}}
        self.assertEqual(gate.verdict(images, {}), [])

    def test_a_mutable_reference_is_reported_with_the_chart_that_renders_it(self):
        images = {"ghcr.io/kyverno/readiness-checker": {"kyverno"}}
        problems = gate.verdict(images, {})
        self.assertEqual(len(problems), 1)
        self.assertIn("via kyverno", problems[0])
        self.assertIn("moving target", problems[0])

    def test_one_image_rendered_by_several_charts_names_all_of_them(self):
        images = {"docker.io/library/nginx:latest": {"loki", "tempo"}}
        self.assertIn("via loki, tempo", gate.verdict(images, {})[0])

    def test_an_exemption_suppresses_exactly_its_own_image(self):
        images = {"docker.io/library/nginx:latest": {"loki"},
                  "docker.io/library/redis:latest": {"tempo"}}
        problems = gate.verdict(images, {"docker.io/library/nginx": "recorded reason"})
        self.assertEqual(len(problems), 1)
        self.assertIn("redis", problems[0])

    def test_an_exemption_the_fleet_no_longer_renders_mutably_fails(self):
        """An exemption list nobody re-checks only ever widens."""
        images = {"quay.io/cilium/cilium@sha256:" + "0" * 64: {"cilium"}}
        problems = gate.verdict(images, {"docker.io/library/nginx": "recorded reason"})
        self.assertEqual(len(problems), 1)
        self.assertIn("outlived its reason", problems[0])

    def test_an_exemption_for_an_image_now_pinned_by_tag_fails(self):
        """Pinning the image is the fix; leaving the exemption behind is the rot."""
        images = {"docker.io/library/nginx:1.31-alpine": {"loki"}}
        problems = gate.verdict(images, {"docker.io/library/nginx": "recorded reason"})
        self.assertEqual(len(problems), 1)
        self.assertIn("outlived its reason", problems[0])

    def test_the_recorded_reason_is_quoted_back(self):
        problems = gate.verdict({}, {"docker.io/library/nginx": "waiting on chart 2.0"})
        self.assertIn("waiting on chart 2.0", problems[0])


class TheImageExtractor(unittest.TestCase):
    """A regex that stops matching turns a full fleet into a clean one."""

    def refs(self, text):
        return [m.group(1) for m in gate.IMAGE.finditer(text)]

    def test_a_plain_image_line_matches(self):
        self.assertEqual(self.refs("        image: nginx:1.27\n"), ["nginx:1.27"])

    def test_a_quoted_image_line_matches_without_the_quotes(self):
        self.assertEqual(self.refs('  image: "nginx:1.27"\n'), ["nginx:1.27"])

    def test_a_key_merely_ending_in_image_does_not_match(self):
        for line in ("  initImage: nginx:1.27\n", "  image_pull_policy: Always\n"):
            with self.subTest(line=line.strip()):
                self.assertEqual(self.refs(line), [])

    def test_every_image_in_a_multi_document_render_is_found(self):
        text = ("kind: Deployment\n  image: a:1\n---\n"
                "kind: DaemonSet\n  image: b:2\n")
        self.assertEqual(self.refs(text), ["a:1", "b:2"])


class TheShippedExemptionList(unittest.TestCase):
    """An empty allowlist grants nothing, and that is the state to hold."""

    def test_every_entry_carries_a_recorded_reason(self):
        for bare, reason in gate.ALLOWED_MUTABLE.items():
            with self.subTest(image=bare):
                self.assertTrue(reason.strip(),
                                f"{bare} is exempted with no reason recorded, so "
                                f"nothing states what would let it be removed")


if __name__ == "__main__":
    unittest.main()
