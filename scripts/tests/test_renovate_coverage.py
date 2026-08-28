"""Unit tests for the Renovate coverage gate.

The gate answers "is this chart pin watched by a manager that resolves?". Its
own failure mode is a FALSE POSITIVE — reporting a pin covered when nothing
watches it — because that failure is silent in exactly the way the gate exists
to prevent. These tests therefore concentrate on the negative direction.
"""

import unittest

from gateloader import load

cov = load("check-renovate-coverage")


class SubstringFalsePositive(unittest.TestCase):
    """A chart name must not be matched by a longer chart's pin.

    `loki` is a substring of `loki-distributed`. Both are real charts in this
    ecosystem, and Grafana's OSS charts have already moved repositories once. A
    substring test reports `loki` as covered by a `loki-distributed` pin, so a
    genuinely unwatched pin passes the gate.
    """

    PINNED_LONGER = """
                - appName: x
                  chartRepo: https://example.com
                  chart: loki-distributed
                  chartVersion: "1.2.3"
"""

    def setUp(self):
        self.patterns = cov.load_patterns()
        self.assertTrue(self.patterns, "no customManager regexes loaded — this "
                                       "suite would pass vacuously")

    def test_exact_chart_is_covered(self):
        self.assertTrue(
            cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "1.2.3", self.patterns)
        )

    def test_substring_chart_is_not_covered(self):
        self.assertFalse(
            cov.covered_by_custom(self.PINNED_LONGER, "loki", "1.2.3", self.patterns),
            "'loki' reported as covered by a 'loki-distributed' pin — a chart "
            "nothing watches would pass the gate",
        )

    def test_version_mismatch_is_not_covered(self):
        self.assertFalse(
            cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "9.9.9", self.patterns)
        )


class RE2Rejection(unittest.TestCase):
    """Patterns Renovate cannot run must be rejected, not compiled and trusted.

    Python's `re` accepts lookaround and backreferences; Renovate's RE2 does not.
    A pattern using them compiles here and matches nothing in production, which
    would make the gate itself the vacuous thing.
    """

    def test_unsupported_constructs_are_listed(self):
        probes = [p for p, _ in cov.RE2_UNSUPPORTED]
        for needed in (r"\(\?=", r"\(\?<=", r"\\[1-9]"):
            self.assertIn(needed, probes)


class OciRepoUrlShape(unittest.TestCase):
    """The repoURL/chart redundancy ArgoCD requires, asserted rather than described.

    Exercised through the gate's own comparison. A test that re-implements the
    last-segment split inside itself passes against any gate, including one that
    never runs the check — which is what these looked like before they were
    pointed at check_oci_repourl_shape.
    """

    def _pin(self, repo, chart, matrix):
        return cov.Pin("probe.yaml", "applicationsets/probe.yaml", "", repo, chart,
                       "1.0.0", matrix)

    def _verdict(self, pins):
        """Run the shape check in isolation; return (examined, failures)."""
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        seen = cov.check_oci_repourl_shape(pins)
        return seen, list(cov.failures)

    def test_pin_as_written_is_accepted(self):
        pin = self._pin("oci://ghcr.io/n/eks-agent-platform/charts/operator",
                        "operator", False)
        seen, failures = self._verdict([pin])
        self.assertEqual((seen, failures), (1, []))

    def test_tidied_pin_is_rejected(self):
        # Dropping the "redundant" trailing segment makes ArgoCD request
        # .../charts/manifests/<version>, which is not a package.
        pin = self._pin("oci://ghcr.io/n/eks-agent-platform/charts", "operator", False)
        seen, failures = self._verdict([pin])
        self.assertEqual(seen, 1)
        self.assertTrue(failures, "a repoURL that resolves to no package was accepted")

    def test_a_matrix_pin_is_rejected_the_same_way(self):
        """The blind spot itself: written as a matrix element, checked identically.

        Read from source syntax the assertion matched `repoURL:` beside a literal
        `oci://`, a pair a matrix appset never writes — it templates repoURL from
        the element's chartRepo. This asserts the shape check reaches such a pin,
        so narrowing it back to direct-source pins fails here rather than going
        quiet.
        """
        pin = self._pin("oci://docker.io/envoyproxy", "gateway-helm", True)
        seen, failures = self._verdict([pin])
        self.assertEqual(seen, 1, "a matrix-written OCI pin was not examined at all")
        self.assertTrue(failures, "a matrix-written OCI pin was examined and excused")

    def test_https_pins_are_not_subject_to_the_shape_rule(self):
        # Paired with a sound OCI pin so the anti-vacuity guard is satisfied and
        # the only thing under test is whether the https pin was examined.
        ok = self._pin("oci://example.com/charts/thing", "thing", False)
        https = self._pin("https://charts.example.com", "anything", True)
        self.assertEqual(self._verdict([ok, https]), (1, []))

    def test_an_all_https_catalog_is_reported_as_vacuous(self):
        """Examining nothing is not the same as finding nothing."""
        https = self._pin("https://charts.example.com", "anything", True)
        seen, failures = self._verdict([https])
        self.assertEqual(seen, 0)
        self.assertTrue(any("found no OCI pins" in f for f in failures),
                        f"a run that examined no OCI pin reported success: {failures}")

    def test_every_oci_pin_in_the_catalog_is_examined(self):
        """The count the check reports must be the whole OCI population.

        `if not seen` only catches the population reaching zero, so the number is
        asserted against an independent count of the pins themselves — otherwise
        the corpus can fall from five to two without a word.
        """
        pins = cov.rendered_pins()
        expected = sum(1 for p in pins if p.is_oci)
        self.assertGreater(expected, 0, "no OCI pin derived — this asserts nothing")
        self.assertTrue([p for p in pins if p.is_oci and p.matrix],
                        "no OCI pin is written as a matrix element, so the shape "
                        "this test exists for is absent from the catalog")
        seen, failures = self._verdict(pins)
        self.assertEqual(seen, expected,
                         "the shape check examined fewer OCI pins than the catalog has")
        self.assertEqual(failures, [], f"the shipped catalog should pass: {failures}")


class RenderedPinDerivation(unittest.TestCase):
    """Coordinates are read as ArgoCD renders them, whatever the pin's spelling.

    A matrix appset and a literal source produce Applications that are
    indistinguishable at the cluster, so an assertion about a pin that can only
    read one of the two spellings is narrower than the sentence it prints.
    """

    def setUp(self):
        self.pins = cov.rendered_pins()

    def _isolated(self, fn):
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        fn()
        return list(cov.failures)

    def test_both_spellings_are_present(self):
        self.assertTrue([p for p in self.pins if p.matrix])
        self.assertTrue([p for p in self.pins if not p.matrix])

    def test_no_pin_carries_an_unrendered_template(self):
        for pin in self.pins:
            for field in (pin.repo, pin.chart, pin.version):
                self.assertNotIn("{{", field, f"{pin.rel}: {field!r} is unrendered")

    def test_walk_covers_every_literal_pin_shape(self):
        self.assertEqual(self._isolated(lambda: cov.assert_corpus_floor(self.pins)), [])

    def test_floor_rejects_a_walk_that_lost_pins(self):
        kept = [p for p in self.pins if not p.matrix]
        failures = self._isolated(lambda: cov.assert_corpus_floor(kept))
        self.assertTrue(any("dropped out of the walk" in f for f in failures),
                        f"a walk missing every matrix pin was accepted: {failures}")

    def test_floor_names_the_file_that_lost_a_pin(self):
        """A per-file floor, so slack in one file cannot pay for a drop in another.

        Summed repo-wide, a shape the regex misses anywhere raises the number of
        genuine omissions tolerated everywhere.
        """
        victim = next(p for p in self.pins if p.matrix)
        kept = [p for p in self.pins if p is not victim]
        failures = self._isolated(lambda: cov.assert_corpus_floor(kept))
        self.assertTrue(any(victim.appset in f for f in failures),
                        f"the file that lost a pin was not named: {failures}")


class UnrenderableCoordinates(unittest.TestCase):
    """A coordinate this cannot render is reported, never admitted as a literal.

    Admitted, it reaches the walk disguised as a registry path: not `oci://`, not
    matrix, so it lands in the one branch that asserts nothing — while still
    counting toward the total the summary certifies.
    """

    def _keys(self, src):
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        keys = cov._templated_keys(src, "applicationsets/probe.yaml")
        return keys, list(cov.failures)

    def test_the_supported_form_resolves(self):
        keys, failures = self._keys({"repoURL": "{{ .chartRepo }}"})
        self.assertEqual((keys, failures), ({"repoURL": "chartRepo"}, []))

    def test_an_index_call_is_reported(self):
        keys, failures = self._keys({"repoURL": '{{ index . "chartRepo" }}'})
        self.assertEqual(keys, {})
        self.assertTrue(failures, "an unrenderable template form was accepted")

    def test_a_concatenation_is_reported(self):
        keys, failures = self._keys({"repoURL": "oci://{{ .registry }}/charts"})
        self.assertEqual(keys, {})
        self.assertTrue(failures, "a concatenated repoURL was accepted")

    def test_a_literal_is_not_treated_as_templated(self):
        self.assertEqual(self._keys({"repoURL": "oci://example.com/x"}), ({}, []))


class EveryChartSourceIsRead(unittest.TestCase):
    """A template may carry several chart sources, and all of them reach a cluster.

    No ApplicationSet in this catalog does yet, which is exactly why the case is
    constructed here: read from the real tree, a derivation that stops at the
    first chart source is indistinguishable from one that reads them all, and the
    summary line would certify a corpus quietly missing every source after the
    first.
    """

    TWO = {
        "sources": [
            {"repoURL": "https://charts.example.com", "chart": "alpha",
             "targetRevision": "1.0.0"},
            {"chart": "beta", "repoURL": "oci://registry.example.com/wrongnamespace",
             "targetRevision": "2.0.0"},
            {"repoURL": "https://github.com/x/y", "targetRevision": "main"},
        ]
    }

    def test_both_chart_sources_are_returned(self):
        got = cov._chart_sources(self.TWO, "applicationsets/probe.yaml")
        self.assertEqual([s["chart"] for s in got], ["alpha", "beta"],
                         "a chart source after the first was dropped")

    def test_a_source_without_a_chart_is_not_one(self):
        got = cov._chart_sources(self.TWO, "applicationsets/probe.yaml")
        self.assertTrue(all("chart" in s for s in got))

    def test_the_singular_source_key_is_read(self):
        one = {"source": {"repoURL": "oci://r/x", "chart": "x", "targetRevision": "1"}}
        got = cov._chart_sources(one, "applicationsets/probe.yaml")
        self.assertEqual([s["chart"] for s in got], ["x"])


class VersionsAreNotCoerced(unittest.TestCase):
    """A version YAML parsed as a number is rejected, not stringified.

    `str(1.10)` is `'1.1'`. Coerced, the gate compares a pin against a version
    that appears nowhere in the repo and reports a watched pin as unwatched.
    """

    def _literal(self, value):
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        got = cov._literal("targetRevision", value, "applicationsets/probe.yaml", "x")
        return got, list(cov.failures)

    def test_a_quoted_version_passes_through(self):
        self.assertEqual(self._literal("1.10"), ("1.10", []))

    def test_a_yaml_float_is_rejected(self):
        got, failures = self._literal(1.10)
        self.assertIsNone(got)
        self.assertTrue(failures, "a float version was coerced instead of rejected")

    def test_an_absent_field_is_reported_as_absent(self):
        got, failures = self._literal(None)
        self.assertIsNone(got)
        self.assertTrue(any("has no targetRevision" in f for f in failures),
                        f"an absent field was not named as absent: {failures}")

    def test_present_but_numeric_is_not_reported_as_absent(self):
        _, failures = self._literal(4.2)
        self.assertFalse(any("has no targetRevision" in f for f in failures),
                         "a present field was reported as missing, sending the "
                         "reader to the wrong line")


if __name__ == "__main__":
    unittest.main()
