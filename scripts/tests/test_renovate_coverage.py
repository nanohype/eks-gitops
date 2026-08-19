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


if __name__ == "__main__":
    unittest.main()
