"""Unit tests for the label-value gate.

`check_value` decides whether a Kubernetes label value is legal. Its dangerous
direction is returning None (valid) for something the API server will reject —
that ships a manifest which fails at sync, fleet-wide, with every gate green.
"""

import unittest

from gateloader import load

lv = load("check-label-values")


class Accepts(unittest.TestCase):
    def test_plain(self):
        self.assertIsNone(lv.check_value("platform-engineering"))

    def test_dots_underscores_dashes(self):
        self.assertIsNone(lv.check_value("nanohype.eks-gitops_v1"))

    def test_empty_is_legal(self):
        # "" is a valid label value per the API server grammar.
        self.assertIsNone(lv.check_value(""))

    def test_non_string_passes(self):
        # YAML yields bool/int for unquoted true/8080; their serialized forms are
        # always legal, so the gate must not reject them.
        for raw in (True, False, 8080, None):
            self.assertIsNone(lv.check_value(raw), f"rejected {raw!r}")

    def test_pure_template_deferred(self):
        # Resolves at render time; the gate cannot judge it and must not guess.
        self.assertIsNone(lv.check_value("{{ .metadata.labels.environment }}"))

    def test_exactly_max_len(self):
        self.assertIsNone(lv.check_value("a" * lv.MAX_LEN))


class Rejects(unittest.TestCase):
    def test_over_max_len(self):
        self.assertIsNotNone(lv.check_value("a" * (lv.MAX_LEN + 1)))

    def test_leading_dash(self):
        self.assertIsNotNone(lv.check_value("-leading"))

    def test_trailing_dot(self):
        self.assertIsNotNone(lv.check_value("trailing."))

    def test_illegal_characters(self):
        for bad in ("has space", "slash/value", "colon:value", "at@value"):
            self.assertIsNotNone(lv.check_value(bad), f"accepted {bad!r}")

    def test_template_plus_illegal_literal(self):
        # The template elides; the literal remainder must still be judged.
        self.assertIsNotNone(lv.check_value("{{ .x }}/nope"))

    def test_template_plus_overlong_literal(self):
        self.assertIsNotNone(lv.check_value("{{ .x }}" + "a" * (lv.MAX_LEN + 1)))


if __name__ == "__main__":
    unittest.main()
