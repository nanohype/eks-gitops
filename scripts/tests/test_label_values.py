"""Unit tests for the label-value gate.

`check_value` decides whether a Kubernetes label value is legal. Its dangerous
direction is returning None (valid) for something the API server will reject —
that ships a manifest which fails at sync, fleet-wide, with every gate green.
"""

import pathlib
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


class WhichLabelsAreChecked(unittest.TestCase):
    """Labels applied to a resource are checked wherever its metadata sits; the
    labels in a Kyverno pattern are matchers over other resources, where `?*` is
    correct, and only the policy's own are checked."""

    def test_every_metadata_labels_map_is_found_with_its_path(self):
        doc = {"metadata": {"labels": {"a": "1"}},
               "spec": {"template": {"metadata": {"labels": {"b": "2"}}}}}
        self.assertEqual(lv.blocks_for(doc),
                         [(".metadata.labels", {"a": "1"}),
                          (".spec.template.metadata.labels", {"b": "2"})])

    def test_a_list_item_carries_its_index(self):
        doc = {"items": [{"metadata": {"name": "x"}}, {"metadata": {"labels": {"a": "1"}}}]}
        self.assertEqual(lv.blocks_for(doc), [(".items[1].metadata.labels", {"a": "1"})])

    def test_a_labels_key_outside_metadata_is_not_a_label_map(self):
        doc = {"spec": {"selector": {"labels": {"a": "?*"}}}}
        self.assertEqual(lv.blocks_for(doc), [])

    def test_a_kyverno_pattern_is_a_matcher(self):
        pattern = {"validate": {"pattern": {"metadata": {"labels": {"env": "?*"}}}}}
        for kind in sorted(lv.KYVERNO_KINDS):
            with self.subTest(kind=kind):
                doc = {"kind": kind, "metadata": {"labels": {"team": "platform"}},
                       "spec": {"rules": [pattern]}}
                self.assertEqual(lv.blocks_for(doc), [(".metadata.labels", {"team": "platform"})])
                doc["metadata"] = {"name": "x"}
                self.assertEqual(lv.blocks_for(doc), [])


class UnconditionalFloor(unittest.TestCase):
    """The half that is a law about any tree, not about this one.

    `outside_self` decides whether a run saw anything the repo actually ships.
    A count floor cannot answer that — it cannot tell a manifest from one of the
    gate's own fixtures — which is why the two floors are separate and why this
    one is tested on its own.
    """

    def test_manifest_paths_count_as_product(self):
        root = lv.REPO
        paths = [root / "addons/security/kyverno/values.yaml",
                 root / "applicationsets/addons-karpenter.yaml"]
        self.assertEqual(lv.outside_self(paths, root), 2)

    def test_the_gates_own_directories_do_not(self):
        root = lv.REPO
        paths = [root / "scripts/check-label-values.py",
                 root / "policies/kyverno/tests/kyverno-test.yaml",
                 root / "applicationsets/rendertest/go.mod"]
        self.assertEqual(lv.outside_self(paths, root), 0)

    def test_a_mixed_set_counts_only_the_product_half(self):
        root = lv.REPO
        paths = [root / "scripts/gatelib.py",
                 root / "addons/security/kyverno/values.yaml"]
        self.assertEqual(lv.outside_self(paths, root), 1)

    def test_a_path_outside_the_repo_is_not_counted(self):
        # Resolving it against the repo raises, and a file the run reached from
        # somewhere else is not evidence this repo was examined.
        self.assertEqual(lv.outside_self([pathlib.Path("/tmp/elsewhere.yaml")], lv.REPO), 0)
