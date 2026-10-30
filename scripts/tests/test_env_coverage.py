"""Unit tests for the environment-coverage gate, scripts/check-env-coverage.py.

An ApplicationSet's cluster selector decides which environments an addon lands
on, and its values files decide which it can render for. The same missing
`values-<env>.yaml` is correct for an addon whose appset excludes that
environment and fatal for one whose appset does not, and render-addons reads both
as "not deployed here". So what decides this gate's verdict is the reach it
derives from a selector. These hold that derivation on each selector shape, and
the verdict over an appset tree built for each case.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-env-coverage")

EVERY = set(gate.ENVIRONMENTS)
VALUES = "$values/{{ .path }}/values-{{ index .metadata.labels \"environment\" }}.yaml"


def selector(**sel) -> dict:
    return {"matrix": {"generators": [{"clusters": {"selector": sel}},
                                      {"list": {"elements": []}}]}}


def not_in(*envs: str) -> dict:
    return {"key": "environment", "operator": "NotIn", "values": list(envs)}


def appset(generators: list[dict], elements: list[dict]) -> dict:
    gens = [dict(g) for g in generators]
    for g in gens:
        for inner in (g.get("matrix") or {}).get("generators") or []:
            if "list" in inner:
                inner["list"]["elements"] = elements
    return {"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet",
            "metadata": {"name": "addons"},
            "spec": {"generators": gens,
                     "template": {"spec": {"sources": [{"helm": {"valueFiles": [VALUES]}}]}}}}


class Reach(unittest.TestCase):
    def reach(self, generators: list[dict]):
        return gate.reach({"spec": {"generators": generators}}, "addons.yaml")

    def test_no_cluster_selector_reaches_every_environment(self):
        self.assertEqual(self.reach([{"list": {"elements": []}}]),
                         (EVERY, "no cluster selector — reaches every environment"))

    def test_the_secret_type_marker_selects_clusters_not_environments(self):
        envs, why = self.reach([selector(matchLabels={gate.SECRET_TYPE: "cluster"})])
        self.assertEqual((envs, why), (EVERY, "reaches every environment"))

    def test_an_exclusion_narrows_reach(self):
        envs, why = self.reach([selector(matchExpressions=[not_in("hub")])])
        self.assertEqual(envs, EVERY - {"hub"})
        self.assertEqual(why, "excludes hub")

    def test_an_inclusion_narrows_reach(self):
        envs, why = self.reach([selector(matchExpressions=[
            {"key": "environment", "operator": "In", "values": ["production", "staging"]}])])
        self.assertEqual(envs, {"production", "staging"})
        self.assertEqual(why, "only production, staging")

    def test_expressions_narrow_together(self):
        envs, _ = self.reach([selector(matchExpressions=[
            not_in("hub"),
            {"key": "environment", "operator": "In", "values": ["hub", "production"]}])])
        self.assertEqual(envs, {"production"})

    def test_another_label_gates_reach(self):
        self.assertEqual(self.reach([selector(matchLabels={gate.SECRET_TYPE: "cluster",
                                                           "observability/tier": "full"})]),
                         (None, "gated on observability/tier=full"))

    def test_an_expression_on_another_key_gates_reach(self):
        self.assertEqual(self.reach([selector(matchExpressions=[
            {"key": "tier", "operator": "Exists"}])]), (None, "gated on label 'tier' (Exists)"))

    def test_an_operator_it_does_not_read_is_refused_rather_than_guessed(self):
        with self.assertRaisesRegex(ValueError, "unhandled operator 'Exists' on `environment`"):
            self.reach([selector(matchExpressions=[{"key": "environment",
                                                    "operator": "Exists"}])])


class AddonPaths(unittest.TestCase):
    def test_list_elements_carrying_a_chart_are_read(self):
        doc = appset([selector()], [{"appName": "a", "path": "addons/x/a", "chart": "a"},
                                    {"path": "addons/x/b", "chart": "b"},
                                    {"path": "addons/x/kustomized"}])
        self.assertEqual(list(gate.addon_paths(doc, "")), [("a", "addons/x/a"),
                                                           ("b", "addons/x/b")])

    def test_a_single_source_values_path_is_read_once(self):
        doc = appset([selector()], [{"path": "addons/x/a", "chart": "a"}])
        text = ("- $values/addons/x/a/values.yaml\n- $values/addons/y/otel/values.yaml\n"
                "- $values/addons/y/otel/values.yaml\n")
        self.assertEqual(list(gate.addon_paths(doc, text)), [("a", "addons/x/a"),
                                                             ("otel", "addons/y/otel")])


class AnAppsetTree(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        (self.root / "applicationsets").mkdir()
        floor = mock.patch.object(gate, "MIN_PAIRS", 1)
        floor.start()
        self.addCleanup(floor.stop)

    def addon(self, path: str, *envs: str) -> dict:
        d = self.root / path
        d.mkdir(parents=True, exist_ok=True)
        (d / "values.yaml").write_text("{}\n")
        for env in envs:
            (d / f"values-{env}.yaml").write_text("{}\n")
        return {"path": path, "chart": path.rsplit("/", 1)[-1]}

    def write(self, name: str, doc: dict) -> None:
        (self.root / "applicationsets" / name).write_text(yaml.safe_dump(doc))

    def check(self) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch("sys.argv", ["check-env-coverage.py", "--root", str(self.root)]):
            rc = gate.main()
        return rc, out.getvalue()

    def test_an_addon_with_a_values_file_for_every_environment_it_reaches_passes(self):
        el = self.addon("addons/bootstrap/a", "development", "staging", "production", "hub")
        self.write("addons-bootstrap.yaml", appset([selector()], [el]))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("1 appset/addon pair(s)", said)

    def test_an_addon_selected_for_the_hub_without_its_values_fails(self):
        el = self.addon("addons/bootstrap/a", "development", "staging", "production")
        self.write("addons-bootstrap.yaml", appset([selector()], [el]))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("addons-bootstrap.yaml: a is selected for development, hub, production, "
                      "staging (reaches every environment) but carries no values-hub.yaml", said)

    def test_an_addon_its_appset_excludes_from_the_hub_needs_no_hub_values(self):
        el = self.addon("addons/security/a", "development", "staging", "production")
        self.write("addons-security.yaml", appset([selector(matchExpressions=[not_in("hub")])],
                                                  [el]))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_a_label_gated_appset_is_named_and_not_asserted(self):
        gated = self.addon("addons/observability/a")
        el = self.addon("addons/security/b", "development", "staging", "production")
        self.write("addons-observability.yaml", appset(
            [selector(matchLabels={"observability/tier": "full"})], [gated]))
        self.write("addons-security.yaml", appset([selector(matchExpressions=[not_in("hub")])],
                                                  [el]))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("NOT asserted:\n  addons-observability.yaml: gated on "
                      "observability/tier=full", said)
        self.assertIn("(1 label-gated appset(s) not asserted)", said)

    def test_an_addon_path_that_does_not_exist_fails(self):
        el = self.addon("addons/security/b", "development", "staging", "production")
        self.write("addons-security.yaml", appset([selector(matchExpressions=[not_in("hub")])],
                                                  [el, {"path": "addons/security/gone",
                                                        "chart": "gone"}]))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("gone path addons/security/gone does not exist", said)

    def test_a_selector_it_cannot_classify_fails(self):
        el = self.addon("addons/security/b", "development", "staging", "production")
        self.write("addons-security.yaml", appset([selector(matchExpressions=[not_in("hub")])],
                                                  [el]))
        self.write("addons-odd.yaml", appset([selector(matchExpressions=[
            {"key": "environment", "operator": "Exists"}])], [el]))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("addons-odd.yaml: unhandled operator 'Exists'", said)

    def test_an_appset_templating_no_per_environment_file_is_not_read(self):
        el = self.addon("addons/security/b", "development", "staging", "production")
        self.write("addons-security.yaml", appset([selector(matchExpressions=[not_in("hub")])],
                                                  [el]))
        flat = appset([selector()], [self.addon("addons/x/flat")])
        flat["spec"]["template"]["spec"]["sources"] = [{"path": "{{ .path }}"}]
        self.write("addons-flat.yaml", flat)
        (self.root / "applicationsets" / "notes.yaml").write_text("kind: ConfigMap\n")
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("1 appset/addon pair(s)", said)

    def test_fewer_pairs_than_the_floor_cannot_run(self):
        with mock.patch.object(gate, "MIN_PAIRS", 2):
            el = self.addon("addons/bootstrap/a", "development", "staging", "production", "hub")
            self.write("addons-bootstrap.yaml", appset([selector()], [el]))
            rc, said = self.check()
        self.assertEqual(rc, 2, said)
        self.assertIn("compared only 1 appset/addon pair(s), fewer than the 2", said)


if __name__ == "__main__":
    unittest.main()
