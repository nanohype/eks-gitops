"""Unit tests for the render gate's discovery and failure classification.

render-addons is the corpus every other render-based gate reads: the image-pin
gate and the policy-admission gate both import its `discover()` rather than
re-deriving which chart a path belongs to. A unit it does not find is a unit
three gates never examine, and all three print a count derived from the same
short list — so the omission reports itself as a complete run.

It fetches every chart from a registry, so the positive-control sweep exempts
it. These exercise what decides the result without a network: which units exist,
where each is fetched from, and what a render is handed. What an unavailable
chart means is gatelib's, and is held in test_gatelib.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("render-addons")


def appset(sources, generators=None, destination=None):
    doc = {"kind": "ApplicationSet",
           "spec": {"template": {"spec": {"sources": sources}}}}
    if generators is not None:
        doc["spec"]["generators"] = generators
    if destination is not None:
        doc["spec"]["template"]["spec"]["destination"] = destination
    return doc


class OciReferences(unittest.TestCase):
    """ArgoCD resolves the OCI digest from repoURL, so the shape of it decides.

    Appending the chart name to a repoURL that already ends in it produces
    `.../karpenter/karpenter`, which is not a package.
    """

    def unit(self, repo, chart):
        return gate.Unit(appset="a.yaml", chart=chart, version="1.0.0",
                         repo=repo, path="addons/x/y")

    def test_a_repo_url_ending_in_the_chart_name_is_used_as_is(self):
        u = self.unit("oci://public.ecr.aws/karpenter/karpenter", "karpenter")
        self.assertEqual(u.oci_ref(), "oci://public.ecr.aws/karpenter/karpenter")

    def test_a_repo_url_naming_the_enclosing_namespace_gets_the_chart_appended(self):
        u = self.unit("oci://ghcr.io/nanohype/charts", "operator")
        self.assertEqual(u.oci_ref(), "oci://ghcr.io/nanohype/charts/operator")

    def test_an_https_repo_is_not_an_oci_one(self):
        self.assertFalse(self.unit("https://kyverno.github.io/kyverno", "kyverno").is_oci)
        self.assertTrue(self.unit("oci://ghcr.io/x/y", "y").is_oci)

    def test_an_oci_chart_is_fetched_from_its_reference(self):
        u = self.unit("oci://ghcr.io/nanohype/charts", "operator")
        self.assertEqual(u.source, "oci://ghcr.io/nanohype/charts/operator")

    def test_an_https_chart_is_fetched_from_its_repository(self):
        u = self.unit("https://kyverno.github.io/kyverno", "kyverno")
        self.assertEqual(u.source, "https://kyverno.github.io/kyverno")


class RecognisingATemplatedField(unittest.TestCase):
    """A templated `chart` is what says an appset renders many units, not one."""

    def test_a_go_template_is_a_template(self):
        self.assertTrue(gate._is_template("{{ .chart }}"))
        self.assertTrue(gate._is_template('{{ index .metadata.labels "environment" }}'))

    def test_a_literal_is_not(self):
        self.assertFalse(gate._is_template("kyverno"))
        self.assertFalse(gate._is_template("3.8.2"))

    def test_a_non_string_is_not(self):
        for value in (None, 3.82, ["{{ .x }}"], {"a": "{{ .x }}"}):
            with self.subTest(value=value):
                self.assertFalse(gate._is_template(value))


class FindingTheChartSource(unittest.TestCase):
    """Multi-source appsets carry a `$values` ref alongside the chart."""

    def test_the_source_carrying_a_chart_key_is_returned(self):
        values_ref = {"repoURL": "{{ .repo }}", "ref": "values"}
        chart = {"repoURL": "https://x", "chart": "loki", "targetRevision": "1"}
        self.assertIs(gate._chart_source([values_ref, chart]), chart)

    def test_an_appset_with_no_chart_source_is_not_ours(self):
        """Kustomize, git-sourced and local-chart appsets render elsewhere."""
        self.assertIsNone(gate._chart_source([{"repoURL": "https://x", "path": "p"}]))

    def test_a_non_mapping_source_is_skipped_rather_than_read(self):
        chart = {"repoURL": "https://x", "chart": "loki"}
        self.assertIs(gate._chart_source(["not-a-mapping", chart]), chart)


class SynthesisingChartParameters(unittest.TestCase):
    """ArgoCD injects the real per-cluster value; the render needs a valid one."""

    def test_a_templated_parameter_takes_its_synthetic_value(self):
        params = gate._synth_params(
            {"parameters": [{"name": "clusterName", "value": "{{ .name }}"}]})
        self.assertEqual(params, [("clusterName", "ci-cluster")])

    def test_a_templated_parameter_with_no_synthetic_value_takes_a_placeholder(self):
        params = gate._synth_params(
            {"parameters": [{"name": "someOther", "value": "{{ .x }}"}]})
        self.assertEqual(params, [("someOther", "ci")])

    def test_a_literal_parameter_is_passed_through(self):
        params = gate._synth_params(
            {"parameters": [{"name": "replicaCount", "value": 3}]})
        self.assertEqual(params, [("replicaCount", "3")])

    def test_a_valueless_parameter_takes_a_synthetic_value(self):
        params = gate._synth_params({"parameters": [{"name": "vpcId"}]})
        self.assertEqual(params, [("vpcId", "vpc-00000000000000000")])

    def test_a_nameless_parameter_is_dropped(self):
        self.assertEqual(gate._synth_params({"parameters": [{"value": "x"}]}), [])

    def test_no_parameters_block_yields_none(self):
        self.assertEqual(gate._synth_params({}), [])
        self.assertEqual(gate._synth_params({"parameters": None}), [])


class TheAddonPathFromValueFiles(unittest.TestCase):
    """A single-source appset states its addon directory only in `valueFiles`."""

    def test_the_base_values_path_is_extracted(self):
        helm = {"valueFiles": [
            "$values/addons/observability/loki/values.yaml",
            "$values/addons/observability/loki/values-production.yaml"]}
        self.assertEqual(gate._path_from_valuefiles(helm),
                         "addons/observability/loki")

    def test_a_per_environment_file_alone_does_not_supply_the_path(self):
        """Matching it would yield a directory that ends in the environment name."""
        helm = {"valueFiles": ["$values/addons/x/y/values-production.yaml"]}
        self.assertIsNone(gate._path_from_valuefiles(helm))

    def test_no_value_files_yields_nothing(self):
        self.assertIsNone(gate._path_from_valuefiles({}))
        self.assertIsNone(gate._path_from_valuefiles({"valueFiles": None}))


class WhatARenderIsHanded(unittest.TestCase):
    """helm renders the fetched archive, never a registry reference.

    A reference would put helm back on the network, where a 429 arrives as a
    line of text with the wait the registry asked for dropped.
    """

    def render(self, env_files=("values.yaml", "values-staging.yaml"), env="staging"):
        root = pathlib.Path(tempfile.mkdtemp())
        unit_dir = root / "addons" / "x" / "y"
        unit_dir.mkdir(parents=True)
        for name in env_files:
            (unit_dir / name).write_text("{}\n")
        unit = gate.Unit(appset="a.yaml", chart="karpenter", version="1.15.1",
                         repo="oci://public.ecr.aws/karpenter/karpenter",
                         path="addons/x/y", params=[("clusterName", "ci-cluster")],
                         namespace="kube-system")
        archive = root / "karpenter-1.15.1.tgz"
        ran = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))
        fetch = mock.Mock(return_value=archive)
        with mock.patch.object(gate, "REPO_ROOT", root), \
                mock.patch.object(gate.gatelib, "chart_archive_or_exit", fetch), \
                mock.patch.object(gate.subprocess, "run", ran):
            result = gate.render(unit, env)
        return result, fetch, ran, archive, unit_dir

    def test_the_archive_is_fetched_from_the_unit_source_and_rendered(self):
        result, fetch, ran, archive, unit_dir = self.render()
        self.assertEqual(result, (True, "rendered"))
        fetch.assert_called_once_with("oci://public.ecr.aws/karpenter/karpenter",
                                      "karpenter", "1.15.1")
        cmd = ran.call_args.args[0]
        self.assertEqual(cmd[:4], ["helm", "template", "karpenter", str(archive)])
        self.assertNotIn("--version", cmd)
        self.assertFalse(any(str(a).startswith("oci://") for a in cmd))
        self.assertEqual(cmd[4:], ["--namespace", "kube-system",
                                   "--set", "clusterName=ci-cluster",
                                   "-f", str(unit_dir / "values.yaml"),
                                   "-f", str(unit_dir / "values-staging.yaml")])

    def test_an_environment_with_no_delta_fetches_nothing(self):
        result, fetch, ran, _, _ = self.render(env_files=("values.yaml",))
        self.assertEqual(result, (True, "no env delta"))
        fetch.assert_not_called()
        ran.assert_not_called()


class TheDiscoveredCorpus(unittest.TestCase):
    """Every unit three gates share comes from here."""

    @classmethod
    def setUpClass(cls):
        cls.units = gate.discover()

    def test_every_appset_declaring_a_chart_contributes_a_unit(self):
        """Non-emptiness is not a floor: one unit satisfies it, and the omission
        this walk can produce is partial rather than total.

        Derived per file rather than counted, so the assertion holds as the
        catalog grows and fails on the appset that stops being seen.
        """
        contributing = {u.appset for u in self.units}
        missed = []
        for path in sorted(gate.APPSET_DIR.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text())
            if not doc or doc.get("kind") != "ApplicationSet":
                continue
            spec = doc.get("spec") or {}
            sources = ((spec.get("template") or {}).get("spec") or {}).get("sources") or []
            if gate._chart_source(sources) is None:
                continue  # kustomize / git-sourced — not this gate's corpus
            if path.name not in contributing:
                missed.append(path.name)
        self.assertEqual(missed, [],
                         "these ApplicationSets pin a Helm chart and produced no "
                         "render unit, so this gate and the two importing its "
                         "discover() never examine them")

    def test_every_matrix_element_pinning_a_chart_becomes_a_unit(self):
        """A matrix appset contributes one unit per list element, and dropping
        one is the shape that leaves the other gates' counts looking whole."""
        for path in sorted(gate.APPSET_DIR.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text())
            if not doc or doc.get("kind") != "ApplicationSet":
                continue
            spec = doc.get("spec") or {}
            sources = ((spec.get("template") or {}).get("spec") or {}).get("sources") or []
            src = gate._chart_source(sources)
            if src is None or not gate._is_template(src.get("chart")):
                continue
            elements = [e for e in gate._list_elements(spec) if "chart" in e]
            got = [u for u in self.units if u.appset == path.name]
            with self.subTest(appset=path.name):
                self.assertEqual(
                    sorted(u.chart for u in got),
                    sorted(str(e["chart"]) for e in elements),
                    "the units discovered for this appset are not its list "
                    "elements — an element was dropped from the corpus three "
                    "gates share")

    def test_every_unit_names_a_directory_that_exists(self):
        """A typo in an element's `path` removes the addon from three gates."""
        for u in self.units:
            with self.subTest(unit=f"{u.appset}:{u.chart}"):
                self.assertTrue((gate.REPO_ROOT / u.path).is_dir(),
                                f"{u.appset} points {u.chart} at '{u.path}', "
                                f"which is not a directory")

    def test_no_unit_carries_an_unrendered_template(self):
        for u in self.units:
            with self.subTest(unit=f"{u.appset}:{u.chart}"):
                for field in (u.chart, u.version, u.repo, u.path):
                    self.assertNotIn("{{", field)

    def test_every_unit_carries_a_version(self):
        for u in self.units:
            with self.subTest(unit=f"{u.appset}:{u.chart}"):
                self.assertTrue(u.version.strip())

    def test_units_are_unique_per_appset_and_chart(self):
        """Two units for one chart double-count the corpus the floor is read against."""
        seen = [(u.appset, u.chart, u.path) for u in self.units]
        self.assertEqual(len(seen), len(set(seen)))

    def test_every_skipped_chart_is_one_the_corpus_contains(self):
        """A skip naming a chart no appset pins excuses nothing and reads as care."""
        charts = {u.chart for u in self.units}
        for chart in gate.SKIP_CHARTS:
            with self.subTest(chart=chart):
                self.assertIn(chart, charts)


if __name__ == "__main__":
    unittest.main()
