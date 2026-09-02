"""Unit tests for the render gate's discovery and failure classification.

render-addons is the corpus every other render-based gate reads: the image-pin
gate and the policy-admission gate both import its `discover()` rather than
re-deriving which chart a path belongs to. A unit it does not find is a unit
three gates never examine, and all three print a count derived from the same
short list — so the omission reports itself as a complete run.

It templates every chart against a registry, so the positive-control sweep
exempts it. These exercise the two halves that decide what happens without a
network: which units exist, and what a helm failure means.
"""

from __future__ import annotations

import unittest

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


class UnreachableIsNotAVerdict(unittest.TestCase):
    """Exit 1 is a finding about a pin; exit 2 is a fact about the network.

    Collapsing them makes an outage read as a defect in the catalogue, and
    trains readers to re-run a red gate rather than read it.
    """

    def test_a_missing_chart_version_is_a_finding_about_this_repo(self):
        for err in ('Error: chart "loki" version "9.9.9" not found',
                    "Error: no chart version found for kyverno-3.99.0",
                    "Error: failed to fetch ...: 404 Not Found"):
            with self.subTest(err=err):
                self.assertTrue(gate.registry_answered(err))

    def test_a_connection_failure_is_a_fact_about_the_network(self):
        for err in ("Error: dial tcp 1.2.3.4:443: i/o timeout",
                    "Get https://x: dial tcp: lookup x: no such host",
                    "Error: TLS handshake timeout",
                    "Error: connection refused"):
            with self.subTest(err=err):
                self.assertFalse(gate.registry_answered(err))

    def test_a_message_naming_both_is_read_as_unreachable(self):
        """An unreachable registry cannot testify about what it holds."""
        self.assertFalse(gate.registry_answered(
            "Error: chart not found: dial tcp 1.2.3.4:443: i/o timeout"))

    def test_an_unrecognised_failure_is_not_treated_as_a_finding(self):
        self.assertFalse(gate.registry_answered("Error: something entirely new"))

    def test_the_classification_ignores_case(self):
        self.assertTrue(gate.registry_answered("Error: NO CHART VERSION FOUND"))
        self.assertFalse(gate.registry_answered("Error: I/O Timeout"))


class TheDiscoveredCorpus(unittest.TestCase):
    """Every unit three gates share comes from here."""

    @classmethod
    def setUpClass(cls):
        cls.units = gate.discover()

    def test_the_walk_finds_units(self):
        self.assertTrue(self.units,
                        "discovery matched no ApplicationSet, so this gate and the "
                        "two that import it would each report a complete run over "
                        "an empty corpus")

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
