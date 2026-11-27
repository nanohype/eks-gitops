"""Unit tests for the Loki log-volume gate's verdict.

The gate holds one relation: the alert that warns about the volume must fire
strictly before the fraction at which Loki stops accepting every push. Both
operands come from elsewhere — the cutoff from a rendered chart, the threshold
from a shipped alert file — so the gate reaches a chart repository and the
positive-control sweep exempts it.

What that leaves untested is the comparison itself, and the comparison is the
gate. These supply both operands directly.

The alert-reading half is exercised against fixture files rather than the shipped
one: the shipped rule is a single sample of a shape with several failure modes,
and the ones that matter are the shapes it does not have.

TheGateRunWhole runs main() end to end without the network: a fixture tree, a
chart served by fakeregistry through registry.py's own client and cache, and the
real helm rendering it, so the stages are proven composed and not only apart.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import fakeregistry as fake
import registry
import yaml
from gateloader import load

gate = load("check-log-volume-budget")

HAS_HELM = shutil.which("helm") is not None

REL = "addons/observability/loki/values-production.yaml"


def config(cutoff=0.9, retention="2160h", retention_enabled=True):
    """A rendered Loki config carrying only the keys this gate reads."""
    cfg: dict = {"ingester": {"wal": {}}, "limits_config": {}, "compactor": {}}
    if cutoff is not None:
        cfg["ingester"]["wal"]["disk_full_threshold"] = cutoff
    if retention is not None:
        cfg["limits_config"]["retention_period"] = retention
    if retention_enabled is not None:
        cfg["compactor"]["retention_enabled"] = retention_enabled
    return cfg


def alert_file(rules) -> pathlib.Path:
    """Write a Grafana alerting manifest carrying `rules` and return its path."""
    tmp = pathlib.Path(tempfile.mkdtemp()) / "loki-disk.yaml"
    tmp.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "grafana.integreatly.org/v1beta1",
                "kind": "GrafanaAlertRuleGroup",
                "spec": {"rules": rules},
            }
        )
    )
    return tmp


def fill_rule(expr=None, threshold=0.75, uid=None):
    return {
        "uid": uid or gate.FILL_RULE,
        "data": [
            {"refId": "A", "model": {"expr": expr or f"max({gate.GAUGE})"}},
            {
                "refId": "B",
                "model": {"conditions": [{"evaluator": {"type": "gt", "params": [threshold]}}]},
            },
        ],
    }


class ReadingTheAlert(unittest.TestCase):
    """The alert supplies the left operand. Every way it can fail to is a pass."""

    def setUp(self):
        self.original = (gate.ALERT, gate.ROOT)
        gate.failures.clear()

    def tearDown(self):
        gate.ALERT, gate.ROOT = self.original
        gate.failures.clear()

    def threshold(self, rules):
        # ROOT moves with ALERT: the gate reports the alert path relative to the
        # repo root, so a fixture outside it would raise instead of failing.
        gate.ALERT = alert_file(rules)
        gate.ROOT = gate.ALERT.parent
        return gate.alert_threshold()

    def test_the_evaluator_threshold_is_returned(self):
        self.assertEqual(self.threshold([fill_rule(threshold=0.75)]), 0.75)
        self.assertEqual(gate.failures, [])

    def test_a_file_with_no_such_rule_fails_rather_than_returning_nothing(self):
        """Deleting the rule must not read as 'no threshold to compare against'."""
        self.assertIsNone(self.threshold([fill_rule(uid="something-else")]))
        self.assertEqual(len(gate.failures), 1)
        self.assertIn("no rule with uid", gate.failures[0])

    def test_a_file_with_no_rules_at_all_fails(self):
        self.assertIsNone(self.threshold([]))
        self.assertIn("no rule with uid", gate.failures[0])

    def test_a_rule_querying_the_edge_counter_fails_twice(self):
        """It increments once per transition into the throttled state.

        A cluster throttled for a week increments it once, so a rate() alert on it
        reads as quiet through exactly the outage it exists to report.
        """
        self.threshold([fill_rule(expr=f"max(rate({gate.EDGE_COUNTER}[5m]))")])
        joined = " ".join(gate.failures)
        self.assertIn("does not query", joined)
        self.assertIn("increments once per transition", joined)

    def test_a_rule_querying_both_still_fails_on_the_edge_counter(self):
        self.threshold([fill_rule(expr=f"max({gate.GAUGE}) or max({gate.EDGE_COUNTER})")])
        self.assertEqual(len(gate.failures), 1)
        self.assertIn("increments once per transition", gate.failures[0])

    def test_a_rule_with_no_evaluator_fails(self):
        rule = fill_rule()
        rule["data"] = [{"refId": "A", "model": {"expr": f"max({gate.GAUGE})"}}]
        self.assertIsNone(self.threshold([rule]))
        self.assertIn("carries no evaluator threshold", gate.failures[0])


class TheCutoffComparison(unittest.TestCase):
    """The gate's whole claim: the warning leads the cutoff, with room to act."""

    def test_a_warning_ahead_of_the_cutoff_passes(self):
        problems, leads = gate.environment_verdict(config(cutoff=0.9), 0.75, REL)
        self.assertEqual(problems, [])
        self.assertTrue(leads)

    def test_a_warning_at_the_cutoff_leaves_no_window(self):
        """Equal is not ahead: the alert and the outage arrive together."""
        problems, leads = gate.environment_verdict(config(cutoff=0.75), 0.75, REL)
        self.assertFalse(leads)
        self.assertIn("no window in which to act", problems[0])

    def test_a_warning_past_the_cutoff_fails(self):
        problems, leads = gate.environment_verdict(config(cutoff=0.7), 0.75, REL)
        self.assertFalse(leads)
        self.assertIn("fires at 0.75 but ingestion stops at 0.7", problems[0])

    def test_an_inherited_cutoff_fails(self):
        """Unset, the lead time depends on a chart default that can move."""
        problems, leads = gate.environment_verdict(config(cutoff=None), 0.75, REL)
        self.assertFalse(leads)
        self.assertIn("sets no ingester.wal.disk_full_threshold", problems[0])

    def test_a_cutoff_written_as_a_string_is_still_compared(self):
        problems, leads = gate.environment_verdict(config(cutoff="0.9"), 0.75, REL)
        self.assertEqual(problems, [])
        self.assertTrue(leads)

    def test_an_environment_that_failed_the_comparison_is_not_counted_as_covered(self):
        """The closing line reports how many environments the comparison covered.

        Counting a failed one there would say the relation was checked and held.
        """
        _, leads = gate.environment_verdict(config(cutoff=0.5), 0.75, REL)
        self.assertFalse(leads)


class RetentionMustActuallyDelete(unittest.TestCase):
    """A cutoff nothing deletes toward is a cutoff that arrives on a schedule."""

    def test_a_missing_retention_period_fails(self):
        problems, _ = gate.environment_verdict(config(retention=None), 0.75, REL)
        self.assertIn("sets no limits_config.retention_period", problems[0])

    def test_retention_disabled_in_the_compactor_fails(self):
        """`retention_period` applies only when the compactor enforces it."""
        problems, _ = gate.environment_verdict(config(retention_enabled=False), 0.75, REL)
        self.assertIn("compactor.retention_enabled is not true", problems[0])

    def test_an_absent_compactor_block_fails(self):
        problems, _ = gate.environment_verdict(config(retention_enabled=None), 0.75, REL)
        self.assertIn("compactor.retention_enabled is not true", problems[0])

    def test_a_truthy_non_true_value_does_not_satisfy_it(self):
        """Loki reads the key as a bool; `"true"` is a string the chart passes on."""
        problems, _ = gate.environment_verdict(config(retention_enabled="true"), 0.75, REL)
        self.assertIn("compactor.retention_enabled is not true", problems[0])

    def test_every_failure_is_reported_from_one_pass(self):
        """A gate that returns on the first problem hides the rest behind a fix."""
        problems, _ = gate.environment_verdict(
            config(cutoff=None, retention=None, retention_enabled=False), 0.75, REL
        )
        self.assertEqual(len(problems), 3)


class TheChartPin(unittest.TestCase):
    """The chart rendered is the one the ApplicationSet installs, read from it."""

    def pin(self, sources):
        doc = {"kind": "ApplicationSet", "spec": {"template": {"spec": {"sources": sources}}}}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            appset = root / "applicationsets" / "addons-observability.yaml"
            appset.parent.mkdir()
            appset.write_text(yaml.safe_dump(doc))
            out = io.StringIO()
            with (
                mock.patch.object(gate, "ROOT", root),
                mock.patch.object(gate, "APPSET", appset),
                contextlib.redirect_stdout(out),
            ):
                try:
                    return gate.chart_pin(), out.getvalue()
                except SystemExit as exc:
                    return exc.code, out.getvalue()

    def test_the_chart_source_is_the_pin(self):
        pin, _ = self.pin(
            [
                {"repoURL": "https://github.com/example/eks-gitops", "ref": "values"},
                {
                    "repoURL": "https://grafana.github.io/helm-charts",
                    "chart": "loki",
                    "targetRevision": "6.29.0",
                },
            ]
        )
        self.assertEqual(pin, ("https://grafana.github.io/helm-charts", "6.29.0"))

    def test_an_appset_with_no_chart_source_cannot_run(self):
        rc, out = self.pin(
            [
                {
                    "repoURL": "https://github.com/example/eks-gitops",
                    "path": "addons/observability/loki",
                }
            ]
        )
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("applicationsets/addons-observability.yaml declares no chart source", out)


class TheEnvironmentCorpus(unittest.TestCase):
    """The gate reads the environments off the tree, so an added one is checked."""

    def test_every_shipped_values_file_is_an_environment(self):
        envs = gate.environments()
        self.assertTrue(
            envs,
            "the addon carries no values-<env>.yaml, so this gate would examine no environment",
        )
        for env in envs:
            with self.subTest(env=env):
                self.assertTrue((gate.ADDON / f"values-{env}.yaml").exists())

    def test_the_shipped_alert_names_the_gauge_the_ingester_sets_every_tick(self):
        gate.failures.clear()
        threshold = gate.alert_threshold()
        self.assertEqual(gate.failures, [])
        self.assertIsNotNone(threshold)


# A chart that renders what the upstream one renders for this gate: the Loki
# ConfigMap carrying config.yaml, here built from `loki.config` in the values.
LOKI_CONFIGMAP = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: loki
data:
  config.yaml: |
{{ toYaml .Values.loki.config | indent 4 }}
"""


@unittest.skipUnless(HAS_HELM, "helm is not on PATH")
class TheGateRunWhole(unittest.TestCase):
    """main() over a fixture tree, its chart fetched by the real client and rendered by helm.

    Each stage has its own tests above. These hold the composition: the pin read
    off the ApplicationSet is the chart fetched, every environment's values reach
    the render, the verdict is per environment, and each way a stage can fail
    ends the run with the status that failure earns.
    """

    REPO = "https://charts.example/grafana"
    VERSION = "6.29.0"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.addon = self.root / "addons" / "observability" / "loki"
        self.addon.mkdir(parents=True)
        self.appset = self.root / "applicationsets" / "addons-loki.yaml"
        self.appset.parent.mkdir()
        self.alert = self.root / "dashboards" / "base" / "alerting" / "loki-disk.yaml"
        self.alert.parent.mkdir(parents=True)
        self.write_appset(self.VERSION)
        self.alert.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "grafana.integreatly.org/v1beta1",
                    "kind": "GrafanaAlertRuleGroup",
                    "spec": {"rules": [fill_rule(threshold=0.8)]},
                }
            )
        )
        self.values("values.yaml", config(cutoff=0.9, retention="720h"))
        self.values("values-development.yaml", {})
        self.values("values-production.yaml", {"limits_config": {"retention_period": "2160h"}})

        self.repo = fake.ChartRepository(
            self.REPO,
            {
                ("loki", self.VERSION): fake.chart_archive(
                    "loki",
                    self.VERSION,
                    {"configmap.yaml": LOKI_CONFIGMAP},
                    values="loki:\n  config: {}\n",
                )
            },
        )
        self.cache = self.root / "cache"
        self.hosts = fake.serve(self, registry, {self.REPO: self.repo}, self.cache)
        self.failures: list[str] = []
        for patch in (
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(gate, "APPSET", self.appset),
            mock.patch.object(gate, "ADDON", self.addon),
            mock.patch.object(gate, "ALERT", self.alert),
            mock.patch.object(gate, "failures", self.failures),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def write_appset(self, version):
        self.appset.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "argoproj.io/v1alpha1",
                    "kind": "ApplicationSet",
                    "metadata": {"name": "addons-loki"},
                    "spec": {
                        "template": {
                            "spec": {
                                "sources": [
                                    {
                                        "repoURL": self.REPO,
                                        "chart": "loki",
                                        "targetRevision": version,
                                    },
                                    {"repoURL": "https://git.example/eks-gitops", "ref": "values"},
                                ]
                            }
                        }
                    },
                }
            )
        )

    def values(self, name, loki_config):
        (self.addon / name).write_text(yaml.safe_dump({"loki": {"config": loki_config}}))

    def run_gate(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = gate.main()
            except SystemExit as exc:
                rc = exc.code
        return rc, out.getvalue()

    def test_a_tree_whose_alert_leads_every_cutoff_passes(self):
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("log-volume budget OK: 2 environment(s)", out)
        self.assertIn("fires at 0.8", out)
        self.assertIn("(2 checked)", out)
        self.assertEqual(
            self.hosts.urls,
            [f"{self.REPO}/index.yaml", f"{self.REPO}/loki-{self.VERSION}.tgz"],
            "the chart fetched is not the one the ApplicationSet pins",
        )

    def test_a_second_run_reads_the_chart_from_the_cache(self):
        self.assertEqual(self.run_gate()[0], 0)
        asked = list(self.hosts.urls)
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.hosts.urls, asked, "a cached, intact chart was fetched again")

    def test_an_environment_whose_cutoff_falls_to_the_alert_fails_naming_it(self):
        self.values("values-production.yaml", {"ingester": {"wal": {"disk_full_threshold": 0.8}}})
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "FAIL  addons/observability/loki/values-production.yaml: the fill alert fires at 0.8 "
            "but ingestion stops at 0.8",
            out,
        )
        self.assertNotIn("values-development.yaml", out)

    def test_retention_the_render_turns_off_fails(self):
        self.values("values-development.yaml", {"compactor": {"retention_enabled": False}})
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("values-development.yaml: compactor.retention_enabled is not true", out)

    def test_a_tree_with_no_environment_fails(self):
        for env in ("development", "production"):
            (self.addon / f"values-{env}.yaml").unlink()
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "FAIL  addons/observability/loki carries no values-<env>.yaml, so this gate "
            "examined no environment",
            out,
        )

    def test_a_pin_the_repository_does_not_list_is_a_finding(self):
        self.write_appset("6.30.0")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("answered, and its answer rules the pin out", out)
        self.assertIn("lists no loki 6.30.0", out)

    def test_a_repository_that_stays_down_cannot_run(self):
        self.repo.answer = lambda req: fake.http_error(req.full_url, 503)
        rc, out = self.run_gate()
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn(
            "Cannot run: loki 6.29.0 from https://charts.example/grafana could not be read", out
        )
        self.assertTrue(self.hosts.waits, "a 503 was not retried")
        self.assertNotIn("FAIL", out)

    def test_a_chart_helm_cannot_render_cannot_run(self):
        self.repo.charts[("loki", self.VERSION)] = fake.chart_archive(
            "loki", self.VERSION, {"configmap.yaml": "{{ .Values.missing.key }}\n"}
        )
        rc, out = self.run_gate()
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("Cannot run: helm could not render loki for development.", out)

    def test_a_render_without_the_loki_configmap_cannot_run(self):
        self.repo.charts[("loki", self.VERSION)] = fake.chart_archive(
            "loki",
            self.VERSION,
            {"configmap.yaml": LOKI_CONFIGMAP.replace("name: loki", "name: other")},
            values="loki:\n  config: {}\n",
        )
        rc, out = self.run_gate()
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("the development render produced no loki ConfigMap carrying config.yaml", out)


if __name__ == "__main__":
    unittest.main()
