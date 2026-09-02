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
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

import yaml
from gateloader import load

gate = load("check-log-volume-budget")

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
    tmp.write_text(yaml.safe_dump({"apiVersion": "grafana.integreatly.org/v1beta1",
                                   "kind": "GrafanaAlertRuleGroup",
                                   "spec": {"rules": rules}}))
    return tmp


def fill_rule(expr=None, threshold=0.75, uid=None):
    return {
        "uid": uid or gate.FILL_RULE,
        "data": [
            {"refId": "A",
             "model": {"expr": expr or f"max({gate.GAUGE})"}},
            {"refId": "B",
             "model": {"conditions": [
                 {"evaluator": {"type": "gt", "params": [threshold]}}]}},
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
        self.threshold([fill_rule(
            expr=f"max({gate.GAUGE}) or max({gate.EDGE_COUNTER})")])
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
        problems, _ = gate.environment_verdict(
            config(retention_enabled=False), 0.75, REL)
        self.assertIn("compactor.retention_enabled is not true", problems[0])

    def test_an_absent_compactor_block_fails(self):
        problems, _ = gate.environment_verdict(
            config(retention_enabled=None), 0.75, REL)
        self.assertIn("compactor.retention_enabled is not true", problems[0])

    def test_a_truthy_non_true_value_does_not_satisfy_it(self):
        """Loki reads the key as a bool; `"true"` is a string the chart passes on."""
        problems, _ = gate.environment_verdict(
            config(retention_enabled="true"), 0.75, REL)
        self.assertIn("compactor.retention_enabled is not true", problems[0])

    def test_every_failure_is_reported_from_one_pass(self):
        """A gate that returns on the first problem hides the rest behind a fix."""
        problems, _ = gate.environment_verdict(
            config(cutoff=None, retention=None, retention_enabled=False), 0.75, REL)
        self.assertEqual(len(problems), 3)


class TheEnvironmentCorpus(unittest.TestCase):
    """The gate reads the environments off the tree, so an added one is checked."""

    def test_every_shipped_values_file_is_an_environment(self):
        envs = gate.environments()
        self.assertTrue(envs, "the addon carries no values-<env>.yaml, so this gate "
                              "would examine no environment")
        for env in envs:
            with self.subTest(env=env):
                self.assertTrue((gate.ADDON / f"values-{env}.yaml").exists())

    def test_the_shipped_alert_names_the_gauge_the_ingester_sets_every_tick(self):
        gate.failures.clear()
        threshold = gate.alert_threshold()
        self.assertEqual(gate.failures, [])
        self.assertIsNotNone(threshold)


if __name__ == "__main__":
    unittest.main()
