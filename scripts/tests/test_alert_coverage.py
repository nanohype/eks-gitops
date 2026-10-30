"""Unit tests for the alert-state coverage gate, scripts/check-alert-coverage.py.

A rule that guards `<selector> != 0` states that zero is a different condition,
and the gate requires some rule in the same group to report it with
`== bool 0`. A bare `== 0` matches the series and reports the value 0, which
Grafana's `gt 0` threshold never trips on, so it appears to cover the state and
does not. These hand the gate rule groups built from the kube-state-metrics
selectors the catalog's alerts use, and hold each verdict: covered, covered
without the bool modifier, uncovered, exempt because zero is healthy, and an
exemption naming a rule that is gone.
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

gate = load("check-alert-coverage")

LAST_RUN = 'kube_customresource_status_field{customresource_kind="EvalSuite",field="lastRunAt"}'
FIRED = ('kube_customresource_status_field{customresource_kind="BudgetPolicy",'
         'field="killSwitchFiredAt"}')


def group(*rules: tuple[str, str], name: str = "g") -> dict:
    """A GrafanaAlertRuleGroup holding one Prometheus query per (title, expr)."""
    return {"apiVersion": "grafana.integreatly.org/v1beta1", "kind": "GrafanaAlertRuleGroup",
            "metadata": {"name": name},
            "spec": {"rules": [{"uid": title.lower(), "title": title,
                                "data": [{"refId": "A", "model": {"expr": expr}}]}
                               for title, expr in rules]}}


GUARDED = ("AgentEvalBelowThreshold", f"min(score) < 0.8 and {LAST_RUN} != 0")
COVERED = ("AgentEvalStale", f"{LAST_RUN} == bool 0")


class AlertFiles(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.alerting = self.root / "dashboards" / "base" / "alerting"
        self.alerting.mkdir(parents=True)
        for name, value in (("REPO_ROOT", self.root), ("ALERT_DIR", self.alerting)):
            patch = mock.patch.object(gate, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def write(self, name: str, *docs: dict) -> None:
        (self.alerting / name).write_text(yaml.safe_dump_all(docs))

    def check(self) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = gate.main()
        return rc, out.getvalue()


class AnExcludedState(AlertFiles):
    def test_covered_with_the_bool_modifier_passes(self):
        self.write("evals.yaml", group(GUARDED, COVERED))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("ok        AgentEvalBelowThreshold", said)
        self.assertIn("All 1 excluded alert state(s) are covered.", said)

    def test_covered_without_the_bool_modifier_never_fires(self):
        self.write("evals.yaml", group(GUARDED, ("AgentEvalStale", f"{LAST_RUN} == 0")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("CONFLICT  AgentEvalBelowThreshold", said)
        self.assertIn("uses `== 0` without the bool modifier", said)

    def test_uncovered_is_somebodys_job(self):
        self.write("evals.yaml", group(GUARDED))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("UNCOVERED AgentEvalBelowThreshold", said)
        self.assertIn("evals.yaml:AgentEvalBelowThreshold: excludes the zero state", said)

    def test_a_cover_in_another_group_does_not_count(self):
        self.write("evals.yaml", group(GUARDED, name="a"), group(COVERED, name="b"))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("UNCOVERED", said)

    def test_selectors_are_compared_ignoring_whitespace(self):
        spaced = LAST_RUN.replace(",", ", ")
        self.write("evals.yaml", group(GUARDED, ("AgentEvalStale", f"{spaced} ==  bool  0")))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_a_cover_on_another_selector_does_not_count(self):
        other = LAST_RUN.replace("EvalSuite", "AgentFleet")
        self.write("evals.yaml", group(GUARDED, ("Other", f"{other} == bool 0")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("UNCOVERED", said)

    def test_a_zero_comparison_inside_parentheses_is_not_read_as_a_cover(self):
        self.write("evals.yaml", group(GUARDED, ("Grouped", f"count(({LAST_RUN} == 0)) > 0")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("UNCOVERED", said)
        self.assertNotIn("CONFLICT", said)


class ZeroIsHealthy(AlertFiles):
    FIRED_RULE = ("AgentKillSwitchFired", f"{FIRED} != 0")

    def test_the_exempt_guard_needs_no_cover(self):
        self.write("agent-platform.yaml", group(self.FIRED_RULE))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("healthy   AgentKillSwitchFired: zero is the healthy state "
                      "(killSwitchFiredAt)", said)

    def test_the_exemption_is_keyed_on_the_file(self):
        self.write("elsewhere.yaml", group(self.FIRED_RULE))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("UNCOVERED AgentKillSwitchFired", said)

    def test_an_exemption_for_a_rule_that_is_gone_is_stale(self):
        self.write("agent-platform.yaml", group(("Renamed", f"{FIRED} != 0")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("STALE     exemption for missing rule AgentKillSwitchFired", said)
        self.assertIn("ZERO_IS_HEALTHY exempts rule 'AgentKillSwitchFired', which no longer "
                      "exists", said)

    def test_every_exemption_says_why(self):
        for key, reason in gate.ZERO_IS_HEALTHY.items():
            with self.subTest(key=key):
                self.assertEqual(len(key), 3)
                self.assertTrue(reason.strip())


class TheCorpus(AlertFiles):
    def test_no_alert_files_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.check()
        self.assertIn("no alert files under dashboards/base/alerting", str(raised.exception.code))

    def test_no_guard_anywhere_would_pass_vacuously(self):
        self.write("evals.yaml", group(COVERED))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("no `!= 0` guards found", said)

    def test_what_is_no_rule_group_is_not_read(self):
        self.write("contact-points.yaml", {"kind": "GrafanaContactPoint", "metadata": {}},
                   group(GUARDED, COVERED))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_a_group_with_no_query_is_skipped(self):
        empty = {"kind": "GrafanaAlertRuleGroup", "spec": {"rules": [
            {"title": "NoQuery", "data": [{"refId": "A", "model": {}}, {"refId": "B"}]}]}}
        self.write("evals.yaml", empty, group(GUARDED, COVERED))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_a_rule_without_a_title_is_named_by_its_uid(self):
        rule_group = {"spec": {"rules": [{"uid": "u-1", "data": [{"model": {"expr": "up"}}]},
                                         {"data": [{"model": {"expr": "down"}}]}]}}
        self.assertEqual(gate.rule_exprs(rule_group), [("u-1", "up"), ("?", "down")])


if __name__ == "__main__":
    unittest.main()
