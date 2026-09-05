"""Unit tests for the burn-rate budget gate.

The defect this gate exists for was a number that agreed with nothing: a
summary claiming 100% budget consumed where its own expression spends 10%. So
the cases here concentrate on the two ways a gate like this reports a false
pass — reading the figure from somewhere that cannot disagree with it, and
quietly dropping a rule out of the corpus so its claim is never read.

Every term of the arithmetic comes from a different place in the tree, and each
of those places gets a fixture that moves it.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import shutil
import tempfile
import unittest
from fractions import Fraction

import yaml
from gateloader import load

gate = load("check-burn-rate-budgets")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# The objective is read out of the render, so the planted fixtures are rendered
# too rather than compared against a stub. The job running these installs
# kustomize; a checkout without it skips rather than aborting the runner on the
# gate's exit-2 refusal.
HAS_KUSTOMIZE = shutil.which("kustomize") is not None


def burn_expr(budget, factor, long_window, short_window,
              guard=None, numerator=None, denominator=None):
    """A dual-window burn expression in the shape this catalog writes them.

    Two metric selectors by default, because the real rules divide one by
    another and a rule whose two selectors disagree about the objective is one
    of the cases below.
    """
    num = numerator or NUMERATOR
    den = denominator or DENOMINATOR

    def half(window):
        return (f"(sum(rate({num}[{window}])) / "
                f"clamp_min(sum(rate({den}[{window}])), 0.001) / "
                f"{budget} > bool {factor})")

    expr = half(long_window) + " * " + half(short_window)
    if guard is not None:
        expr += f" * (sum(rate({den}[{long_window}])) > bool {guard})"
    return expr


def rule(title, summary, expr):
    return {"uid": title.lower(), "title": title,
            "annotations": {"summary": summary},
            "data": [{"refId": "A", "model": {"refId": "A", "expr": expr}},
                     {"refId": "B", "model": {"refId": "B", "expression": "A"}}]}


def group(name, *rules):
    return {"apiVersion": "grafana.integreatly.org/v1beta1",
            "kind": "GrafanaAlertRuleGroup",
            "metadata": {"name": name},
            "spec": {"rules": list(rules)}}


def dashboard(name, *exprs):
    return {"apiVersion": "grafana.integreatly.org/v1beta1",
            "kind": "GrafanaDashboard",
            "metadata": {"name": name},
            "spec": {"json": json.dumps(
                {"title": name,
                 "panels": [{"type": "timeseries", "title": f"p{i}",
                             "targets": [{"expr": e}]}
                            for i, e in enumerate(exprs)]})}}


NUMERATOR = 'svc_request_duration_seconds_bucket{job="svc",le="1"}'
DENOMINATOR = 'svc_request_duration_seconds_count{job="svc"}'
PANELS = (f"sum(rate({NUMERATOR}[30d])) / sum(rate({DENOMINATOR}[30d]))",)


class ReadingTheExpression(unittest.TestCase):
    """What the rule itself states, before anything is compared to it."""

    def test_the_burn_factor_is_the_one_divided_by_the_budget(self):
        expr = burn_expr("0.01", "14.4", "1h", "5m")
        self.assertEqual(gate.factors(expr), {Fraction("14.4")})

    def test_a_traffic_guard_is_not_a_burn_factor(self):
        """`sum(rate(...)) > bool 0.0167` keeps an idle service from alerting on
        a ratio computed from no requests. Counted as a factor it makes a rule
        look like two contradictory claims about one rate of spend, and the
        rules carrying one are the majority of this catalog."""
        expr = burn_expr("0.001", "14.4", "1h", "5m", guard="0.0167")
        self.assertEqual(gate.factors(expr), {Fraction("14.4")})

    def test_the_long_window_is_the_period_the_claim_is_about(self):
        expr = burn_expr("0.01", "6", "6h", "30m")
        window, selectors = gate.long_window(expr)
        self.assertEqual(window, 6 * 3600)
        self.assertIn(NUMERATOR, selectors)

    def test_the_short_confirmation_window_is_not_taken_for_it(self):
        """The short window exists to stop a spike that has already stopped from
        firing; a claim about it would be a claim about a different alert."""
        expr = burn_expr("0.01", "14.4", "1h", "5m")
        self.assertEqual(gate.long_window(expr)[0], 3600)

    def test_a_rule_with_no_burn_comparison_is_not_in_the_corpus(self):
        found = list(gate.burn_rules(self.planted()))
        self.assertEqual([r["title"] for _p, _g, r, _e in found], ["Burn"])

    def planted(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "g.yaml").write_text(yaml.safe_dump(group(
            "g",
            rule("Burn", "burning (2% in 1h)",
                 burn_expr("0.01", "14.4", "1h", "5m")),
            rule("Rate", "error rate above 5%",
                 f"sum(rate({DENOMINATOR}[5m])) > 0.05"))))
        return d


class TheDurationGrammar(unittest.TestCase):
    def test_units_convert(self):
        for text, want in (("5m", 300), ("1h", 3600), ("1d", 86400),
                           ("3d", 259200), ("30d", 2592000), ("1w", 604800)):
            with self.subTest(duration=text):
                self.assertEqual(gate.seconds(text), want)

    def test_seconds_render_as_the_unit_a_file_would_write(self):
        for total, want in ((2592000, "30d"), (259200, "3d"), (3600, "1h"),
                            (1800, "30m"), (604800, "1w")):
            with self.subTest(seconds=total):
                self.assertEqual(gate.human(total), want)

    def test_a_factor_renders_as_the_decimal_in_the_expression(self):
        """Exact arithmetic is what makes the comparison an equality rather than
        a tolerance, but `72/5` is not a string anyone can search the file for."""
        self.assertEqual(gate.decimal(Fraction("14.4")), "14.4")
        self.assertEqual(gate.decimal(Fraction(1)), "1")
        self.assertEqual(gate.decimal(Fraction(6)), "6")


@unittest.skipUnless(HAS_KUSTOMIZE, "kustomize is not on PATH")
class TheVerdict(unittest.TestCase):
    """main() over a planted alerting directory and dashboard corpus."""

    def verdict(self, rules, panel_exprs=PANELS, ship_dashboard=True):
        """main() over a planted tree, rendered the way the real one is.

        `ship_dashboard=False` writes the dashboard and leaves it out of the
        kustomization's `resources`, which is what a panel that stops being
        delivered looks like from disk.
        """
        root = pathlib.Path(tempfile.mkdtemp())
        base = root / "dashboards" / "base"
        alerts = base / "alerting"
        boards = base / "platform"
        alerts.mkdir(parents=True)
        boards.mkdir(parents=True)
        (alerts / "g.yaml").write_text(yaml.safe_dump(group("slo", *rules)))
        (boards / "d.yaml").write_text(
            yaml.safe_dump(dashboard("d", *panel_exprs)))
        resources = ["  - alerting/g.yaml"]
        if ship_dashboard:
            resources.append("  - platform/d.yaml")
        (base / "kustomization.yaml").write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\nresources:\n" + "\n".join(resources) + "\n")
        saved = (gate.ROOT, gate.ALERT_DIR, gate.KUSTOMIZE_ROOT)
        gate.ROOT, gate.ALERT_DIR, gate.KUSTOMIZE_ROOT = root, alerts, base
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = gate.main()
        finally:
            gate.ROOT, gate.ALERT_DIR, gate.KUSTOMIZE_ROOT = saved
        return rc, out.getvalue()

    def tiers(self):
        """The four-tier ladder, each claim the one its expression spends
        against a 30d objective."""
        return [
            rule("Fast", "burning fast (2% in 1h)",
                 burn_expr("0.01", "14.4", "1h", "5m")),
            rule("Slow", "burning (5% in 6h)",
                 burn_expr("0.01", "6", "6h", "30m")),
            rule("Ticket1d", "burning slowly (10% in 1d)",
                 burn_expr("0.01", "3", "1d", "2h")),
            rule("Ticket3d", "burning slowest (10% in 3d)",
                 burn_expr("0.01", "1", "3d", "6h")),
        ]

    def test_a_consistent_ladder_passes(self):
        """The control. Without it every case below could be failing for a
        reason the case did not plant."""
        rc, out = self.verdict(self.tiers())
        self.assertEqual(rc, 0, out)

    def test_the_defect_this_gate_was_written_for(self):
        """Factor 1 over 3d against a 30d objective spends 10%, not 100%. The
        expression is right and only the sentence is wrong, which is why every
        rule-level validation passed it."""
        tiers = self.tiers()
        tiers[3]["annotations"]["summary"] = "burning (100% over 3d)"
        rc, out = self.verdict(tiers)
        self.assertEqual(rc, 1, out)
        self.assertIn("claims '100% over 3d'", out)
        self.assertIn("spends 10% over 3d", out)
        self.assertIn("1 x 3d / 30d", out)

    def test_a_factor_that_drifts_from_its_claim_is_reported(self):
        tiers = self.tiers()
        tiers[0]["data"][0]["model"]["expr"] = burn_expr(
            "0.01", "7.2", "1h", "5m")
        rc, out = self.verdict(tiers)
        self.assertEqual(rc, 1, out)
        self.assertIn("burn factor 7.2", out)

    def test_an_objective_window_that_moves_on_the_dashboard_is_reported(self):
        """The term that lives in another file. Nothing in the alerting
        directory changes here, and every claim in it becomes wrong."""
        rc, out = self.verdict(
            self.tiers(),
            panel_exprs=(f"sum(rate({NUMERATOR}[60d])) / "
                         f"sum(rate({DENOMINATOR}[60d]))",))
        self.assertEqual(rc, 1, out)
        self.assertIn("60d objective", out)
        self.assertEqual(out.count("claims"), 4)

    def test_a_claim_compared_to_nothing_is_reported(self):
        """No panel measures what the rule burns against, so the figure agrees
        with whatever it says. That is the state the defect survived in."""
        rc, out = self.verdict(
            self.tiers(), panel_exprs=('sum(rate(other_metric{job="x"}[30d]))',))
        self.assertEqual(rc, 1, out)
        self.assertIn("compared to nothing", out)

    def test_a_burn_rule_stating_no_figure_is_reported(self):
        """Otherwise deleting the claim removes the rule from this gate's
        corpus, and that is the edit most likely to accompany a wrong one."""
        tiers = self.tiers()
        tiers[0]["annotations"]["summary"] = "budget burning fast"
        rc, out = self.verdict(tiers)
        self.assertEqual(rc, 1, out)
        self.assertIn("states no budget figure", out)

    def test_a_summary_naming_another_window_is_reported(self):
        tiers = self.tiers()
        tiers[0]["annotations"]["summary"] = "burning fast (2% in 2h)"
        rc, out = self.verdict(tiers)
        self.assertEqual(rc, 1, out)
        self.assertIn("measures over 1h", out)

    def test_two_burn_factors_in_one_rule_are_reported(self):
        tiers = self.tiers()
        tiers[0]["data"][0]["model"]["expr"] = (
            f"(sum(rate({NUMERATOR}[1h])) / 0.01 > bool 14.4)"
            f" * (sum(rate({NUMERATOR}[5m])) / 0.01 > bool 6)")
        rc, out = self.verdict(tiers)
        self.assertEqual(rc, 1, out)
        self.assertIn("2 different burn factors", out)

    def test_two_objective_windows_for_one_rule_are_reported(self):
        """Which panel states the objective decides the figure. A tree stating
        both has not decided, and picking one here would be this gate choosing
        the answer it checks against."""
        rc, out = self.verdict(self.tiers(), panel_exprs=(
            f"sum(rate({NUMERATOR}[30d]))",
            f"sum(rate({DENOMINATOR}[7d]))",
        ))
        self.assertEqual(rc, 1, out)
        self.assertIn("which of those", out.lower())

    def test_a_panel_that_stops_being_delivered_is_reported(self):
        """The dashboard is on disk, unedited, and renders fine — it is simply
        no longer in the kustomization's `resources`. The rules still ship and
        still burn; the panel measuring what they burn against does not. A
        figure anchored to a document no cluster receives is anchored to
        nothing."""
        rc, out = self.verdict(self.tiers(), ship_dashboard=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("no dashboard delivered by", out)

    def test_a_render_that_fails_cannot_run(self):
        """Exit 2. A kustomization that does not build says nothing about which
        panels a cluster receives, and the dashboards on disk say nothing about
        it either."""
        root = pathlib.Path(tempfile.mkdtemp())
        base = root / "dashboards" / "base"
        base.mkdir(parents=True)
        (base / "kustomization.yaml").write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\nresources:\n  - platform/gone.yaml\n")
        with self.assertRaises(SystemExit) as caught, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            gate.delivered_dashboards(base)
        self.assertEqual(caught.exception.code, gate.gatelib.CANNOT_RUN)
        self.assertIn("could not be read", out.getvalue())

    def test_no_burn_rule_at_all_cannot_run(self):
        """Exit 2. A directory with no burn rule reports what a directory of
        correct claims reports."""
        rc, out = self.verdict([rule("Rate", "error rate above 5%",
                                     f"sum(rate({DENOMINATOR}[5m])) > 0.05")])
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("no burn-rate rule", out)


class TheShippedCatalog(unittest.TestCase):
    """Over the tree, so a rule added with a wrong figure fails here."""

    def test_the_catalog_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(gate.main(), 0, out.getvalue())

    def test_the_ladder_carries_more_than_one_factor(self):
        """A catalog whose tiers all shared a factor would pass a gate that
        derived the figure from any one of them, so the corpus this runs over is
        asserted rather than assumed."""
        seen = set()
        for _p, _g, _r, expr in gate.burn_rules(gate.ALERT_DIR):
            seen |= gate.factors(expr)
        self.assertGreaterEqual(len(seen), 3, seen)

    def test_every_burn_rule_is_anchored_to_a_measured_objective(self):
        """The figure is only as good as the thing it is compared against."""
        windows = gate.objective_windows()
        for path, group_name, r, expr in gate.burn_rules(gate.ALERT_DIR):
            with self.subTest(rule=f"{path.name}:{r.get('title')}"):
                selectors = gate.long_window(expr)[1]
                self.assertTrue(
                    [s for s in selectors if s in windows],
                    f"{group_name}/{r.get('title')} burns against "
                    f"{selectors} and no dashboard panel measures any of them")

    def test_the_rules_this_reads_are_rules_the_catalog_delivers(self):
        """This gate reads the alerting directory; a cluster receives what the
        kustomization renders. It does not take the second reading itself,
        because check-alert-severity-routes.py already refuses a rule group on
        disk that the same root does not render — so the corpus here is the
        delivered one by way of that gate.

        Asserted rather than assumed. The two gates have to agree on the root
        and on the kind, and a narrowing on either side would otherwise leave
        this one reading files no cluster has, silently.
        """
        routes = load("check-alert-severity-routes")
        self.assertEqual(routes.KUSTOMIZE_ROOT, gate.KUSTOMIZE_ROOT,
                         "the two alerting gates render different roots, so one "
                         "of them is asserting over a tree the other does not")
        self.assertIn(gate.RULE_GROUP, routes.ALERTING_KINDS,
                      f"{routes.__name__} no longer refuses an unrendered "
                      f"{gate.RULE_GROUP}, so this gate's corpus is files on "
                      f"disk rather than what a cluster receives")

    def test_the_objective_is_read_from_the_dashboards_not_declared_here(self):
        """A constant agreeing with the standard today and compared to nothing
        tomorrow is the defect this gate was written for, one level up."""
        source = (ROOT / "scripts" / "check-burn-rate-budgets.py").read_text()
        self.assertNotIn("2592000", source)
        self.assertNotIn('"30d"', source)
        self.assertIn('subprocess.run(["kustomize", "build"', source)


if __name__ == "__main__":
    unittest.main()
