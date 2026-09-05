"""Unit tests for the alert-routing gate.

The gate's own failure mode is a FALSE PASS: reporting a rule as routed when
nothing delivers it. That failure is silent in the one moment it matters,
because an alert reaching nobody looks exactly like an alert that has not
fired — so these concentrate on the cases where a route looks present and is
not.

The keys the gate routes on come from the policy, so the fixtures vary the
POLICY as well as the rules. A gate that read a hardcoded `severity` would pass
every case here that uses that key and none of the ones that do not, which is
what separates deriving the keys from listing them.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import tempfile
import unittest

import yaml
from gateloader import load

gate = load("check-alert-severity-routes")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def rule_group(name, *rules):
    return {"apiVersion": "grafana.integreatly.org/v1beta1",
            "kind": "GrafanaAlertRuleGroup",
            "metadata": {"name": name},
            "spec": {"rules": [{"title": t, "labels": labels}
                               for t, labels in rules]}}


def contact_point(name):
    return {"apiVersion": "grafana.integreatly.org/v1beta1",
            "kind": "GrafanaContactPoint",
            "metadata": {"name": name},
            "spec": {"name": name, "receivers": []}}


def policy(route):
    return {"apiVersion": "grafana.integreatly.org/v1beta1",
            "kind": "GrafanaNotificationPolicy",
            "metadata": {"name": "routes"},
            "spec": {"route": route}}


def exact(key, value):
    return {"name": key, "value": value, "isEqual": True, "isRegex": False}


class TheVerdict(unittest.TestCase):
    """main() over a planted alerting directory."""

    def verdict(self, *docs):
        root = pathlib.Path(tempfile.mkdtemp())
        alerting = root / "dashboards" / "base" / "alerting"
        alerting.mkdir(parents=True)
        for i, doc in enumerate(docs):
            (alerting / f"{i:02d}-{doc['kind']}.yaml").write_text(yaml.safe_dump(doc))
        saved = (gate.ROOT, gate.ALERTING)
        gate.ROOT, gate.ALERTING = root, alerting
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = gate.main()
        finally:
            gate.ROOT, gate.ALERTING = saved
        return rc, out.getvalue()

    ROUTED = policy({"receiver": "low",
                     "routes": [{"receiver": "urgent", "matchers": [exact("severity", "page")]},
                                {"receiver": "low", "matchers": [exact("severity", "ticket")]}]})

    def healthy(self):
        return (self.ROUTED, contact_point("urgent"), contact_point("low"),
                rule_group("g", ("Paging", {"severity": "page"}),
                           ("Ticketing", {"severity": "ticket"})))

    def test_a_routed_catalog_passes(self):
        """The control. Without it every case below could be failing for a
        reason the case did not plant."""
        rc, out = self.verdict(*self.healthy())
        self.assertEqual(rc, 0, out)

    def test_a_severity_no_route_matches_is_reported(self):
        """The defect, exactly: the rule parses, evaluates and changes state,
        and its label selects no route."""
        rc, out = self.verdict(
            self.ROUTED, contact_point("urgent"), contact_point("low"),
            rule_group("g", ("Loud", {"severity": "critical"})))
        self.assertEqual(rc, 1)
        self.assertIn("severity=critical", out)
        self.assertIn("root receiver", out)

    def test_a_rule_missing_a_routed_key_is_reported(self):
        """Same bucket by a different path: no label at all takes the root
        route as surely as an unrouted value does."""
        rc, out = self.verdict(
            self.ROUTED, contact_point("urgent"), contact_point("low"),
            rule_group("g", ("Silent", {"service": "portal"})))
        self.assertEqual(rc, 1)
        self.assertIn("carries no 'severity' label", out)

    def test_no_policy_at_all_is_reported(self):
        """The state this gate was written against — every rule delivered by the
        workspace default policy and its empty default contact point."""
        rc, out = self.verdict(rule_group("g", ("Paging", {"severity": "page"})))
        self.assertEqual(rc, 1)
        self.assertIn("delivered by no GrafanaNotificationPolicy", out)

    def test_two_policies_are_reported(self):
        """Grafana keeps one tree per instance, so a second is not additional
        routing — it is whichever reconciled last."""
        rc, out = self.verdict(self.ROUTED, policy({"receiver": "low"}),
                               contact_point("low"),
                               rule_group("g", ("Paging", {"severity": "page"})))
        self.assertEqual(rc, 1)
        self.assertIn("2 GrafanaNotificationPolicy", out)

    def test_a_policy_matching_on_nothing_is_reported(self):
        """A tree with no matcher routes everything to the root, so the
        severities the rules carry decide nothing."""
        rc, out = self.verdict(policy({"receiver": "low"}), contact_point("low"),
                               rule_group("g", ("Paging", {"severity": "page"})))
        self.assertEqual(rc, 1)
        self.assertIn("matches on no label at all", out)

    def test_a_route_to_an_undeclared_receiver_is_reported(self):
        rc, out = self.verdict(
            self.ROUTED, contact_point("low"),
            rule_group("g", ("Paging", {"severity": "page"}),
                       ("Ticketing", {"severity": "ticket"})))
        self.assertEqual(rc, 1)
        self.assertIn("receiver 'urgent'", out)
        self.assertIn("nowhere to deliver", out)

    def test_a_contact_point_no_route_names_is_reported(self):
        """The direction that rots. A destination nothing reaches is a
        declaration nobody re-reads, and it widens the same way an unused
        exemption does."""
        rc, out = self.verdict(
            self.ROUTED, contact_point("urgent"), contact_point("low"),
            contact_point("orphan"),
            rule_group("g", ("Paging", {"severity": "page"}),
                       ("Ticketing", {"severity": "ticket"})))
        self.assertEqual(rc, 1)
        self.assertIn("'orphan'", out)

    def test_no_rule_group_at_all_cannot_run(self):
        """Exit 2. A directory with no rules is a gate that examined nothing,
        which reports the same as a catalog whose rules are all routed."""
        rc, out = self.verdict(self.ROUTED, contact_point("urgent"),
                               contact_point("low"))
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertIn("examined no rule", out)

    def test_a_missing_directory_cannot_run(self):
        saved = gate.ALERTING
        gate.ALERTING = pathlib.Path(tempfile.mkdtemp()) / "gone"
        try:
            with self.assertRaises(SystemExit) as caught, \
                    contextlib.redirect_stdout(io.StringIO()):
                gate.documents(gate.ALERTING)
            self.assertEqual(caught.exception.code, gate.gatelib.CANNOT_RUN)
        finally:
            gate.ALERTING = saved


class TheKeysComeFromThePolicy(unittest.TestCase):
    """Not from a list here, so a routing decision added later is covered."""

    def test_a_key_other_than_severity_is_required_of_every_rule(self):
        keys = gate.routing_keys({"receiver": "r", "routes": [
            {"receiver": "r", "matchers": [exact("team", "platform")]}]})
        self.assertEqual(keys, {"team"})

    def test_every_key_the_tree_matches_on_is_collected(self):
        keys = gate.routing_keys({"receiver": "r", "routes": [
            {"receiver": "a", "matchers": [exact("severity", "page")]},
            {"receiver": "b", "matchers": [exact("team", "platform")],
             "routes": [{"receiver": "c", "matchers": [exact("region", "us-west-2")]}]}]})
        self.assertEqual(keys, {"severity", "team", "region"})

    def test_a_nested_route_is_a_delivery_decision_too(self):
        """`routes` nests, and a child route delivers as much as a top-level
        one — walking only the first level reports a nested destination as
        absent."""
        root = {"receiver": "r", "routes": [
            {"receiver": "a", "matchers": [exact("severity", "page")],
             "routes": [{"receiver": "deep", "matchers": [exact("severity", "urgent")]}]}]}
        self.assertEqual(len(list(gate.routes_of(root))), 3)
        self.assertIn("deep", {n.get("receiver") for n in gate.routes_of(root)})

    def test_a_regex_matcher_routes_its_key_but_vouches_for_no_value(self):
        """Deciding which values a pattern admits means running the pattern, and
        a gate reporting a value as routed because it looked like it might match
        would be asserting the thing it exists to check."""
        node = {"receiver": "r", "matchers": [
            {"name": "severity", "value": "page|ticket", "isRegex": True}]}
        self.assertEqual(gate.routing_keys(node), {"severity"})
        self.assertEqual(gate.matcher_pairs(node), [])


class TheShippedCatalogRoutes(unittest.TestCase):
    """Over the tree, so a rule added with a new severity fails here."""

    def test_every_severity_the_rules_use_is_routed(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 0)

    def test_the_rules_carry_at_least_two_severities(self):
        """A catalog using one severity would pass a gate that routed only that
        one, so the corpus this runs over is asserted rather than assumed."""
        docs = gate.documents(gate.ALERTING)
        severities = {str(labels.get("severity"))
                      for _, d in docs if d.get("kind") == gate.RULE_GROUP
                      for _, labels in gate.rule_labels(d)}
        self.assertGreaterEqual(len(severities), 2, severities)

    def test_every_declared_contact_point_takes_its_secret_from_a_reference(self):
        """A credential in git is the other way to make a route resolve, and it
        is not one this catalog takes."""
        for path, doc in gate.documents(gate.ALERTING):
            if doc.get("kind") != gate.CONTACT_POINT:
                continue
            for receiver in (doc.get("spec") or {}).get("receivers") or []:
                with self.subTest(contact_point=path.name, type=receiver.get("type")):
                    self.assertTrue(receiver.get("valuesFrom"),
                                    "this receiver carries no valuesFrom, so whatever "
                                    "it authenticates with is committed here")


if __name__ == "__main__":
    unittest.main()
