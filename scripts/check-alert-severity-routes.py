#!/usr/bin/env python3
"""Every label a rule routes on selects a route that exists.

WHY THIS EXISTS

A rule labelled `severity: page` is asking for a human to be woken. Grafana
keeps that promise by matching the label against a notification policy tree and
delivering to the receiver the matching route names. With no matching route the
alert falls to the tree's root, and with no tree at all it falls to the
workspace default policy and its empty default contact point.

Nothing else in this repository can see that. kubeconform SKIPs the
grafana.integreatly.org CRDs, the rules and the policy are separate documents
that never reference each other by name, and an alert that reaches nobody looks
exactly like an alert that has not fired. The signal arrives at the moment
nobody is watching a dashboard, which is the moment the delivery path is the
only thing there is.

WHAT IT CHECKS

The keys come from the POLICY, not from a list here. Whatever label keys the
routes match on are the keys that make a claim about delivery, so:

  * every value a rule carries for one of those keys matches a route for that
    key — an unrouted value falls to the root receiver, which is the bucket
    this gate exists to keep things out of;
  * every rule carries every key the policy routes on, because a rule missing
    one lands in the same bucket by a different path;
  * every receiver a route names is a contact point this catalog declares, in
    both directions — a route to a receiver nobody declares delivers nothing,
    and a contact point no route names is a destination that will not be
    reached by anything and rots the way an unread exemption does.

Derived rather than listed, so a new severity value, a new routing key or a
renamed contact point is caught by this gate rather than by an incident.

WHAT IT DOES NOT CHECK

Two facts about systems outside this repository, both of which must also hold
before a page is delivered, and neither of which is readable from this tree:

  * whether Amazon Managed Grafana ACCEPTS the contact point. A workspace
    enumerates the destination types it will create in its own configuration,
    and that configuration is the landing-zone managed-monitoring component's.
  * whether the credential each receiver reads is seeded. The contact points
    take theirs from a Secret an ExternalSecret materialises out of Secrets
    Manager, and what is in Secrets Manager is not in this repository.

So this asserts that the CATALOG routes every urgency it claims, which is the
half that lives here. A green run is not an assertion that a page arrived.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALERTING = ROOT / "dashboards" / "base" / "alerting"

RULE_GROUP = "GrafanaAlertRuleGroup"
POLICY = "GrafanaNotificationPolicy"
CONTACT_POINT = "GrafanaContactPoint"


def under_root(path: pathlib.Path) -> str:
    """`path` relative to the repository when it is inside it, else as given.

    Not `relative_to` alone: it RAISES for a path outside the root, and the one
    place this is called from is a refusal about a directory that is missing.
    A refusal that crashes while composing its own message exits with a
    traceback and the status of a rejection, which is the reading this gate's
    exit codes exist to keep apart.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def documents(directory: pathlib.Path) -> list[tuple[pathlib.Path, dict]]:
    """Every YAML document under `directory`, with the file it came from.

    The file is carried because a finding has to name one: these are eight
    files of near-identical shape and "a rule is unrouted" is not actionable
    without saying which.
    """
    if not directory.is_dir():
        print(f"Cannot run: {under_root(directory)} does not exist, so the "
              f"alert rules whose routing this gate checks are not there at all.")
        print("This gate examined nothing, which is not the same as finding nothing.")
        sys.exit(gatelib.CANNOT_RUN)
    out = []
    for path in sorted(directory.glob("*.yaml")):
        for doc in gatelib.read_yaml_all(path):
            if isinstance(doc, dict):
                out.append((path, doc))
    return out


def routes_of(route: dict):
    """Every route in the tree, depth first, including the root.

    Recursive because `routes` nests, and a nested route is as much a delivery
    decision as a top-level one.
    """
    yield route
    for child in route.get("routes") or []:
        if isinstance(child, dict):
            yield from routes_of(child)


def matcher_pairs(route: dict) -> list[tuple[str, str]]:
    """(label key, value) for every EXACT matcher on one route.

    Regex matchers are excluded rather than guessed at: deciding which rule
    labels a pattern admits means running the pattern, and a gate that reports
    a value as routed because it looked like it might match would be asserting
    the thing it exists to check. A regex route still counts as a route for its
    key — it just cannot vouch for a particular value.
    """
    pairs = []
    for m in route.get("matchers") or []:
        if not isinstance(m, dict) or m.get("isRegex"):
            continue
        name, value = m.get("name"), m.get("value")
        if isinstance(name, str) and isinstance(value, str):
            pairs.append((name, value))
    return pairs


def routing_keys(route: dict) -> set[str]:
    """The label keys the tree makes decisions on, exact or regex."""
    keys = set()
    for node in routes_of(route):
        for m in node.get("matchers") or []:
            if isinstance(m, dict) and isinstance(m.get("name"), str):
                keys.add(m["name"])
    return keys


def rule_labels(doc: dict):
    """(rule title, labels) for every rule in a GrafanaAlertRuleGroup."""
    for rule in (doc.get("spec") or {}).get("rules") or []:
        if not isinstance(rule, dict):
            continue
        labels = rule.get("labels")
        yield str(rule.get("title") or rule.get("uid") or "<unnamed>"), \
            labels if isinstance(labels, dict) else {}


def main() -> int:
    docs = documents(ALERTING)
    failures: list[str] = []

    policies = [(p, d) for p, d in docs if d.get("kind") == POLICY]
    contact_points = {str((d.get("spec") or {}).get("name")
                          or (d.get("metadata") or {}).get("name")): p
                      for p, d in docs if d.get("kind") == CONTACT_POINT}
    rule_groups = [(p, d) for p, d in docs if d.get("kind") == RULE_GROUP]

    if not rule_groups:
        print(f"FAIL  no {RULE_GROUP} found under "
              f"{under_root(ALERTING)} — this gate examined no rule, which "
              f"reports the same as a catalog whose rules are all routed.")
        return gatelib.CANNOT_RUN
    if not policies:
        print(f"FAIL  {len(rule_groups)} rule group(s) are delivered by no "
              f"{POLICY}. Every label they carry selects the workspace default "
              f"policy and its empty default contact point, so a rule asking to "
              f"page reaches nobody.")
        return 1
    if len(policies) > 1:
        print(f"FAIL  {len(policies)} {POLICY} resources: "
              f"{', '.join(sorted(str(p.name) for p, _ in policies))}. Grafana "
              f"keeps one routing tree per instance, so which of these delivers "
              f"an alert is decided by whichever reconciled last.")
        return 1

    _, policy = policies[0]
    root = (policy.get("spec") or {}).get("route") or {}
    keys = routing_keys(root)
    if not keys:
        print(f"FAIL  the {POLICY} matches on no label at all, so every alert "
              f"takes the root route and the severities the rules carry decide "
              f"nothing.")
        return 1

    # Which values each key can be routed to, and which receivers are reachable.
    routed: dict[str, set[str]] = {k: set() for k in keys}
    receivers = {str(node.get("receiver")) for node in routes_of(root)
                 if node.get("receiver")}
    reached: set[str] = set()
    for node in routes_of(root):
        pairs = matcher_pairs(node)
        for key, value in pairs:
            routed.setdefault(key, set()).add(value)
        if pairs and node.get("receiver"):
            reached.add(str(node["receiver"]))

    for receiver in sorted(receivers):
        if receiver not in contact_points:
            failures.append(
                f"the notification policy routes to receiver '{receiver}' and no "
                f"{CONTACT_POINT} in this catalog declares it — Grafana has "
                f"nowhere to deliver what that route matches.")
    for name in sorted(contact_points):
        if name not in receivers:
            failures.append(
                f"{contact_points[name].name} declares the contact point '{name}' "
                f"and no route in the notification policy names it — a "
                f"destination nothing reaches is one nobody re-reads.")

    for path, doc in rule_groups:
        group = (doc.get("metadata") or {}).get("name", path.name)
        for title, labels in rule_labels(doc):
            for key in sorted(keys):
                value = labels.get(key)
                if value is None:
                    failures.append(
                        f"{path.name}: {group}/{title} carries no '{key}' label and "
                        f"the notification policy routes on it, so this rule takes "
                        f"the root route whatever it is asking for.")
                elif str(value) not in routed.get(key, set()):
                    failures.append(
                        f"{path.name}: {group}/{title} is labelled {key}={value} and "
                        f"no route matches that value — it falls to the root "
                        f"receiver, which is where an unrouted alert goes to be "
                        f"read late or not at all.")

    if failures:
        print(f"{len(failures)} alert-routing problem(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1

    covered = sum(len(v) for v in routed.values())
    print(f"✓ every alert rule routes to a declared contact point: "
          f"{sum(len(list(rule_labels(d))) for _, d in rule_groups)} rule(s) across "
          f"{len(rule_groups)} group(s), matched on "
          f"{', '.join(sorted(keys))} against {covered} routed value(s) reaching "
          f"{len(contact_points)} contact point(s)")
    print("  what AMG accepts and what Secrets Manager holds are outside this "
          "repository and outside this claim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
