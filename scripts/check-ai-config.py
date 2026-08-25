#!/usr/bin/env python3
"""The AI control plane's own CRs are internally consistent and policy-conformant.

Sixteen gates check the catalog's manifests; none checked what the AI platform's
CRs say to each other. Three edits that break at runtime passed every one of
them: a ModelGateway route naming a model the Platform's allowlist omits, a
BudgetPolicy whose platformRef names nothing, and a bare foundation-model id.

Each fails in a different place and none fails here without this gate. The
allowlist mismatch surfaces as an AccessDenied at the first invocation, which
reads as an IAM problem. The dangling budget reference means the kill-switch has
nothing to suspend, and a budget that cannot fire looks exactly like a budget
that has not fired. The bare model id is refused by Bedrock with a
ValidationException on the first call, on a path nobody exercises until an agent
runs.

WHAT IT ASSERTS

  Model ids (nanohype llm-policy)
    * Every id is a cross-region inference profile, never a bare
      foundation-model id. Bedrock reports inferenceTypesSupported:
      [INFERENCE_PROFILE] for the whole Claude family, so there is no on-demand
      path and `anthropic.claude-sonnet-5` is a ValidationException, not a
      slower route.
    * The geo prefix is `us.`, matching the single region the policy names.
      `global.` is a valid profile and the wrong one here: it may route outside
      the jurisdiction the account's service-control policy exists to bound.
    * Every id names a tier the policy defines, so a model outside the
      default/escalation/light set cannot arrive without this file changing too.

  Internal references
    * Every ModelGateway route's modelId appears in its Platform's allowedModels.
    * Every ModelGateway and BudgetPolicy platformRef names a Platform that
      exists in the same overlay.
    * Every Platform's budget.name names a BudgetPolicy that exists.
    * Every Platform's tenant names a Tenant that exists.

  Budget
    * Every Platform carries a budget reference, and its BudgetPolicy sets
      killSwitchEnabled. A spend ceiling nothing enforces is a dashboard.

The corpus is asserted, not assumed: finding no Platform CRs fails rather than
passing, because a glob that stops matching reports exactly what a clean tree
reports.
"""

from __future__ import annotations

import importlib.util
import argparse
import pathlib
import sys

import yaml

# Shared helpers, loaded by path: these are hyphenated executables run from
# varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


ROOT = pathlib.Path(__file__).resolve().parent.parent

# nanohype llm-policy: the model tiers, as inference-profile ids. Claude is the
# primary family and Bedrock the delivery, so these are the only ids a route or
# an allowlist may name.
#
# A SNAPSHOT, committed here on purpose, and a cache rather than a second source
# of truth. Resolving the standard at run time from a sibling checkout, an env
# var or a local cache would make this gate a function of the machine it runs
# on: none of those exist on a CI runner, so the gate would take a skip branch
# and report success in the one place it actually gates. Held in the repo, the
# check is deterministic and identical everywhere.
#
# The cost of a snapshot is drift, so check_policy_drift() below compares it
# against the published standard WHEREVER that resolves, and says plainly when
# it could not. The comparison is an extra assertion, never a precondition —
# the tier check above runs either way.
POLICY_MODELS = {
    "us.anthropic.claude-sonnet-5": "default",
    "us.anthropic.claude-opus-5": "escalation",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0": "light",
}

# Where the published standard may be found, in order. Absence is not failure;
# a stale snapshot is.
STANDARD_PATHS = (
    pathlib.Path.home() / "codes/nanohype/nanohype/standards/llm-policy.json",
    ROOT.parent / "nanohype/standards/llm-policy.json",
)


def check_policy_drift() -> tuple[list[str], str]:
    """(problems, what-was-compared) for the snapshot against the standard."""
    import json

    for path in STANDARD_PATHS:
        if not path.is_file():
            continue
        try:
            doc = gatelib.read_json(path)
            models = doc["content"]["models"]
        except (ValueError, KeyError) as exc:
            return ([f"{path} is not a readable llm-policy standard ({exc}). The "
                     f"snapshot in this file could not be checked for drift."],
                    f"unreadable: {path}")
        want = {v: k for k, v in models.items()}
        if want != POLICY_MODELS:
            only_std = sorted(set(want) - set(POLICY_MODELS))
            only_here = sorted(set(POLICY_MODELS) - set(want))
            return ([f"POLICY_MODELS has drifted from {path}. "
                     f"In the standard and not here: {only_std or 'none'}. "
                     f"Here and not in the standard: {only_here or 'none'}. "
                     f"Update the snapshot in this file to match."],
                    f"compared against {path}")
        return ([], f"matches {path}")

    return ([], "NOT COMPARED — the published standard resolves nowhere on this "
                "machine, so the snapshot is unverified here. The tier check "
                "still ran.")

# The geo prefix the policy names, matching its single preferred region. A
# `global.` profile resolves and routes anywhere, which is the reason it is
# excluded rather than an oversight.
GEO_PREFIX = "us."

AI_KINDS = {"Platform", "Tenant", "BudgetPolicy", "ModelGateway", "AgentFleet"}


def load(paths) -> list[tuple[pathlib.Path, dict]]:
    docs = []
    for p in paths:
        for d in gatelib.read_yaml_all(p):
            if isinstance(d, dict) and d.get("kind") in AI_KINDS:
                docs.append((p, d))
    return docs


def model_ids(doc: dict):
    """(where, id) for every model id a document names."""
    spec = doc.get("spec") or {}
    for m in (spec.get("identity") or {}).get("allowedModels") or []:
        yield "identity.allowedModels", m
    for route in spec.get("routes") or []:
        if isinstance(route, dict) and route.get("modelId"):
            yield f"routes[{route.get('name', '?')}].modelId", route["modelId"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()

    base = root / "addons/ai-platform"
    paths = sorted(p for p in base.rglob("*.yaml")) if base.is_dir() else []
    docs = load(paths)

    platforms = {d["metadata"]["name"]: (p, d) for p, d in docs if d["kind"] == "Platform"}
    tenants = {d["metadata"]["name"] for _, d in docs if d["kind"] == "Tenant"}
    budgets = {d["metadata"]["name"]: d for _, d in docs if d["kind"] == "BudgetPolicy"}
    gateways = [(p, d) for p, d in docs if d["kind"] == "ModelGateway"]

    if not platforms:
        print("FAIL  found no Platform CRs under addons/ai-platform/ — the AI control "
              "plane is either gone or this gate stopped matching it, and both report "
              "the same clean result.")
        return 2

    failures, drift_note = check_policy_drift()
    checked = 0

    def rel(p):
        return p.relative_to(root)

    # ── model ids ────────────────────────────────────────────────────────────
    for path, doc in docs:
        for where, mid in model_ids(doc):
            checked += 1
            loc = f"{rel(path)} {doc['kind']}/{doc['metadata']['name']} {where}"
            if "." not in mid.split(".", 1)[0] and not mid.startswith(("us.", "eu.", "apac.", "global.")):
                failures.append(
                    f"{loc}: {mid!r} is a bare foundation-model id. Bedrock reports "
                    f"INFERENCE_PROFILE-only for this family, so the first call is a "
                    f"ValidationException.")
                continue
            if not mid.startswith(GEO_PREFIX):
                failures.append(
                    f"{loc}: {mid!r} does not carry the {GEO_PREFIX!r} geo prefix. The "
                    f"prefix must match the deploy region — a global profile may route "
                    f"outside the jurisdiction the account's SCP bounds.")
                continue
            if mid not in POLICY_MODELS:
                failures.append(
                    f"{loc}: {mid!r} is not one of the tiers llm-policy names "
                    f"({', '.join(sorted(POLICY_MODELS))}).")

    # ── internal references ──────────────────────────────────────────────────
    for path, doc in gateways:
        name = doc["metadata"]["name"]
        spec = doc.get("spec") or {}
        ref = (spec.get("platformRef") or {}).get("name")
        checked += 1
        if ref not in platforms:
            failures.append(
                f"{rel(path)} ModelGateway/{name}: platformRef names {ref!r}, which no "
                f"Platform in this overlay defines.")
            continue
        allowed = set(((platforms[ref][1].get("spec") or {}).get("identity") or {})
                      .get("allowedModels") or [])
        for route in spec.get("routes") or []:
            checked += 1
            mid = route.get("modelId")
            if allowed and mid not in allowed:
                failures.append(
                    f"{rel(path)} ModelGateway/{name} route {route.get('name')!r}: "
                    f"modelId {mid!r} is absent from Platform/{ref}'s allowedModels, so "
                    f"the route resolves and every invocation is denied by IAM.")

    for name, (path, doc) in sorted(platforms.items()):
        spec = doc.get("spec") or {}
        checked += 1
        tenant = spec.get("tenant")
        if tenant not in tenants:
            failures.append(
                f"{rel(path)} Platform/{name}: tenant {tenant!r} names no Tenant CR in "
                f"this overlay.")
        budget = (spec.get("budget") or {}).get("name")
        checked += 1
        if not budget:
            failures.append(
                f"{rel(path)} Platform/{name}: carries no budget reference, so nothing "
                f"bounds its spend.")
        elif budget not in budgets:
            failures.append(
                f"{rel(path)} Platform/{name}: budget {budget!r} names no BudgetPolicy, "
                f"so the kill-switch has nothing to suspend and a budget that cannot "
                f"fire is indistinguishable from one that has not.")
        elif not budgets[budget].get("spec", {}).get("killSwitchEnabled"):
            failures.append(
                f"{rel(path)} BudgetPolicy/{budget}: killSwitchEnabled is not set. A "
                f"spend ceiling nothing enforces is a dashboard.")

    for name, doc in sorted(budgets.items()):
        checked += 1
        ref = (doc.get("spec") or {}).get("platformRef", {}).get("name")
        if ref not in platforms:
            failures.append(
                f"BudgetPolicy/{name}: platformRef names {ref!r}, which no Platform "
                f"defines — the policy applies to nothing.")

    if failures:
        print(f"AI control-plane configuration has {len(failures)} problem(s) "
              f"({checked} assertion(s) over {len(docs)} CR(s)):\n")
        for f in failures:
            print(f"  {f}")
        return 1

    print(f"  llm-policy snapshot: {drift_note}")
    print(f"✓ {checked} assertion(s) over {len(docs)} AI control-plane CR(s): every model "
          f"id is a {GEO_PREFIX}-prefixed inference profile at an llm-policy tier, every "
          f"route is allowlisted, and every Platform has an enforcing budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
