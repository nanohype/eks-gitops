#!/usr/bin/env python3
"""An addon carries a values file for every environment its ApplicationSet reaches.

An ApplicationSet's cluster selector decides which environments an addon lands
on. Its values files decide which environments it can be rendered for. Nothing
compared the two, and they disagree in the direction that fails at sync:

  addons-bootstrap.yaml selects every cluster with no `environment NotIn [hub]`
  exclusion, and templates `values-{{ environment }}.yaml` unconditionally. A
  bootstrap addon without values-hub.yaml is therefore selected for the hub and
  its Application points at a valueFile that does not exist.

WHY NO EXISTING GATE CATCHES IT

render-addons.py treats a missing `values-<env>.yaml` as "this addon is not
deployed to this environment" and returns success — which is correct for an
addon whose appset excludes that environment, and wrong for one whose appset
does not. The distinction is in the selector, and render-addons never reads it.
So the helm-render gate is green on exactly the manifest that breaks.

That asymmetry is the whole point of this gate: the same missing file is either
correct or fatal depending on a fact held in a different file.

HOW REACH IS DERIVED

From the `clusters` generator's selector, not from a list:

  * `matchExpressions` with key `environment` and operator NotIn/In narrows the
    set. This is how the catalog spells an exclusion today.
  * a `matchLabels` entry other than the secret-type marker (for example
    `observability/tier: full`) narrows reach to clusters carrying that label.
    Which environments those are is not knowable from this repo, so an addon
    behind such a label is reported as label-gated and its env set is not
    asserted — stated rather than silently assumed to be all four.
  * otherwise the appset reaches every environment.

An appset whose selector this parser cannot classify FAILS rather than being
skipped, so a new selector shape cannot quietly opt out of the check.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"

ENVIRONMENTS = ["development", "staging", "production", "hub"]

# The label every cluster Secret carries; it selects clusters, not environments.
SECRET_TYPE = "argocd.argoproj.io/secret-type"

# A floor on the corpus. A glob that stops matching reports what a clean tree
# reports, so the count is asserted rather than inferred from a quiet run.
MIN_PAIRS = 20


def matrix_generators(doc: dict):
    gens = (doc.get("spec") or {}).get("generators") or []
    for g in gens:
        if "matrix" in g:
            yield from (g["matrix"].get("generators") or [])
        else:
            yield g


def reach(doc: dict, name: str) -> tuple[set[str] | None, str]:
    """(environments the appset reaches, why) — None means label-gated."""
    sel = None
    for g in matrix_generators(doc):
        if "clusters" in g:
            sel = (g["clusters"] or {}).get("selector") or {}
            break
    if sel is None:
        return set(ENVIRONMENTS), "no cluster selector — reaches every environment"

    envs = set(ENVIRONMENTS)
    why = []

    extra_labels = {k: v for k, v in (sel.get("matchLabels") or {}).items()
                    if k != SECRET_TYPE}
    if extra_labels:
        return None, ("gated on " + ", ".join(f"{k}={v}" for k, v in sorted(extra_labels.items())))

    for expr in sel.get("matchExpressions") or []:
        key, op = expr.get("key"), expr.get("operator")
        vals = set(expr.get("values") or [])
        if key != "environment":
            return None, f"gated on label {key!r} ({op})"
        if op == "NotIn":
            envs -= vals
            why.append(f"excludes {', '.join(sorted(vals))}")
        elif op == "In":
            envs &= vals
            why.append(f"only {', '.join(sorted(vals))}")
        else:
            raise ValueError(f"{name}: unhandled operator {op!r} on `environment`")

    return envs, "; ".join(why) or "reaches every environment"


# `$values/<path>/values-<env>.yaml` on a single-source appset. Nine of this
# catalog's Helm appsets use that shape instead of a matrix list element, and
# reading only the list shape left every one of them out of the comparison —
# including addons-otel-agent, which is one of the two that reach the hub.
SOURCE_PATH = re.compile(r"\$values/(?P<path>addons/[^/\s]+/[^/\s]+)/values\.yaml")


def addon_paths(doc: dict, text: str):
    """(appName, path) for every addon this appset templates per-env values for."""
    seen = set()
    for g in matrix_generators(doc):
        for el in (g.get("list") or {}).get("elements") or []:
            if isinstance(el, dict) and el.get("path") and el.get("chart"):
                rel = el["path"]
                seen.add(rel)
                yield el.get("appName") or rel.rsplit("/", 1)[-1], rel
    for m in SOURCE_PATH.finditer(text):
        rel = m.group("path")
        if rel not in seen:
            seen.add(rel)
            yield rel.rsplit("/", 1)[-1], rel


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()
    appsets = root / "applicationsets"

    failures: list[str] = []
    gated: list[str] = []
    pairs = 0

    for path in sorted(appsets.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
                continue
            name = path.name
            # Only appsets that template a per-environment values file are in
            # scope: one that does not cannot break on a missing delta.
            if "values-{{" not in path.read_text():
                continue
            try:
                envs, why = reach(doc, name)
            except ValueError as exc:
                failures.append(str(exc))
                continue
            if envs is None:
                gated.append(f"{name}: {why}")
                continue
            for app, rel in addon_paths(doc, path.read_text()):
                d = root / rel
                if not d.is_dir():
                    failures.append(f"{name}: {app} path {rel} does not exist")
                    continue
                pairs += 1
                missing = [e for e in sorted(envs)
                           if not (d / f"values-{e}.yaml").exists()]
                if missing:
                    failures.append(
                        f"{name}: {app} is selected for {', '.join(sorted(envs))} "
                        f"({why}) but carries no "
                        f"{', '.join('values-' + m + '.yaml' for m in missing)}. "
                        f"ArgoCD templates that valueFile unconditionally, so the "
                        f"Application points at a file that does not exist and the "
                        f"sync fails — while the helm-render gate reads the same "
                        f"absence as 'not deployed to this environment' and passes.")

    if pairs < MIN_PAIRS:
        print(f"FAIL  compared only {pairs} appset/addon pair(s), fewer than the "
              f"{MIN_PAIRS} this catalog carries — the parser and the tree disagree "
              f"about shape, so a pass here would prove nothing.")
        return 2

    if gated:
        print("Label-gated appsets — reach is not derivable from this repo, so their "
              "environment coverage is NOT asserted:")
        for g in gated:
            print(f"  {g}")
        print()

    if failures:
        print(f"{len(failures)} addon(s) reachable in an environment they cannot render:\n")
        for f in failures:
            print(f"  {f}")
        return 1

    print(f"✓ {pairs} appset/addon pair(s): every addon carries a values file for "
          f"every environment its ApplicationSet selector reaches "
          f"({len(gated)} label-gated appset(s) not asserted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
