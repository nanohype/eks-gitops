#!/usr/bin/env python3
"""Sync-wave gate — assert the documented deploy ordering holds across the
applied ApplicationSets.

Sync waves are how the catalog expresses "X before Y": cert-manager and the CNI
must be up before anything that needs TLS or pod networking; security admission
before the workloads it guards; the autoscaler before the pods it schedules. The
ordering is documented in CLAUDE.md ("Sync Waves") and lives, unenforced, as a
per-ApplicationSet annotation plus per-Application waves. A wave typo — an
observability chart set below security, an operations addon jumped ahead of the
CNI — renders clean, schema-validates clean, and only surfaces as a stuck sync or
a crash-loop on a real cluster. This gate catches it at PR time.

Two assertions:

  A. CATEGORY ORDERING. The eight primary addon categories deploy in the
     documented sequence — bootstrap < networking < security < observability <
     operations < ai-platform < argo-platform < apps — read from each category's
     primary ApplicationSet's own sync-wave annotation.

  B. PER-APPLICATION BANDS. Every Application's wave sits inside its category's
     documented band (CLAUDE.md), so no single addon can be nudged into a
     conflicting slot. The one intentional cross-band deployer — karpenter, which
     the catalog documents at wave 5 so the autoscaler is ready before the
     workloads it must provision nodes for — is allow-listed explicitly.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSET_DIR = REPO_ROOT / "applicationsets"
WAVE_ANNOTATION = "argocd.argoproj.io/sync-wave"

# The documented category sequence and the primary ApplicationSet that anchors
# each category's wave (auxiliary appsets — the operator at 21, the agent CRs at
# 44 — deploy around it but do not set the category's anchor).
PRIMARY_ORDER = [
    ("bootstrap", "addons-bootstrap.yaml"),
    ("networking", "addons-networking.yaml"),
    ("security", "addons-security.yaml"),
    ("observability", "addons-observability.yaml"),
    ("operations", "addons-operations-helm.yaml"),
    ("ai-platform", "addons-ai-platform.yaml"),
    ("argo-platform", "addons-argo-platform.yaml"),
]

# Per-category wave bands (inclusive), from CLAUDE.md "Sync Waves".
BANDS = {
    "bootstrap": (0, 2),
    "networking": (1, 1),
    "security": (10, 12),
    "policies": (20, 23),
    "observability": (29, 34),
    "gateway-crds": (30, 30),
    "operations": (40, 44),
    "ai-platform": (21, 44),
    "argo-platform": (50, 52),
    "apps": (50, 60),
}

# Documented cross-band exceptions: (category, addon, wave). karpenter is
# catalogued under operations but deploys at wave 5 — after the CNI, before
# security and workloads — so the autoscaler can provision nodes for everything
# that follows.
EXCEPTIONS = {("operations", "karpenter", 5)}

# ApplicationSets whose category is not derivable from an addons/<category>/ path.
FILE_CATEGORY = {
    "secret-stores.yaml": "bootstrap",
    "kyverno-policies.yaml": "policies",
    "gateway-api-crds.yaml": "gateway-crds",
    "agent-platform.yaml": "ai-platform",
    "addons-agent-operator.yaml": "ai-platform",
    "dashboards.yaml": "apps",
}


def _category(appset_file: str, path: str | None) -> str | None:
    if path:
        m = re.match(r"addons/([^/]+)/", path)
        if m:
            return m.group(1)
    return FILE_CATEGORY.get(appset_file)


def _list_elements(spec: dict) -> list[dict]:
    for gen in spec.get("generators", []) or []:
        for inner in (gen.get("matrix", {}) or {}).get("generators", []) or []:
            lst = inner.get("list")
            if lst and lst.get("elements"):
                return lst["elements"]
    return []


def _single_path(spec: dict) -> str | None:
    for src in spec.get("template", {}).get("spec", {}).get("sources", []) or []:
        for vf in (src.get("helm", {}) or {}).get("valueFiles", []) or []:
            m = re.match(r"\$values/(.+)/values\.yaml$", vf)
            if m:
                return m.group(1)
        if src.get("path") and "{{" not in src["path"]:
            return src["path"]
    return None


def main() -> int:
    appset_waves: dict[str, int] = {}
    apps: list[tuple[str, str, str, int]] = []  # appset, category, addon, wave

    for appset_file in sorted(APPSET_DIR.glob("*.yaml")):
        doc = yaml.safe_load(appset_file.read_text())
        if not doc or doc.get("kind") != "ApplicationSet":
            continue
        name = appset_file.name
        spec = doc["spec"]
        ann = doc["metadata"].get("annotations", {}) or {}
        if WAVE_ANNOTATION in ann:
            appset_waves[name] = int(ann[WAVE_ANNOTATION])

        elements = _list_elements(spec)
        if elements:
            for el in elements:
                path = el.get("path")
                cat = _category(name, path)
                addon = (path or el.get("appName", "")).rsplit("/", 1)[-1]
                apps.append((name, cat, addon, int(el["syncWave"])))
        else:
            path = _single_path(spec)
            cat = _category(name, path)
            tmpl_ann = (
                spec.get("template", {}).get("metadata", {}).get("annotations", {}) or {}
            )
            wave = tmpl_ann.get(WAVE_ANNOTATION, ann.get(WAVE_ANNOTATION))
            addon = (path or name).rsplit("/", 1)[-1]
            apps.append((name, cat, addon, int(wave)))

    errors: list[str] = []

    # A. Category ordering.
    print("Category ordering (primary appset anchors):")
    prev_cat, prev_wave = None, None
    for cat, primary in PRIMARY_ORDER:
        if primary not in appset_waves:
            errors.append(f"category '{cat}': primary appset {primary} not found or has no sync-wave")
            continue
        wave = appset_waves[primary]
        marker = "ok"
        if prev_wave is not None and wave < prev_wave:
            marker = "CONFLICT"
            errors.append(
                f"category ordering: {cat} (wave {wave}) deploys before {prev_cat} "
                f"(wave {prev_wave}) — must be >= it"
            )
        print(f"  {marker:9} {cat:15} wave {wave:>3}  ({primary})")
        prev_cat, prev_wave = cat, wave

    # B. Per-Application bands.
    print("\nPer-Application wave bands:")
    for name, cat, addon, wave in apps:
        if cat is None:
            errors.append(f"{name}: cannot classify addon '{addon}' into a category")
            continue
        if (cat, addon, wave) in EXCEPTIONS:
            print(f"  allow     {cat:15} {addon:24} wave {wave:>3}  (documented exception)")
            continue
        if cat not in BANDS:
            errors.append(f"{name}: category '{cat}' has no documented wave band")
            continue
        lo, hi = BANDS[cat]
        if not lo <= wave <= hi:
            errors.append(
                f"{name}: {addon} wave {wave} outside {cat} band [{lo}, {hi}]"
            )
            print(f"  CONFLICT  {cat:15} {addon:24} wave {wave:>3}  (band [{lo}, {hi}])")

    if errors:
        print(f"\n{len(errors)} sync-wave conflict(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"\nAll {len(apps)} Applications respect the documented wave ordering.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
