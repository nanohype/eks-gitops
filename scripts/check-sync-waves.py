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

Three assertions:

  A. CATEGORY ORDERING. The eight primary addon categories deploy in the
     documented sequence — bootstrap < networking < security < observability <
     operations < ai-platform < argo-platform < apps — read from each category's
     primary ApplicationSet's own sync-wave annotation.

  B. PER-APPLICATION BANDS. Every Application's wave sits inside its category's
     documented band (CLAUDE.md), so no single addon can be nudged into a
     conflicting slot. The one intentional cross-band deployer — karpenter, which
     the catalog documents at wave 5 so the autoscaler is ready before the
     workloads it must provision nodes for — is allow-listed explicitly.

  C. CRD PRECEDENCE. Both of the above order Applications WITHIN their own
     category. Neither can see the one ordering that actually breaks a sync: an
     Application that RENDERS a custom resource syncing before the Application
     that installs its CRD. That is not a band violation — both sides can sit
     perfectly inside their documented bands and still be inverted — so A and B
     stayed green while the operator chart rendered a WorkflowTemplate at wave 21
     against argoproj.io CRDs that arrived at 52.

     CRD_PRECEDENCE names each CRD-providing ApplicationSet and the ApplicationSets
     that render manifests of its group. The provider must sync STRICTLY BEFORE
     every consumer. Both sides are named files, so a wave edit on either side
     fails here, and every `*-crds.yaml` ApplicationSet must be accounted for.

     A controller that merely WATCHES a CRD is not a consumer — it starts, finds
     no such kind, and retries. Conflating the two produces false conflicts; see
     the gateway-api entry, which has no consumers for exactly that reason.
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
    # CRD-only Applications, each placed immediately ahead of the first thing
    # that declares one of its kinds rather than inside a consumer's band.
    "workflow-crds": (13, 13),
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
    "argo-workflows-crds.yaml": "workflow-crds",
    "agent-platform.yaml": "ai-platform",
    "addons-agent-operator.yaml": "ai-platform",
    "dashboards.yaml": "apps",
}

# C. Which ApplicationSet installs a CRD, and which ones RENDER A MANIFEST of a
# kind in that group. The provider must sync strictly before every consumer.
#
# "Renders a manifest" is the whole distinction, and getting it wrong produces
# false conflicts. A CONTROLLER that merely watches a CRD is not a consumer here:
# it starts, finds no such kind, and retries. Envoy Gateway and the operator's
# ModelGateway controller are both in that category — they CREATE Gateway and
# HTTPRoute objects at runtime, which is why the operator reports phase=Pending
# rather than failing to sync. Only a manifest ArgoCD applies at sync time can be
# rejected by an API server that has never heard of its kind.
#
# Consumers are declared rather than derived because the one that matters renders
# from a chart in another repository: charts/operator lives in
# eks-agent-platform, so this repo's CI cannot template it. Each edge therefore
# carries the evidence that put it there. Every claim below was checked by
# rendering, not by reading a values file.
#
# Every `*-crds.yaml` ApplicationSet must appear here, with an empty consumer map
# and a `note` if it has none — so adding a CRD Application without thinking about
# who depends on it fails rather than passing silently.
CRD_PRECEDENCE = {
    "argo-workflows-crds.yaml": {
        "group": "argoproj.io",
        "consumers": {
            # `helm template op charts/operator` renders kind: WorkflowTemplate.
            "addons-agent-operator.yaml":
                "charts/operator renders a WorkflowTemplate (eks-agent-platform)",
        },
        # These CRDs are sourced from the chart's own repo at the tag matching the
        # chart pin, so the two must move together. Splitting the CRDs out of the
        # chart created that coupling; this is what keeps it honest, because a
        # Renovate bump to one and not the other would leave the controller
        # running against a different CRD generation with nothing complaining.
        "version_lock": {
            "appset": "addons-argo-workflows.yaml",
            "chart": "argo-workflows",
            "tag_prefix": "argo-workflows-",
        },
    },
    "gateway-api-crds.yaml": {
        "group": "gateway.networking.k8s.io",
        "consumers": {},
        "note": (
            "No ApplicationSet renders a Gateway API manifest. gateway-helm and "
            "ai-gateway-helm render none (checked); the operator chart names the "
            "group only in an RBAC rule, which needs no CRD; agent-platform ships "
            "nanohype.dev CRs only. Envoy Gateway and the ModelGateway controller "
            "create Gateway/HTTPRoute at RUNTIME, so wave 30 is about controller "
            "readiness, not sync ordering. Do not add consumers here without "
            "rendering them first."
        ),
    },
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


def _target_revision(appset_file: pathlib.Path) -> str | None:
    """The git targetRevision of a single-source (manifest directory) appset."""
    doc = yaml.safe_load(appset_file.read_text())
    for src in (doc["spec"]["template"]["spec"].get("sources")
                or [doc["spec"]["template"]["spec"].get("source") or {}]):
        if src.get("repoURL", "").startswith("https://github.com/"):
            return src.get("targetRevision")
    return None


def _chart_version(appset_file: pathlib.Path, chart: str) -> str | None:
    """The pinned version of `chart` in a Helm-sourced appset."""
    doc = yaml.safe_load(appset_file.read_text())
    for src in (doc["spec"]["template"]["spec"].get("sources") or []):
        if src.get("chart") == chart:
            return str(src.get("targetRevision"))
    for el in _list_elements(doc["spec"]):
        if el.get("chart") == chart:
            return str(el.get("chartVersion"))
    return None


def _single_path(spec: dict) -> str | None:
    for src in spec.get("template", {}).get("spec", {}).get("sources", []) or []:
        for vf in (src.get("helm", {}) or {}).get("valueFiles", []) or []:
            m = re.match(r"\$values/(.+)/values\.yaml$", vf)
            if m:
                return m.group(1)
        if src.get("path") and "{{" not in src["path"]:
            return src["path"]
    return None



# The README publishes a sync-wave table. It is the first thing a reader consults
# to learn what deploys when, and nothing has ever compared it to the catalog —
# so a band whose addons were deleted goes on being documented. Wave 6 read
# "Accelerators (gpu-operator, nvidia-dra-driver)" for as long as those addons
# have not existed.
#
# Only one direction is asserted: every wave the README documents must be a wave
# something actually syncs at. The reverse — every wave in use appearing in the
# table — is deliberately NOT required, because the table groups bands ("29-34")
# and summarises, and demanding a row per wave would turn a readable overview
# into a generated list.
README = pathlib.Path(__file__).resolve().parent.parent / "README.md"
README_WAVE_ROW = re.compile(r"^\|\s*(-?\d+)(?:\s*-\s*\d+)?\s*\|", re.M)


def documented_waves_exist(apps) -> list[str]:
    if not README.is_file():
        return [f"{README.name} does not exist — the wave table cannot be checked"]
    rows = [int(m) for m in README_WAVE_ROW.findall(README.read_text(encoding="utf-8"))]
    if not rows:
        return [
            "the README sync-wave table matched no rows — README_WAVE_ROW no longer "
            "matches its formatting, so this check is asserting nothing"
        ]
    in_use = {wave for _, _, _, wave in apps}
    # -1 is the app-of-apps root, which lives in landing-zone rather than in an
    # ApplicationSet here, so it is documented without appearing in `apps`.
    problems = []
    for wave in sorted(set(rows)):
        if wave == -1:
            continue
        if wave not in in_use:
            problems.append(
                f"README documents sync wave {wave}, but no Application in "
                f"applicationsets/ syncs at it — the row outlived its addons"
            )
    return problems


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
    errors.extend(documented_waves_exist(apps))

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

    # C. CRD precedence — the ordering A and B structurally cannot see.
    print("\nCRD precedence (provider before every consumer):")

    # Every CRD-only ApplicationSet has to be accounted for, so a new one cannot
    # arrive without someone deciding who depends on it.
    for name in sorted(appset_waves):
        if name.endswith("-crds.yaml") and name not in CRD_PRECEDENCE:
            errors.append(
                f"CRD precedence: {name} installs CRDs but is not in "
                f"CRD_PRECEDENCE — declare which ApplicationSets render its "
                f"kinds, or record why none do"
            )
            print(f"  UNDECLARED  {name}")

    for provider, edge in sorted(CRD_PRECEDENCE.items()):
        group = edge["group"]
        if provider not in appset_waves:
            errors.append(
                f"CRD precedence: provider {provider} ({group}) is not an "
                f"ApplicationSet with a sync-wave annotation"
            )
            print(f"  MISSING   {group:28} provider {provider}")
            continue
        pw = appset_waves[provider]
        if not edge["consumers"]:
            if not edge.get("note"):
                errors.append(
                    f"CRD precedence: {provider} lists no consumers and gives no "
                    f"reason — an empty edge must say why it is empty"
                )
                print(f"  UNEXPLAINED {group:28} {provider} @{pw}")
            else:
                print(f"  none      {group:28} {provider} @{pw} "
                      f"(no ApplicationSet renders this group)")
            continue
        for consumer, evidence in sorted(edge["consumers"].items()):
            if consumer not in appset_waves:
                errors.append(
                    f"CRD precedence: consumer {consumer} named for {group} is "
                    f"not an ApplicationSet with a sync-wave annotation"
                )
                print(f"  MISSING   {group:28} consumer {consumer}")
                continue
            cw = appset_waves[consumer]
            if pw >= cw:
                errors.append(
                    f"CRD precedence: {consumer} (wave {cw}) renders {group} "
                    f"manifests but {provider} installs those CRDs at wave {pw} "
                    f"— the CRDs must exist first ({evidence})"
                )
                print(f"  CONFLICT  {group:28} {provider} @{pw} -> "
                      f"{consumer} @{cw}")
            else:
                print(f"  ok        {group:28} {provider} @{pw} -> "
                      f"{consumer} @{cw}")

        lock = edge.get("version_lock")
        if not lock:
            continue
        got = _target_revision(APPSET_DIR / provider)
        chart_ver = _chart_version(APPSET_DIR / lock["appset"], lock["chart"])
        if chart_ver is None:
            errors.append(
                f"CRD version lock: chart '{lock['chart']}' not found in "
                f"{lock['appset']} — the lock cannot be evaluated"
            )
            print(f"  MISSING   version lock  {lock['chart']} in {lock['appset']}")
            continue
        want = f"{lock['tag_prefix']}{chart_ver}"
        if got != want:
            errors.append(
                f"CRD version lock: {provider} is pinned to '{got}' but "
                f"{lock['appset']} pins chart {lock['chart']} {chart_ver}, so the "
                f"CRDs should come from '{want}' — the controller and its CRDs "
                f"would be different generations"
            )
            print(f"  CONFLICT  version lock  {got} != {want}")
        else:
            print(f"  ok        version lock  {provider} @ {got} tracks "
                  f"{lock['chart']} {chart_ver}")

    if errors:
        print(f"\n{len(errors)} sync-wave conflict(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"\nAll {len(apps)} Applications respect the documented wave ordering.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
