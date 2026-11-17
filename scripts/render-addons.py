#!/usr/bin/env python3
"""Helm-render gate — template every upstream-charted addon against its
appset-pinned chart version with the committed base + per-env values.

WHY THIS EXISTS
    Most addons are a base ``values.yaml`` plus per-env deltas
    (``values-{development,staging,production,hub}.yaml``), and until an addon
    reaches an ArgoCD sync it is never helm-templated. A key the chart does not
    accept renders clean through kustomize and kubeconform — nothing in this
    repo templates the chart — and only fails at sync, fleet-wide, after merge.
    Several upstream charts ship a ``values.schema.json`` that rejects unknown
    keys outright (cert-manager is the canonical example), so a single typo in a
    values file is a fleet-wide sync failure with no pre-merge signal. This gate
    templates each addon at PR time: an unknown key, a malformed override, or a
    chart bump that drops a value fails the build instead of the fleet.

SOURCE OF TRUTH
    Chart coordinates are DERIVED from the ApplicationSets, never re-declared
    here. For each applied ApplicationSet (``applicationsets/*.yaml``; the
    non-applied ``opt-in/`` set is out of scope) the chart source is the one
    ``spec.template.spec.sources`` entry that carries a ``chart`` field:

      * a matrix appset templates ``chart``/``chartVersion``/``chartRepo`` from
        its ``list`` generator's elements — one render unit per element;
      * a single-cluster appset pins ``chart``/``targetRevision``/``repoURL``
        literally — one render unit, its values path read from ``helm.valueFiles``.

    Sources with a ``path`` and no ``chart`` are kustomize dirs or git-sourced
    charts (druid's local chart, the agent operator from its own repo); they are
    rendered by ``task kustomize:build`` / their own repo's CI, not here, and are
    skipped by construction. Any ``--set`` parameters the appset passes are
    reproduced with synthetic values so the render matches what ArgoCD does at
    sync (e.g. aws-load-balancer-controller refuses to render without clusterName).

FETCHING
    Each chart is fetched through registry.py's client into the chart
    cache and rendered from that local archive, so helm never reaches a
    registry here. A registry that answers that the pinned version is not there,
    or lists it with no digest to check its archive against, exits 1 — a pin
    that does not resolve to a verifiable archive is a finding about this repo.
    Any other fetch failure, a rate limit that outlasts the client's retries
    included, exits 2: it says nothing about the catalogue.

Run ``render-addons.py`` to render every env, or ``--env staging`` for one.
``--list`` prints the discovered units without rendering. ``--fetch`` fills
the chart cache with every pinned chart, renders nothing, and removes every
cached file no pin names.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

import gatelib
import registry
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Seconds one helm render may run before the gate gives up on it. A subprocess
# with no deadline turns a stalled render into a job that hangs until the CI
# runner's own ceiling, with no diagnostic naming the command that stalled.
RENDER_TIMEOUT = 300
APPSET_DIR = REPO_ROOT / "applicationsets"
ENVIRONMENTS = ["development", "staging", "production", "hub"]

# Charts that cannot be pulled anonymously, as a run for a pull request from a
# fork, which holds no registry login, would pull them. Keyed by chart name,
# mapped to the reason — the same posture as the kubeconform first-party skips
# in ci.yml: record the gap explicitly rather than pretend to cover it.
#
# A skip is re-tested on every run (see stale_skips below). Declaring the gap is
# honest; leaving it declared after it closes is not, and the difference is
# invisible without asking.
#
# The map is EMPTY, and its one historical entry is worth keeping in view: the
# NVIDIA DRA driver was skipped because oci://nvcr.io denies anonymous pulls, and
# while that reason stayed true it hid a second problem behind it — the appset
# named a chart (`k8s-dra-driver-gpu`) that existed under no registry at all. The
# pin could not have rendered even with NGC credentials, and no gate could say
# so, because the credential wall answered first. The accelerator stack has since
# been deleted; the lesson is that a declared gap can conceal an undeclared one.
SKIP_CHARTS: dict[str, str] = {}

# Synthetic values for the appset's templated --set parameters. The render only
# needs a syntactically valid, chart-accepted value; the real per-cluster value
# is injected by ArgoCD from the cluster Secret at sync time.
PARAM_SYNTH = {
    "clusterName": "ci-cluster",
    "vpcId": "vpc-00000000000000000",
}


@dataclass
class Unit:
    appset: str
    chart: str
    version: str
    repo: str  # https helm repo URL or oci:// chart ref base
    path: str  # addon dir relative to repo root, e.g. addons/operations/velero
    params: list[tuple[str, str]] = field(default_factory=list)
    namespace: str = ""  # ArgoCD destination namespace the addon syncs into

    @property
    def is_oci(self) -> bool:
        return self.repo.startswith("oci://")

    @property
    def source(self) -> str:
        """Where the registry client fetches the chart from: its OCI reference, or the repo."""
        return self.oci_ref() if self.is_oci else self.repo

    def oci_ref(self) -> str:
        # ArgoCD appends the chart name to the OCI repoURL unless the repoURL
        # already ends in it. Every OCI pin in the catalog currently ends in its
        # chart name, so the second branch is what runs; the first is kept
        # because the appset schema permits either shape.
        if self.repo.rsplit("/", 1)[-1] == self.chart:
            return self.repo
        return f"{self.repo}/{self.chart}"


def _is_template(value) -> bool:
    return isinstance(value, str) and "{{" in value


def _chart_source(sources: list[dict]) -> dict | None:
    """The one source that references a Helm chart repo (has a ``chart`` key)."""
    for src in sources:
        if isinstance(src, dict) and "chart" in src:
            return src
    return None


def _synth_params(helm: dict) -> list[tuple[str, str]]:
    params = []
    for p in helm.get("parameters", []) or []:
        name, value = p.get("name"), p.get("value")
        if name is None:
            continue
        if _is_template(value) or value is None:
            value = PARAM_SYNTH.get(name, "ci")
        params.append((name, str(value)))
    return params


def _path_from_valuefiles(helm: dict) -> str | None:
    for vf in helm.get("valueFiles", []) or []:
        m = re.match(r"\$values/(.+)/values\.yaml$", vf)
        if m:
            return m.group(1)
    return None


def _list_elements(spec: dict) -> list[dict]:
    """Every list-generator element, via the shared walk.

    This returned on the FIRST list generator, so an appset declaring two had the
    second one's addons silently absent from the render corpus — and the
    "Rendered N addon×env combinations" line is computed from the same list, so
    the undercount reported itself as a full run.
    """
    return gatelib.list_elements({"spec": spec})


def discover() -> list[Unit]:
    units: list[Unit] = []
    for appset_file in sorted(APPSET_DIR.glob("*.yaml")):
        doc = yaml.safe_load(appset_file.read_text())
        if not doc or doc.get("kind") != "ApplicationSet":
            continue
        spec = doc.get("spec", {})
        sources = (spec.get("template", {}).get("spec", {}) or {}).get("sources", [])
        chart_src = _chart_source(sources)
        if chart_src is None:
            continue  # kustomize / git-sourced / local-chart appset — not ours
        helm = chart_src.get("helm", {}) or {}
        params = _synth_params(helm)
        name = appset_file.name

        if _is_template(chart_src["chart"]):
            # Matrix appset — one render unit per list element.
            for el in _list_elements(spec):
                if "chart" not in el:
                    continue
                units.append(
                    Unit(
                        appset=name,
                        chart=str(el["chart"]),
                        version=str(el["chartVersion"]),
                        repo=str(el["chartRepo"]),
                        path=str(el["path"]),
                        params=params,
                        namespace=str(el.get("namespace", "")),
                    )
                )
        else:
            # Single-cluster appset — chart pinned literally on the source.
            path = _path_from_valuefiles(helm)
            if path is None:
                continue
            dest = (spec.get("template", {}).get("spec", {}) or {}).get("destination", {}) or {}
            units.append(
                Unit(
                    appset=name,
                    chart=str(chart_src["chart"]),
                    version=str(chart_src["targetRevision"]),
                    repo=str(chart_src["repoURL"]),
                    path=path,
                    params=params,
                    namespace=str(dest.get("namespace", "")),
                )
            )
    return units


def render(unit: Unit, env: str | None) -> tuple[bool, str]:
    # The directory is the discriminator, and it has to be checked first.
    #
    # "this addon has no delta for this environment" and "the ApplicationSet
    # points at a path that does not exist" produced the same answer here, and
    # that answer was success. So a typo in an appset element's `path` removed
    # the addon from this gate with no signal at all: nothing rendered, nothing
    # failed, and the summary counted one fewer unit than the fleet contains.
    #
    # A missing directory is never a legitimate skip. A missing values-<env>.yaml
    # inside a real directory always is.
    unit_dir = REPO_ROOT / unit.path
    if not unit_dir.is_dir():
        return (False, f"path '{unit.path}' does not exist — the ApplicationSet element points at nothing")

    base = unit_dir / "values.yaml"
    value_files = []
    if base.exists():
        value_files.append(base)
    if env is not None:
        env_file = unit_dir / f"values-{env}.yaml"
        if not env_file.exists():
            return (True, "no env delta")  # addon not deployed to this env
        value_files.append(env_file)

    archive = gatelib.chart_archive_or_exit(unit.source, unit.chart, unit.version)

    # Render into the namespace ArgoCD will actually sync into. `helm template`
    # otherwise reports `.Release.Namespace` as "default", so anything keyed on
    # it — a RoleBinding subject, a webhook's service reference, a chart that
    # refuses to install into `default` at all — renders differently here than
    # at sync, which is the one thing this gate exists to rule out. The appset's
    # destination namespace was already being collected and then dropped.
    cmd = ["helm", "template", unit.chart, str(archive)]
    if unit.namespace:
        cmd += ["--namespace", unit.namespace]
    for name, value in unit.params:
        cmd += ["--set", f"{name}={value}"]
    for vf in value_files:
        cmd += ["-f", str(vf)]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RENDER_TIMEOUT)
    if proc.returncode != 0:
        return (False, proc.stderr.strip() or proc.stdout.strip())
    return (True, "rendered")


def stale_skips(units: list[Unit]) -> list[tuple[str, str]]:
    """Skips whose stated reason no longer holds.

    Every entry in SKIP_CHARTS claims a chart cannot be fetched without
    credentials. That claim expires: upstream re-hosts, a registry drops its
    auth requirement, a chart moves. Nothing re-reads the reason, so the skip
    outlives it and the addon stays uncovered for a reason that stopped being
    true — which is worse than never having declared it, because the entry reads
    as a considered decision.

    So ask the registry, as a client holding no login and no cached archive. If
    that fetch succeeds, the chart is fetchable anonymously and the skip must
    go. A login stored where this runs, or an archive an earlier fetch left in
    the chart cache, would answer for a client that has neither, so the fetch
    is handed no credentials and a cache of its own, deleted once it returns.
    """
    stale = []
    for u in units:
        if u.chart not in SKIP_CHARTS:
            continue
        with tempfile.TemporaryDirectory() as empty:
            try:
                registry.chart_archive(u.source, u.chart, u.version,
                                       cache=pathlib.Path(empty), credentials={})
            except registry.ChartUnavailable:
                continue
        stale.append((u.chart, SKIP_CHARTS[u.chart]))
    return stale


# Floors on what was EXAMINED, not on what was found. Printing a denominator
# is not gating on it: this gate printed its count and exited 0 against a
# tree containing only the scripts — which is what a renamed directory or a
# wrong working directory looks like. Set well under the real numbers, so
# they catch "matched almost nothing", never "someone removed one".
MIN_COMBINATIONS = 60


def fetch_all(units: list[Unit]) -> int:
    """Fetch every pinned chart into the chart cache; drop every file no pin names.

    CI runs this in one job that every rendering job waits on, so a registry is
    read once per pin set rather than once per job, and the cache that job
    carries to the next pin set holds that set and nothing older.
    """
    kept = {gatelib.chart_archive_or_exit(u.source, u.chart, u.version)
            for u in units if u.chart not in SKIP_CHARTS}
    if not kept:
        print("Cannot run: discovery found no chart to fetch, so an empty cache would "
              "read as a complete one.")
        return gatelib.CANNOT_RUN
    dropped = registry.prune_archives(kept)
    print(f"Fetched {len(kept)} pinned chart archive(s) into {registry.CHART_CACHE}; "
          f"removed {dropped} cached file(s) no pin names.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--env", choices=ENVIRONMENTS, help="render one environment (default: all)")
    ap.add_argument("--list", action="store_true", help="print discovered units and exit")
    ap.add_argument("--fetch", action="store_true",
                    help="fetch every pinned chart into the chart cache, render nothing, "
                         "and remove every cached file no pin names")
    args = ap.parse_args()

    units = discover()
    if args.list:
        for u in units:
            tag = "  [SKIP]" if u.chart in SKIP_CHARTS else ""
            print(f"{u.appset:32} {u.chart:32} {u.version:12} {u.path}{tag}")
        return 0
    if args.fetch:
        return fetch_all(units)

    gatelib.require('helm')

    rendered = [u for u in units if u.chart not in SKIP_CHARTS]
    skipped = [u for u in units if u.chart in SKIP_CHARTS]
    envs = [args.env] if args.env else ENVIRONMENTS

    failures: list[str] = []
    count = 0
    for u in rendered:
        for env in envs:
            ok, msg = render(u, env)
            if msg == "no env delta":
                continue
            count += 1
            label = f"{u.chart}@{u.version} ({env})"
            if ok:
                print(f"  ok    {label}")
            else:
                print(f"  FAIL  {label}")
                failures.append(f"{label} [{u.appset}]\n{msg}")

    print()
    for u in skipped:
        print(f"  skip  {u.chart}@{u.version} — {SKIP_CHARTS[u.chart]}")

    stale = stale_skips(skipped)
    print(f"\nRendered {count} addon×env combinations, {len(failures)} failed.")
    if count < MIN_COMBINATIONS:
        print(f"FAIL  rendered {count} combination(s), under the floor of "
              f"{MIN_COMBINATIONS}. Discovery matched almost nothing, so a clean "
              f"result here describes the discovery and not the fleet.")
        return 2

    if stale:
        print("\n" + "=" * 72)
        print("\nThese skips claim a chart cannot be fetched, but it can:")
        for chart, reason in stale:
            print(f"\n  {chart}")
            print(f"    declared: {reason}")
            print("    an anonymous fetch just succeeded")
        print("\nRemove the entry from SKIP_CHARTS so the addon is rendered. A skip whose")
        print("reason has expired reads as a considered decision and covers nothing.")
        return 1

    if failures:
        print("\n" + "=" * 72)
        for f in failures:
            print(f"\n{f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
