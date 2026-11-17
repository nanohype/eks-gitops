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

CUSTOM RESOURCE DEFINITIONS
    ArgoCD renders a Helm source with ``--include-crds`` unless the source sets
    ``helm.skipCrds: true`` (argo-cd util/helm/cmd.go), so a chart's ``crds/``
    directory, a subchart's included, is part of what that Application owns.
    This gate renders the same way, and then asks the one question no
    per-chart render can: does any CRD belong to two Applications? Two owners
    of one CRD take turns overwriting it on every self-heal, at whatever
    release and channel each one carries, and ArgoCD reports that as a
    SharedResourceWarning on an Application that otherwise looks healthy.

    The question is asked of every cluster-scoped object, not only CRDs
    (CLUSTER_SCOPED_KINDS): gateway-helm's bundle carried a second copy of the
    Gateway API safe-upgrades ValidatingAdmissionPolicy as well as the CRDs, and
    a cluster-scoped object has one name per cluster whatever namespace each
    Application targets. Namespaced objects are not compared — two Applications
    syncing into different namespaces own different objects. Nor are two
    Applications whose cluster selectors require different values of one label
    (otel-gateway's full and floor tiers): they never land on the same cluster.

    The directory sources that install CRDs (gateway-api-crds,
    argo-workflows-crds) are not charts and are not rendered here, so what they
    own is recorded in DIRECTORY_OWNERS against the exact (repoURL,
    targetRevision, path) it was read from. A record whose source no longer
    matches its ApplicationSet fails the gate, so moving a pin or a channel
    cannot leave a stale record certifying the old contents.

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
from typing import Any

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

# What a directory-source Application owns, recorded against the exact source it
# was read from. Those sources are manifest directories in another repository,
# read at a pinned tag, so no render here sees what they install; a chart that
# installs the same object is a second owner all the same. A CRD is matched by
# group where the directory owns the whole group: argoproj.io is shared by four
# projects' charts, so argo-workflows-crds is matched by the CRDs it installs.
#
# `source` must equal the ApplicationSet's template source. A pin bump or a
# channel change (config/crd/standard -> experimental adds the
# gateway.networking.x-k8s.io group) makes it differ, and directory_owner_drift
# fails the gate until the record is re-read from the new source.
@dataclass(frozen=True)
class DirectoryOwner:
    appset: str
    source: tuple[str, str, str]  # (repoURL, targetRevision, path)
    crd_groups: tuple[str, ...] = ()
    objects: tuple[str, ...] = ()  # object_key()s: "Kind/name"

    @property
    def label(self) -> str:
        repo, rev, path = self.source
        return f"{self.appset} ({repo.removeprefix('https://github.com/')} {rev} {path})"


DIRECTORY_OWNERS = (
    DirectoryOwner(
        appset="gateway-api-crds.yaml",
        source=("https://github.com/kubernetes-sigs/gateway-api", "v1.7.0",
                "config/crd/standard"),
        crd_groups=("gateway.networking.k8s.io",),
        objects=("ValidatingAdmissionPolicy/safe-upgrades.gateway.networking.k8s.io",
                 "ValidatingAdmissionPolicyBinding/safe-upgrades.gateway.networking.k8s.io"),
    ),
    DirectoryOwner(
        appset="argo-workflows-crds.yaml",
        source=("https://github.com/argoproj/argo-workflows", "v4.1.6",
                "manifests/base/crds/full"),
        objects=tuple(f"CustomResourceDefinition/{plural}.argoproj.io" for plural in (
            "clusterworkflowtemplates", "cronworkflows", "workflowartifactgctasks",
            "workfloweventbindings", "workflows", "workflowtaskresults",
            "workflowtasksets", "workflowtemplates")),
    ),
)

# Cluster-scoped kinds, by API group. One name per cluster, so two Applications
# rendering one are two owners whatever their destination namespaces.
CLUSTER_SCOPED_KINDS = {
    "": {"Namespace"},
    "apiextensions.k8s.io": {"CustomResourceDefinition"},
    "admissionregistration.k8s.io": {
        "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
        "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding",
        "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"},
    "apiregistration.k8s.io": {"APIService"},
    "rbac.authorization.k8s.io": {"ClusterRole", "ClusterRoleBinding"},
    "scheduling.k8s.io": {"PriorityClass"},
    "storage.k8s.io": {"StorageClass", "CSIDriver"},
    "networking.k8s.io": {"IngressClass"},
    "gateway.networking.k8s.io": {"GatewayClass"},
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
    skip_crds: bool = False  # the source's helm.skipCrds — ArgoCD omits crds/ when set
    # The clusters generator's matchLabels: which clusters the Application lands on.
    cluster_labels: dict[str, str] = field(default_factory=dict)

    @property
    def owner(self) -> str:
        """How this unit is named as the owner of a rendered object."""
        return f"{self.appset} {self.path}"

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


def _cluster_labels(doc: dict) -> dict[str, str]:
    """Every matchLabels entry of the ApplicationSet's clusters generators.

    matchExpressions are not read: they can only narrow where an Application
    lands, so leaving them out can only make two Applications look able to
    share a cluster, never hide that they can.
    """
    labels: dict[str, str] = {}
    for gen in gatelib.matrix_generators(doc):
        if "clusters" in gen:
            sel = (gen.get("clusters") or {}).get("selector") or {}
            labels.update({str(k): str(v) for k, v in (sel.get("matchLabels") or {}).items()})
    return labels


def can_share_a_cluster(a: dict[str, str], b: dict[str, str]) -> bool:
    """False only when two selectors require different values of one label."""
    return all(b[k] == v for k, v in a.items() if k in b)


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
        skip_crds = helm.get("skipCrds") is True
        cluster_labels = _cluster_labels(doc)
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
                        skip_crds=skip_crds,
                        cluster_labels=cluster_labels,
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
                    skip_crds=skip_crds,
                    cluster_labels=cluster_labels,
                )
            )
    return units


# The C loader where the platform has it: CRD-heavy charts render megabytes, and
# a render is parsed once per chart per environment.
_BaseLoader: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _ManifestLoader(_BaseLoader):
    """A safe loader that reads what Kubernetes reads.

    A plain `=` scalar resolves to YAML 1.1's value tag, which PyYAML's safe
    loaders have no constructor for; the API server's YAML decoder reads it as
    the string "=". prometheus-operator-crds renders one in an enum. A subclass,
    so the module-wide SafeLoader is left as it was.
    """


def _value_scalar(loader: Any, node: Any) -> Any:
    return loader.construct_scalar(node)


_ManifestLoader.add_constructor("tag:yaml.org,2002:value", _value_scalar)


def cluster_objects(manifest: str) -> set[str]:
    """The key of every cluster-scoped object in a rendered manifest stream.

    A key is "Kind/name": kinds in CLUSTER_SCOPED_KINDS are unique per API group,
    and the group is checked before a kind counts.
    """
    keys = set()
    for doc in yaml.load_all(manifest, Loader=_ManifestLoader):
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        api_version = str(doc.get("apiVersion", ""))
        group = api_version.partition("/")[0] if "/" in api_version else ""
        if kind not in CLUSTER_SCOPED_KINDS.get(group, ()):
            continue
        name = (doc.get("metadata") or {}).get("name")
        if name:
            keys.add(f"{kind}/{name}")
    return keys


def object_ownership(owners: dict[str, set[str]],
                     directory: tuple[DirectoryOwner, ...] = DIRECTORY_OWNERS,
                     selectors: dict[str, dict[str, str]] | None = None) -> list[str]:
    """Every cluster-scoped object more than one Application would install on one cluster.

    ``owners`` maps an object key to the render units that rendered it. A
    directory source that owns the object — by CRD group or by key — is an
    owner too. ``selectors`` maps an owner to its cluster selector's
    matchLabels; two owners whose selectors require different values of one
    label never land on the same cluster (otel-gateway's full and floor tiers),
    so they are not two owners of anything. An owner with no recorded selector
    is taken to reach every cluster.
    """
    selectors = selectors or {}
    problems = []
    for key in sorted(owners):
        holders = set(owners[key])
        kind, _, name = key.partition("/")
        group = name.split(".", 1)[1] if kind == "CustomResourceDefinition" and "." in name else None
        for d in directory:
            if key in d.objects or (group is not None and group in d.crd_groups):
                holders.add(d.label)
        ordered = sorted(holders)
        if any(can_share_a_cluster(selectors.get(a, {}), selectors.get(b, {}))
               for i, a in enumerate(ordered) for b in ordered[i + 1:]):
            problems.append(f"{key} is installed by {len(holders)} Applications: "
                            + ", ".join(sorted(holders)))
    return problems


def _template_source(appset_file: pathlib.Path) -> tuple[str, str, str] | None:
    doc = yaml.safe_load(appset_file.read_text())
    src = ((((doc or {}).get("spec") or {}).get("template") or {}).get("spec") or {}).get("source")
    if not isinstance(src, dict):
        return None
    return (str(src.get("repoURL", "")), str(src.get("targetRevision", "")),
            str(src.get("path", "")))


def directory_owner_drift(directory: tuple[DirectoryOwner, ...] = DIRECTORY_OWNERS,
                          appset_dir: pathlib.Path | None = None) -> list[str]:
    """Every DIRECTORY_OWNERS record whose ApplicationSet no longer reads its source."""
    appset_dir = appset_dir or APPSET_DIR
    problems = []
    for d in directory:
        path = appset_dir / d.appset
        if not path.is_file():
            problems.append(f"{d.appset}: recorded as a directory owner, but there is no such "
                            f"ApplicationSet")
            continue
        live = _template_source(path)
        if live != d.source:
            problems.append(f"{d.appset}: ownership recorded for {d.source}, but the "
                            f"ApplicationSet reads {live}. Re-read what that source installs "
                            f"and update DIRECTORY_OWNERS in scripts/render-addons.py")
    return problems


def render(unit: Unit, env: str | None,
           objects: dict[str, set[str]] | None = None) -> tuple[bool, str]:
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
    # What ArgoCD does with a Helm source (argo-cd util/helm/cmd.go): crds/ is
    # rendered, and so applied and owned, unless the source opts out.
    if not unit.skip_crds:
        cmd.append("--include-crds")
    for name, value in unit.params:
        cmd += ["--set", f"{name}={value}"]
    for vf in value_files:
        cmd += ["-f", str(vf)]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RENDER_TIMEOUT)
    if proc.returncode != 0:
        return (False, proc.stderr.strip() or proc.stdout.strip())
    if objects is not None:
        try:
            keys = cluster_objects(proc.stdout)
        except yaml.YAMLError as e:
            return (False, f"the render is not YAML ArgoCD could apply: {e}")
        for key in keys:
            objects.setdefault(key, set()).add(unit.owner)
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
    objects: dict[str, set[str]] = {}
    count = 0
    for u in rendered:
        for env in envs:
            ok, msg = render(u, env, objects)
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

    shared = object_ownership(objects, selectors={u.owner: u.cluster_labels for u in rendered})
    drift = directory_owner_drift()
    n_crds = sum(1 for k in objects if k.startswith("CustomResourceDefinition/"))
    print(f"Rendered {len(objects)} cluster-scoped object(s), {n_crds} of them "
          f"CustomResourceDefinitions; {len(shared)} with more than one owning Application.")
    if shared:
        print("\n" + "=" * 72)
        print("\nA cluster-scoped object two Applications install is overwritten by each in")
        print("turn, at whatever release and channel each carries, and pruned by whichever")
        print("stops rendering it. Give it one owner: turn the chart's bundled copy off in")
        print("its values, or set skipCrds on its source.\n")
        for problem in shared:
            print(f"  {problem}")
    if drift:
        print("\n" + "=" * 72)
        print("\nA directory-source ownership record no longer describes its source:\n")
        for problem in drift:
            print(f"  {problem}")

    if failures:
        print("\n" + "=" * 72)
        for f in failures:
            print(f"\n{f}")
        return 1
    return 1 if shared or drift else 0


if __name__ == "__main__":
    sys.exit(main())
