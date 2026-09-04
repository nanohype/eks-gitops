#!/usr/bin/env python3
"""The Loki volume's ingestion cutoff is declared, and warned about before it.

WHY THIS EXISTS

Loki bounds nothing by stored bytes. `retention_period` reacts to the AGE of a
chunk and never to the size of the volume, so a cluster producing more than the
volume holds fills it while every retention control reports healthy. The whole
config surface carries no store-size cap and no per-tenant volume quota; the one
disk-aware control is `ingester.wal.disk_full_threshold`, at or above which the
ingester rejects EVERY push. `common.path_prefix` puts the WAL on the singleBinary
PVC, so that fraction governs the whole volume and crossing it stops ingestion
for every workload at once.

WHAT THIS GATE DOES NOT DO, AND WHY

It does not check that the volume is big enough. That check is not available to
CI, and building it anyway would produce the most dangerous artefact here — a
green assertion that reads as proof the volume fits. Two independent reasons:

  * The PVC size in values.yaml is not the size in effect. The delivering
    ApplicationSet declares `.spec.volumeClaimTemplates` under
    `ignoreDifferences` with `RespectIgnoreDifferences=true`, so ArgoCD never
    reconciles it, and the field is immutable on a StatefulSet besides. CI would
    be asserting against a number with no authority over the running volume.

  * Bytes counted and bytes stored are different quantities. `ingestion_rate_mb`
    charges uncompressed entry bytes at the distributor; chunks land gzipped.
    The ratio is a property of the log corpus, not of any config, and it is not
    derivable from this repo.

So capacity is left to the alert, which measures a live fraction and needs
neither number. What CI can know is that the warning still leads the cutoff, and
that both are declared rather than inherited — which is exactly what an edit
would break silently.

WHAT IT CHECKS

Per environment, from the RENDERED Loki config rather than the values files, so
a chart default or a per-env override that changes either number is read as it
would be applied:

  * `ingester.wal.disk_full_threshold` is set explicitly. Inherited, the alert's
    lead time depends on an upstream default that can move under a chart bump
    with nothing to compare against.
  * `retention_period` is set explicitly, and the compactor is actually enforcing
    it — retention that deletes nothing makes the cutoff arrive on a schedule.
  * The fill alert's threshold is strictly below the cutoff, so there is a window
    in which to act. Raise the cutoff, lower the alert, or delete the rule, and
    this fails.
  * The alert names the gauge Loki actually sets on every tick, not the
    edge-triggered failure counter — alerting on `rate()` of that counter reads
    as quiet through a sustained outage, because it counts the transition into
    the throttled state rather than the writes rejected while in it.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

import yaml

_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSET = ROOT / "applicationsets" / "addons-loki.yaml"
ADDON = ROOT / "addons" / "observability" / "loki"
ALERT = ROOT / "dashboards" / "base" / "alerting" / "loki-disk.yaml"

# The rule and gauge the alert must keep using. Named here rather than discovered
# so that deleting the rule fails: a gate that checks whatever rules it finds
# reports success over an empty set.
FILL_RULE = "loki-volume-approaching-cutoff"
GAUGE = "loki_ingester_wal_disk_usage_percent"

# Set on every tick regardless of state, so a threshold on it is honest. Its
# neighbour loki_ingester_wal_disk_full_failures_total counts the TRANSITION into
# the throttled state, so a cluster throttled for a week increments it once.
EDGE_COUNTER = "loki_ingester_wal_disk_full_failures_total"

NETWORK_TIMEOUT = 300

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


def chart_pin() -> tuple[str, str]:
    """Chart coordinates DERIVED from the ApplicationSet, never re-declared."""
    doc = gatelib.read_yaml(APPSET)
    sources = ((doc.get("spec") or {}).get("template") or {}).get("spec", {}).get("sources") or []
    for src in sources:
        if isinstance(src, dict) and "chart" in src:
            return str(src["repoURL"]), str(src["targetRevision"])
    print(f"Cannot run: {APPSET.relative_to(ROOT)} declares no chart source, so this "
          f"gate has no chart to render and examined nothing.")
    sys.exit(gatelib.CANNOT_RUN)


def environments() -> list[str]:
    """Every environment the addon ships a values file for.

    Derived from the tree rather than listed, so an environment added without a
    threshold is checked rather than skipped.
    """
    return sorted(p.name[len("values-"):-len(".yaml")]
                  for p in ADDON.glob("values-*.yaml"))


def render(repo: str, version: str, env: str) -> dict:
    """The Loki config as the chart produces it for one environment."""
    cmd = ["helm", "template", "loki", "loki", "--repo", repo, "--version", version,
           "-n", "monitoring",
           "-f", str(ADDON / "values.yaml"),
           "-f", str(ADDON / f"values-{env}.yaml")]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
    if proc.returncode != 0:
        err = ((proc.stderr or "") + (proc.stdout or "")).strip()
        print(f"Cannot run: helm could not render loki for {env}.")
        print(err)
        print("Nothing was examined, which is not the same as nothing being wrong.")
        sys.exit(gatelib.CANNOT_RUN)
    for doc in yaml.safe_load_all(proc.stdout):
        if (doc and doc.get("kind") == "ConfigMap"
                and doc["metadata"]["name"] == "loki"
                and "config.yaml" in (doc.get("data") or {})):
            return yaml.safe_load(doc["data"]["config.yaml"])
    print(f"Cannot run: the {env} render produced no loki ConfigMap carrying "
          f"config.yaml, so no threshold could be read.")
    sys.exit(gatelib.CANNOT_RUN)


def alert_threshold() -> float | None:
    """The fill rule's evaluator threshold, read from the shipped alert."""
    docs = gatelib.read_yaml_all(ALERT)
    for doc in docs:
        for rule in ((doc.get("spec") or {}).get("rules") or []):
            if rule.get("uid") != FILL_RULE:
                continue
            queries = list(rule.get("data") or [])
            exprs = [(d.get("model") or {}).get("expr", "") for d in queries]
            joined = " ".join(e for e in exprs if e)
            if GAUGE not in joined:
                fail(f"{ALERT.relative_to(ROOT)}: rule {FILL_RULE!r} does not query "
                     f"{GAUGE}. That gauge is set on every tick; {EDGE_COUNTER} counts "
                     f"only the transition into the throttled state, so a rule keyed "
                     f"on it reads as quiet through a sustained outage.")
            if EDGE_COUNTER in joined:
                fail(f"{ALERT.relative_to(ROOT)}: rule {FILL_RULE!r} queries "
                     f"{EDGE_COUNTER}, which increments once per transition rather "
                     f"than per rejected write.")
            for d in queries:
                for cond in ((d.get("model") or {}).get("conditions") or []):
                    params = (cond.get("evaluator") or {}).get("params") or []
                    if params:
                        return float(params[0])
            fail(f"{ALERT.relative_to(ROOT)}: rule {FILL_RULE!r} carries no evaluator "
                 f"threshold, so nothing states when it fires.")
            return None
    fail(f"{ALERT.relative_to(ROOT)}: no rule with uid {FILL_RULE!r}. The volume's "
         f"ingestion cutoff is reached with no warning ahead of it.")
    return None


def environment_verdict(cfg: dict, warn: float | None,
                        rel: str) -> tuple[list[str], bool]:
    """Everything wrong with one environment's rendered Loki config.

    Separate from the render because the render reaches a chart repository and
    this does not. The three assertions are what decide the gate's outcome, so
    they are reachable with a config supplied directly rather than only through a
    network round trip.

    Returns the problems found and whether the alert leads a declared cutoff —
    the second is what the closing line counts, so an environment that failed the
    comparison is not also reported as one the comparison covered.
    """
    wal = ((cfg.get("ingester") or {}).get("wal") or {})
    limits = cfg.get("limits_config") or {}
    comp = cfg.get("compactor") or {}
    problems: list[str] = []
    leads = False

    cutoff = wal.get("disk_full_threshold")
    if cutoff is None:
        problems.append(
            f"{rel}: the render sets no ingester.wal.disk_full_threshold, so the "
            f"fraction at which Loki stops accepting every push is an upstream "
            f"default. The alert's lead time then depends on a number that can "
            f"move under a chart bump with nothing here to compare against.")
    elif warn is not None and not warn < float(cutoff):
        problems.append(
            f"{rel}: the fill alert fires at {warn} but ingestion stops at "
            f"{cutoff}. There is no window in which to act — and no remedy is "
            f"fast: a retention cut must sync, wait a compaction interval, then "
            f"clear retention_delete_delay before a byte is freed, and the volume "
            f"cannot be grown through this repo at all.")
    else:
        leads = True

    if limits.get("retention_period") is None:
        problems.append(
            f"{rel}: the render sets no limits_config.retention_period. Nothing "
            f"then deletes on a schedule, and the volume reaches the cutoff.")
    if comp.get("retention_enabled") is not True:
        problems.append(
            f"{rel}: compactor.retention_enabled is not true, so retention_period "
            f"deletes nothing however it is set and the cutoff arrives regardless.")
    return problems, leads


def main() -> int:
    repo, version = chart_pin()
    warn = alert_threshold()
    envs = environments()
    if not envs:
        fail(f"{ADDON.relative_to(ROOT)} carries no values-<env>.yaml, so this gate "
             f"examined no environment.")

    checked = 0
    for env in envs:
        cfg = render(repo, version, env)
        rel = f"addons/observability/loki/values-{env}.yaml"
        problems, leads = environment_verdict(cfg, warn, rel)
        for problem in problems:
            fail(problem)
        checked += 1 if leads else 0

    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1

    print(f"log-volume budget OK: {len(envs)} environment(s) declare an explicit "
          f"ingestion cutoff with retention enforced against it, and the fill alert "
          f"fires at {warn} — strictly ahead of every declared cutoff ({checked} "
          f"checked). Capacity itself is deliberately not asserted here: the PVC size "
          f"is under ignoreDifferences and the compression ratio is a property of the "
          f"corpus, so the volume's fit is watched by {GAUGE} at runtime.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
