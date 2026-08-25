#!/usr/bin/env python3
"""check-serviceaccount-bindings.py — a pod may only name a ServiceAccount that exists.

Kubernetes binds a pod to its ServiceAccount by NAME, and so does an EKS Pod Identity
association. Neither fails when the name is wrong. A pod naming a ServiceAccount that
does not exist is rejected at admission, but the far more common shape is the reverse
and it is silent: the ServiceAccount exists, the pod runs, and the association that
was supposed to give it AWS credentials keys off a different name — so the workload
quietly falls back to the node role and gets AccessDenied on a data path nobody
watches. Every manifest is valid, every Application is Healthy, and the function is
absent.

This gate holds the half that lives in this repo: within a chart, the names pods use
and the names the chart creates must be the same set, in both directions.

  - a pod naming a ServiceAccount the chart does not create is a pod that will not
    schedule, or that silently runs as `default`
  - a ServiceAccount no pod uses is either dead config or, worse, the name an external
  Pod Identity association is bound to while the real pods run as something else and
  fall back to node credentials

The cross-repo half cannot be gated from here: landing-zone composes the associations
and this repo composes the ServiceAccounts. What makes that bearable is that each side
now names the other's file, and this check makes the in-chart set unambiguous, so
there is one list to compare rather than a rendering to reconstruct.
"""

import importlib.util
import pathlib
import subprocess
import sys
from pathlib import Path

import yaml

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


# Seconds a child process may run before the gate gives up on it. A subprocess
# with no deadline turns an unreachable registry into a job that hangs until the
# CI runner's own ceiling, with no diagnostic naming the command that stalled.
# NETWORK_TIMEOUT covers commands that resolve a remote chart or registry;
# LOCAL_TIMEOUT covers commands that only read the working tree.
LOCAL_TIMEOUT = 120

# Charts rendered from this repo. Upstream-charted addons are covered by
# render-addons.py, which templates them against their appset-pinned versions.
CHART_GLOB = "catalog/*/chart"

# Minimal values needed to make a chart render at all. A chart that requires an input
# it cannot default is not a finding here — it is the chart's contract with its
# consumer, and render-addons.py documents the same pattern for --set parameters.
RENDER_VALUES = {
    "druid": ["--set", "hostedId=ci"],
}

# ServiceAccounts a chart creates for something other than a pod in the same chart.
# Each entry names what consumes it, so "unused" stays a finding rather than a
# rubber stamp.
EXTERNAL_CONSUMERS = {
    ("druid", "druid-msk-client"): (
        "Bound by landing-zone's druid msk_client Pod Identity association and assumed "
        "by the MSK admin tooling that provisions topics out of band, not by a pod this "
        "chart ships."
    ),
}


def render(chart: Path) -> list[dict]:
    name = chart.parent.name
    values = chart.parent / "values.yaml"
    cmd = ["helm", "template", name, str(chart)]
    if values.exists():
        cmd += ["-f", str(values)]
    cmd += RENDER_VALUES.get(name, [])
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=LOCAL_TIMEOUT)
    if out.returncode != 0:
        print(f"::error file={chart}::helm template failed\n{out.stderr.strip()[:1200]}")
        return []
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def pod_specs(doc: dict):
    """Every PodSpec a document carries, whatever wraps it."""
    kind = doc.get("kind", "")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        yield spec
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        yield (spec.get("template") or {}).get("spec") or {}
    if kind == "CronJob":
        jt = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
        yield jt.get("spec") or {}
    # Argo WorkflowTemplates and Druid task templates carry a bare PodSpec-alike.
    if "serviceAccountName" in spec:
        yield spec


def main() -> int:
    gatelib.require('helm')
    repo = Path(__file__).resolve().parent.parent
    charts = sorted(repo.glob(CHART_GLOB))
    if not charts:
        print(f"::error::no charts matched {CHART_GLOB} — this gate verified nothing")
        return 1

    failures = []
    for chart in charts:
        name = chart.parent.name
        docs = render(chart)
        if not docs:
            failures.append(f"::error file={chart}::rendered no documents")
            continue

        created = {d["metadata"]["name"] for d in docs if d.get("kind") == "ServiceAccount"}
        used = set()
        for d in docs:
            for ps in pod_specs(d):
                if sa := ps.get("serviceAccountName"):
                    used.add(sa)

        for sa in sorted(used - created):
            failures.append(
                f"::error file={chart}::a pod runs as ServiceAccount {sa!r}, which this chart "
                f"does not create\n"
                f"    It will not schedule, or it will silently run as `default` with none of\n"
                f"    the AWS identity its Pod Identity association was meant to give it."
            )
        for sa in sorted(created - used):
            if (name, sa) in EXTERNAL_CONSUMERS:
                continue
            failures.append(
                f"::error file={chart}::ServiceAccount {sa!r} is created and no pod in this "
                f"chart runs as it\n"
                f"    Either a pod should and does not — in which case its Pod Identity\n"
                f"    association is attached to nothing and the real pods run on the node\n"
                f"    role — or the ServiceAccount is dead config. If something outside this\n"
                f"    chart consumes it, say so in EXTERNAL_CONSUMERS with what."
            )

        print(f"  {name}: {len(created)} ServiceAccount(s), {len(used)} used by pods")

    print()
    if failures:
        for f in failures:
            print(f)
        print(f"\n{len(failures)} ServiceAccount binding problem(s).")
        return 1
    print("Every pod names a ServiceAccount its chart creates, and every ServiceAccount has a consumer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
