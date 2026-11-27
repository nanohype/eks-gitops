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

import sys
from pathlib import Path

import gatelib
import yaml

import catalog

# The environment each chart renders for. The gate reads one render per chart, as
# it did when it set no environment at all, so a ServiceAccount that only some
# environment's values add or rename is outside what it sees.
ENVIRONMENT = "production"

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


def render(chart: catalog.CatalogChart) -> list[dict]:
    """The chart's documents, rendered the way scripts/catalog.py renders it."""
    try:
        manifests = catalog.render(chart, ENVIRONMENT)
    except catalog.RenderFailed as exc:
        print(f"::error file={chart.path}::helm template failed\n{exc}")
        return []
    return [d for d in yaml.safe_load_all(manifests) if d]


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
    gatelib.require("helm")
    repo = Path(__file__).resolve().parent.parent
    charts = catalog.discover(repo)
    if not charts:
        print(f"::error::no charts matched {catalog.CHART_GLOB} — this gate verified nothing")
        return gatelib.CANNOT_RUN

    failures = []
    for chart in charts:
        name = chart.name
        try:
            docs = render(chart)
        except catalog.CannotRender as exc:
            print(f"Cannot run: {exc}. No chart after it was checked.")
            return gatelib.CANNOT_RUN
        if not docs:
            failures.append(f"::error file={chart.path}::rendered no documents")
            continue

        created = {d["metadata"]["name"] for d in docs if d.get("kind") == "ServiceAccount"}
        used = set()
        for d in docs:
            for ps in pod_specs(d):
                if sa := ps.get("serviceAccountName"):
                    used.add(sa)

        for sa in sorted(used - created):
            failures.append(
                f"::error file={chart.path}::a pod runs as ServiceAccount {sa!r}, which this chart "
                f"does not create\n"
                f"    It will not schedule, or it will silently run as `default` with none of\n"
                f"    the AWS identity its Pod Identity association was meant to give it."
            )
        for sa in sorted(created - used):
            if (name, sa) in EXTERNAL_CONSUMERS:
                continue
            failures.append(
                f"::error file={chart.path}::ServiceAccount {sa!r} is created and no pod in this "
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
    print(
        "Every pod names a ServiceAccount its chart creates, and every ServiceAccount has a consumer."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
