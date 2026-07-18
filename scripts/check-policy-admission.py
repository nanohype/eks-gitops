#!/usr/bin/env python3
"""Policy-admission gate — render the addon fleet and prove no addon is denied by
this repo's own Kyverno policies on an Enforce-tier cluster.

WHY THIS EXISTS
    The catalog's core promise is that a vended cluster works. On staging and
    production the Kyverno policies run in Enforce mode (the overlays flip
    validationFailureAction to Enforce), so a workload that violates a policy is
    DENIED at admission — a first CREATE has no old object, and
    allowExistingViolations only grandfathers objects that already exist.

    require-labels (Deployment/StatefulSet/DaemonSet must carry the 5-label org
    tier), require-probes, require-run-as-non-root, and require-resource-limits
    all carry a hand-maintained namespace exclusion list. The addon fleet cannot
    satisfy these policies: upstream charts never stamp the org
    platform.nanohype.dev/* labels, device plugins and security agents need
    root/host access, and batch jobs have no service-style probes. If an addon
    lands in a namespace that is NOT on the exclusion list, its Deployment/
    DaemonSet is denied — and nothing before this gate would have caught it. The
    policies render clean, kubeconform clean, and kyverno's own unit tests pass;
    the contradiction only surfaces when the addon meets the policy on a real
    Enforce cluster. That is exactly how a `require-labels` tier extension shipped
    against a fleet whose grafana-operator, falco, kagent, agentgateway, and
    accelerator namespaces were never excluded.

WHAT IT DOES
    1. STRUCTURAL — parses the four exclusion-bearing base policies and asserts
       every rule's namespace exclusion list is IDENTICAL. The lists diverging is
       itself the bug class (a namespace excluded from three policies but not the
       fourth), so they are pinned equal here.
    2. FUNCTIONAL — discovers every Helm addon from the ApplicationSets (the same
       discovery scripts/render-addons.py uses — the single source of truth),
       renders each into its real ArgoCD destination namespace with base + each
       Enforce environment's values, adds the two Kustomize-sourced workloads that
       land pods (the aws-neuron device plugin and the grafana dashboards' token
       rotator), then runs `kyverno apply` against the Enforce overlay of the
       best-practices + pod-security policies. Any denial fails the build. It also
       runs the Audit overlay (development) with --audit-warn to prove the Audit
       variant is well-formed and matches — a warn on dev, a deny on staging/prod.

SCOPE
    Addons only — the fleet the exclusion lists govern. Tenant workloads (druid,
    the apps-tenants matrix) are the intended SUBJECT of these policies: they must
    comply, and that is the tenant chart's responsibility, gated on the tenant's
    own render path, not here. Git-sourced addons (the agent operator, pulled from
    eks-agent-platform) render in their own repo's CI; here they are covered by
    namespace exclusion only. Charts that cannot be pulled by credential-less CI
    (nvidia's NGC-gated DRA driver, see render-addons.SKIP_CHARTS) are likewise
    covered by exclusion only.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile

import yaml

# Helm charts occasionally emit the YAML `=` default-value sentinel (e.g. `- =`
# inside a ConfigMap payload). PyYAML's SafeLoader has no constructor for it and
# raises; the rendered text is only inspected for kind/namespace here, so map the
# sentinel to its literal scalar rather than fail the parse.
yaml.SafeLoader.add_constructor(
    "tag:yaml.org,2002:value",
    lambda loader, node: loader.construct_scalar(node),
)

# Reuse render-addons' discovery + repo setup — the ApplicationSets are the one
# source of truth for what the fleet is and where each addon lands. The module
# file is hyphenated (render-addons.py), so it is loaded by path rather than
# imported by name.
_ra_path = pathlib.Path(__file__).resolve().parent / "render-addons.py"
_spec = importlib.util.spec_from_file_location("render_addons", _ra_path)
render_addons = importlib.util.module_from_spec(_spec)
sys.modules["render_addons"] = render_addons  # dataclass resolves annotations here
_spec.loader.exec_module(render_addons)
REPO_ROOT = render_addons.REPO_ROOT
SKIP_CHARTS = render_addons.SKIP_CHARTS
add_repos = render_addons.add_repos
discover = render_addons.discover

POLICY_DIR = REPO_ROOT / "policies" / "kyverno"

# The four policies whose exclusion lists must agree, as (group, file) pairs.
EXCLUSION_POLICIES = [
    ("best-practices", "require-labels.yaml"),
    ("best-practices", "require-probes.yaml"),
    ("pod-security-standards", "require-non-root.yaml"),
    ("pod-security-standards", "require-resource-limits.yaml"),
]

# The two policy groups that carry the exclusion-bearing validation policies and
# ship both an Audit (development) and Enforce (staging/production) overlay.
POLICY_GROUPS = ["best-practices", "pod-security-standards"]

# Enforce runs on staging + production; both flip the base policies to Enforce.
ENFORCE_ENVS = ["staging", "production"]

# Kinds Kyverno's workload policies (and their autogen pod-controller variants)
# evaluate. Namespace-scoped, so they must carry metadata.namespace for the
# exclusion match to fire — helm -n stamps it on most charts; this backfills any
# the chart left unqualified so the gate never under-reports.
WORKLOAD_KINDS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet",
    "ReplicaSet", "ReplicationController", "Job", "CronJob",
}

# Kustomize-sourced addon workloads that render pods but carry no Helm chart, so
# discover() (chart-keyed) never sees them: (kustomize root relative to repo,
# destination namespace, per-env overlays or None for an env-agnostic root).
KUSTOMIZE_WORKLOADS = [
    ("addons/accelerators/aws-neuron-device-plugin", "aws-neuron", True),
    ("dashboards/base", "grafana-operator", False),
]


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def check_exclusion_parity() -> bool:
    """Assert every exclusion-bearing rule shares one identical namespace set."""
    print("── Exclusion-list parity ──────────────────────────────────────────")
    lists: dict[str, list[str]] = {}
    for group, fname in EXCLUSION_POLICIES:
        doc = yaml.safe_load((POLICY_DIR / group / "base" / fname).read_text())
        for rule in doc["spec"]["rules"]:
            key = f"{doc['metadata']['name']}/{rule['name']}"
            # A rule's exclusion is the union of every `exclude.any` entry's
            # namespaces (Kyverno ORs them), not just the first — reading only
            # any[0] would silently drop a second entry's namespaces from the
            # parity comparison.
            excl: list[str] = []
            for entry in rule["exclude"]["any"]:
                excl.extend(entry.get("resources", {}).get("namespaces", []) or [])
            lists[key] = sorted(set(excl))

    baseline_key, baseline = next(iter(lists.items()))
    ok = True
    for key, ns in lists.items():
        if ns != baseline:
            ok = False
            missing = sorted(set(baseline) - set(ns))
            extra = sorted(set(ns) - set(baseline))
            print(f"  MISMATCH {key} vs {baseline_key}:")
            if missing:
                print(f"    missing: {missing}")
            if extra:
                print(f"    extra:   {extra}")
    if ok:
        print(f"  ok    {len(lists)} rules share one {len(baseline)}-namespace "
              f"exclusion set")
    else:
        print("  FAIL  exclusion lists diverge — reconcile all four policies")
    print()
    return ok


def _prepare(rendered: str, namespace: str) -> str:
    """Normalise a chart/kustomize render into the manifest set ArgoCD actually
    syncs, evaluated in the right namespace:

      * drop Helm ``test`` hooks — ArgoCD skips them, so they never hit admission
        (a chart's test Pod is not a deployed workload);
      * backfill metadata.namespace on workload kinds the chart left unqualified,
        so the Kyverno namespace exclusion matches (helm -n stamps most, not all);
        an explicit namespace the chart sets is left untouched.
    """
    docs = []
    for doc in yaml.safe_load_all(rendered):
        # Skip anything that is not a Kubernetes object. helm v4 prints OCI pull
        # progress (`Pulled: …`, `Digest: …`) to stdout ahead of the manifests on
        # a fresh pull; those parse as kind-less mappings and would otherwise be
        # written back and rejected by kyverno ("Object 'Kind' is missing").
        if not isinstance(doc, dict) or not doc.get("kind"):
            continue
        anns = (doc.get("metadata") or {}).get("annotations") or {}
        if "test" in str(anns.get("helm.sh/hook", "")):
            continue
        if doc.get("kind") in WORKLOAD_KINDS:
            doc.setdefault("metadata", {}).setdefault("namespace", namespace)
        docs.append(doc)
    return "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)


def render_fleet(dest: pathlib.Path) -> int:
    """Render every addon into its namespace under `dest`; return unit count
    (-1 on a render failure)."""
    units = [u for u in discover() if u.chart not in SKIP_CHARTS]
    aliases = add_repos(units)
    count = 0

    for u in units:
        if not u.namespace:
            continue  # CRDs-only / no destination — nothing for the gate to check
        chart_ref = u.oci_ref() if u.is_oci else f"{aliases[u.repo]}/{u.chart}"
        base = REPO_ROOT / u.path / "values.yaml"
        for env in ENFORCE_ENVS:
            env_file = REPO_ROOT / u.path / f"values-{env}.yaml"
            if not env_file.exists():
                continue  # addon not deployed to this env
            cmd = ["helm", "template", u.chart, chart_ref, "--version", u.version,
                   "-n", u.namespace]
            for name, value in u.params:
                cmd += ["--set", f"{name}={value}"]
            if base.exists():
                cmd += ["-f", str(base)]
            cmd += ["-f", str(env_file)]
            proc = _run(cmd)
            if proc.returncode != 0:
                print(f"  helm render FAILED {u.chart}@{u.version} ({env}):\n"
                      f"{proc.stderr.strip()}")
                return -1
            (dest / f"{u.chart}-{env}.yaml").write_text(
                _prepare(proc.stdout, u.namespace))
            count += 1

    for path, namespace, per_env in KUSTOMIZE_WORKLOADS:
        roots = ([f"{path}/overlays/{e}" for e in ENFORCE_ENVS]
                 if per_env else [path])
        for root in roots:
            proc = _run(["kustomize", "build", "--enable-helm",
                         str(REPO_ROOT / root)])
            if proc.returncode != 0:
                print(f"  kustomize build FAILED {root}:\n{proc.stderr.strip()}")
                return -1
            tag = root.replace("/", "_")
            (dest / f"{tag}.yaml").write_text(_prepare(proc.stdout, namespace))
            count += 1

    return count


def build_policies(mode: str, dest: pathlib.Path) -> list[str]:
    """kustomize-build each policy group's overlay for `mode`; return file paths.
    mode is an overlay name: 'development' (Audit) or 'production' (Enforce)."""
    files = []
    for group in POLICY_GROUPS:
        overlay = POLICY_DIR / group / "overlays" / mode
        proc = _run(["kustomize", "build", str(overlay)])
        if proc.returncode != 0:
            print(f"  kustomize build FAILED {overlay}:\n{proc.stderr.strip()}")
            sys.exit(2)
        out = dest / f"{group}-{mode}.yaml"
        out.write_text(proc.stdout)
        files.append(str(out))
    return files


def kyverno_apply(policies: list[str], resources: pathlib.Path,
                  audit_warn: bool) -> subprocess.CompletedProcess:
    cmd = ["kyverno", "apply", *policies, "--resource", str(resources)]
    if audit_warn:
        cmd.append("--audit-warn")
    return _run(cmd)


def main() -> int:
    parity_ok = check_exclusion_parity()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        resources = tmpdir / "rendered"
        resources.mkdir()

        print("── Rendering addon fleet ──────────────────────────────────────────")
        count = render_fleet(resources)
        if count < 0:
            return 1
        print(f"  rendered {count} addon×env manifests into their namespaces\n")

        print("── Enforce-mode admission (staging/production overlay) ─────────────")
        enforce_policies = build_policies("production", tmpdir)
        enforce = kyverno_apply(enforce_policies, resources, audit_warn=False)
        shown = False
        for line in enforce.stdout.splitlines():
            if "failed:" in line or line.startswith("pass:"):
                print(f"  {line}")
                shown = shown or "failed:" in line
        enforce_ok = enforce.returncode == 0
        if not enforce_ok and not shown:
            # Non-zero for a reason other than a policy denial (a resource that
            # failed to load, a bad policy build) — surface it so CI is debuggable.
            print(f"  kyverno apply exited {enforce.returncode}:")
            print((enforce.stderr or enforce.stdout).strip())
        print(f"  {'ok    no addon denied on an Enforce-tier cluster' if enforce_ok else 'FAIL  an addon would be DENIED at admission (see above)'}\n")

        print("── Audit-mode (development overlay, --audit-warn) ──────────────────")
        audit_policies = build_policies("development", tmpdir)
        audit = kyverno_apply(audit_policies, resources, audit_warn=True)
        summary = next((l for l in audit.stdout.splitlines()
                        if l.startswith("pass:")), "")
        print(f"  {summary or 'audit run complete'}")
        # --audit-warn downgrades Audit-mode violations to warnings, so a healthy
        # run still exits 0; a non-zero exit here is a genuine error (a policy that
        # failed to build, a resource kyverno could not load), not a policy warn.
        # Verify the Audit overlay actually ran clean rather than trusting it.
        audit_ok = audit.returncode == 0
        if audit_ok:
            print("  ok    Audit overlay builds; violations warn (not deny) on dev\n")
        else:
            print(f"  FAIL  Audit overlay run errored (exit {audit.returncode}):")
            print((audit.stderr or audit.stdout).strip())
            print()

    if parity_ok and enforce_ok and audit_ok:
        print("Policy-admission gate PASSED.")
        return 0
    print("Policy-admission gate FAILED.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
