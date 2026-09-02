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
    platform.nanohype.dev/* labels, security agents need root/host access, and batch jobs have no service-style probes. If an addon
    lands in a namespace that is NOT on the exclusion list, its Deployment/
    DaemonSet is denied — and nothing before this gate would have caught it. The
    policies render clean, kubeconform clean, and kyverno's own unit tests pass;
    the contradiction only surfaces when the addon meets the policy on a real
    Enforce cluster.

WHAT IT DOES
    1. STRUCTURAL — parses the four exclusion-bearing base policies and asserts
       every rule's namespace exclusion list is IDENTICAL. The lists diverging is
       itself the bug class (a namespace excluded from three policies but not the
       fourth), so they are pinned equal here.
    2. FUNCTIONAL — discovers every Helm addon from the ApplicationSets (the same
       discovery scripts/render-addons.py uses — the single source of truth),
       renders each into its real ArgoCD destination namespace with base + each
       Enforce environment's values, adds the Kustomize-sourced workload that
       lands pods (the grafana dashboards' token rotator), then runs
       `kyverno apply` against the Enforce overlay of the
       best-practices + pod-security policies. Any denial fails the build. It also
       runs the Audit overlay (development) to prove the Audit variant matches the
       same rules and downgrades them — a warn on dev, a deny on staging/prod.
    3. CANARY — the functional half is rendered alongside a deliberately
       non-compliant workload in a namespace on no exclusion list, and the run is
       required to report exactly that one resource failing exactly the rules the
       structural half found. See "WHY THE CANARY" below.
    4. COVERAGE — asserts every namespace the fleet lands a workload kind in is on
       the exclusion list, so a new addon in a new namespace is reported here as
       uncovered rather than evaluated for real on a vended cluster.
    5. RUNTIME POD — the mirror image of the canary. Everything above is built
       from committed manifests, so a pod a CONTROLLER creates at runtime is
       invisible to all of it. One Argo-shaped workflow pod rides along and must
       be ADMITTED, and must be shown to have been evaluated. See "WHY THE
       RUNTIME POD".

WHY THE CANARY
    Without it this gate passed while evaluating NOTHING. Every namespace the
    fleet renders into is on the 25-namespace exclusion list, so Kyverno correctly
    matched zero resources and reported `pass: 0, fail: 0, warn: 0, error: 0,
    skip: 0` — and the gate, whose only verdict was `kyverno apply`'s exit code,
    called that "no addon denied".

    "Every addon is properly excluded", "the engine loaded no resources" and "the
    policy build produced no rules" are the same output, and an exit code cannot
    tell them apart. The canary separates them: it is the one resource that MUST
    be denied, so a run that does not deny it has not evaluated anything, and the
    gate says so instead of passing.

    That makes the exit code useless (it is now permanently non-zero), so the
    verdict is parsed out of `--policy-report --output-format json` per resource
    and per rule. The canary is generated here rather than committed as a manifest:
    ArgoCD watches this repo, and a root-running probe-less Deployment sitting in a
    synced path is a hazard the gate does not need.

WHY THE RUNTIME POD
    The canary proves the gate evaluated SOMETHING. It cannot prove the gate
    evaluated everything that meets these policies on a real cluster, because the
    render only ever produces what a chart or kustomize root emits — and a
    controller that creates pods at runtime emits nothing at render time.

    require-probes matched `Pod` and denied every Argo Workflows step pod at
    Enforce. The eval tier could not start on staging or production, and no gate
    in this repo could see it: eval-runner receives no rendered workload, so it
    was never on the exclusion list and never showed up as uncovered either. The
    coverage check reports namespaces the fleet RENDERS into; this reports what
    happens to a pod nobody renders.

    The verdict is two-sided on purpose. "No rule denied it" and "no rule ever
    saw it" are the same empty result set, and the second is the failure being
    guarded against — so admission alone is not enough, the pod must also be
    observed passing at least one rule.

SCOPE
    Addons only — the fleet the exclusion lists govern. Tenant workloads (druid,
    the apps-tenants matrix) are the intended SUBJECT of these policies: they must
    comply, and that is the tenant chart's responsibility, gated on the tenant's
    own render path, not here. Git-sourced addons (the agent operator, pulled from
    eks-agent-platform) render in their own repo's CI; here they are covered by
    namespace exclusion only. render-addons.SKIP_CHARTS, which would carve out any
    chart credential-less CI cannot pull, is currently EMPTY — every addon in the
    catalog is rendered and evaluated here.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

import yaml

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


# Helm charts occasionally emit the YAML `=` default-value sentinel (e.g. `- =`
# inside a ConfigMap payload). PyYAML's SafeLoader has no constructor for it and
# raises; the rendered text is only inspected for kind/namespace here, so map the
# sentinel to its literal scalar rather than fail the parse.
yaml.SafeLoader.add_constructor(
    "tag:yaml.org,2002:value",
    # The value tag only ever produces a ScalarNode; PyYAML's stub types the
    # callback's node as the base Node, which construct_scalar does not accept.
    lambda loader, node: loader.construct_scalar(node),  # type: ignore[arg-type]
)

# Reuse render-addons' discovery + repo setup — the ApplicationSets are the one
# source of truth for what the fleet is and where each addon lands. The module
# file is hyphenated (render-addons.py), so it is loaded by path rather than
# imported by name.
_ra_path = pathlib.Path(__file__).resolve().parent / "render-addons.py"
_spec = importlib.util.spec_from_file_location("render_addons", _ra_path)
assert _spec and _spec.loader, f"{_ra_path} is not loadable as a module"
render_addons = importlib.util.module_from_spec(_spec)
sys.modules["render_addons"] = render_addons  # dataclass resolves annotations here
_spec.loader.exec_module(render_addons)
REPO_ROOT = render_addons.REPO_ROOT

# Seconds a child process may run before the gate gives up on it. A subprocess
# with no deadline turns an unreachable registry into a job that hangs until the
# CI runner's own ceiling, with no diagnostic naming the command that stalled.
# NETWORK_TIMEOUT covers commands that resolve a remote chart or registry;
# LOCAL_TIMEOUT covers commands that only read the working tree.
NETWORK_TIMEOUT = 300
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

# A floor on addon×env manifests rendered into the resource file. Set well under
# what the catalog produces, so it catches "discovery matched almost nothing"
# rather than "an addon was retired".
MIN_RENDERED = 40


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
    ("dashboards/base", "grafana-operator", False),
]

# ── The canary ──────────────────────────────────────────────────────────
# The gate's proof that it evaluated anything. A Deployment in a namespace on NO
# exclusion list, violating every exclusion-bearing rule at once: no org label
# tier, no probes, no resource limits, root user. Every rule the structural half
# finds must report it, in both overlays.
#
# A Deployment (not a bare Pod) because the four policies match pod CONTROLLERS
# and Kyverno evaluates them through its autogen rules — a Pod canary would prove
# the base rules fire while leaving the autogen variants, which are what actually
# meet the fleet, unexercised.
CANARY_NAMESPACE = "policy-gate-canary"
CANARY_NAME = "policy-gate-canary"
CANARY_MANIFEST = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {CANARY_NAME}
  namespace: {CANARY_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {CANARY_NAME}
  template:
    metadata:
      labels:
        app: {CANARY_NAME}
    spec:
      containers:
        - name: canary
          image: registry.k8s.io/pause:3.10
          securityContext:
            runAsNonRoot: false
            runAsUser: 0
"""

# ── The runtime pod ─────────────────────────────────────────────────────
# The fleet render is built from charts and kustomize roots, so every resource
# this gate sees is a manifest somebody committed. That is a blind spot with a
# shape: pods created at RUNTIME by a controller are never rendered by anything,
# meet the policies for the first time on a live Enforce cluster, and are denied
# where no CI run can observe it.
#
# That is exactly how require-probes came to deny the whole eval tier. Argo
# Workflows creates a step pod per template — `init`, `wait` and `main`
# containers, none of which carry probes, none of which can — in the eval-runner
# namespace, which is on no exclusion list because the operator's chart renders
# no workload there for the gate to have noticed.
#
# So the gate now carries one, shaped the way Argo actually builds it, and
# requires it to be ADMITTED. The assertion is deliberately two-sided (see
# judge): it must produce at least one `pass`, which is what proves it was
# loaded and evaluated rather than quietly missing, and zero denials.
#
# Its namespace is NOT added to `landed`. eval-runner belongs on no exclusion
# list precisely because these pods are meant to comply on their own merits —
# recording it would invert the claim this check exists to make.
RUNTIME_POD_NAMESPACE = "eval-runner"
RUNTIME_POD_NAME = "policy-gate-runtime-pod"
RUNTIME_POD_MANIFEST = f"""apiVersion: v1
kind: Pod
metadata:
  name: {RUNTIME_POD_NAME}
  namespace: {RUNTIME_POD_NAMESPACE}
  labels:
    workflows.argoproj.io/workflow: {RUNTIME_POD_NAME}
    workflows.argoproj.io/completed: "false"
spec:
  restartPolicy: Never
  serviceAccountName: eval-runner
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  initContainers:
    - name: init
      image: quay.io/argoproj/argoexec:v3.7.3
      command: ["argoexec", "init"]
      resources:
        requests: {{cpu: 10m, memory: 64Mi}}
        limits: {{cpu: 100m, memory: 256Mi}}
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 8737
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: ["ALL"]
  containers:
    - name: wait
      image: quay.io/argoproj/argoexec:v3.7.3
      command: ["argoexec", "wait"]
      resources:
        requests: {{cpu: 10m, memory: 64Mi}}
        limits: {{cpu: 100m, memory: 256Mi}}
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 8737
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: ["ALL"]
    - name: main
      image: ghcr.io/nanohype/eks-agent-platform/eval-runner:0.1.0
      command: ["/bin/sh", "-c", "true"]
      resources:
        requests: {{cpu: 100m, memory: 256Mi}}
        limits: {{cpu: "1", memory: 1Gi}}
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: ["ALL"]
"""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault("timeout", NETWORK_TIMEOUT)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def check_exclusion_parity() -> tuple[bool, set[str], set[str]]:
    """Assert every exclusion-bearing rule shares one identical namespace set.

    Returns (ok, excluded_namespaces, rule_keys). The two extra returns are what
    the functional half checks itself against: the namespace set is the coverage
    baseline, and the rule keys are the set the canary must trip in full — read
    off the policies rather than restated here, so adding a rule to a policy
    without extending the canary fails instead of quietly going unexercised.
    """
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
    return ok, set(baseline), set(lists)


def _prepare(rendered: str, namespace: str, landed: set[str]) -> str:
    """Normalise a chart/kustomize render into the manifest set ArgoCD actually
    syncs, evaluated in the right namespace:

      * drop Helm ``test`` hooks — ArgoCD skips them, so they never hit admission
        (a chart's test Pod is not a deployed workload);
      * backfill metadata.namespace on workload kinds the chart left unqualified,
        so the Kyverno namespace exclusion matches (helm -n stamps most, not all);
        an explicit namespace the chart sets is left untouched.

    Every namespace a workload kind actually lands in is recorded into `landed`,
    which is what the coverage check compares against the exclusion list. It is
    collected here rather than from the ApplicationSet destination because a chart
    is free to place a workload somewhere other than the release namespace, and
    the coverage claim is about where pods END UP.
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
            landed.add(doc["metadata"]["namespace"])
        docs.append(doc)
    return "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)


def render_fleet(dest: pathlib.Path) -> tuple[int, set[str]]:
    """Render every addon into its namespace under `dest`, plus the canary.

    Returns (unit count, namespaces a workload kind landed in); count is -1 on a
    render failure."""
    units = [u for u in discover() if u.chart not in SKIP_CHARTS]
    aliases = add_repos(units)
    landed: set[str] = set()
    count = 0

    for u in units:
        if not u.namespace:
            continue  # CRDs-only / no destination — nothing for the gate to check
        chart_ref = u.oci_ref() if u.is_oci else f"{aliases[u.repo]}/{u.chart}"
        # Same discriminator as render-addons.py, and the same reason. A missing
        # directory meant "not deployed to this env" here too, so an appset
        # element pointing at nothing dropped silently out of the admission gate
        # as well — and neither gate backstopped the other, because both were
        # blind in exactly the same place.
        unit_dir = REPO_ROOT / u.path
        if not unit_dir.is_dir():
            print(f"  path '{u.path}' does not exist — the ApplicationSet element "
                  f"points at nothing, so {u.chart} reaches this gate never")
            return -1, landed
        base = unit_dir / "values.yaml"
        for env in ENFORCE_ENVS:
            env_file = unit_dir / f"values-{env}.yaml"
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
                return -1, landed
            (dest / f"{u.chart}-{env}.yaml").write_text(
                _prepare(proc.stdout, u.namespace, landed))
            count += 1

    for path, namespace, per_env in KUSTOMIZE_WORKLOADS:
        roots = ([f"{path}/overlays/{e}" for e in ENFORCE_ENVS]
                 if per_env else [path])
        for root in roots:
            proc = _run(["kustomize", "build", "--enable-helm",
                         str(REPO_ROOT / root)])
            if proc.returncode != 0:
                print(f"  kustomize build FAILED {root}:\n{proc.stderr.strip()}")
                return -1, landed
            tag = root.replace("/", "_")
            (dest / f"{tag}.yaml").write_text(
                _prepare(proc.stdout, namespace, landed))
            count += 1

    # The canary rides in with the fleet so it meets exactly the policy build the
    # fleet meets. Deliberately NOT recorded in `landed`: its namespace is
    # excluded from nothing by design, and the coverage check would read that as
    # an uncovered addon.
    (dest / "zz-policy-gate-canary.yaml").write_text(CANARY_MANIFEST)

    # Same reasoning, opposite verdict — the runtime pod must be ADMITTED. Also
    # not recorded in `landed`; see the comment on RUNTIME_POD_MANIFEST.
    (dest / "zz-policy-gate-runtime-pod.yaml").write_text(RUNTIME_POD_MANIFEST)

    return count, landed


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
                  audit_warn: bool) -> tuple[dict | None, subprocess.CompletedProcess]:
    """Run kyverno and return its parsed policy report.

    The exit code is deliberately NOT the verdict — the canary makes it
    permanently non-zero — so the report is requested as JSON and read per
    resource. A report that will not parse returns None, which every caller
    treats as a failure rather than as an empty result set.
    """
    cmd = ["kyverno", "apply", *policies, "--resource", str(resources),
           "--policy-report", "--output-format", "json"]
    if audit_warn:
        cmd.append("--audit-warn")
    proc = _run(cmd)
    try:
        return json.loads(proc.stdout), proc
    except json.JSONDecodeError:
        return None, proc


def _rule_key(result: dict) -> str:
    """`policy/rule` for a report entry, with Kyverno's autogen prefix stripped.

    Kyverno derives pod-controller variants of every pod rule and reports them
    under a generated name (`autogen-<rule>`, `autogen-cronjob-<rule>`), so a
    report never names a rule the way the policy file does. Normalising here is
    what lets the canary be checked against the rule set read off the policies.
    """
    rule = result.get("rule", "")
    for prefix in ("autogen-cronjob-", "autogen-"):
        if rule.startswith(prefix):
            rule = rule[len(prefix):]
            break
    return f"{result.get('policy', '')}/{rule}"


def _is_canary(result: dict) -> bool:
    return any(r.get("namespace") == CANARY_NAMESPACE
               and r.get("name") == CANARY_NAME
               for r in result.get("resources", []))


def _is_runtime_pod(result: dict) -> bool:
    return any(r.get("namespace") == RUNTIME_POD_NAMESPACE
               and r.get("name") == RUNTIME_POD_NAME
               for r in result.get("resources", []))


def judge_runtime_pod(results: list[dict]) -> bool:
    """The runtime pod must be admitted, AND must have been evaluated.

    One assertion would not do. "No rule denied it" and "no rule ever saw it"
    produce the same empty result set, and the second is the failure this whole
    check exists to catch — a pod the gate never rendered cannot be denied here
    no matter how badly it would fare on a real cluster.

    So the verdict is two-sided: at least one rule must report `pass` on it,
    which can only happen if it was loaded and matched, and no rule may report
    fail/warn/error. Reverting require-probes to match `Pod` trips the second;
    dropping the pod from the render trips the first.
    """
    hits = [r for r in results if _is_runtime_pod(r)]
    passes = [r for r in hits if r.get("result") == "pass"]
    denials = [r for r in hits if r.get("result") in ("fail", "warn", "error")]

    if not passes:
        print("  FAIL  the runtime pod was evaluated by NO rule — it was not "
              "rendered, or no policy")
        print("        matches a bare Pod any more. An unevaluated pod cannot be "
              "denied here, which is")
        print("        indistinguishable from being admitted.")
        return False
    if denials:
        print(f"  FAIL  the runtime pod was denied by {len(denials)} rule(s) — "
              f"an Argo workflow step pod")
        print("        would be rejected at admission on an Enforce cluster, and "
              "the eval tier could not run:")
        for r in denials:
            print(f"          [{r.get('result')}] {r.get('policy')}/{r.get('rule')}")
        return False
    print(f"  ok    runtime pod admitted — evaluated by {len(passes)} rule(s), "
          f"denied by none")
    return True


def judge(label: str, report: dict | None, proc: subprocess.CompletedProcess,
          expected_rules: set[str], canary_result: str) -> bool:
    """Verdict for one kyverno run, read out of the report rather than the exit code.

    Two independent things have to hold, and they fail for opposite reasons:

      * every expected rule reported the canary at `canary_result` — otherwise the
        run evaluated less than it claims to, and a silent no-op would otherwise
        read as a clean pass;
      * nothing OTHER than the canary was flagged — that is the original question,
        an addon that would be denied at admission on a vended enforce cluster.
    """
    print(f"── {label} ──")
    if report is None:
        # Kyverno emits NOTHING on stdout and exits 0 when its rules matched no
        # resource — the exact shape of the defect this canary exists to catch,
        # and indistinguishable from success to any exit-code check. Name it as
        # what it is rather than as a JSON problem.
        if not proc.stdout.strip() and proc.returncode == 0:
            print("  FAIL  kyverno matched NO resource and reported nothing "
                  "(exit 0, empty report).")
            print("        The canary should have been evaluated. Either it was "
                  "not rendered, or the")
            print("        policy build produced no rules, or the resources "
                  "failed to load.")
        else:
            print(f"  FAIL  kyverno produced no parseable report "
                  f"(exit {proc.returncode}):")
            print((proc.stderr or proc.stdout).strip()[:2000])
        print()
        return False

    results = report.get("results") or []
    summary = report.get("summary") or {}
    print(f"  {', '.join(f'{k}: {v}' for k, v in summary.items())}")

    canary_hits = {_rule_key(r) for r in results
                   if _is_canary(r) and r.get("result") == canary_result}
    # The runtime pod is judged separately and more precisely, so it is not also
    # counted as a foreign addon — its verdict names what actually broke.
    foreign = [r for r in results
               if not _is_canary(r) and not _is_runtime_pod(r)
               and r.get("result") in ("fail", "warn", "error")]

    ok = True
    unexercised = sorted(expected_rules - canary_hits)
    if unexercised:
        ok = False
        print(f"  FAIL  the canary was not {canary_result}ed by {len(unexercised)} "
              f"of {len(expected_rules)} rules — this run did not evaluate them:")
        for key in unexercised:
            print(f"          {key}")
        print("        Either the policy build produced no such rule, the resources "
              "failed to load,")
        print("        or a new rule matches kinds the canary does not carry — "
              "extend the canary.")
    else:
        print(f"  ok    canary {canary_result}ed by all {len(expected_rules)} rules "
              f"— the run evaluated every one")

    if foreign:
        ok = False
        print(f"  FAIL  {len(foreign)} non-canary result(s) — these are real "
              f"addon workloads:")
        for r in foreign[:20]:
            res = (r.get("resources") or [{}])[0]
            print(f"          [{r.get('result')}] {r.get('policy')}/{r.get('rule')} "
                  f"{res.get('kind')} {res.get('namespace')}/{res.get('name')}")
        if len(foreign) > 20:
            print(f"          … and {len(foreign) - 20} more")
    else:
        print("  ok    no addon flagged")

    if not judge_runtime_pod(results):
        ok = False
    print()
    return ok


def check_namespace_coverage(landed: set[str], excluded: set[str]) -> bool:
    """Assert every namespace the fleet lands a workload in is excluded.

    The exclusion list is what makes the fleet admissible at all, and it is
    hand-maintained. A new addon in a new namespace is a workload the policies
    WILL evaluate on a vended cluster — which the canary run alone would not
    report unless that workload also happened to violate a rule. This names it
    directly, so "uncovered" and "compliant" stop being the same signal.
    """
    print("── Exclusion coverage ──")
    uncovered = sorted(landed - excluded)
    if uncovered:
        print(f"  FAIL  {len(uncovered)} namespace(s) receive fleet workloads but "
              f"are on no exclusion list:")
        for ns in uncovered:
            print(f"          {ns}")
        print("        Add them to all four policies, or confirm the workload is "
              "meant to comply.")
        print()
        return False
    print(f"  ok    all {len(landed)} namespaces receiving fleet workloads are "
          f"excluded")
    print()
    return True


def main() -> int:
    gatelib.require('helm', 'kyverno')
    parity_ok, excluded, expected_rules = check_exclusion_parity()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        resources = tmpdir / "rendered"
        resources.mkdir()

        print("── Rendering addon fleet ──────────────────────────────────────────")
        count, landed = render_fleet(resources)
        if count < 0:
            return 1
        print(f"  rendered {count} addon×env manifests into their namespaces, "
              f"plus the canary\n")
        # A floor on what was RENDERED, not on what was found. `count` was
        # printed and compared only against a render failure, so a discovery
        # that matched almost nothing produced a fleet of a handful of manifests
        # and the run still reported that no addon would be denied.
        if count < MIN_RENDERED:
            print(f"  FAIL  {count} manifest(s) rendered, below the floor of "
                  f"{MIN_RENDERED}. The policies were evaluated against a fleet "
                  f"this catalog does not have, and 'no addon flagged' is a "
                  f"statement about that fleet rather than this one.\n")
            return 2

        coverage_ok = check_namespace_coverage(landed, excluded)

        # Enforce (staging/production): the canary must be DENIED by every rule.
        enforce_ok = judge(
            "Enforce-mode admission (staging/production overlay)",
            *kyverno_apply(build_policies("production", tmpdir), resources,
                           audit_warn=False),
            expected_rules=expected_rules, canary_result="fail")

        # Audit (development), --audit-warn: the SAME rules must match the canary
        # and downgrade it to a warning. Asserting the warn rather than just a
        # clean exit is what proves the two overlays differ only in severity — an
        # Audit overlay that had stopped matching would exit 0 either way.
        audit_ok = judge(
            "Audit-mode (development overlay, --audit-warn)",
            *kyverno_apply(build_policies("development", tmpdir), resources,
                           audit_warn=True),
            expected_rules=expected_rules, canary_result="warn")

    if parity_ok and coverage_ok and enforce_ok and audit_ok:
        print("Policy-admission gate PASSED.")
        return 0
    print("Policy-admission gate FAILED.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
