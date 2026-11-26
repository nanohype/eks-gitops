#!/usr/bin/env python3
"""Policy-admission gate — render the addon fleet and prove no addon is denied by
this repo's own Kyverno policies on an Enforce-tier cluster.

WHY THIS EXISTS
    The catalog's core promise is that a vended cluster works. On staging and
    production the Kyverno ValidatingPolicies run at Deny (the overlays set
    validationActions to [Deny]), so a workload that violates a policy is DENIED
    at admission — a first CREATE has no old object, and the existing-violation
    allowance each validation carries only grandfathers objects that already
    exist.

    require-labels (Deployment/StatefulSet/DaemonSet must carry the 5-label org
    tier), require-readiness-probe, require-liveness-probe,
    require-run-as-non-root, require-cpu-limit and require-memory-limit all carry
    a hand-maintained namespace exclusion list. The addon fleet cannot
    satisfy these policies: upstream charts never stamp the org
    platform.nanohype.dev/* labels, security agents need root/host access, and batch jobs have no service-style probes. If an addon
    lands in a namespace that is NOT on the exclusion list, its Deployment/
    DaemonSet is denied — and nothing before this gate would have caught it. The
    policies render clean, kubeconform clean, and kyverno's own unit tests pass;
    the contradiction only surfaces when the addon meets the policy on a real
    Enforce cluster.

WHAT IT DOES
    1. STRUCTURAL — parses the six exclusion-bearing base policies and asserts
       every policy's namespace exclusion list is IDENTICAL, and that nothing
       else narrows what a policy matches. The lists diverging is itself the bug
       class (a namespace excluded from five policies but not the sixth), so they
       are pinned equal here. It also derives each policy's existing-violation
       term from its `compliant` term and requires the two to agree (see
       existing_violation_problems): no `kyverno` run can show an UPDATE that
       turns a compliant object non-compliant, so the term is held to its form.
    2. FUNCTIONAL — discovers every Helm addon from the ApplicationSets (the same
       discovery scripts/render-addons.py uses — the single source of truth),
       renders each into its real ArgoCD destination namespace with base + each
       Enforce environment's values, adds the Kustomize-sourced workload that
       lands pods (the grafana dashboards' token rotator), then runs
       `kyverno apply` against the Deny overlay of the
       best-practices + pod-security policies. Any denial fails the build. It also
       runs the Audit overlay (development) to prove it matches the same
       validations, and asserts structurally that each overlay sets the
       validationActions its environment is meant to have — [Audit] on dev,
       [Deny] on staging/prod — along with failurePolicy Fail, admission
       evaluation left on, and the validation expression that tier carries.
       (`kyverno apply` reports a ValidatingPolicy
       violation as `fail` under either action; its --audit-warn does nothing for
       ValidatingPolicy in 1.20, so the action cannot be read off the report.)
    3. CANARY — the functional half is rendered alongside a deliberately
       non-compliant workload in a namespace on no exclusion list, and the run is
       required to report exactly that one resource failing exactly the
       validations the structural half found. See "WHY THE CANARY" below.
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

    require-probes (now require-readiness-probe and require-liveness-probe)
    matched `Pod` and denied every Argo Workflows step pod at Enforce. The eval
    tier could not start on staging or production, and no gate
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
import re
import subprocess
import sys
import tempfile

import gatelib
import yaml

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

# Reuse render-addons' discovery and its SKIP_CHARTS — the ApplicationSets are the
# one source of truth for what the fleet is and where each addon lands. The module
# file is hyphenated (render-addons.py), so it is loaded by path rather than
# imported by name.
_ra_path = pathlib.Path(__file__).resolve().parent / "render-addons.py"
_spec = importlib.util.spec_from_file_location("render_addons", _ra_path)
assert _spec and _spec.loader, f"{_ra_path} is not loadable as a module"
render_addons = importlib.util.module_from_spec(_spec)
sys.modules["render_addons"] = render_addons  # dataclass resolves annotations here
_spec.loader.exec_module(render_addons)
REPO_ROOT = render_addons.REPO_ROOT

# Seconds one helm render, kustomize build or kyverno apply may run before the
# gate gives up on it. A subprocess with no deadline turns a stalled command into
# a job that hangs until the CI runner's own ceiling, with no diagnostic naming
# the command. Chart archives are read through registry.py, which bounds its own
# reads, so helm here renders an archive already on disk.
RENDER_TIMEOUT = 300
SKIP_CHARTS = render_addons.SKIP_CHARTS
discover = render_addons.discover

POLICY_DIR = REPO_ROOT / "policies" / "kyverno"

# The six policies whose exclusion lists must agree, as (group, file) pairs.
EXCLUSION_POLICIES = [
    ("best-practices", "require-labels.yaml"),
    ("best-practices", "require-readiness-probe.yaml"),
    ("best-practices", "require-liveness-probe.yaml"),
    ("pod-security-standards", "require-non-root.yaml"),
    ("pod-security-standards", "require-cpu-limit.yaml"),
    ("pod-security-standards", "require-memory-limit.yaml"),
]

# The label the API server stamps on every Namespace with its own name: a NotIn
# on it is the namespace-name exclusion the policies share.
NAMESPACE_NAME_LABEL = "kubernetes.io/metadata.name"

# The validationActions each overlay must set on every ValidatingPolicy it
# renders. `kyverno apply` cannot tell Audit from Deny (see main), so the split
# between the tiers is asserted here, on the rendered policies themselves.
EXPECTED_ACTIONS = {
    "development": ["Audit"],
    "staging": ["Deny"],
    "production": ["Deny"],
}

# The validation expression each overlay renders on every exclusion-bearing
# ValidatingPolicy. The base admits an UPDATE to an object that already violated
# (`existingViolation`, the legacy allowExistingViolations); the legacy engine
# applied that under Enforce only, so the Audit tier judges the new object alone.
GRANDFATHERED = "variables.compliant || variables.existingViolation"
EXPECTED_EXPRESSION = {
    "development": "variables.compliant",
    "staging": GRANDFATHERED,
    "production": GRANDFATHERED,
}

# Matches `object.` where it is not the tail of `oldObject.` or another name.
OBJECT_REF = re.compile(r"(?<![\w.])object\.")

# The two policy groups that carry the exclusion-bearing validation policies and
# ship both an Audit (development) and Deny (staging/production) overlay.
POLICY_GROUPS = ["best-practices", "pod-security-standards"]

# Deny runs on staging + production; both set the base policies to [Deny].
ENFORCE_ENVS = ["staging", "production"]

# A floor on addon×env manifests rendered. Set well under what the catalog
# produces; see the note at the comparison for why it is a number rather than a
# quantity derived from the same walk.
MIN_RENDERED = 40

# Kinds Kyverno's workload policies (and their autogen pod-controller variants)
# evaluate. Namespace-scoped, so they must carry metadata.namespace for the
# exclusion match to fire — helm -n stamps it on most charts; this backfills any
# the chart left unqualified so the gate never under-reports. ReplicationController
# stays although Kyverno 1.20's CEL autogen derives no RC variant, so no policy
# matches the RC object itself: the Pods it creates are matched by the Pod rules,
# so the namespace it lands in must still be covered.
WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
}

# Kustomize-sourced addon workloads that render pods but carry no Helm chart, so
# discover() (chart-keyed) never sees them: (kustomize root relative to repo,
# destination namespace, per-env overlays or None for an env-agnostic root).
KUSTOMIZE_WORKLOADS = [
    ("dashboards/base", "grafana-operator", False),
]

# ── The canary ──────────────────────────────────────────────────────────
# The gate's proof that it evaluated anything. A Deployment in a namespace on NO
# exclusion list, violating every exclusion-bearing validation at once: no org
# label tier, no probes, no resource limits, root user. Every validation the
# structural half finds must report it, in both overlays.
#
# A Deployment (not a bare Pod) because the policies match pod CONTROLLERS —
# directly, or through the autogen variants Kyverno derives from a Pod policy —
# and a Pod canary would prove the Pod validations fire while leaving the
# controller variants, which are what actually meet the fleet, unexercised.
#
# A ValidatingPolicy reports only the FIRST validation that fails. A policy with
# two would let the canary reach the first and never the second, so every
# exclusion-bearing policy holds exactly one, and the structural half refuses
# more (see check_exclusion_parity).
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
# That is exactly how require-probes (now the two probe policies) came to deny
# the whole eval tier. Argo
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
#
# The operator submits every run under its Platform's own eval ServiceAccount,
# eval-<platform>, which it creates in that namespace, so the pod names eval-ops:
# the account of ops, the one Platform this catalog declares.
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
  serviceAccountName: eval-ops
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
      image: ghcr.io/nanohype/eks-agent-platform/eval-runner:0.1.2
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
    kw.setdefault("timeout", RENDER_TIMEOUT)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def exclusion_of(doc: dict) -> tuple[list[str] | None, list[str]]:
    """The namespace names a ValidatingPolicy excludes, and what else narrows it.

    The shared exclusion is ONE matchExpression on the namespace-name label with
    operator NotIn. Anything else that narrows what the policy matches — another
    expression, an objectSelector, a matchCondition, excludeResourceRules, a
    namespace matchLabels — is reported as a problem rather than folded in:
    each of those exempts objects the parity comparison cannot see, which is the
    drift this check exists to stop. Returns (names or None, problems).
    """
    spec = doc.get("spec") or {}
    mc = spec.get("matchConstraints") or {}
    problems: list[str] = []
    for field in ("objectSelector", "excludeResourceRules"):
        if mc.get(field):
            problems.append(f"matchConstraints.{field} narrows the match")
    if spec.get("matchConditions"):
        problems.append("matchConditions narrow the match")
    selector = mc.get("namespaceSelector") or {}
    if selector.get("matchLabels"):
        problems.append("namespaceSelector.matchLabels narrows the match")
    exprs = selector.get("matchExpressions") or []
    if len(exprs) != 1:
        problems.append(f"namespaceSelector carries {len(exprs)} matchExpressions, not one")
        return None, problems
    expr = exprs[0]
    if expr.get("key") != NAMESPACE_NAME_LABEL or expr.get("operator") != "NotIn":
        problems.append(
            f"the namespaceSelector expression is {expr.get('key')} "
            f"{expr.get('operator')}, not {NAMESPACE_NAME_LABEL} NotIn"
        )
        return None, problems
    return sorted(set(expr.get("values") or [])), problems


def _normalise(expression: str) -> str:
    return " ".join(str(expression).split())


def existing_violation_problems(doc: dict) -> list[str]:
    """What is wrong with a policy's emulation of allowExistingViolations.

    The term may admit an UPDATE only when the OLD object fails the same check
    the new one is held to. Its other direction — an UPDATE that turns a
    compliant object non-compliant is refused — has no test: `kyverno test` sets
    object and oldObject to the same resource for an UPDATE, and `kyverno apply`
    evaluates as a background scan with no old object. A term that admitted
    every UPDATE would pass every row and every run. So it is held to its form:
    `existingViolation` must be exactly `compliant` read off oldObject, negated,
    behind the UPDATE guard, and the base validation must be the two OR'd.
    """
    spec = doc.get("spec") or {}
    variables = {
        v.get("name"): v.get("expression")
        for v in spec.get("variables") or []
        if isinstance(v, dict)
    }
    problems: list[str] = []
    compliant = variables.get("compliant")
    existing = variables.get("existingViolation")
    if compliant is None or existing is None:
        return [
            "declares no `compliant` and `existingViolation` variables to derive "
            "the existing-violation term from"
        ]
    want = _normalise(
        "oldObject != null && has(oldObject.kind) && !("
        + OBJECT_REF.sub("oldObject.", str(compliant))
        + ")"
    )
    if _normalise(existing) != want:
        problems.append(
            f"existingViolation is not `compliant` read off oldObject and "
            f"negated behind the UPDATE guard — want `{want}`"
        )
    validations = spec.get("validations") or []
    if validations and _normalise(validations[0].get("expression", "")) != GRANDFATHERED:
        problems.append(f"the base validation is not `{GRANDFATHERED}`")
    return problems


def check_exclusion_parity() -> tuple[bool, set[str], set[str]]:
    """Assert every exclusion-bearing policy shares one identical namespace set.

    Returns (ok, excluded_namespaces, validation_keys). The two extra returns are
    what the functional half checks itself against: the namespace set is the
    coverage baseline, and the keys (`policy/<validation index>`) are the set the
    canary must trip in full — read off the policies rather than restated here,
    so adding a validation without extending the canary fails instead of quietly
    going unexercised.

    A policy must hold exactly one validation. A ValidatingPolicy reports only the
    first that fails, so the canary could never reach a second, and the key for
    it would be one no run can report: the gate would fail on every run, which is
    the right outcome but the wrong diagnostic, so it is named here instead.
    """
    print("── Exclusion-list parity ──────────────────────────────────────────")
    lists: dict[str, list[str]] = {}
    keys: set[str] = set()
    ok = True
    for group, fname in EXCLUSION_POLICIES:
        doc = gatelib.read_yaml(POLICY_DIR / group / "base" / fname)
        name = (doc.get("metadata") or {}).get("name", fname)
        if doc.get("kind") != "ValidatingPolicy":
            ok = False
            print(f"  FAIL  {group}/{fname} is a {doc.get('kind')}, not a ValidatingPolicy")
            continue
        names, problems = exclusion_of(doc)
        for problem in problems:
            ok = False
            print(f"  FAIL  {name}: {problem}")
        validations = (doc.get("spec") or {}).get("validations") or []
        if len(validations) != 1:
            ok = False
            print(
                f"  FAIL  {name} holds {len(validations)} validations, not one — a "
                f"ValidatingPolicy reports only the first that fails"
            )
        keys.update(f"{name}/{i}" for i in range(len(validations)))
        for problem in existing_violation_problems(doc):
            ok = False
            print(f"  FAIL  {name}: {problem}")
        if names is not None:
            lists[name] = names

    if not lists:
        print("  FAIL  no policy carries a readable exclusion list")
        print()
        return False, set(), keys
    baseline_key, baseline = next(iter(lists.items()))
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
        print(f"  ok    {len(lists)} policies share one {len(baseline)}-namespace exclusion set")
    else:
        print(f"  FAIL  exclusion lists diverge — reconcile all {len(EXCLUSION_POLICIES)} policies")
    print()
    return ok, set(baseline), keys


def check_validation_actions(mode: str, policy_files: list[str]) -> bool:
    """Every ValidatingPolicy an overlay renders is set up for that tier.

    `kyverno apply` reports a violation as `fail` whether the policy would Audit
    or Deny it, and it evaluates as a background scan, so the run cannot prove
    the overlays differ or that admission evaluates at all. This does, on the
    rendered objects: the tier's validationActions, failurePolicy Fail (an
    Ignore lets a request through whenever Kyverno cannot answer), admission
    evaluation not switched off (which turns the Deny tier into nothing while
    every run still reports the canary), and the tier's validation expression.
    It also refuses an overlay that rendered fewer ValidatingPolicies than the
    exclusion-bearing set, which would satisfy the comparison vacuously.
    """
    want = EXPECTED_ACTIONS[mode]
    want_expression = EXPECTED_EXPRESSION[mode]
    seen = 0
    ok = True
    for path in policy_files:
        for doc in yaml.safe_load_all(pathlib.Path(path).read_text()):
            if not isinstance(doc, dict) or doc.get("kind") != "ValidatingPolicy":
                continue
            seen += 1
            name = doc["metadata"]["name"]
            spec = doc.get("spec") or {}
            got = spec.get("validationActions")
            if got != want:
                ok = False
                print(f"  FAIL  {mode}: {name} has validationActions {got}, want {want}")
            if spec.get("failurePolicy") != "Fail":
                ok = False
                print(
                    f"  FAIL  {mode}: {name} has failurePolicy "
                    f"{spec.get('failurePolicy')}, want Fail"
                )
            admission = (spec.get("evaluation") or {}).get("admission") or {}
            if admission.get("enabled") is False:
                ok = False
                print(
                    f"  FAIL  {mode}: {name} sets evaluation.admission.enabled false, "
                    f"so it evaluates nothing at admission"
                )
            expressions = [
                _normalise(v.get("expression", "")) for v in spec.get("validations") or []
            ]
            if expressions != [want_expression]:
                ok = False
                print(f"  FAIL  {mode}: {name} validates {expressions}, want ['{want_expression}']")
    if seen < len(EXCLUSION_POLICIES):
        print(
            f"  FAIL  {mode}: rendered {seen} ValidatingPolicies, expected at least "
            f"{len(EXCLUSION_POLICIES)}"
        )
        return False
    if ok:
        print(
            f"  ok    {mode}: all {seen} ValidatingPolicies set validationActions {want}, "
            f"failurePolicy Fail, admission on, validating `{want_expression}`"
        )
    return ok


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
        # Skip anything that is not a Kubernetes object. A kind-less mapping
        # written back makes kyverno reject the whole resource file ("Object
        # 'Kind' is missing"), and a run that evaluates nothing reports no addon
        # as denied.
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


def workloads(prepared: str) -> list[dict]:
    """The objects of a prepared render that the admission policies evaluate.

    Every rule under test matches a kind in WORKLOAD_KINDS, so nothing else
    changes a verdict. `kyverno apply` also loads every resource into an
    in-memory API server before evaluating, and that server refuses some objects
    a cluster accepts, so handing it the rest of a chart risks the run for no
    information.
    """
    return [
        d
        for d in yaml.safe_load_all(prepared)
        if isinstance(d, dict) and d.get("kind") in WORKLOAD_KINDS
    ]


def distinct_identities(docs: list[dict]) -> list[dict]:
    """One object per (apiVersion, kind, namespace, name), as an API server holds.

    `kyverno apply` loads every resource it is given into an in-memory API server
    and refuses the whole run on a second object with the same identity. The
    fleet renders each addon once per Enforce environment, so every workload a
    chart ships unchanged across them arrives twice.

    An exact repeat carries nothing new and is dropped. A repeat that DIFFERS is
    an environment's own variant of that object — a workload with other replicas
    or other values — and dropping it would leave that variant unevaluated, so it
    is kept under a name suffixed with its position. The policies here match on
    kind, namespace and labels, never on name, so the suffix changes what is
    reported and not what is decided.
    """
    kept: dict[tuple, list[dict]] = {}
    out: list[dict] = []
    for doc in docs:
        meta = doc.get("metadata") or {}
        key = (doc.get("apiVersion"), doc.get("kind"), meta.get("namespace"), meta.get("name"))
        variants = kept.setdefault(key, [])
        if any(v == doc for v in variants):
            continue
        if variants:
            doc = {**doc, "metadata": {**meta, "name": f"{meta.get('name')}--{len(variants) + 1}"}}
        variants.append(doc)
        out.append(doc)
    return out


def render_fleet(dest: pathlib.Path) -> tuple[int, set[str]]:
    """Render every addon into its namespace under `dest`, plus the canary.

    Returns (unit count, namespaces a workload kind landed in); count is -1 on a
    render failure."""
    units = [u for u in discover() if u.chart not in SKIP_CHARTS]
    landed: set[str] = set()
    count = 0
    fleet: list[dict] = []

    for u in units:
        if not u.namespace:
            continue  # CRDs-only / no destination — nothing for the gate to check
        # Same discriminator as render-addons.py, and the same reason. A missing
        # directory meant "not deployed to this env" here too, so an appset
        # element pointing at nothing dropped silently out of the admission gate
        # as well — and neither gate backstopped the other, because both were
        # blind in exactly the same place.
        unit_dir = REPO_ROOT / u.path
        if not unit_dir.is_dir():
            print(
                f"  path '{u.path}' does not exist — the ApplicationSet element "
                f"points at nothing, so {u.chart} reaches this gate never"
            )
            return -1, landed
        base = unit_dir / "values.yaml"
        for env in ENFORCE_ENVS:
            env_file = unit_dir / f"values-{env}.yaml"
            if not env_file.exists():
                continue  # addon not deployed to this env
            archive = gatelib.chart_archive_or_exit(u.source, u.chart, u.version)
            cmd = ["helm", "template", u.chart, str(archive), "-n", u.namespace]
            for name, value in u.params:
                cmd += ["--set", f"{name}={value}"]
            if base.exists():
                cmd += ["-f", str(base)]
            cmd += ["-f", str(env_file)]
            proc = _run(cmd)
            if proc.returncode != 0:
                print(f"  helm render FAILED {u.chart}@{u.version} ({env}):\n{proc.stderr.strip()}")
                return -1, landed
            fleet += workloads(_prepare(proc.stdout, u.namespace, landed))
            count += 1

    for path, namespace, per_env in KUSTOMIZE_WORKLOADS:
        roots = [f"{path}/overlays/{e}" for e in ENFORCE_ENVS] if per_env else [path]
        for root in roots:
            proc = _run(["kustomize", "build", "--enable-helm", str(REPO_ROOT / root)])
            if proc.returncode != 0:
                print(f"  kustomize build FAILED {root}:\n{proc.stderr.strip()}")
                return -1, landed
            fleet += workloads(_prepare(proc.stdout, namespace, landed))
            count += 1

    (dest / "fleet.yaml").write_text(
        "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in distinct_identities(fleet))
    )

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
    mode is an overlay name: 'development' (Audit), 'staging' or 'production'
    (Deny)."""
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


def kyverno_apply(
    policies: list[str], resources: pathlib.Path
) -> tuple[dict | None, subprocess.CompletedProcess]:
    """Run kyverno and return its parsed policy report.

    The exit code is deliberately NOT the verdict — the canary makes it
    permanently non-zero — so the report is requested as JSON and read per
    resource. A report that will not parse returns None, which every caller
    treats as a failure rather than as an empty result set.
    """
    cmd = [
        "kyverno",
        "apply",
        *policies,
        "--resource",
        str(resources),
        "--policy-report",
        "--output-format",
        "json",
    ]
    proc = _run(cmd)
    return report_json(proc.stdout), proc


def report_json(stdout: str) -> dict | None:
    """The JSON report out of `kyverno apply` stdout, or None if there is none.

    The CLI can print notices to stdout ahead of the report, so the report starts
    at the first line that opens a JSON object. Anything after the object is ignored; anything that
    does not decode to an object is no report.
    """
    lines = stdout.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("{"):
            rest = "".join(lines[i:])
            try:
                doc, _ = json.JSONDecoder().raw_decode(rest)
            except json.JSONDecodeError:
                return None
            return doc if isinstance(doc, dict) else None
    return None


def _rule_key(result: dict) -> str:
    """`policy/<validation index>` for a report entry.

    A ValidatingPolicy result names no rule (every one reads `validation`); which
    validation failed is in its `cel.validationIndex` property, and an autogen
    controller variant reports under the policy's own name. This is the key
    check_exclusion_parity derives from each policy's validations. A result with
    no index keys as `policy/?`, which matches no expected key.
    """
    index = (result.get("properties") or {}).get("cel.validationIndex", "?")
    return f"{result.get('policy', '')}/{index}"


def _is_canary(result: dict) -> bool:
    return any(
        r.get("namespace") == CANARY_NAMESPACE and r.get("name") == CANARY_NAME
        for r in result.get("resources", [])
    )


def _is_runtime_pod(result: dict) -> bool:
    return any(
        r.get("namespace") == RUNTIME_POD_NAMESPACE and r.get("name") == RUNTIME_POD_NAME
        for r in result.get("resources", [])
    )


def judge_runtime_pod(results: list[dict]) -> bool:
    """The runtime pod must be admitted, AND must have been evaluated.

    One assertion would not do. "No rule denied it" and "no rule ever saw it"
    produce the same empty result set, and the second is the failure this whole
    check exists to catch — a pod the gate never rendered cannot be denied here
    no matter how badly it would fare on a real cluster.

    So the verdict is two-sided: at least one rule must report `pass` on it,
    which can only happen if it was loaded and matched, and no rule may report
    fail/warn/error. Reverting a probe policy to match `Pod` trips the second;
    dropping the pod from the render trips the first.
    """
    hits = [r for r in results if _is_runtime_pod(r)]
    passes = [r for r in hits if r.get("result") == "pass"]
    denials = [r for r in hits if r.get("result") in ("fail", "warn", "error")]

    if not passes:
        print(
            "  FAIL  the runtime pod was evaluated by NO rule — it was not rendered, or no policy"
        )
        print(
            "        matches a bare Pod any more. An unevaluated pod cannot be "
            "denied here, which is"
        )
        print("        indistinguishable from being admitted.")
        return False
    if denials:
        print(
            f"  FAIL  the runtime pod was denied by {len(denials)} rule(s) — "
            f"an Argo workflow step pod"
        )
        print(
            "        would be rejected at admission on an Enforce cluster, and "
            "the eval tier could not run:"
        )
        for r in denials:
            print(f"          [{r.get('result')}] {r.get('policy')}/{r.get('rule')}")
        return False
    print(f"  ok    runtime pod admitted — evaluated by {len(passes)} rule(s), denied by none")
    return True


def judge(
    label: str,
    report: dict | None,
    proc: subprocess.CompletedProcess,
    expected_rules: set[str],
    canary_result: str = "fail",
) -> bool:
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
            print(
                "  FAIL  kyverno matched NO resource and reported nothing (exit 0, empty report)."
            )
            print(
                "        The canary should have been evaluated. Either it was not rendered, or the"
            )
            print("        policy build produced no rules, or the resources failed to load.")
        else:
            print(f"  FAIL  kyverno produced no parseable report (exit {proc.returncode}):")
            print((proc.stderr or proc.stdout).strip()[:2000])
        print()
        return False

    results = report.get("results") or []
    summary = report.get("summary") or {}
    print(f"  {', '.join(f'{k}: {v}' for k, v in summary.items())}")

    canary_hits = {
        _rule_key(r) for r in results if _is_canary(r) and r.get("result") == canary_result
    }
    # The runtime pod is judged separately and more precisely, so it is not also
    # counted as a foreign addon — its verdict names what actually broke.
    foreign = [
        r
        for r in results
        if not _is_canary(r)
        and not _is_runtime_pod(r)
        and r.get("result") in ("fail", "warn", "error")
    ]

    ok = True
    unexercised = sorted(expected_rules - canary_hits)
    if unexercised:
        ok = False
        print(
            f"  FAIL  the canary was not {canary_result}ed by {len(unexercised)} "
            f"of {len(expected_rules)} validations — this run did not evaluate them:"
        )
        for key in unexercised:
            print(f"          {key}")
        print(
            "        Either the policy build produced no such validation, the "
            "resources failed to load,"
        )
        print(
            "        or a new validation matches kinds the canary does not carry — "
            "extend the canary."
        )
    else:
        print(
            f"  ok    canary {canary_result}ed by all {len(expected_rules)} validations "
            f"— the run evaluated every one"
        )

    if foreign:
        ok = False
        print(f"  FAIL  {len(foreign)} non-canary result(s) — these are real addon workloads:")
        for r in foreign[:20]:
            res = (r.get("resources") or [{}])[0]
            print(
                f"          [{r.get('result')}] {r.get('policy')}/{r.get('rule')} "
                f"{res.get('kind')} {res.get('namespace')}/{res.get('name')}"
            )
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
        print(
            f"  FAIL  {len(uncovered)} namespace(s) receive fleet workloads but "
            f"are on no exclusion list:"
        )
        for ns in uncovered:
            print(f"          {ns}")
        print(
            f"        Add them to all {len(EXCLUSION_POLICIES)} policies, or confirm the "
            "workload is meant to comply."
        )
        print()
        return False
    print(f"  ok    all {len(landed)} namespaces receiving fleet workloads are excluded")
    print()
    return True


def main() -> int:
    gatelib.require("helm", "kyverno")
    parity_ok, excluded, expected_rules = check_exclusion_parity()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        resources = tmpdir / "rendered"
        resources.mkdir()

        print("── Rendering addon fleet ──────────────────────────────────────────")
        count, landed = render_fleet(resources)
        if count < 0:
            return 1
        print(f"  rendered {count} addon×env manifests into their namespaces, plus the canary\n")
        # A constant, not a derivation. Bounding the render by the discovered
        # units was written first and is circular: discover() reads the same
        # ApplicationSets the render does, so a discovery that matched almost
        # nothing lowers the bound by exactly as much as it lowers the count and
        # the comparison holds. Nothing else in the tree enumerates the fleet.
        #
        # The canary and the runtime pod keep every rule-coverage assertion green
        # regardless of how much fleet was rendered, so without a floor here a run
        # over almost no fleet is indistinguishable from a clean one.
        if count < MIN_RENDERED:
            print(
                f"  FAIL  {count} manifest(s) rendered, below the floor of "
                f"{MIN_RENDERED}. The policies were evaluated against a fleet "
                f"this catalog does not have, and 'no addon flagged' is a "
                f"statement about that fleet rather than this one.\n"
            )
            return gatelib.CANNOT_RUN

        coverage_ok = check_namespace_coverage(landed, excluded)

        # The tier split, read off the rendered overlays (see
        # check_validation_actions for why the runs below cannot show it).
        print("── validationActions per overlay ──")
        built = {mode: build_policies(mode, tmpdir) for mode in EXPECTED_ACTIONS}
        # Every overlay is checked and reported before the verdict is taken, so
        # one wrong tier does not hide another.
        actions = {mode: check_validation_actions(mode, files) for mode, files in built.items()}
        actions_ok = all(actions.values())
        print()

        # Deny (staging/production): the canary must be refused by every
        # validation, and nothing else may be.
        enforce_ok = judge(
            "Deny admission (production overlay)",
            *kyverno_apply(built["production"], resources),
            expected_rules=expected_rules,
        )

        # Audit (development): the SAME validations must match the canary.
        # `kyverno apply` reports it `fail` here too — the CLI's --audit-warn has
        # no effect on ValidatingPolicy — so what tells the tiers apart is the
        # validationActions check above. This run proves the Audit overlay still
        # matches: one that had stopped matching would report no canary result.
        audit_ok = judge(
            "Audit overlay (development)",
            *kyverno_apply(built["development"], resources),
            expected_rules=expected_rules,
        )

    if parity_ok and coverage_ok and actions_ok and enforce_ok and audit_ok:
        print("Policy-admission gate PASSED.")
        return 0
    print("Policy-admission gate FAILED.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
