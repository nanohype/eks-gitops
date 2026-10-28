#!/usr/bin/env python3
"""Every rendered policy overlay is a policy Kyverno will actually accept.

The other Kyverno gates in this repo check what a policy DOES. `kyverno test`
proves each rule passes a compliant resource and fails a violating one, and
check-policy-admission.py proves the fleet is admissible against the Enforce
tier. Neither asks the prior question: will the API server accept this
policy at all?

Kyverno enforces semantic rules that no JSON schema encodes and no behavioural
test reaches. One example, on a ClusterPolicy verifyImages rule:

    spec.rules[0].verifyImages[0].mutateDigest: Invalid value: true:
    mutateDigest must be set to false for 'Audit' failure action

A policy carrying that combination renders clean through kustomize, passes
kubeconform (the schema permits both fields independently), and passes
`kyverno test` — which loads the policy in a context that does not run this
validation. It then fails to apply on every cluster whose overlay is Audit. A
policy Kyverno cannot load at all fails the same way and is quieter still:
`kyverno apply` drops it and reports `error: 0`. The policy-admission gate
renders only the Enforce tier, so an invalid Audit overlay never reaches it.

So this renders EVERY policy overlay — every group, every environment — and runs
each through Kyverno's own validation. An overlay the API server would reject
fails the build instead of the sync.

It also asserts what Kyverno itself will not: every rendered
ImageValidatingPolicy, in every environment, pins the digest it verified
(`mutateDigest: true`) and refuses an image that reaches validation unpinned
(`verifyDigest: true`). Either set false is valid Kyverno, so nothing above
catches it, and it reopens the window between admission resolving a tag and the
kubelet resolving it again. An overlay can patch either field, so this reads the
rendered overlays rather than the base.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import subprocess
import sys

import yaml

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


ROOT = pathlib.Path(__file__).resolve().parent.parent

# Seconds a child process may run before the gate gives up on it. A subprocess
# with no deadline turns an unreachable registry into a job that hangs until the
# CI runner's own ceiling, with no diagnostic naming the command that stalled.
# NETWORK_TIMEOUT covers commands that resolve a remote chart or registry;
# LOCAL_TIMEOUT covers commands that only read the working tree.
LOCAL_TIMEOUT = 120
POLICIES = ROOT / "policies" / "kyverno"
ENVS = ("development", "staging", "production")

# A syntactically trivial Pod. The point is to make Kyverno load and validate the
# policy, not to test behaviour — behaviour is kyverno test's job. Any resource
# will do; this one is chosen to be uninteresting to every rule.
PROBE = """apiVersion: v1
kind: Pod
metadata:
  name: policy-validity-probe
  namespace: default
spec:
  containers:
    - name: c
      image: public.ecr.aws/docker/library/busybox:1.36
"""

failures: list[str] = []


# Kinds Kyverno reports as one "policy rule" each in `kyverno apply`'s load
# count, because they carry no `rules` list of their own.
CEL_POLICY_KINDS = {
    "ValidatingPolicy", "NamespacedValidatingPolicy",
    "ImageValidatingPolicy", "NamespacedImageValidatingPolicy",
    "MutatingPolicy", "NamespacedMutatingPolicy",
    "GeneratingPolicy", "NamespacedGeneratingPolicy",
    "DeletingPolicy", "NamespacedDeletingPolicy",
}


def _check_pins_digest(rel, rendered: str) -> None:
    """Every ImageValidatingPolicy pins and requires the digest it verified.

    The CRD defaults both fields to true, so an absent field reads as true here
    the way the API server reads it.
    """
    import yaml as _yaml

    for doc in _yaml.safe_load_all(rendered):
        if not doc or doc.get("kind") != "ImageValidatingPolicy":
            continue
        name = doc["metadata"]["name"]
        cfg = (doc.get("spec") or {}).get("validationConfigurations") or {}
        for field, why in (
            ("mutateDigest", "admission verifies a tag and the kubelet resolves it again "
                             "at pull"),
            ("verifyDigest", "an image whose pin did not happen reaches validation and "
                             "passes on its tag"),
        ):
            if cfg.get(field, True) is not True:
                failures.append(
                    f"{rel}: ImageValidatingPolicy {name} sets {field} {cfg.get(field)!r}. "
                    f"Valid Kyverno, and {why} — the window this policy exists to close."
                )


def rules_in(rendered: str) -> int:
    """Policy rules in a rendered overlay, counted the way `kyverno apply` does.

    A ClusterPolicy or Policy contributes its `rules`; a CEL policy kind, which
    has none, contributes one.

    Parsed, not matched. Counting `- name:` by indentation returned 0 against
    the real render — the depth differs from the source files — so the guard
    that depended on it never fired and the gate kept reporting success while
    kyverno was silently discarding a policy. A detector that reports zero is a
    claim about the detector.
    """
    total = 0
    for doc in yaml.safe_load_all(rendered):
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") in ("ClusterPolicy", "Policy"):
            total += len((doc.get("spec") or {}).get("rules") or [])
        elif doc.get("kind") in CEL_POLICY_KINDS:
            total += 1
    return total


def main() -> int:
    gatelib.require('kustomize', 'kyverno')
    import tempfile

    overlays = sorted(
        p for p in POLICIES.glob("*/overlays/*") if p.is_dir() and (p / "kustomization.yaml").exists()
    )
    if not overlays:
        print("FAIL  found no policy overlays under policies/kyverno/*/overlays/ — "
              "refusing to report validity over an empty set.")
        return 1

    seen_envs = {p.name for p in overlays}
    missing = set(ENVS) - seen_envs
    if missing:
        print(f"FAIL  no overlay found for environment(s) {sorted(missing)} — "
              f"a policy group that renders in only some environments would go unchecked.")
        return 1

    with tempfile.TemporaryDirectory() as td:
        probe = pathlib.Path(td) / "probe.yaml"
        probe.write_text(PROBE)

        for overlay in overlays:
            rel = overlay.relative_to(ROOT)
            build = subprocess.run(
                ["kustomize", "build", str(overlay)], capture_output=True, text=True,
                timeout=LOCAL_TIMEOUT,
            )
            if build.returncode != 0:
                failures.append(f"{rel}: kustomize build failed:\n      {build.stderr.strip()[:300]}")
                continue
            if not build.stdout.strip():
                failures.append(f"{rel}: rendered to nothing — an empty overlay cannot be validated, "
                                f"and would silently install no policy.")
                continue

            rendered = pathlib.Path(td) / f"{overlay.parent.parent.name}-{overlay.name}.yaml"
            rendered.write_text(build.stdout)

            run = subprocess.run(
                ["kyverno", "apply", str(rendered), "--resource", str(probe)],
                capture_output=True, text=True, timeout=LOCAL_TIMEOUT,
            )
            combined = run.stdout + run.stderr

            # ANTI-VACUITY. kyverno silently ignores a document it does not
            # recognise as a policy, so a rendered file whose apiVersion or
            # structure it rejects contributes nothing and the run still reports
            # `error: 0`. Demonstrated: rewriting apiVersion to kyverno.io/vBOGUS
            # left this gate printing "every one accepted by Kyverno".
            #
            # The load count is the signal. Compare the rules kyverno says it
            # applied against the rules present in the render — if kyverno loaded
            # fewer, it discarded a policy, which is exactly the invalidity this
            # gate exists to catch.
            want_rules = rules_in(build.stdout)
            m = re.search(r"Applying (\d+) policy rule\(s\)", combined)
            if not m:
                failures.append(
                    f"{rel}: kyverno printed no rule count, so nothing establishes "
                    f"that it loaded any policy at all. A run that evaluated nothing "
                    f"reports the same `error: 0` as a clean one.")
                continue
            got_rules = int(m.group(1))
            if want_rules and got_rules < want_rules:
                failures.append(
                    f"{rel}: the render carries {want_rules} rule(s) but kyverno "
                    f"loaded only {got_rules} — it discarded a policy it could not "
                    f"parse, and silently reported no error for it.")
                continue
            if got_rules == 0:
                failures.append(
                    f"{rel}: kyverno loaded 0 policy rules from this overlay.")
                continue
            # kyverno apply exits 0 even when a policy fails validation; the
            # signal is the error count in the summary and the validation
            # message on stderr. Read both rather than trusting the exit code.
            if "policy validation error" in combined or "Invalid value" in combined:
                detail = next(
                    (ln.strip() for ln in combined.splitlines()
                     if "Invalid value" in ln or "policy validation error" in ln),
                    "(no detail)",
                )
                failures.append(f"{rel}: Kyverno rejects this policy:\n      {detail[:400]}")
                continue
            if "error: 0" not in combined:
                summary = next((ln.strip() for ln in combined.splitlines() if ln.startswith("pass:")), combined.strip()[:200])
                failures.append(f"{rel}: kyverno reported errors: {summary}")
                continue

            _check_pins_digest(rel, build.stdout)

    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1

    print(f"policy validity OK: {len(overlays)} rendered overlays "
          f"({len({p.parent.parent.name for p in overlays})} groups x {len(seen_envs)} environments), "
          f"every one accepted by Kyverno")
    return 0


if __name__ == "__main__":
    sys.exit(main())
