#!/usr/bin/env python3
"""Every rendered policy overlay is a policy Kyverno will actually accept.

The other Kyverno gates in this repo check what a policy DOES. `kyverno test`
proves each rule passes a compliant resource and fails a violating one, and
check-policy-admission.py proves the fleet is admissible against the Enforce
tier. Neither asks the prior question: will the API server accept this
ClusterPolicy at all?

Kyverno enforces semantic rules that no JSON schema encodes and no behavioural
test reaches. The one that produced this gate:

    spec.rules[0].verifyImages[0].mutateDigest: Invalid value: true:
    mutateDigest must be set to false for 'Audit' failure action

A policy carrying that combination renders clean through kustomize, passes
kubeconform (the schema permits both fields independently), and passes
`kyverno test` — which loads the policy in a context that does not run this
validation. It then fails to apply on every cluster whose overlay is Audit.

That is exactly how it shipped: mutateDigest was set to true in a base that is
Audit, the enforcing overlays were fine, and the development overlay was invalid.
The policy-admission gate only ever renders the Enforce tier, so nothing looked
at it.

So this renders EVERY policy overlay — every group, every environment — and runs
each through Kyverno's own validation. An overlay the API server would reject
fails the build instead of the sync.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
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


def main() -> int:
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
                ["kustomize", "build", str(overlay)], capture_output=True, text=True
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
                capture_output=True, text=True,
            )
            combined = run.stdout + run.stderr
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

    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1

    print(f"policy validity OK: {len(overlays)} rendered overlays "
          f"({len(set(p.parent.parent.name for p in overlays))} groups x {len(seen_envs)} environments), "
          f"every one accepted by Kyverno")
    return 0


if __name__ == "__main__":
    sys.exit(main())
