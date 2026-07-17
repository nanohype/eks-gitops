# Runbook — Render-Gate Failures on PRs

**Severity**: low (nothing is deployed — CI blocked the merge, which is the gate doing its job). **Scope**: the `validate` job in `.github/workflows/ci.yml`, which renders every kustomize root (per environment: development, staging, production, hub) plus the druid catalog chart with synthetic tenant values, then runs three gates over the *rendered* output.

## Symptoms

- A PR check fails on one of: `Zero-placeholder gate`, `Lint YAML`, or a step inside `Validate (<env>)` — render, "Assert no unfilled sentinels", "Schema gate (kubeconform)", or "Misconfiguration gate (trivy config)"
- The PR summary comment shows a red row

## Diagnosis

Reproduce locally before reading CI logs twice — the Taskfile mirrors the pipeline:

```bash
task lint:yaml     # yamllint over the repo
task render        # kustomize + helm render into rendered/ (incl. druid chart)
task scan          # kubeconform + trivy config over rendered/
task validate      # lint + build combined
```

Then map the failing step to what it actually checks:

**Zero-placeholder / render-assert** — an unfilled sentinel (placeholder token, zero account id, account-less ARN) either in source files or appearing only after templating. The fix is always filling the real value; these gates exist precisely so a placeholder never reaches a cluster.

**Render failure** — `kustomize build --enable-helm` or `helm template` errored. Usual causes: overlay missing its `kustomization.yaml`, a `values-{env}.yaml` absent for one of the four environments, or (druid) a template change that breaks under the synthetic `--set` values in the workflow. Note the matrix renders *every* environment — a change that renders fine in development can still fail the hub leg.

**Schema gate (kubeconform)** — strict mode, native kinds from the default kubernetes-json-schema location, CRD kinds from the datreeio CRDs-catalog, deliberately **no** `-ignore-missing-schemas`. Two failure shapes:

- *"could not find schema for <Kind>"* — the kind is new to the repo and neither source knows it. Options, in order of preference: the CRD exists in the datreeio catalog under a different group/version (fix the manifest's apiVersion); contribute the schema upstream to the CRDs-catalog; or add an explicit `-skip <Kind>` in the workflow with a comment justifying it (the existing `-skip Grafana` shows the shape — skips are per-kind, commented, and rare).
- *field/type errors* — a genuinely invalid manifest, or the catalog schema is stricter than the CRD actually deployed (the Grafana skip exists for exactly that mismatch). Verify against the real CRD before assuming the manifest is wrong.

**Misconfiguration gate (trivy config)** — runs over `rendered/`, so every finding reflects post-templating truth with values applied. MEDIUM and above fails the build. The finding ID (`KSV-*`/`AVD-*`) plus the rendered file name tell you which addon and which check.

## Remediation

**Default: fix the manifest.** Most trivy findings have a direct fix — set the securityContext, add resources/probes, drop the capability, pin the tag. The gate severity floor is MEDIUM, so it isn't flagging trivia.

**Exception path: a reasoned `.trivyignore.yaml` entry.** Legitimate only when the flagged configuration *is the component's contract* — the existing entries are the calibration: a device plugin must run as root and hostPath-mount the kubelet socket (KSV-0012/0023); Druid's ConfigMap keys named `*Password` hold `${env:...}` indirection, not secret material (KSV-0109/01010); the overlord's namespace-scoped Role manages Jobs because that is what the k8s task runner does (KSV-0042 et al.). An entry must have all three:

```yaml
- id: KSV-XXXX
  paths:
    - "*<rendered-file-glob-for-exactly-this-addon>*"
  statement: >-
    Why this configuration is the component's contract, and where the
    compensating control lives if there is one.
```

- `paths` scoped to one addon's rendered output — never a bare `id` that suppresses the check repo-wide
- `statement` that survives a cold review: what the finding flags, why it's intentional, compensating control (e.g. registry findings point at the Kyverno verify-images policy)
- If you can't write that statement convincingly, it's a fix, not an ignore

**kubeconform skips** follow the same discipline in the workflow file: per-kind, commented with the concrete schema/CRD mismatch, nothing broader.

## Verification

```bash
task render && task scan     # clean locally
git add <files by name> && git commit ...
```

Push and confirm all four `Validate (<env>)` matrix legs pass — the PR summary comment goes green. For a new `.trivyignore.yaml` entry, also confirm the gate still fails on *other* findings (the entry's `paths` glob should match only the intended rendered file; `grep <id> rendered/ -r` against the trivy output is a quick sanity check that you scoped it tightly).
