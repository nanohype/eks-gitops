# CLAUDE.md — eks-gitops

## Overview

EKS-specific GitOps configuration for ArgoCD addon lifecycle management. Companion to [landing-zone](https://github.com/nanohype/landing-zone) (OpenTofu/Terragrunt infrastructure).

## Directory Structure

```
applicationsets/       → ArgoCD ApplicationSets (App-of-Apps pattern)
addons/                → Addon configurations
  <category>/<addon>/
    # Helm addons (majority):
    values.yaml            → Base Helm values (all environments)
    values-development.yaml → Development delta overrides
    values-staging.yaml    → Staging delta overrides
    values-production.yaml → Production delta overrides
    # Kustomize addons (storage-classes, priority-classes, karpenter-resources):
    base/                  → Kustomization + resource manifests
    overlays/{development,staging,production}/
                           → Environment-specific kustomization.yaml
policies/              → Kyverno ClusterPolicy manifests (pure Kustomize, base/overlays)
catalog/               → Platform-specific workloads (Druid)
```

## Key Conventions

### Sync Waves
Components deploy in order: bootstrap (0, 2) → networking (1) → karpenter (5) → security (10-12) → argo-workflows CRDs (13) → policies (20-23) → observability (29-34) / gateway-api CRDs (30) → operations (40-44) / ai-platform (40-42) → argo-platform (50-52).

CRD-only Applications sit immediately ahead of the first thing that renders one of their kinds, not inside a consumer's band. `scripts/check-sync-waves.py` asserts that precedence directly: an ApplicationSet rendering a manifest whose CRD another ApplicationSet installs must sync strictly after it. A controller that merely *watches* a CRD is not a consumer for this purpose — it retries until the kind exists.

### Helm Values Pattern
Helm addons use a flat directory with ArgoCD multi-source. Each addon has `values.yaml` (base) plus `values-{env}.yaml` (delta only). ApplicationSets reference them via:
```yaml
helm:
  valueFiles:
    - $values/{{ .path }}/values.yaml
    - $values/{{ .path }}/values-{{ index .metadata.labels "environment" }}.yaml
```
Environment-specific values files contain ONLY differences from base — not a full copy.

### Kustomize Addons
Three addons use pure Kustomize (no Helm): storage-classes, priority-classes, karpenter-resources. These use the `base/overlays` pattern with `kustomization.yaml` in each overlay directory. Kyverno policies also use pure Kustomize (resources + JSON patches for enforcement mode).

### ApplicationSet Generator
Most ApplicationSets use a `matrix` generator combining `clusters` selector with a `list` of addons. Two template styles: Helm multi-source (for Helm addons with `$values` ref) and single-source with Kustomize path (for Kustomize addons and policies). Environment is read from cluster secret labels: `{{ index .metadata.labels "environment" }}`.

## Making Changes

### Modifying addon values
**Helm addons:** Edit `values.yaml` for base changes, `values-{env}.yaml` for environment-specific deltas.
**Kustomize addons:** Edit resources in `base/` for base changes, overlay `kustomization.yaml` for environment-specific patches.
Run `task validate` to verify.

### Adding a new addon
**Helm:** Create `addons/<category>/<name>/` with `values.yaml` + three `values-{env}.yaml` files. Add to the appropriate Helm ApplicationSet.
**Kustomize:** Create `addons/<category>/<name>/base/` + three overlay directories. Add to the appropriate Kustomize ApplicationSet.
Categories: `bootstrap`, `networking`, `security`, `observability`, `operations`, `ai-platform`, `argo-platform`.
See `docs/configuration/adding-addons.md` for full guide.

### Adding a new policy
1. Create policy YAML in `policies/kyverno/<group>/base/`
2. Add to base kustomization.yaml resources list
3. Overlay patches control enforcement mode per environment

## Validation Commands

```bash
task lint:yaml              # YAML lint all files
task kustomize:build        # Build all overlays (all environments)
task kustomize:build:env    # Build overlays for ENVIRONMENT (default: development)
task validate               # Lint + build + helm-render + appset-schema + sync-wave gates
task validate:helm-render   # Helm-template every addon against its appset-pinned chart + per-env values
task validate:appset-schema # kubeconform over applicationsets/
task validate:sync-waves    # Assert the documented sync-wave category ordering
task render                 # Render manifests to rendered/ (incl. druid chart)
task scan                   # kubeconform + trivy config gates over rendered/
```

### Local `task validate` is a subset of CI

`task validate` runs the structural gates (lint, kustomize build, helm-render,
ApplicationSet schema, sync-wave ordering, appset render, policy-admission,
dashboards, fork-safety). CI runs those plus several gates that have **no local
`task` target**, so a clean `task validate` is necessary but not sufficient:

- **Zero-placeholder gate** — `scripts/no-placeholders.sh` (CI job `placeholders`)
- **Kyverno unit tests + verify-images signing-identity contract** —
  `kyverno test policies/kyverno/tests` and `scripts/check-image-verification.py`
  (CI job `kyverno`)
- **Secret scan** — gitleaks over the working tree (CI job `secrets`)
- **Render → render-assert → kubeconform → `trivy config`** (CI job `validate`);
  locally this is `task render` then `task scan`, not part of `task validate`

Fork-safety runs in both places but differently — the same split the Taskfile
documents: `task validate` runs it report-only, CI runs it `--blocking`.

## Relationship to Parent Repo

- This is the EKS ArgoCD addon catalog for the nanohype platform
- `landing-zone` (OpenTofu) deploys ArgoCD and creates the App-of-Apps Application pointing to this repo
- Bootstrap addons (cert-manager, external-secrets, etc.) are managed by this repo at wave 0
- Cluster secret labels (set by landing-zone cluster-bootstrap) drive environment selection in ApplicationSets

## CI

- PR and push to main trigger `.github/workflows/ci.yml` (lint → validate per environment → PR summary)
- The validate job renders every kustomize root plus the druid catalog chart, then gates the rendered output: render-assert (no unfilled sentinels), kubeconform strict (native schemas + datreeio CRDs-catalog, no ignore-missing-schemas, via the shared `scripts/kubeconform-scan.sh`), and `trivy config` (misconfiguration scan, MEDIUM+ hard-fails; scoped justified exceptions live in `.trivyignore.yaml`)
- Standalone jobs on every PR: `helm-render` (templates every addon against its appset-pinned chart with base + each env's values — an unknown key fails here, not fleet-wide at sync), `policy-admission` (renders the whole fleet into its real destination namespaces and runs `kyverno apply` against the Enforce-tier best-practice/pod-security policies, so an addon landing in a namespace the policies don't exclude fails here instead of being denied at admission on a vended enforce cluster — also asserts all four exclusion lists stay identical, that every namespace the fleet lands a workload in is on that list, and that a deliberately non-compliant canary is denied by every rule, which is what proves the run evaluated anything), `appsets` (ApplicationSet schema + documented sync-wave ordering), `appset-render` (renders the Karpenter EC2NodeClass patch template the way the ArgoCD ApplicationSet controller does — Go text/template + sprig, `missingkey=error` — against fixture create/adopt/legacy cluster Secrets, so a control-flow edit that breaks the per-cluster render fails here instead of at sync), `secrets` (gitleaks over the working tree), plus the dashboard, fork-safety, and Kyverno policy gates
- Chart pins in `applicationsets/` are watched by Renovate (`renovate.json`); `.github/dependabot.yml` owns the github-actions bumps
- Manual diff rendering available via `.github/workflows/diff.yml`

## Claude Code Tooling

### Commands
- `/validate` — Run `task validate` (lint + kustomize build all environments), diagnose failures
- `/add-addon` — Scaffold a new addon (Helm flat values or Kustomize base/overlays)
- `/add-policy` — Scaffold a new Kyverno ClusterPolicy (base + 3 overlays + ApplicationSet entry)
- `/render` — Render manifests for an environment via `task render`
- `/diff-envs` — Compare rendered output between two environments
- `/chart-versions` — Audit Helm chart versions across all ApplicationSets, flag drift
- `/check-overlay` — Verify environment values files contain only deltas from base

### Agents
- **validator** — Runs 8 structural checks: YAML lint, kustomize build, chart version consistency, overlay delta compliance, structural completeness, ApplicationSet integrity, sync wave ordering, policy enforcement modes

### Guarded Operations
- **Allowed**: `task`, `yamllint`, `kustomize`, `helm search/repo`, `diff`, file rendering
- **Denied**: `kubectl`, `argocd`, `helm install/upgrade/uninstall/delete` — this is a config repo, no cluster mutation
- **Hooks**: YAML files are auto-linted on save; edits to `rendered/` are blocked (generated output)
