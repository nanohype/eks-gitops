# ADR-002: ArgoCD Multi-Source Flat Values

## Status

Accepted

## Context

EKS addons are distributed as upstream Helm charts. Each addon needs a base
configuration shared across every cluster plus a small set of per-environment
differences (replica counts, retention windows, resource limits). The catalog
fans a single ApplicationSet definition across development, staging, production,
and hub clusters, so the layering mechanism has to:

1. Pin chart versions and repositories declaratively in Git.
2. Keep one base configuration per addon, shared across all environments.
3. Express environment differences as deltas only — no full copies of the base.
4. Fetch the upstream chart directly from its Helm/OCI repository, without
   rendering it to raw YAML first (which would forfeit the chart's own upgrade
   path and templating).
5. Resolve which values files apply from a cluster label, so the same
   ApplicationSet element serves every cluster carrying that environment.

## Decision

Use ArgoCD's multi-source Application model. Each Helm addon's ApplicationSet
element carries two sources:

- The upstream chart, fetched from its Helm or OCI repository at a pinned
  version (`chartRepo`, `chart`, `chartVersion` come from the ApplicationSet
  element list).
- This Git repository, referenced with `ref: values`, exposing the addon's
  values files to the chart source via `$values`.

Values live in a flat directory per addon — no `base/overlays` nesting:

```
addons/<category>/<addon>/
  values.yaml              → complete base configuration (all environments)
  values-development.yaml  → development delta only
  values-staging.yaml      → staging delta only
  values-production.yaml   → production delta only
  values-hub.yaml          → hub delta only (where the addon runs on the hub)
```

The chart source resolves both files in order, base first:

```yaml
helm:
  valueFiles:
    - $values/{{ .path }}/values.yaml
    - $values/{{ .path }}/values-{{ index .metadata.labels "environment" }}.yaml
```

ArgoCD merges the environment file on top of the base, so an environment file
holds only its differences. The environment is read from the `environment`
label on the ArgoCD cluster Secret; the Git repository URL is read from the
`gitops/repo-url` annotation on that same Secret rather than hardcoded, keeping
forks self-referential.

Pure-Kustomize addons (storage-classes, priority-classes, karpenter-resources)
and Kyverno policies keep the `base/overlays` pattern — they have no upstream
Helm chart to inflate, so the multi-source model does not apply to them.

## Consequences

**Easier:**

- The upstream chart is consumed as published — Helm templating, hooks, and the
  chart's own upgrade path stay intact. No pre-render to raw YAML.
- Environment differences are explicit and minimal (delta-only values files).
- Chart version and repository are pinned in one place (the ApplicationSet
  element list), where Renovate watches them for currency.
- Adding an environment is one thin `values-<env>.yaml` per addon; adding an
  addon is a flat directory plus one ApplicationSet element.
- The same ApplicationSet element deploys to every cluster with the matching
  `environment` label, with no per-cluster Application definitions.

**More difficult:**

- Values files are not rendered locally by `kustomize build` alone. The
  `validate:helm-render` gate templates every addon against its pinned chart
  with base plus each environment's values so an unknown key fails pre-merge
  rather than fleet-wide at sync.
- The catalog runs two layering models side by side (multi-source Helm for
  charts, `base/overlays` Kustomize for the rest); contributors pick the right
  one per addon type.
- Correct merge precedence depends on file order in `valueFiles` — the base
  must precede the environment delta.

## Supersedes

Replaces the approach recorded in
[ADR-001](001-kustomize-helm-overlays.md) (Kustomize `helmCharts` inflation with
`additionalValuesFiles`). The delta-only principle for environment values files
carries forward unchanged; the mechanism moved from Kustomize Helm inflation to
ArgoCD multi-source `$values` refs.
