# ADR-001: Kustomize + Helm Overlays

## Status

Superseded

## Context

EKS addons are distributed as Helm charts with complex default configurations. We need a mechanism to:

1. Pin chart versions declaratively in Git
2. Provide base configurations shared across all environments
3. Apply minimal environment-specific overrides without duplicating the full values file
4. Maintain compatibility with ArgoCD's source path model

Options considered:

- **Helm only** — ArgoCD manages Helm releases directly. No environment layering without ArgoCD-specific value overrides.
- **Kustomize only** — Requires rendering Helm charts to raw YAML first, losing Helm's templating and upgrade path.
- **Kustomize + Helm** — Kustomize's `helmCharts` field renders charts inline while supporting `valuesFile` and `additionalValuesFiles` for layering.

## Decision

Use Kustomize's built-in Helm chart inflation (`helmCharts` in kustomization.yaml) with the `additionalValuesFiles` pattern:

- `base/kustomization.yaml` defines the chart reference and points `valuesFile` at `base/values.yaml`
- Each overlay's `kustomization.yaml` sets `valuesFile: ../../base/values.yaml` and `additionalValuesFiles: [values.yaml]`
- Overlay `values.yaml` contains only the delta (differences from base)

ArgoCD builds each overlay path with `--enable-helm`, producing the final manifests.

## Consequences

**Easier:**
- Environment differences are explicit and minimal (delta-only overlay files)
- Chart version is pinned in one place (base kustomization.yaml) — overlays reference the same version
- Standard Kustomize tooling works for validation (`kustomize build --enable-helm`)
- Adding a new environment is a thin overlay directory

**More difficult:**
- Requires `--enable-helm` flag for all Kustomize operations
- `additionalValuesFiles` is a newer Kustomize feature (requires >= 5.0)
- Debugging values merging requires understanding both Kustomize and Helm precedence

## Superseded

This approach was replaced by **ArgoCD multi-source** for Helm addons. Chart versions and repository URLs are now defined in ApplicationSet element lists. Values use a flat directory pattern (`values.yaml` + `values-{env}.yaml`) referenced via ArgoCD's `$values` ref mechanism. The delta-only principle for environment values files remains unchanged.

The Kustomize `base/overlays` pattern is retained only for non-Helm addons (storage-classes, priority-classes, karpenter-resources) and Kyverno policies.
