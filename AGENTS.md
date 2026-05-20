# eks-gitops — agent entry point

You're an AI client (or the author of one) about to add a cluster-level addon, register a workload as an ApplicationSet entry, or land a Grafana dashboard. This file gets you running in five minutes. For the wider picture — how this repo fits into the nanohype stack — read the [Platform Reference](https://github.com/nanohype/nanohype/blob/main/docs/platform-reference.md).

## What this repo gives you

ArgoCD App-of-Apps catalog for EKS clusters. Six addon categories, plus ApplicationSets that bind workloads to clusters via labels:

- **`addons/argo-platform/`** — Argo CD, Argo Workflows, Argo Rollouts, Argo Events
- **`addons/bootstrap/`** — cluster bootstrap (cert-manager, external-secrets-operator, metrics-server, aws-load-balancer-controller, ebs-csi-driver, cluster-autoscaler/karpenter)
- **`addons/networking/`** — ingress-nginx, cilium, hubble, network-policies
- **`addons/observability/`** — kube-prometheus-stack, loki, tempo, grafana-cloud-otel-collector
- **`addons/operations/`** — keda, descheduler, reloader, vpa, cluster-overprovisioner
- **`addons/security/`** — kyverno, falco, trivy-operator, gatekeeper

Plus:

- **`applicationsets/`** — ApplicationSet generators that fan addons + tenant workloads out across clusters by label
- **`catalog/`** — per-addon catalog metadata
- **`environments/`** — per-cluster overlays (dev / staging / production)
- **`dashboards/`** — Grafana dashboard JSON consumed by the kube-prometheus-stack Grafana sidecar
- **`policies/`** — Kyverno + Gatekeeper policies enforced cluster-wide

## Contract surface

Every addon:

- Lives at `addons/<category>/<name>/`
- Has a base `values.yaml` plus per-env deltas: `values-dev.yaml`, `values-staging.yaml`, `values-production.yaml`
- Is referenced by an ApplicationSet in `applicationsets/addons-<category>.yaml` with a sync wave
- Sync waves run in order — bootstrap before security before observability before tenant workloads

Every tenant workload (a protohype app, an AgentFleet, etc.):

- Has its own `<app>/gitops/applicationset-entry.yaml` in the application's source repo
- The entry registers into `applicationsets/apps-tenants.yaml` here via a `git` source pointing at the app's repo
- The matrix generator scales over `clusters × [<app>]` so the same entry deploys to every cluster carrying the matching environment label

## Add a new addon

1. Create `addons/<category>/<name>/` with `values.yaml` + per-env deltas (`values-dev.yaml` / `values-staging.yaml` / `values-production.yaml`).
2. Reference the upstream chart by name + version in the values structure (varies per category — see existing addons for the shape).
3. Add an entry to `applicationsets/addons-<category>.yaml` with a sync wave that respects ordering (bootstrap < security < networking < observability < operations < argo-platform < apps).
4. Add the addon's catalog metadata to `catalog/<category>.yaml`.
5. Run `task validate` — checks helm-template renders cleanly across every env, ApplicationSet schema is valid, sync waves don't conflict.
6. Open a PR. CI runs `task validate` + Kyverno policy checks.

## Add a Grafana dashboard

1. Drop the dashboard JSON in `dashboards/<source>.json` (curated standalone) or have the app's chart emit a `ConfigMap` with the `grafana_dashboard: "1"` label.
2. The kube-prometheus-stack Grafana sidecar auto-imports labeled ConfigMaps. Curated dashboards under `dashboards/` ship via the `dashboards.yaml` ApplicationSet.

## Register a tenant workload

The workload's source repo owns the ApplicationSet entry — typically `<app>/gitops/applicationset-entry.yaml`. From this repo's side, you only need to:

1. Add the workload's matrix generator entry to `applicationsets/apps-tenants.yaml` (cluster label selector + workload list).
2. The matrix scales `clusters × [workload]`. Sync waves: apps default to wave `100` (after all platform addons).
3. Confirm the app's chart conforms to the [platform-tenant-contract](https://github.com/nanohype/nanohype/blob/main/standards/platform-tenant-contract.json).

## Conventions

- Helm values: 2-space indent. ApplicationSet manifests: 2-space indent.
- Every addon has all three env deltas (`values-dev.yaml`, `values-staging.yaml`, `values-production.yaml`) — empty is fine, but the file must exist.
- Cluster labels drive ApplicationSet matrix generators. Label clusters with `env: dev|staging|production` + any feature flags (`gpu: true`, `bedrock: true`).
- Sync waves matter — addons that everything depends on (cert-manager, external-secrets) run first (wave 0–10); apps run last (wave 100+).
- Kyverno policies in `policies/` enforce cluster-wide invariants (no privileged pods, image registry allowlist, required labels).

## Pointers

- [`README.md`](README.md) — repo overview
- [`docs/`](docs/) — addon catalog, sync-wave reference, cluster bootstrap process
- [`CLAUDE.md`](CLAUDE.md) — Claude Code session instructions
- [Platform Reference](https://github.com/nanohype/nanohype/blob/main/docs/platform-reference.md) — the stack-wide view
- [`aks-gitops/AGENTS.md`](../aks-gitops/AGENTS.md) — same pattern, Azure-specific differences
- [`kx/AGENTS.md`](../kx/AGENTS.md) — local kind workspace that mirrors this catalog
