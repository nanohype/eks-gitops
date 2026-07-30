# eks-gitops — agent entry point

You're an AI client (or the author of one) about to add a cluster-level addon, register a workload as an ApplicationSet entry, or land a Grafana dashboard. This file gets you running in five minutes. For the wider picture — how this repo fits into the nanohype stack — read the [Platform Reference](https://github.com/nanohype/nanohype/blob/main/docs/platform-reference.md).

## What this repo gives you

ArgoCD App-of-Apps catalog for EKS clusters. Eight addon categories, plus ApplicationSets that bind workloads to clusters via labels (listed in deploy order):

- **`addons/bootstrap/`** — cert-manager, external-secrets, secret-stores, metrics-server, prometheus-operator-crds, reloader, storage-classes, priority-classes, portal-reader
- **`addons/networking/`** — cilium, aws-load-balancer-controller, external-dns
- **`addons/accelerators/`** — gpu-operator, nvidia-dra-driver (Helm) — NVIDIA GPU device plugins, gated on the dedicated `eks-agent-platform/accelerators` cluster label, at waves 6-7 (early, alongside karpenter)
- **`addons/security/`** — kyverno, falco, trivy-operator
- **`addons/observability/`** — otel-agent, otel-gateway, grafana-operator, loki, tempo, kube-state-metrics, opencost
- **`addons/operations/`** — karpenter, karpenter-resources, keda, descheduler, goldilocks, vpa, velero
- **`addons/ai-platform/`** — Envoy AI Gateway, the eks-agent-platform operator (plus their CRDs)
- **`addons/argo-platform/`** — Argo Workflows, Argo Rollouts, Argo Events

Plus:

- **`applicationsets/`** — ApplicationSet generators that fan addons + tenant workloads out across clusters by label
- **`catalog/`** — platform-specific tenant workloads (currently Druid)
- **`dashboards/`** — `GrafanaDashboard` CRs that grafana-operator reconciles into the external Amazon Managed Grafana workspace
- **`policies/`** — Kyverno policies (best-practices, pod-security-standards) enforced cluster-wide

## Contract surface

Every addon:

- Lives at `addons/<category>/<name>/`
- Has a base `values.yaml` plus per-env deltas: `values-development.yaml`, `values-staging.yaml`, `values-production.yaml`
- Is referenced by an ApplicationSet in `applicationsets/addons-<category>.yaml` with a sync wave
- Sync waves run in order — bootstrap before security before observability before tenant workloads

Every tenant workload (an application chart, an AgentFleet, etc.):

- Has its own `<app>/gitops/applicationset-entry.yaml` in the application's source repo
- The entry registers into `applicationsets/opt-in/apps-tenants.yaml` here via a `git` source pointing at the app's repo. This appset lives under `opt-in/` — a default install never applies it (app-of-apps sources `path: applicationsets` without `directory.recurse`), so enabling tenant workloads is a deliberate repoint-and-wire step (see [`applicationsets/opt-in/README.md`](applicationsets/opt-in/README.md)).
- The matrix generator scales over `clusters × [<app>]` so the same entry deploys to every cluster carrying the matching environment label

## Add a new addon

1. Create `addons/<category>/<name>/` with `values.yaml` + per-env deltas (`values-development.yaml` / `values-staging.yaml` / `values-production.yaml`).
2. Reference the upstream chart by name + version in the values structure (varies per category — see existing addons for the shape).
3. Add an entry to `applicationsets/addons-<category>.yaml` with a sync wave that respects ordering (bootstrap < networking < security < observability < operations < ai-platform < argo-platform < apps).
4. If your addon lands in a **new namespace**, add it to the Kyverno exclusion lists in `policies/kyverno/best-practices/base/` and `policies/kyverno/pod-security-standards/base/` (all four policies share one identical set) — or make the addon's workloads satisfy the label/probe/limit/non-root policies. Otherwise a vended staging/production cluster runs those policies in Enforce mode and denies your Deployment at admission.
5. Run `task validate` — helm-templates every addon against its appset-pinned chart with base + each env's values (an unknown key fails here, not fleet-wide at sync), renders the whole fleet through the Enforce-tier Kyverno policies (so a missing namespace exclusion fails here, not at admission on a real cluster), schema-validates the ApplicationSets, and checks the documented sync-wave ordering, on top of YAML lint, kustomize build, and the dashboard/fork-safety gates.
6. Open a PR. CI runs the same gates plus Kyverno policy tests, a gitleaks secret scan, and a per-environment render → schema → misconfiguration scan.

## Add a Grafana dashboard

1. Add a `GrafanaDashboard` CR under `dashboards/base/{platform,addons}/` (reference a grafana.com dashboard id or inline JSON) with `instanceSelector` label `dashboards: external`, and register it in `dashboards/base/kustomization.yaml`.
2. grafana-operator reconciles the `GrafanaDashboard` CRs and pushes them to the external Amazon Managed Grafana workspace. The `dashboards.yaml` ApplicationSet ships them into the `grafana-operator` namespace.

## Register a tenant workload

The workload's source repo owns the ApplicationSet entry — typically `<app>/gitops/applicationset-entry.yaml`. From this repo's side, you only need to:

1. Add the workload's matrix generator entry to `applicationsets/opt-in/apps-tenants.yaml` (cluster label selector + workload list). This is an **opt-in** appset — a default install does not apply it, so a fork enabling tenant workloads repoints its org-specific URLs first (see [`applicationsets/opt-in/README.md`](applicationsets/opt-in/README.md)).
2. The matrix scales `clusters × [workload]`. Sync waves: apps default to wave `100` (after all platform addons).
3. Confirm the app's chart conforms to the [platform-tenant-contract](https://github.com/nanohype/nanohype/blob/main/standards/platform-tenant-contract.json).

## Conventions

- Helm values: 2-space indent. ApplicationSet manifests: 2-space indent.
- Every addon has all three env deltas (`values-development.yaml`, `values-staging.yaml`, `values-production.yaml`) — empty is fine, but the file must exist.
- Cluster labels drive ApplicationSet matrix generators. The `environment` label (`development|staging|production|hub`) selects the per-env values; opt-in addon groups select on additional labels (both set by cluster-bootstrap) — `eks-agent-platform/enabled: "true"` gates the operator onto agent-platform clusters, and `eks-agent-platform/accelerators: "true"` gates the GPU device plugins onto clusters with accelerator node pools.
- Sync waves matter — addons that everything depends on (cert-manager, external-secrets) run first (wave 0–10); apps run last (wave 100+).
- Kyverno policies in `policies/` enforce cluster-wide invariants (no privileged pods, image registry allowlist, required labels).

## Pointers

- [`README.md`](README.md) — repo overview
- [`docs/`](docs/) — addon catalog, sync-wave reference, cluster bootstrap process
- [`CLAUDE.md`](CLAUDE.md) — Claude Code session instructions
- [Platform Reference](https://github.com/nanohype/nanohype/blob/main/docs/platform-reference.md) — the stack-wide view
- [`kx/AGENTS.md`](../kx/AGENTS.md) — local kind workspace that mirrors this catalog
