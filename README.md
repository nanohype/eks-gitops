# EKS GitOps Repository

GitOps configuration for EKS cluster addons, managed by ArgoCD. The EKS ArgoCD addon catalog for the nanohype platform.

**AI clients / agents start here:** [`AGENTS.md`](AGENTS.md). For the stack-wide view, see the [Platform Reference](https://github.com/nanohype/nanohype/blob/main/docs/platform-reference.md).

## Features

- **App-of-Apps pattern** with ArgoCD ApplicationSets for multi-cluster deployment
- **ArgoCD multi-source Helm values** — base values with flat environment-specific deltas
- **Matrix generators** — environment selection from cluster secret labels
- **Sync wave ordering** — deterministic deployment order across addon categories
- **Four environments** — development, staging, production (workload clusters), plus hub (the eks-fleet control plane, observability + bootstrap only), each with appropriate sizing and policies
- **CI validation** — YAML lint, per-env render → schema → misconfiguration scan, helm-render, policy-admission, ApplicationSet schema, sync-wave, and secret-scan gates on every PR

## Companion Repository

This repository is the EKS ArgoCD addon catalog. Infrastructure is provisioned by [landing-zone](https://github.com/nanohype/landing-zone) (OpenTofu/Terragrunt), which deploys ArgoCD and creates the App-of-Apps Application pointing to this repository.

## Forking

This catalog is **vended**: you fork it, point your own hub at your fork, and your edits take effect. No source changes are needed to repoint it.

**How it works.** Every applied ApplicationSet reads its Git source from the cluster, not a hardcoded URL:

```yaml
repoURL: '{{ index .metadata.annotations "gitops/repo-url" }}'
```

`cluster-bootstrap` (in landing-zone) stamps `gitops/repo-url` on the ArgoCD cluster Secret. Set it to your fork and every Application follows. A CI gate (**Fork-safety gate**, `scripts/check-hardcoded-org.py --blocking`) fails the build if a catalog `repoURL` is ever hardcoded — a hardcoded ref would silently keep a fork syncing from upstream while its own edits sat unread.

**Intentionally NOT templated** — these are consumed, not forked, so they correctly point at upstream:

- `nanohype/eks-agent-platform` — the operator's own source/chart. You consume the product; you don't fork it.
- `ghcr.io/nanohype/*` images and `oci://` charts — pulled like any registry.
- The Kyverno keyless-signing identity (`subjectRegExp`) — a signing identity to *verify against*, not a source to sync from.
- Everything under `applicationsets/opt-in/` — not applied by a default install; its org-specific URLs are a documented repoint-before-enabling step (see [`applicationsets/opt-in/README.md`](applicationsets/opt-in/README.md)).

**To fork:** fork this repo → set `gitops/repo-url` on your cluster Secret (via landing-zone) to your fork → optionally repoint the `opt-in/` appsets if you enable them.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│              ArgoCD (deployed by landing-zone)                     │
├─────────────────────────────────────────────────────────────────────┤
│                    App-of-Apps Application                          │
│                    (points to this repository)                      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ApplicationSets                                  │
├─────────────────────────────────────────────────────────────────────┤
│  ├── addons-bootstrap (cert-manager, external-secrets, ...)         │
│  ├── addons-bootstrap-kustomize (storage-classes, priority-classes) │
│  ├── secret-stores (ClusterSecretStores)                            │
│  ├── addons-networking (Cilium, ALB Controller)                     │
│  ├── addons-external-dns (External DNS)                             │
│  ├── addons-karpenter (Karpenter)                                   │
│  ├── addons-accelerators-helm (gpu-operator, nvidia-dra-driver)     │
│  ├── addons-accelerators-kustomize (aws-neuron-device-plugin)       │
│  ├── addons-security (Kyverno, Trivy, Falco)                        │
│  ├── kyverno-policies (PSS, best-practices, networking, ...)        │
│  ├── addons-agent-operator (eks-agent-platform operator)            │
│  ├── gateway-api-crds (Gateway API CRDs)                            │
│  ├── addons-observability (kube-state-metrics, Loki, Tempo, Alloy)  │
│  ├── addons-opencost (OpenCost)                                     │
│  ├── addons-operations-helm (VPA, Goldilocks, Descheduler, KEDA)    │
│  ├── addons-operations-kustomize (Karpenter Resources)              │
│  ├── addons-velero (Velero)                                         │
│  ├── addons-ai-platform (kagent, agentgateway + CRDs)               │
│  ├── agent-platform (Tenant/Platform/Budget/ModelGateway CRs)       │
│  ├── addons-argo-platform (Rollouts, Events, Workflows)             │
│  ├── druid-tenants                                                  │
│  └── dashboards (GrafanaDashboards)                                 │
└─────────────────────────────────────────────────────────────────────┘

Plus opt-in ApplicationSets under `applicationsets/opt-in/` (`apps-tenants`,
`clusters-appset`, `portal-tenants`) — not applied by a default install; see
[`applicationsets/opt-in/README.md`](applicationsets/opt-in/README.md).
```

## Directory Structure

```
eks-gitops/
├── applicationsets/                    # ArgoCD ApplicationSets (see Architecture above)
│   ├── addons-*.yaml                    # one per addon group (bootstrap, networking,
│   │                                    #   security, observability, operations, ...)
│   ├── agent-platform.yaml              # eks-agent-platform CRs (Tenant/Platform/...)
│   ├── kyverno-policies.yaml
│   ├── gateway-api-crds.yaml
│   ├── secret-stores.yaml
│   ├── dashboards.yaml
│   ├── druid-tenants.yaml
│   └── opt-in/                          # NOT applied by default (apps/clusters/portal)
│
├── addons/                             # Addon configurations
│   ├── bootstrap/{cert-manager,external-secrets,metrics-server,
│   │              prometheus-operator-crds,reloader,secret-stores,
│   │              storage-classes,priority-classes,portal-reader}/
│   ├── networking/{cilium,aws-load-balancer-controller,external-dns,mcp-tunnel}/
│   ├── security/{kyverno,trivy-operator,falco}/
│   ├── observability/{loki,tempo,alloy,grafana-operator,
│   │                  kube-state-metrics,opencost}/
│   ├── operations/{velero,vpa,goldilocks,descheduler,karpenter,
│   │               karpenter-resources,keda}/
│   ├── accelerators/{gpu-operator,nvidia-dra-driver,aws-neuron-device-plugin}/
│   ├── argo-platform/{argo-rollouts,argo-events,argo-workflows}/
│   └── ai-platform/{agent-platform,kagent,kagent-crds,agentgateway,
│                    agentgateway-crds,operator}/
│
├── policies/                           # Kyverno policies (pure Kustomize)
│   └── kyverno/{pod-security-standards,best-practices,networking,
│                supply-chain,tests}/
│
├── environments/                       # Cluster-config ConfigMaps
│   ├── development/
│   ├── staging/
│   ├── production/
│   └── hub/
│
├── catalog/                            # Platform-specific workloads
│   └── druid/
│
├── dashboards/                         # GrafanaDashboard CRs (grafana-operator)
│
├── scripts/                            # CI gate + validation scripts
│
└── docs/                               # Documentation
```

## Sync Wave Ordering

| Wave | Components | Rationale |
|------|------------|-----------|
| -1 | App-of-Apps | Root application |
| 0 | Bootstrap Helm (cert-manager, external-secrets, prometheus-operator-crds) | Foundational CRDs |
| 1 | Networking (Cilium, ALB Controller, External DNS); Secret Stores (ClusterSecretStores) | CNI/ingress + secret backends |
| 2 | Bootstrap continued (metrics-server, reloader, storage-classes, priority-classes) | Cluster essentials |
| 5 | Karpenter | Nodes must be ready before workloads |
| 6 | Accelerators (gpu-operator, aws-neuron-device-plugin, nvidia-dra-driver) | GPU/Neuron device plugins advertised before workloads |
| 10 | Security (Kyverno, Trivy, Falco) | Policy engine before policies |
| 20 | Kyverno Policies | After Kyverno is ready |
| 21 | Agent Operator (eks-agent-platform) | Operator + CRDs before the agent platform consumes them |
| 30 | Observability (Loki, Tempo, Alloy), Gateway API CRDs; OpenCost (33) | After security |
| 40 | AI Platform (kagent, agentgateway); Operations (Velero, VPA, Goldilocks, Descheduler, KEDA) | After operator + observability |
| 42 | Operations kustomize (Karpenter Resources) | After operations Helm |
| 44 | Agent Platform CRs | After the AI-platform runtime is up |
| 50 | Argo Platform (Rollouts, Events, Workflows); Druid tenants | Application layer |
| 60 | Dashboards | After the systems they chart exist |

## Environment Differences

| Setting | Development | Staging | Production |
|---------|-------------|---------|------------|
| Replicas | 1 | 2-3 | 2-3 |
| Kyverno Mode | Audit | Enforce | Enforce |
| Velero | Disabled | Enabled | Enabled |
| Karpenter CPU | 50 | 75 | 200 |
| Loki Retention | 7d | 30d | 90d |
| Falco Memory Limit | 1Gi | 2Gi | 4Gi |

## Prerequisites

Tools required for local development:

- [task](https://taskfile.dev/installation/) >= 3.0
- [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) >= 5.0
- [helm](https://helm.sh/docs/intro/install/) >= 3.0
- [yamllint](https://yamllint.readthedocs.io/) >= 1.0

Infrastructure prerequisites (deployed by landing-zone):

- ArgoCD and App-of-Apps root Application
- EKS cluster with IRSA and cluster secret labels

## Commands

```bash
task                          # Show all available tasks
task lint:yaml                # Lint all YAML files
task kustomize:build          # Build all overlays (all environments)
task kustomize:build:env      # Build overlays for ENVIRONMENT (default: development)
task validate                 # Run all validations (lint + build)
task render                   # Render manifests to rendered/ directory
task clean                    # Remove rendered output
```

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Environment Configuration](docs/configuration/environments.md)
- [Adding Addons](docs/configuration/adding-addons.md)
- [Contributing](docs/development/contributing.md)
- Runbooks
  - [Troubleshooting](docs/runbooks/troubleshooting.md)
  - [Addon Sync Stuck or Degraded](docs/runbooks/addon-sync-degraded.md)
  - [Rolling Back an Addon](docs/runbooks/rollback.md)
  - [Druid Operations](docs/runbooks/druid-operations.md)
  - [AI Platform — Budget, Kill-Switch, and Model Access](docs/runbooks/ai-platform-budget-killswitch.md)
  - [Render-Gate Failures on PRs](docs/runbooks/render-gate-failures.md)

## License

[Apache 2.0](LICENSE)
