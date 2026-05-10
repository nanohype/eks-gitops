# EKS GitOps Repository

GitOps configuration for EKS cluster addons, managed by ArgoCD. Part of a multi-cloud GitOps strategy (`eks-gitops`, `gke-gitops`, `aks-gitops`).

## Features

- **App-of-Apps pattern** with ArgoCD ApplicationSets for multi-cluster deployment
- **ArgoCD multi-source Helm values** — base values with flat environment-specific deltas
- **Matrix generators** — environment selection from cluster secret labels
- **Sync wave ordering** — deterministic deployment order across addon categories
- **Three environments** — dev, staging, production with appropriate sizing and policies
- **CI validation** — automated YAML lint and Kustomize build on every PR

## Companion Repository

This repository is the EKS variant of a multi-cloud GitOps strategy. Infrastructure is provisioned by [aws-eks](https://github.com/stxkxs/aws-eks) (CDK), which deploys ArgoCD and creates the App-of-Apps Application pointing to this repository.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ArgoCD (deployed by CDK)                         │
├─────────────────────────────────────────────────────────────────────┤
│                    App-of-Apps Application                          │
│                    (points to this repository)                      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ApplicationSets (10)                             │
├─────────────────────────────────────────────────────────────────────┤
│  ├── addons-bootstrap (cert-manager, external-secrets, ...)        │
│  ├── addons-bootstrap-kustomize (storage-classes, priority-classes) │
│  ├── addons-networking (Cilium, ALB Controller, External DNS)      │
│  ├── addons-security (Kyverno, Trivy, Falco)                      │
│  ├── addons-observability (Loki, Tempo, Grafana Agent, OpenCost)   │
│  ├── addons-operations-helm (Velero, VPA, Goldilocks, ...)         │
│  ├── addons-operations-kustomize (Karpenter Resources)             │
│  ├── addons-argo-platform (Rollouts, Events, Workflows)            │
│  ├── kyverno-policies (PSS, Best Practices)                        │
│  └── druid-tenants                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
eks-gitops/
├── applicationsets/                    # ArgoCD ApplicationSets (10)
│   ├── addons-bootstrap.yaml
│   ├── addons-bootstrap-kustomize.yaml
│   ├── addons-networking.yaml
│   ├── addons-security.yaml
│   ├── addons-observability.yaml
│   ├── addons-operations-helm.yaml
│   ├── addons-operations-kustomize.yaml
│   ├── addons-argo-platform.yaml
│   ├── kyverno-policies.yaml
│   └── druid-tenants.yaml
│
├── addons/                             # Addon configurations
│   ├── bootstrap/{cert-manager,external-secrets,metrics-server,
│   │              prometheus-operator-crds,reloader,storage-classes,
│   │              priority-classes}/
│   ├── networking/{cilium,aws-load-balancer-controller,external-dns}/
│   ├── security/{kyverno,trivy-operator,falco}/
│   ├── observability/{loki,tempo,grafana-agent,opencost}/
│   ├── operations/{velero,vpa,goldilocks,descheduler,karpenter,
│   │               karpenter-resources,keda}/
│   └── argo-platform/{argo-rollouts,argo-events,argo-workflows}/
│
├── policies/                           # Kyverno policies (pure Kustomize)
│   └── kyverno/{pod-security-standards,best-practices}/
│
├── environments/                       # Cluster-config ConfigMaps
│   ├── dev/
│   ├── staging/
│   └── production/
│
├── catalog/                            # Platform-specific workloads
│   └── druid/
│
└── docs/                               # Documentation
```

## Sync Wave Ordering

| Wave | Components | Rationale |
|------|------------|-----------|
| -1 | App-of-Apps | Root application |
| 0 | Bootstrap Helm (cert-manager, external-secrets, prometheus-operator-crds) | Foundational CRDs |
| 1 | Networking (Cilium, ALB Controller, External DNS) | CNI and ingress |
| 2 | Bootstrap continued (metrics-server, reloader, storage-classes, priority-classes) | Cluster essentials |
| 5 | Karpenter | Nodes must be ready before workloads |
| 10-12 | Security (Kyverno, Trivy, Falco) | Policy engine before policies |
| 20-21 | Kyverno Policies | After Kyverno is ready |
| 30-33 | Observability (Loki, Tempo, Grafana Agent, OpenCost) | After security |
| 40-44 | Operations (Velero, VPA, Goldilocks, Descheduler, Karpenter Resources, KEDA) | After everything |
| 50-52 | Argo Platform (Rollouts, Events, Workflows) | Application layer |

## Environment Differences

| Setting | Dev | Staging | Production |
|---------|-----|---------|------------|
| Replicas | 1 | 2-3 | 2-3 |
| Kyverno Mode | Audit | Enforce | Enforce |
| Velero | Disabled | Enabled | Enabled |
| Karpenter CPU | 50 | 75 | 200 |
| Loki Retention | 7d | 14d | 90d |
| Falco Memory Limit | 1Gi | 2Gi | 4Gi |

## Prerequisites

Tools required for local development:

- [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) >= 5.0
- [helm](https://helm.sh/docs/intro/install/) >= 3.0
- [yamllint](https://yamllint.readthedocs.io/) >= 1.0

Infrastructure prerequisites (deployed by CDK):

- ArgoCD and App-of-Apps root Application
- EKS cluster with IRSA and cluster secret labels

## Commands

```bash
make help                # Show all available targets
make lint-yaml           # Lint all YAML files
make kustomize-build     # Build all overlays (all environments)
make kustomize-build-env # Build overlays for ENVIRONMENT (default: dev)
make validate            # Run all validations (lint + build)
make render              # Render manifests to rendered/ directory
make clean               # Remove rendered output
```

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Environment Configuration](docs/configuration/environments.md)
- [Adding Addons](docs/configuration/adding-addons.md)
- [Contributing](docs/development/contributing.md)
- [Troubleshooting](docs/runbooks/troubleshooting.md)

## License

[MIT](LICENSE)
