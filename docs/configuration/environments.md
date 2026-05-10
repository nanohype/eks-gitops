# Environment Configuration

## Environments

| Environment | Purpose | Cluster Name | Kyverno Mode |
|-------------|---------|--------------|--------------|
| dev | Development and testing | dev-eks | Audit |
| staging | Pre-production validation | staging-eks | Enforce |
| production | Live workloads | production-eks | Enforce |

## Cluster Config

Each environment has a `cluster-config.yaml` ConfigMap in `environments/<env>/`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-config
  namespace: argocd
  labels:
    environment: dev  # Used by ApplicationSet generators
data:
  environment: "dev"
  provider: "aws"
  cluster_name: "dev-eks"
  region: "us-west-2"
```

The `environment` label on the cluster secret is what ApplicationSets use to select the correct values files or overlay paths. The `provider` field identifies this as an EKS cluster in the multi-cloud strategy.

## Environment Differences

### Replica Counts

| Component | Dev | Staging | Production |
|-----------|-----|---------|------------|
| Cilium Operator | 1 | default (from base) | default (from base) |
| Kyverno Admission | 1 | 3 | 3 |
| Kyverno Background | 1 | 2 | 2 |
| Kyverno Reports | 1 | 2 | 2 |
| Loki | 1 | 3 | 3 |
| Goldilocks Dashboard | 1 | 2 | 2 |

### Retention and Storage

| Component | Dev | Staging | Production |
|-----------|-----|---------|------------|
| Loki Retention | 7 days | 14 days | 90 days |
| Loki Storage | 10Gi | 50Gi | 100Gi |
| Tempo Retention | 3 days | 7 days | 30 days |
| Tempo Storage | 10Gi | 50Gi | 100Gi |

### Backup Configuration

| Setting | Dev | Staging | Production |
|---------|-----|---------|------------|
| Velero Enabled | No | Yes | Yes |
| Backup Bucket | none | aws-eks-staging-backups | aws-eks-production-backups |
| Node Agent | No | Yes | Yes |
| Daily Backups | Disabled | Enabled | Enabled |

### Security

| Setting | Dev | Staging | Production |
|---------|-----|---------|------------|
| Trivy Severity | CRITICAL | HIGH,CRITICAL | HIGH,CRITICAL |
| Scan Concurrency | 3 | 5 | 5 |
| Falco Memory Limit | 1Gi | 2Gi | 4Gi |
| Falco Priority | notice | warning | warning |

## Adding a New Environment

1. Create `environments/<name>/cluster-config.yaml` with appropriate `provider`, `cluster_name`, and `region`
2. For Helm addons: create `values-<name>.yaml` (delta only) in each addon directory under `addons/<category>/<addon>/`
3. For Kustomize addons (storage-classes, priority-classes, karpenter-resources): create `overlays/<name>/kustomization.yaml` referencing `../../base`
4. For policies: create overlay with appropriate enforcement mode patches
5. Ensure the ArgoCD cluster secret has label `environment: <name>`
