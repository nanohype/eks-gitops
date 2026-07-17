# Environment Configuration

## Environments

| Environment | Purpose | Cluster Name | Kyverno Mode |
|-------------|---------|--------------|--------------|
| development | Development and testing | development-platform | Audit |
| staging | Pre-production validation | staging-platform | Enforce |
| production | Live workloads | production-platform | Enforce |
| hub | The eks-fleet management/control plane (Crossplane + ArgoCD + portal). Runs the observability stack + bootstrap deps only — excluded from the workload catalog. | hub-fleet | n/a |

## Cluster Config

Each environment has a `cluster-config.yaml` ConfigMap in `environments/<env>/`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-config
  namespace: argocd
  labels:
    environment: development  # Used by ApplicationSet generators
data:
  environment: "development"
  provider: "aws"
  cluster_name: "development-platform"
  region: "us-west-2"
```

The `environment` label on the cluster secret is what ApplicationSets use to select the correct values files or overlay paths. The `provider` field identifies this as an EKS (AWS) cluster.

## Environment Differences

### Replica Counts

| Component | Development | Staging | Production |
|-----------|-----|---------|------------|
| Cilium Operator | 1 | default (from base) | default (from base) |
| Kyverno Admission | 1 | 3 | 3 |
| Kyverno Background | 1 | 2 | 2 |
| Kyverno Reports | 1 | 2 | 2 |
| Loki | 1 | 3 | 3 |
| Goldilocks Dashboard | 1 | 2 | 2 |

### Retention and Storage

| Component | Development | Staging | Production |
|-----------|-----|---------|------------|
| Loki Retention | 7 days | 14 days | 90 days |
| Loki Storage | 10Gi | 50Gi | 100Gi |
| Tempo Retention | 3 days | 7 days | 30 days |
| Tempo Storage | 10Gi | 50Gi | 100Gi |

### Backup Configuration

| Setting | Development | Staging | Production |
|---------|-----|---------|------------|
| Velero Enabled | No | Yes | Yes |
| Backup Bucket | none | injected per cluster | injected per cluster |
| Node Agent | No | Yes | Yes |
| Daily Backups | Disabled | Enabled | Enabled |

The backup bucket is not committed. landing-zone builds it per cluster as
`${cluster_name}-${account_id}-${region}-velero`, and cluster-bootstrap publishes
the finished name on the ArgoCD cluster Secret as the `velero/backup-bucket`
annotation; the `addons-velero` ApplicationSet injects it (with the `region`
label) as a Helm value. Development runs no Velero — the ApplicationSet selects
`environment NotIn [hub, development]`.

### Security

| Setting | Development | Staging | Production |
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
