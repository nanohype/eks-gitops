# Environment Configuration

## How environment is selected

There is no `environments/` tree of ConfigMaps in this repo. Environment is a
**label on the ArgoCD cluster Secret**, stamped by landing-zone
`cluster-bootstrap` when the cluster is registered with the hub.

| Label / annotation | Set by | Used for |
| --- | --- | --- |
| `environment: development\|staging\|production\|hub` | cluster-bootstrap | ApplicationSet value-file and overlay selection (`values-{{ environment }}.yaml`) |
| `region` | cluster-bootstrap | Per-cluster Helm values (Loki/Tempo S3 region, etc.) |
| `observability/tier: full\|floor` | cluster-bootstrap | Which observability appsets target the cluster |
| `eks-agent-platform/enabled: "true"` | cluster-bootstrap | Operator + agent-platform appsets |
| `eks-agent-platform/accelerators: "true"` | cluster-bootstrap | GPU device-plugin appsets |
| `observability/loki-bucket`, `tempo-bucket`, `velero/backup-bucket`, … | cluster-bootstrap (opt-in) | Per-cluster S3 targets injected as Helm values |

ApplicationSets read these with `{{ index .metadata.labels "environment" }}`
(and the matching annotations). A cluster without the label is simply not
selected.

## Environments

| Environment | Purpose | Typical cluster name | Kyverno Mode |
|-------------|---------|----------------------|--------------|
| development | Development and testing | development-platform | Audit |
| staging | Pre-production validation | staging-platform | Enforce |
| production | Live workloads | production-platform | Enforce |
| hub | eks-fleet management plane (Crossplane + ArgoCD + portal). Bootstrap + observability only — excluded from the workload catalog. | hub-fleet | n/a |

## Environment differences

Per-env behaviour lives in **addon deltas**, not a central ConfigMap:

- Helm addons: `addons/<category>/<addon>/values-<env>.yaml` (delta only)
- Kustomize addons: `overlays/<env>/`
- Kyverno: env overlays for Audit vs Enforce

### Replica counts (indicative)

| Component | Development | Staging | Production |
|-----------|-------------|---------|------------|
| Cilium Operator | 1 | default | default |
| Kyverno Admission | 1 | 3 | 3 |
| Kyverno Background | 1 | 2 | 2 |
| Kyverno Reports | 1 | 2 | 2 |
| Loki | 1 | 1 | 1 |

### Retention and storage

| Component | Development | Staging | Production |
|-----------|-------------|---------|------------|
| Loki Retention | 7 days | 30 days | 90 days |
| Tempo Retention | 3 days | 7 days | 30 days |

### Backup

| Setting | Development | Staging | Production |
|---------|-------------|---------|------------|
| Velero | No | Yes | Yes |
| Backup bucket | — | cluster-Secret annotation | cluster-Secret annotation |

The bucket name is not committed. landing-zone builds it per cluster;
cluster-bootstrap publishes `velero/backup-bucket` on the Secret;
`addons-velero` injects it. Development is `environment NotIn [hub, development]`.

## Adding a new environment

1. **landing-zone**: vend the cluster and ensure cluster-bootstrap stamps
   `environment: <name>` (and the other labels/annotations the appsets need)
   on the ArgoCD cluster Secret.
2. For Helm addons: add `values-<name>.yaml` deltas under each addon that
   differs from base.
3. For Kustomize addons: add `overlays/<name>/`.
4. For policies: Audit vs Enforce overlay as appropriate.
5. Confirm ApplicationSets select the new cluster
   (`kubectl get applications -n argocd` on the hub).
