# Runbook — Druid Operations

**Severity**: high for tenant-facing outages (query path down), medium for single-component degradation. **Scope**: the chart this repo owns outright — `catalog/druid/chart/` (plus base `catalog/druid/values.yaml`). There is no default ApplicationSet wiring Druid onto the fleet; a tenant deploy is an opt-in (or out-of-band) Application that points at this chart. Namespace convention when wired: `druid-<tenant>`, never on the hub.

The cluster is ZooKeeper-less (`druid.discovery.type=k8s` via druid-kubernetes-extensions, leader election over ConfigMaps) and TLS-only (`druid.enablePlaintextPort=false`). Components: coordinator, overlord, historical (StatefulSets), broker, router (Deployments); ingestion tasks run as Jobs launched by the overlord (druid-kubernetes-overlord-extensions). Each component gets its own Karpenter NodePool from the chart, backed by a shared EC2NodeClass.

## Keystore secret rotation

The PKCS#12 keystore/truststore password is shared by cert-manager (which encrypts the keystores it writes) and the Druid pods (which read them back). The chain:

```
AWS Secrets Manager <tenant keystore secret>  (Values.secrets.keystore, property "password")
  → ExternalSecret <name>-keystore-password    (refreshInterval: 1h, ClusterSecretStore aws-secrets-manager)
  → k8s Secret <name>-keystore-password
  → cert-manager Certificate <name>-druid-tls  (keystores.pkcs12.passwordSecretRef)
  → keystore.p12 / truststore.p12 in Secret <name>-druid-tls, mounted at /opt/druid/conf/druid/cluster/tls
  → pods: DRUID_TLS_KEYSTORE_PASSWORD env + druid.server.https.keyStorePassword=${env:...}
```

Rotation procedure:

1. Update the `password` property of the tenant's keystore secret in AWS Secrets Manager.
2. Sync the ExternalSecret — wait for the 1h `refreshInterval` or force it:
   ```bash
   kubectl -n druid-<tenant> annotate externalsecret <name>-keystore-password \
     force-sync=$(date +%s) --overwrite
   kubectl -n druid-<tenant> get externalsecret <name>-keystore-password   # SecretSynced/Ready
   ```
3. Have cert-manager re-encrypt the keystores with the new password:
   ```bash
   cmctl renew <name>-druid-tls -n druid-<tenant>
   # or: kubectl -n druid-<tenant> delete secret <name>-druid-tls   (cert-manager reissues)
   ```
4. Roll the pods. Druid reloads keystore *files* from disk every 180s (`reloadSslContextSeconds`), but the *password* env var is read once at process start — a rotation is not complete until every pod restarts:
   ```bash
   kubectl -n druid-<tenant> rollout restart statefulset -l app.kubernetes.io/name=druid
   kubectl -n druid-<tenant> rollout restart deployment
   ```
5. Order matters only in one place: do not restart pods between steps 2 and 3 — a pod starting with the new password while the TLS secret still holds keystores encrypted with the old one fails at JVM keystore load.

The metadata/admin/system credentials rotate the same way (steps 1–2, then restart) minus the cert-manager step — they are plain env vars from their ExternalSecret-backed Secrets.

## Probe semantics

All five components probe over HTTPS `httpGet` (the kubelet skips certificate verification for HTTPS probes, so the chart's self-signed internal CA is fine; the endpoints are on Druid's unsecured-path list, so basic-auth doesn't block them):

| Component | Port | Liveness | Readiness |
|---|---|---|---|
| coordinator | 8281 | `/status/health` | `/status/health` |
| broker | 8282 | `/status/health` | `/druid/broker/v1/readiness` |
| historical | 8283 | `/status/health` | `/druid/historical/v1/readiness` |
| overlord | 8290 | `/status/health` | `/status/health` |
| router | 9088 | `/status/health` | `/status/health` |

Timing: startupProbe allows 60s initial delay + 60 failures × 10s ≈ **11 minutes to come up** before the kubelet starts killing; liveness/readiness then run at 10s periods with `initialDelaySeconds: 180`. What the two distinct readiness endpoints mean:

- **Broker** `/druid/broker/v1/readiness` returns 503 until the broker has synced the full segment view from historicals — a broker that is alive but not ready is *correct* behavior during historical restarts; don't chase it.
- **Historical** `/druid/historical/v1/readiness` returns 503 until all assigned segments are loaded from deep storage. Large tenants can hold readiness for a while after a reschedule — segment cache is an `emptyDir`, so every pod replacement re-pulls its assignment from S3.

A pod stuck in `Running` but never `Ready` past those windows: check the JVM actually bound the TLS port (`kubectl logs` for keystore errors), then metadata connectivity (`DRUID_METADATA_STORAGE_*` env from the metadata ExternalSecret), then segment-load progress in the coordinator console.

## Scaling

Per-component `replicas` and `resources` live in the values layering: `catalog/druid/values.yaml` (base) → `catalog/druid/tenants/<tenant>/values.yaml` → `values-{env}.yaml`. Change them there and let ArgoCD sync — `selfHeal: true` reverts manual `kubectl scale` within minutes.

- **Historical** — the usual scale-out target for query capacity. New replicas go Ready only after loading their segment assignment (see probes above); scale one step at a time on large tenants so rebalancing doesn't thundering-herd deep storage.
- **Broker / router** — stateless; scale freely for query concurrency.
- **Coordinator / overlord** — leader-elected; additional replicas are warm standbys, not capacity.
- **Ingestion (task) capacity** — not replica-driven: the overlord launches task pods as Jobs from the task template. Capacity is governed by task tuning in the runtime properties and the task NodePool limits, not by scaling a StatefulSet.

Nodes follow automatically: each component pins to its own Karpenter NodePool via nodeSelector, so scaling replicas provisions/consolidates EC2 without manual node work. If pods stay `Pending`, check the component's NodePool limits and Karpenter events before anything else.

## Verification

```bash
argocd app get druid-<tenant>                          # Synced / Healthy
kubectl -n druid-<tenant> get pods -o wide             # all Ready, spread across component pools
kubectl -n druid-<tenant> get externalsecrets          # all SecretSynced
kubectl -n druid-<tenant> get certificate              # <name>-druid-tls Ready
```

End-to-end: port-forward the router (9088) and run a trivial query through it — the router exercises broker discovery, the broker exercises historical TLS, and a 200 proves the whole mTLS mesh agrees on the keystore password.
