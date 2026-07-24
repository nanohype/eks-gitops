# Runbook — Observability tier (floor | full)

**Severity**: medium — a wrong tier does not break a cluster, it silently changes what you can see about one, and one step here has a cost consequence that is not reversible after the fact. **Scope**: the `observability/tier` cluster-Secret label and every ApplicationSet that selects on it.

## What the tier is

Every cluster declares one of two observability substrates, as an always-set label on its ArgoCD registration Secret:

| | `floor` | `full` |
| --- | --- | --- |
| metrics | CloudWatch — Container Insights (infrastructure) + EMF (application) | that, plus Amazon Managed Prometheus |
| logs | CloudWatch Logs | that, plus Loki |
| traces | AWS X-Ray | Tempo |
| dashboards | the CloudWatch dashboard landing-zone builds | that, plus Amazon Managed Grafana |

**Both tiers run the same node agent and the same gateway, on the same `telemetry.monitoring.svc:4317/4318` endpoint.** Only the gateway's exporters differ. A tenant chart is byte-identical across tiers — if you find yourself changing an application to move a cluster between tiers, something is wrong and this runbook is the wrong tool.

The label is set by landing-zone's `cluster-bootstrap` from `observability_tier`, or by a fleet vend from `spec.observabilityTier`. It is never edited directly on the Secret: ArgoCD's cluster Secret is terraform-owned, and a manual edit is reverted on the next apply.

## Bringing up the first floor cluster

Steps 1–3 are ordinary. **Step 4 is not optional and has no second chance** — custom-metric cardinality is billed as it is emitted, and a bad dimension set is not refundable after you notice it.

### 1. Confirm the tier landed

```bash
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster \
  -o custom-columns='CLUSTER:.metadata.name,TIER:.metadata.labels.observability/tier'
```

Every cluster must show `floor` or `full`. A blank means the Secret predates the label — re-apply `cluster-bootstrap` for that cluster. A blank tier matches **no** generator, so the cluster gets the node agent and nothing else.

### 2. Confirm the right gateway, and only one

```bash
kubectl get application -n argocd | grep otel
```

Exactly one of `otel-gateway` / `otel-gateway-floor` per cluster. Both would be a selector bug — they share `fullnameOverride: otel-gateway` and would fight over the same objects.

```bash
kubectl get svc -n monitoring telemetry
kubectl get sa -n monitoring otel-gateway-cw
```

The `telemetry` Service must exist and have endpoints either way — that is the tenant contract, and it does not vary by tier.

### 3. Confirm the Container Insights producer

```bash
aws eks describe-addon --cluster-name <cluster> --addon-name amazon-cloudwatch-observability \
  --query 'addon.{status:status,version:addonVersion}'
aws cloudwatch list-metrics --namespace ContainerInsights \
  --dimensions Name=ClusterName,Value=<cluster> --query 'length(Metrics)'
```

A non-zero count means landing-zone's alarms finally have data. **Zero after ~10 minutes means the addon is on the wrong pipeline**: from v6.2.0 the addon can run either Classic (CloudWatch-format names — `node_cpu_utilization`, `cluster_failed_node_count`) or OTel Container Insights (Prometheus-native names), and every alarm this platform ships reads the CloudWatch-format set. Check that `containerInsights.enabled` is true and `otelContainerInsights.enabled` is false for the pinned version.

### 4. Measure EMF cardinality before vending a second floor cluster

The floor gateway publishes application metrics to CloudWatch as EMF, under the `Platform/OTel` namespace. The config starts deliberately narrow — `dimension_rollup_option: NoDimensionRollup` and `resource_to_telemetry_conversion` off — because widening later is a config change while a cardinality bill is not refundable.

Nothing in CI can check this. No gate parses collector config, and the cost depends on the workloads actually running, not on the config.

```bash
# How many distinct custom metrics the floor gateway is minting
aws cloudwatch list-metrics --namespace Platform/OTel --query 'length(Metrics)'

# What dimensions they carry — this is the number that multiplies
aws cloudwatch list-metrics --namespace Platform/OTel \
  --query 'Metrics[].Dimensions[].Name' --output text | tr '\t' '\n' | sort | uniq -c | sort -rn

# The bill, once a day of data exists
aws cloudwatch get-metric-statistics --namespace AWS/Usage \
  --metric-name CallCount --dimensions Name=Type,Value=Resource \
  Name=Resource,Value=PutMetricData Name=Service,Value=CloudWatch Name=Class,Value=None \
  --start-time "$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 86400 --statistics Sum
```

What you are looking for is an unbounded dimension — anything derived from a pod name, a request id, a user id, a URL path with an identifier in it. One of those turns a handful of metrics into thousands of series.

If the count is larger than you expected, the lever is `metric_declarations` in `addons/observability/otel-gateway-floor/values.yaml`: pin an explicit dimension set per metric selector instead of accepting whatever the datapoint carries. Narrowing is safe to do at any time; it does not retroactively remove what was already emitted.

## Flipping a live cluster between tiers

**Do not flip a cluster carrying traffic without reading this.** The flip is a terraform change plus an ArgoCD convergence, and there is a window in the middle where telemetry is going nowhere.

`full` → `floor` prunes the Loki, Tempo, kube-state-metrics, grafana-operator, dashboards and full-gateway Applications (every one of those appsets sets `prune: true`) and creates the floor gateway. `floor` → `full` is the reverse, and additionally **requires the `managed-monitoring` substrate to already exist for that cluster** — an AMP workspace, the endpoints Secret, and the AMP Pod Identity association. Flipping the label without that gives you a full-tier gateway that cannot resolve `AMP_REMOTE_WRITE_URL` and sits in `CreateContainerConfigError`.

Procedure:

1. **Full → floor only**: confirm nothing depends on the trace or log query paths you are about to remove. Loki and Tempo are pruned; anything stored in them is gone with their buckets' retention.
2. Change `observability_tier` in the cluster's `cluster-bootstrap` leaf (or `spec.observabilityTier` on the `Cluster` CR for a vended one) and apply. The label moves.
3. Watch the two gateways swap. They share `fullnameOverride: otel-gateway`, so ordering matters — ArgoCD prunes the old Application and creates the new one, and for a short window the `telemetry` Service has no endpoints. **Tenant OTLP exports fail during that window.** SDKs retry, so a short gap is absorbed; do it outside a deploy.

   ```bash
   kubectl get endpoints -n monitoring telemetry -w
   ```

4. Confirm the new gateway is exporting, using the checks in step 3 and 4 above.

The gap has not been measured on a production-sized cluster. If you need a zero-gap flip, the shape that gives it is a rename of one side's `fullnameOverride` so the two can coexist for one sync — that is a real change to this repo, not something to improvise during a flip.

## Symptoms and causes

| Symptom | Cause |
| --- | --- |
| An expected observability Application does not exist | The cluster's tier does not match the appset's selector. Check the label first — a blank label matches nothing. |
| `dashboards` Application permanently `Degraded` on a floor cluster | It should not be there. `dashboards` is gated `full`; on floor its 45 Grafana CRs have no CRDs. Check the selector edit landed. |
| A tenant Application `Degraded` on a floor cluster, `GrafanaDashboard` unknown | The tenant appset's `grafanaDashboard.enabled` parameter is not deriving from the tier. It renders `false` for any cluster whose label is not `full`, including a blank one. |
| Tenant OTLP exports failing on a floor cluster | The `telemetry` Service or the floor gateway is missing. The endpoint is identical at both tiers; a tenant chart should never need to know the tier. |
| Landing-zone CloudWatch alarms in `INSUFFICIENT_DATA` | The Container Insights producer is absent or on the OTel pipeline. See step 3. |
| Floor gateway pod in `CreateContainerConfigError` | Usually a full-tier gateway on a floor cluster — it wants the `managed-monitoring-endpoints` Secret, which a floor cluster has no reason to have. |

## Related

- [ADR: telemetry-pipeline standard](https://github.com/nanohype/nanohype/blob/main/standards/telemetry-pipeline.json) — the tier vocabulary and the invariant that a workload chart is identical across tiers
- [addon-sync-degraded.md](./addon-sync-degraded.md) — generic Application convergence failures
