# Troubleshooting

## Kustomize Build Failures

```bash
# Build Kustomize overlays for a specific environment
make kustomize-build-env ENVIRONMENT=dev
```

**Common issues:**

- **Invalid YAML** — run `yamllint -c .yamllint.yaml <file>` first
- **Missing base reference** — Kustomize overlays must reference `../../base` correctly
- **Missing values files** — Helm addons need `values.yaml` + three `values-{env}.yaml` files
- **Kustomize addon path** — ensure `overlays/<env>/kustomization.yaml` exists for Kustomize addons

## ApplicationSet Not Generating Applications

1. Verify the cluster secret exists and has the correct labels:
   ```bash
   kubectl get secrets -n argocd -l argocd.argoproj.io/secret-type=cluster
   kubectl get secret <name> -n argocd -o jsonpath='{.metadata.labels.environment}'
   ```

2. Check ApplicationSet controller logs:
   ```bash
   kubectl logs -n argocd -l app.kubernetes.io/component=applicationset-controller
   ```

3. Verify the `environment` label is set on the cluster secret — this is required for values file and overlay path resolution

## Helm Values Not Applying

1. Verify the ApplicationSet element has the correct `path` pointing to the addon directory

2. Ensure both values files exist in the addon directory:
   - `values.yaml` (base)
   - `values-<environment>.yaml` (environment delta)

3. Verify environment delta values files only contain overrides (not full base copy)

4. Check Helm chart version supports the values being set — some keys change between versions

5. Check ArgoCD Application sources — the `$values` ref must resolve to the correct Git repository and branch

## Sync Stuck or Failing

1. Check ArgoCD application status:
   ```bash
   argocd app get <app-name>
   argocd app sync <app-name> --dry-run
   ```

2. Review sync errors in the ArgoCD UI

3. Check if CRDs are missing — CRD-dependent resources fail if the CRD chart hasn't synced yet. Verify sync waves are ordered correctly.

4. Verify RBAC permissions for the ArgoCD service account

5. For StatefulSet volume issues, check the `ignoreDifferences` section in the observability ApplicationSet

## Kyverno Policy Issues

1. Check policy status:
   ```bash
   kubectl get clusterpolicy
   kubectl describe clusterpolicy <name>
   ```

2. View policy reports:
   ```bash
   kubectl get policyreport -A
   kubectl get clusterpolicyreport
   ```

3. In dev, policies are in Audit mode — violations generate reports but don't block. In staging/production, policies Enforce — violations are rejected.

## Velero Backup Issues

1. Verify Velero is running:
   ```bash
   kubectl get pods -n velero
   velero backup get
   ```

2. Check backup storage location:
   ```bash
   velero backup-location get
   ```

3. In dev, backups are disabled — no backup storage location is configured. Ensure you're checking the correct environment.

## Falco Issues

1. Check Falco pods for OOMKills (known memory leak in modern-bpf driver):
   ```bash
   kubectl get pods -n falco
   kubectl describe pod -n falco -l app.kubernetes.io/name=falco
   ```

2. If pods are OOMKilled, verify memory limits are set high enough (2Gi+ recommended)

3. Check Falco logs for driver initialization:
   ```bash
   kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50
   ```

4. For persistent OOM issues, consider scheduling daily rolling restarts of the DaemonSet until the upstream fix ships
