Scaffold a new addon with all required files.

Gather the following from the user (or from $ARGUMENTS if provided):
1. **Category**: one of bootstrap, networking, security, observability, operations, argo-platform
2. **Addon name**: kebab-case (e.g., `metrics-server`)
3. **Type**: Helm (default) or Kustomize
4. **Namespace**: Kubernetes namespace for the addon
5. **Sync wave**: the ArgoCD sync wave number (bootstrap: 0-2, networking: 1, karpenter: 5, security: 10-12, policies: 20-21, observability: 30-33, operations: 40-44, argo-platform: 50-52)

**For Helm addons, also gather:**
6. **Helm chart name**: the chart name in the repository
7. **Helm repo URL**: the Helm repository URL
8. **Chart version**: the specific version to pin

---

## Helm Addon (default)

Create these 4 files:

### `addons/<category>/<name>/values.yaml`
```yaml
# <Addon name> - base configuration
```
(Populate with sensible defaults if the user provides them, otherwise leave as a placeholder comment.)

### `addons/<category>/<name>/values-dev.yaml`
```yaml
# <Addon name> - Dev overrides
# Uses base configuration — no environment overrides
```

### `addons/<category>/<name>/values-staging.yaml`
```yaml
# <Addon name> - Staging overrides
# Uses base configuration — no environment overrides
```

### `addons/<category>/<name>/values-production.yaml`
```yaml
# <Addon name> - Production overrides
# Uses base configuration — no environment overrides
```

### ApplicationSet entry
Add the addon to the appropriate ApplicationSet in `applicationsets/addons-<category>.yaml` (or `addons-<category>-helm.yaml` for operations) under `spec.generators[0].matrix.generators[1].list.elements`:
```yaml
- appName: <addon-name>
  namespace: <namespace>
  chartRepo: <repo-url>
  chart: <chart-name>
  chartVersion: <version>
  path: addons/<category>/<addon-name>
  syncWave: "<wave>"
```

---

## Kustomize Addon

Create these 4+ files:

### `addons/<category>/<name>/base/kustomization.yaml`
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - <resource>.yaml
```

### `addons/<category>/<name>/base/<resource>.yaml`
Create the Kubernetes resource manifests.

### `addons/<category>/<name>/overlays/<env>/kustomization.yaml` (for dev, staging, production)
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base
```

### ApplicationSet entry
Add the addon to the appropriate Kustomize ApplicationSet (e.g., `addons-bootstrap-kustomize.yaml` or `addons-operations-kustomize.yaml`):
```yaml
- appName: <addon-name>
  namespace: <namespace>
  path: addons/<category>/<addon-name>
  syncWave: "<wave>"
```

---

After creating all files, run `make validate` to confirm everything builds correctly.
