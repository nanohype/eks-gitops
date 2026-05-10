# Adding a New Addon

Step-by-step guide for adding a new addon to the platform.

## Helm Addon (default)

Most addons use Helm charts managed via ArgoCD multi-source.

### 1. Create the Directory

```bash
mkdir -p addons/<category>/<addon-name>
```

Categories: `bootstrap`, `networking`, `security`, `observability`, `operations`, `argo-platform`

### 2. Create Base Values

**`values.yaml`:** Add the complete base values shared across all environments.

```yaml
# <Addon name> - base configuration

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi

tolerations:
  - key: CriticalAddonsOnly
    operator: Exists
```

### 3. Create Environment Values

For each environment, create a delta-only values file. Only include values that differ from base:

**`values-dev.yaml`:**
```yaml
# <Addon name> - Dev overrides
# Uses base configuration — no environment overrides
```

**`values-staging.yaml`** and **`values-production.yaml`:** Same pattern — only include overrides.

### 4. Add to ApplicationSet

Edit the appropriate Helm ApplicationSet in `applicationsets/` (e.g., `addons-security.yaml`, `addons-operations-helm.yaml`):

```yaml
- list:
    elements:
      # ... existing entries ...
      - appName: <addon-name>
        namespace: <target-namespace>
        chartRepo: <helm-repo-url>
        chart: <chart-name>
        chartVersion: <version>
        path: addons/<category>/<addon-name>
        syncWave: "<wave-number>"
```

Choose a sync wave appropriate for the addon's category (see [Architecture Overview](../architecture/overview.md)).

---

## Kustomize Addon

For addons that deploy raw Kubernetes resources without Helm.

### 1. Create the Directory Structure

```bash
mkdir -p addons/<category>/<addon-name>/base
mkdir -p addons/<category>/<addon-name>/overlays/{dev,staging,production}
```

### 2. Create Base Resources

**`base/kustomization.yaml`:**
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - <resource>.yaml
```

**`base/<resource>.yaml`:** The Kubernetes resource manifests.

### 3. Create Overlays

**`overlays/<env>/kustomization.yaml`:**
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base
```

Add patches in overlays as needed for environment-specific configuration.

### 4. Add to ApplicationSet

Edit the appropriate Kustomize ApplicationSet (e.g., `addons-bootstrap-kustomize.yaml`, `addons-operations-kustomize.yaml`):

```yaml
- list:
    elements:
      # ... existing entries ...
      - appName: <addon-name>
        namespace: <target-namespace>
        path: addons/<category>/<addon-name>
        syncWave: "<wave-number>"
```

---

## Validate

```bash
# Lint
make lint-yaml

# Build all environments
make kustomize-build

# Render to inspect output
make render ENVIRONMENT=dev
```

## Commit and PR

Follow the branch naming convention: `feat/add-<addon-name>`
