Scaffold a new Kyverno ClusterPolicy with all required files.

Gather the following from the user (or from $ARGUMENTS if provided):
1. **Policy group**: existing group (pod-security-standards, best-practices) or new group name
2. **Policy name**: kebab-case (e.g., `require-readonly-rootfs`)
3. **Title**: human-readable title for the annotation
4. **Category**: Kyverno policy category (e.g., Pod Security Standards, Best Practices)
5. **Severity**: low, medium, or high
6. **Target resources**: Kubernetes resource kinds to match (e.g., Pod, Deployment)
7. **Validation rule**: description of what the policy enforces

Then create the policy following existing patterns in the codebase:

### `policies/kyverno/<group>/base/<policy-name>.yaml`
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: <policy-name>
  annotations:
    policies.kyverno.io/title: <title>
    policies.kyverno.io/category: <category>
    policies.kyverno.io/severity: <severity>
    policies.kyverno.io/subject: <target-resources>
    policies.kyverno.io/description: >-
      <description of what this policy enforces>
spec:
  admission: true
  emitWarning: false
  validationFailureAction: Audit
  background: true
  rules:
    - name: <rule-name>
      skipBackgroundRequests: true
      match:
        any:
          - resources:
              kinds:
                <target-resource-kinds>
      exclude:
        any:
          - resources:
              namespaces:
                - kube-system
                - kube-public
                - kube-node-lease
                - argocd
                - kyverno
                - trivy-system
                - cert-manager
                - external-secrets
                - monitoring
                - velero
      validate:
        allowExistingViolations: true
        message: "<validation failure message>"
        pattern:
          <validation pattern>
```

### Add to base kustomization.yaml
Add `- <policy-name>.yaml` to `policies/kyverno/<group>/base/kustomization.yaml` resources list.

### If new policy group — create group overlays
If the policy group doesn't exist yet, create:

**`policies/kyverno/<group>/base/kustomization.yaml`**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - <policy-name>.yaml
```

**`policies/kyverno/<group>/overlays/dev/kustomization.yaml`**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

# Dev: Audit mode (warn but don't block)
patches:
  - patch: |-
      - op: replace
        path: /spec/validationFailureAction
        value: Audit
    target:
      kind: ClusterPolicy
```

**`policies/kyverno/<group>/overlays/staging/kustomization.yaml`** and **production**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

# <Env>: Enforce mode (block non-compliant resources)
patches:
  - patch: |-
      - op: replace
        path: /spec/validationFailureAction
        value: Enforce
    target:
      kind: ClusterPolicy
```

**Add to `applicationsets/kyverno-policies.yaml`** under `spec.generators[0].matrix.generators[1].list.elements`:
```yaml
- name: kyverno-<group>
  path: policies/kyverno/<group>
  syncWave: "<next-available-wave>"
```

After creating all files, run `make validate` to confirm everything builds correctly.
