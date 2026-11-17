Scaffold a new Kyverno ValidatingPolicy with all required files.

Gather the following from the user (or from $ARGUMENTS if provided):
1. **Policy group**: existing group (pod-security-standards, best-practices, networking, supply-chain) or new group name
2. **Policy name**: kebab-case (e.g., `require-readonly-rootfs`)
3. **Title**: human-readable title for the annotation
4. **Category**: Kyverno policy category (e.g., Pod Security Standards, Best Practices)
5. **Severity**: low, medium, or high
6. **Target resources**: Kubernetes resource kinds to match (e.g., Pod, Deployment)
7. **Validation**: description of what the policy enforces, as ONE CEL expression

Then create the policy following existing patterns in the codebase. Use
`policies.kyverno.io/v1` CEL kinds only: Kyverno 1.20 does not execute the legacy
`kyverno.io` ClusterPolicy/Policy, and `scripts/check-policy-validity.py` refuses one.

One validation per policy. A ValidatingPolicy reports only the FIRST validation
that fails, so a second could never be shown to fire by `kyverno test` or by the
policy-admission canary; two checks are two policies.

### `policies/kyverno/<group>/base/<policy-name>.yaml`
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
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
  # Base is Audit; the staging and production overlays patch this to [Deny].
  validationActions: [Audit]
  failurePolicy: Fail
  evaluation:
    admission:
      enabled: true
    background:
      enabled: true
  matchConstraints:
    # If this policy governs tenant workloads beside require-labels and the
    # others, copy their 25-namespace list verbatim and add the file to
    # EXCLUSION_POLICIES in scripts/check-policy-admission.py, which pins the
    # lists identical.
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
            - kube-system
            - kube-public
            - kube-node-lease
            - kyverno
    resourceRules:
      - apiGroups: ["<group>"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["<plural-resources>"]
  variables:
    - name: compliant
      expression: <CEL over object>
    # An UPDATE to an object that already violated the check is admitted — what
    # the legacy allowExistingViolations did. Write it in exactly this form, the
    # `compliant` expression with object. read as oldObject.: an exclusion-bearing
    # policy is held to it by scripts/check-policy-admission.py. On a CREATE
    # oldObject is null or empty and the guard is false.
    - name: existingViolation
      expression: oldObject != null && has(oldObject.kind) && !(<the same CEL over oldObject>)
  validations:
    - expression: variables.compliant || variables.existingViolation
      message: "<validation failure message>"
```

A Pod policy gets autogen variants for every pod controller by default; write
its paths from `object.spec` / `oldObject.spec` so autogen can rewrite them.

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

**`policies/kyverno/<group>/overlays/development/kustomization.yaml`**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

# Development: Audit — a violation lands in a PolicyReport and is admitted.
# The legacy engine applied allowExistingViolations under Enforce only, so the
# Audit tier judges the new object alone.
patches:
  - patch: |-
      - op: replace
        path: /spec/validationActions
        value: [Audit]
      - op: test
        path: /spec/validations/0/expression
        value: variables.compliant || variables.existingViolation
      - op: replace
        path: /spec/validations/0/expression
        value: variables.compliant
    target:
      group: policies.kyverno.io
      kind: ValidatingPolicy
```

**`policies/kyverno/<group>/overlays/staging/kustomization.yaml`** and **production**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

# <Env>: Deny — a non-compliant resource is refused at admission.
patches:
  - patch: |-
      - op: replace
        path: /spec/validationActions
        value: [Deny]
    target:
      group: policies.kyverno.io
      kind: ValidatingPolicy
```

**Add to `applicationsets/kyverno-policies.yaml`** under `spec.generators[0].matrix.generators[1].list.elements`:
```yaml
- name: kyverno-<group>
  path: policies/kyverno/<group>
  syncWave: "<next-available-wave>"
```

Add a pass row and a fail row for the policy to `policies/kyverno/tests/kyverno-test.yaml`
(`isValidatingPolicy: true`, fixtures in `resources.yaml`, rows against a kind the
policy actually matches — `scripts/kyverno-test.sh` fails a row its policy never
evaluated), and an `operation: UPDATE` row to `policies/kyverno/tests/existing-violations/`.

After creating all files, run `task validate` to confirm everything builds correctly.
