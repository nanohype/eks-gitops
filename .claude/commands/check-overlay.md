Verify that environment values files contain only deltas from base.

Steps:
1. Find all Helm addons (directories matching `addons/*/*/values.yaml`)
2. For each addon, compare every `values-{env}.yaml` against its `values.yaml`
3. Flag any key-value pairs in environment files that exactly duplicate the base defaults

For each addon, report:
- **Clean**: environment file contains only delta values (or is empty / comment-only)
- **Duplicates found**: list the duplicated keys with their values

Example output:
```
addons/networking/cilium
  values-dev.yaml          — Clean (1 override: operator.replicas)
  values-staging.yaml      — Clean (no overrides)
  values-production.yaml   — Clean (no overrides)

addons/security/kyverno
  values-dev.yaml          — DUPLICATE: replicaCount: 1 (same as base)
  values-staging.yaml      — Clean (1 override: replicaCount)
  values-production.yaml   — Clean (2 overrides: replicaCount, resources)
```

To detect duplicates, parse both YAML files and walk the key hierarchy. A key is a duplicate if:
- It exists in both base and environment file
- The values are identical (same type and value)

Read all files directly — do not run cluster commands.
