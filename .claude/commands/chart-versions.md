Audit Helm chart versions across all ApplicationSets.

Steps:
1. Read all ApplicationSet files in `applicationsets/*.yaml`
2. Extract `appName`, `chart`, `chartRepo`, and `chartVersion` from each element in the list generators
3. Present a summary table:

```
| Addon                         | Chart                    | Repo                                          | Version |
|-------------------------------|--------------------------|-----------------------------------------------|---------|
| cilium                        | cilium                   | https://helm.cilium.io                        | 1.18.6  |
| kyverno                       | kyverno                  | https://kyverno.github.io/kyverno             | 3.5.0   |
```

4. Flag any issues:
   - Multiple addons using the same chart at different versions
   - Charts from the same repository at significantly different versions (may indicate missed upgrades)

5. Optionally, if the user requests it, run `helm repo add` and `helm search repo` to check for newer versions available upstream.

Read files directly — do not run cluster commands.
