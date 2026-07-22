# Runbook — Rolling Back an Addon

**Severity**: depends on the blast radius of the bad release — a broken CNI or cert-manager upgrade is critical; a broken dashboard is low. **Scope**: chart-version pins and values changes for any addon in `applicationsets/` + `addons/`.

## Symptoms

- An addon degraded immediately after a chart-pin bump or values change merged to `main`
- `argocd app get <app>` shows the new `targetRevision`/chart version with `Degraded` health or failing hooks
- Workload regressions (crash loops, failed probes, behavior changes) correlated with the last merge touching that addon

## Diagnosis

Identify exactly what changed and where the pin lives:

```bash
git log --oneline -10 -- applicationsets/ addons/<category>/<addon>/
argocd app get <app-name>            # confirm the deployed chart version
argocd app history <app-name>        # deploy timeline
```

Chart versions for upstream Helm addons are pinned in the ApplicationSet list elements (`chartVersion` in `applicationsets/addons-*.yaml`), not in the addon directory. Values changes live in `addons/<category>/<addon>/values.yaml` (base) or `values-{env}.yaml` (per-env delta). Kustomize addons (storage-classes, priority-classes, karpenter-resources, portal-reader) pin everything in `base/` + overlays. The druid catalog chart is versioned by this repo itself — rolling it back means reverting the chart templates/values, there is no upstream pin.

Before rolling back, check the failure isn't environment-scoped: a bad `values-staging.yaml` delta needs a one-file revert, not a chart-pin revert across all environments.

## Remediation

**The durable rollback is a git revert.** Every generated Application runs `automated: {prune: true, selfHeal: true}`, and the ApplicationSet controller owns the Application spec — so `argocd app rollback` and `argocd app set` are both reverted within minutes. Anything that must stick goes through `main`:

1. Revert the offending commit (or just the pin/values hunk):
   ```bash
   git revert <sha>            # or hand-edit chartVersion back and commit
   ```
2. Open a PR. The revert passes through the same gates as the original change (yamllint, render, render-assert, kubeconform, trivy) — a revert that fails CI means the old pin has since become invalid (e.g. schema catalog moved on) and needs a fix-forward instead.
3. Merge. ArgoCD detects the new `main` within its polling interval and syncs the reverted version; `prune: true` removes resources the newer chart introduced.

**Buying time during a live incident** — manual levers are temporary by design, use them only to stabilize while the revert PR lands:

- `argocd app set <app> --sync-policy none` pauses automation until the ApplicationSet controller reconciles the Application spec back (minutes). Scaling the applicationset-controller to zero extends that window but freezes app generation cluster-wide — last resort, scale it back immediately after.
- `argocd app rollback <app> <history-id>` redeploys the previous revision but is undone by self-heal unless automation is paused first.

**Version-specific gotchas:**

- Charts that manage CRDs (kyverno, prometheus-operator-crds, kagent-crds, agentgateway-crds): Helm chart-version reverts do not downgrade CRDs already applied. Verify the older chart tolerates the newer CRD schema; if not, this is a fix-forward, not a rollback.
- StatefulSet-backed addons (loki, tempo, druid): a revert that changes `volumeClaimTemplates` will not apply — those fields are immutable and deliberately covered by `ignoreDifferences`. Data-format downgrades (e.g. a store schema migrated on upgrade) may also need the component's own downgrade procedure first.

## Verification

```bash
argocd app get <app-name>                    # Synced + Healthy at the reverted version
argocd app history <app-name>                # newest entry = reverted revision
kubectl -n <addon-namespace> get pods        # workloads back to steady state
```

Confirm the app remains Synced across a self-heal interval, and re-enable anything paused (`--sync-policy automated`, applicationset-controller replicas) if a manual lever was used. Then track the failed upgrade as its own work item — the pin bump will come back (Renovate watches chart versions; `.github/dependabot.yml` owns only the github-actions bumps), and the next attempt needs whatever the postmortem found.
