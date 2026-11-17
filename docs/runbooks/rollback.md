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

- Charts that manage CRDs (kyverno, prometheus-operator-crds, envoy-gateway-crds, envoy-ai-gateway-crds): ArgoCD renders a chart's CRDs (`--include-crds`) and applies them like any other manifest, so a chart-version revert re-applies the older CRD rather than leaving the newer one in place. Verify the older schema still serves every version the cluster has stored and that the running controller tolerates it; if not, this is a fix-forward, not a rollback.
- Never roll back by deleting an ApplicationSet element that owns CRDs (`envoy-gateway-crds`, `envoy-ai-gateway-crds`). No ApplicationSet here sets `preserveResourcesOnDeletion`, so the controller deletes the removed element's Application with cascade, and that deletes its CRDs and every resource of their kinds on every cluster it reached. That includes reverting the change that split Envoy Gateway's CRDs out of `gateway-helm`. Fix forward. If CRD ownership truly has to move back, do it the way it moved out: turn prune off on the Applications involved (`autoPrune: false`) and let that reach every cluster first.
- `addons-ai-platform.yaml` can turn one Application's automated prune off without a second ApplicationSet: every element carries `autoPrune`, and its `templatePatch` restates `prune` from it (`applicationsets/rendertest` renders the patch against every element). Every element runs `autoPrune: true` today. The lever is for moving ownership of something an Application installs: set `autoPrune: false` in its own change, let that reach every cluster, then make the move. Turning prune back on — setting `autoPrune: true` again, or reverting the change that set it false — means the next sync deletes everything that Application still tracks and no longer renders, CRDs included, and with a CRD every resource of its kind. Before it lands, list what each opted-in cluster's copy of the Application would prune, and confirm every entry is meant to go:
  ```bash
  kubectl -n argocd get application <app> -o json \
    | jq -r '.status.resources[]? | select(.requiresPruning) | .kind + "/" + .name'
  ```
  The last use was `envoy-gateway`, off while Envoy Gateway's CRDs moved to `envoy-gateway-crds`; with prune back on, a cluster that ran the old bundled `crds` subchart prunes the three `gateway.networking.x-k8s.io` CRDs (`xbackends`, `xbackendtrafficpolicies`, `xmeshes`) only that subchart installed, and a cluster bootstrapped since has none.
- StatefulSet-backed addons (loki, tempo, druid): a revert that changes `volumeClaimTemplates` will not apply — those fields are immutable and deliberately covered by `ignoreDifferences`. Data-format downgrades (e.g. a store schema migrated on upgrade) may also need the component's own downgrade procedure first.

## Verification

```bash
argocd app get <app-name>                    # Synced + Healthy at the reverted version
argocd app history <app-name>                # newest entry = reverted revision
kubectl -n <addon-namespace> get pods        # workloads back to steady state
```

Confirm the app remains Synced across a self-heal interval, and re-enable anything paused (`--sync-policy automated`, applicationset-controller replicas) if a manual lever was used. Then track the failed upgrade as its own work item — the pin bump will come back (Renovate watches chart versions and the GitHub Actions pins alike), and the next attempt needs whatever the postmortem found.
