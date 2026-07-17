# Threat Model

STRIDE analysis of the eks-gitops **catalog**, organized by trust boundary. This
repo is not a running system — it is the GitOps source of truth (Helm values,
kustomize overlays, ArgoCD ApplicationSets, Kyverno policies) that a customer
**forks** and points a hub cluster at. Every mitigation below is a control that
lives **in this repo**, cited to the component that implements it, with the
residual risk a fork should weigh.

The substrate this catalog deploys onto — the EKS control plane, node security,
Terraform state, per-tenant IAM — is modeled separately in the
[landing-zone threat model](../../landing-zone/docs/threat-model.md). Where this
model says "owned by landing-zone" it means exactly that boundary.

## Trust boundaries

```
customer fork ──ArgoCD app-of-apps──► ApplicationSets ──► fleet of clusters
      │                                     │
      │  repoURL from cluster-Secret        ├─► Kyverno admission (sign/PSS/best-practice)
      │  annotation (not hardcoded)         ├─► workload images ──Cosign keyless──► ghcr.io/nanohype/*
      │                                     ├─► ExternalSecrets ──Pod Identity──► AWS Secrets Manager
   CI gate                                  ├─► agent platform (budget/model/kill-switch CRs)
 (render→kubeconform→trivy,                 └─► per-tenant namespaces (druid, agents)
  fork-safety, sign-identity)
```

## 1. Fork / catalog integrity  (`scripts/check-hardcoded-org.py`, `applicationsets/`)

- **Tampering / Denial of the fork's own config** — a hardcoded catalog `repoURL`
  strands a fork: the customer's clusters keep syncing from `nanohype/eks-gitops`
  upstream and the fork's edits silently never take effect. Mitigated: every
  applied ApplicationSet resolves its source from
  `{{ index .metadata.annotations "gitops/repo-url" }}` off the ArgoCD cluster
  Secret (druid-tenants.yaml:25,43,52), and `check-hardcoded-org.py:89` matches
  any `repoURL:` pointing at the catalog repo, exiting non-zero under `--blocking`
  (:167) — wired as the CI **fork-safety** job (ci.yml:122-130). Expected count: 0.
- **Residual** — the gate is deliberately catalog-only and non-recursive: it does
  not touch `applicationsets/opt-in/` (never applied by app-of-apps) or published
  artifacts (`ghcr.io/nanohype/*`, the eks-agent-platform product repo), which a
  fork *consumes* rather than forks. A fork enabling an opt-in ApplicationSet must
  repoint its org-specific URLs by hand (documented in opt-in/README.md).

## 2. GitOps sync / app-of-apps  (`.github/workflows/ci.yml`, ApplicationSet syncPolicy)

- **Tampering** — a merged manifest deploys fleet-wide with no further review.
  Mitigated at PR time by a render→validate→scan gate: kustomize/helm render every
  overlay (ci.yml:150-185), `kubeconform -strict` with **no** `-ignore-missing-schemas`
  (ci.yml:251-259), and `trivy config` hard-failing on **MEDIUM+** against the
  *rendered* output (ci.yml:273-278). The workflow itself is least-privilege
  (`permissions: contents: read`, ci.yml:9-11).
- **Denial of service / drift** — ApplicationSet `syncPolicy` runs `selfHeal` +
  `prune` with a bounded retry/backoff (druid-tenants.yaml:58-70), so manual drift
  is reverted and a transient sync failure retries rather than wedging.
- **Residual** — CI proves manifests *render, schema-validate, and scan clean*; it
  does not prove they are *correct policy*. Branch protection + human PR review is
  the control that a malicious-but-valid change must pass, and that lives in GitHub
  settings, not this repo. CI has no cluster, so first-party CRDs
  (Platform/Tenant/ModelGateway/BudgetPolicy, Grafana) are schema-skipped
  (ci.yml:258) and validated only against the real webhook out-of-band.

## 3. Image supply chain  (`policies/kyverno/supply-chain/`, `scripts/check-image-verification.py`)

- **Spoofing / Tampering of a workload image** — a hand-pushed or altered
  `ghcr.io/nanohype/*` image. Mitigated: the `verify-images` ClusterPolicy requires
  (`required: true`) a keyless Cosign signature from the GitHub Actions OIDC issuer,
  scoped to `ghcr.io/nanohype/*`, with an anchored org- and tag-bound
  `subjectRegExp` (verify-images.yaml:40-59, :56). Base is `Audit`
  (verify-images.yaml:21); the **production overlay patches it to `Enforce`**
  (overlays/production/kustomization.yaml:11-17), blocking unsigned images at
  admission.
- **Repudiation of a weakened policy** — `kyverno test` cannot reach Fulcio/Rekor,
  so it reports Pass regardless of attestor. The structural gate
  `check-image-verification.py:79-110` closes that hole: it fails the build if
  `required` flips, the issuer changes, or the subjectRegExp loses its anchor, its
  org scope, or its `refs/tags` binding — run in CI (ci.yml:85-88).
- **Residual** — verification is signature-presence only: `mutateDigest` /
  `verifyDigest` are `false` (verify-images.yaml:43-45), so a tag is not yet pinned
  to a digest. Third-party images (anything outside `ghcr.io/nanohype/*`) are
  unmatched and pass unsigned — their trust is the upstream registry's, not this
  policy's.

## 4. Admission / pod security  (`policies/kyverno/{best-practices,pod-security-standards}/`)

- **Elevation of privilege** — a root or unconstrained pod. Mitigated by Kyverno
  ClusterPolicies: `runAsNonRoot: true` (require-non-root.yaml:51-54), CPU + memory
  limits (require-resource-limits.yaml:52-57,90-95), required probes and the
  `app.kubernetes.io/name` label (require-probes.yaml, require-labels.yaml:53-56).
  Base is `Audit`; each group's **production overlay patches every ClusterPolicy to
  `Enforce`** — both `best-practices/overlays/production/kustomization.yaml:8-14`
  (require-labels, require-probes) and
  `pod-security-standards/overlays/production/kustomization.yaml:8-14`
  (require-non-root, require-resource-limits).
  `kyverno test` proves each rule passes a compliant and fails a violating resource
  (ci.yml:76-77), and `trivy config` MEDIUM+ backstops the rendered manifests.
- **Residual** — the policies carry a fixed exclude list of platform/system
  namespaces (argocd, kyverno, cert-manager, monitoring, …) and set
  `allowExistingViolations: true`, so pre-existing violators and every excluded
  namespace are unenforced. Non-production overlays stay `Audit`. A fork tightening
  posture should shrink the exclude list and promote `Enforce` earlier.

## 5. Secrets  (`addons/bootstrap/secret-stores/`, `catalog/druid/chart/templates/externalsecret.yaml`)

- **Information disclosure** — a plaintext secret committed to a (public) catalog.
  Mitigated by construction: secrets are pulled at runtime from AWS Secrets Manager
  via a `ClusterSecretStore` with **no auth block and no static keys** — the
  operator authenticates through an EKS Pod Identity association
  (cluster-secret-store.yaml:9-18). Workloads reference only Secrets Manager keys,
  never literals (externalsecret.yaml:9-33; the druid keystore password is read
  back through an env var, :86-111). Cloud IAM is externalized too: the agent
  operator's `role-arn` is injected from a **cluster-Secret annotation**, so the
  AWS account ID never lands in git (addons-agent-operator.yaml:67).
  `no-placeholders.sh` blocks the JVM `changeit` default and `FILL_ME`-class
  sentinels from shipping as config.
- **Residual** — the architecture is backstopped by an enforced scan: a
  **gitleaks** job scans the working tree on every PR and push (`ci.yml`
  `secrets` job), failing the build on a committed credential — so a raw secret
  pasted into a values file no longer merges. gitleaks is pattern- and
  entropy-based, so a novel secret format it has no rule for can still slip; a
  fork handling real secrets should pair it with GitHub push-protection and
  narrow its allowlist to the repo's known example values.

## 6. Agent platform governance  (`addons/ai-platform/`, `dashboards/base/alerting/agent-platform.yaml`)

- **Elevation of privilege (an over-privileged LLM)** — the bundled kagent runtime
  ships a `kagent-tools` ServiceAccount bound to cluster-admin and a `grafana-mcp`
  wired to an admin token. Both are **refused**: `kagent-tools: enabled: false` and
  `grafana-mcp: enabled: false` (kagent/values.yaml:32,170-171). Model access is an
  explicit `allowedModels` allowlist, not a family wildcard
  (platform.yaml:25-27), and operator sessions cap at 1h (:31).
- **Denial of service (runaway spend)** — a two-tier budget with
  `killSwitchEnabled: true` and `alertThresholdsPercent: [50,80,100]`
  (platform.yaml:39-42). Grafana **paging** alerts fire the instant the kill-switch
  stamps (agent-platform.yaml:49-70), when a budget crosses its cap (:108,165), and
  when evals regress or go stale (:224,284), each linking the recovery runbook
  (docs/runbooks/ai-platform-budget-killswitch.md).
- **Residual** — this repo only **declares** the `BudgetPolicy` / `Platform` /
  `ModelGateway` CRs and the alert rules. The *enforcement* — measuring spend,
  suspending a Platform, revoking IRSA — is the eks-agent-platform operator (a
  separate repo). The alert PromQL is untestable in CI (KSM CRDs are schema-skipped)
  and correct only if each selector matches the series KSM emits.

## 7. Multi-tenancy  (`applicationsets/druid-tenants.yaml`, `catalog/druid/chart/templates/role.yaml`)

- **Elevation of privilege / cross-tenant reach** — one tenant reaching another's
  workloads. Mitigated: the druid ApplicationSet lands each tenant in its own
  `druid-<name>` namespace (druid-tenants.yaml:55-57), and the tenant chart's Role
  is namespace-scoped with **enumerated verbs, never `"*"`** so a new API verb does
  not silently widen the grant (role.yaml:14-20). Kyverno admission (boundaries 3-4)
  applies fleet-wide across tenant namespaces.
- **Residual** — namespace + RBAC scoping is soft isolation on shared nodes; it is
  **not** a NetworkPolicy or node-level boundary. Per-tenant IAM isolation (IRSA /
  Pod Identity, one role per tenant) is minted by **landing-zone**, not this repo —
  a cross-repo dependency a fork must keep intact.

## 8. Denial of service / availability  (`catalog/druid/`)

- **Denial of service** — a node drain or rolling upgrade taking a stateful role
  fully offline. Mitigated: one PodDisruptionBudget per long-running druid role
  (poddisruptionbudget.yaml:9-11) and soft topology spread across zones
  (_helpers.tpl:481-492). ApplicationSet retry/backoff (druid-tenants.yaml:65-70)
  absorbs transient sync failures, and the resource-limits ClusterPolicy
  (boundary 4) caps noisy-neighbor consumption.
- **Residual** — HA is per-role and single-cluster: PDBs self-gate on `replicas>1`,
  topology spread is `ScheduleAnyway` (advisory, not hard), and there is no
  cross-region or cross-cluster failover in the catalog. Regional resilience is a
  substrate/landing-zone concern.

## What this model excludes

- **The running cluster and its substrate** — EKS control plane, node security,
  Terraform state, org guardrails: owned by the
  [landing-zone threat model](../../landing-zone/docs/threat-model.md).
- **Per-tenant IAM** — IRSA/Pod Identity role minting and the agent-iam boundary
  are provisioned by landing-zone; this catalog only *consumes* the role ARNs.
- **Agent-platform enforcement logic** — the budget reconciler, kill-switch
  suspension, and admission webhook live in the eks-agent-platform operator repo;
  this catalog declares the CRs and the alerts, not the controller that acts on them.
- **Runtime Cosign cryptography** — Kyverno + Fulcio/Rekor verify signatures at
  admission in-cluster; CI only checks the signing-**identity** contract
  structurally (it cannot reach Rekor offline).
- **Application-layer threats inside tenant workloads** (druid, agent code).
