# Threat Model

STRIDE analysis of the eks-gitops **catalog**, organized by trust boundary. This
repo is not a running system — it is the GitOps source of truth (Helm values,
kustomize overlays, ArgoCD ApplicationSets, Kyverno policies) that a customer
**forks** and points a hub cluster at. Every mitigation below is a control that
lives **in this repo**, cited to the component that implements it, with the
residual risk a fork should weigh.

The substrate this catalog deploys onto — the EKS control plane, node security,
Terraform state, per-tenant IAM — is modeled separately in the
[landing-zone threat model](https://github.com/nanohype/landing-zone/blob/main/docs/threat-model.md). Where this
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
  Secret (e.g. addons-observability.yaml and siblings), and `check-hardcoded-org.py:89` matches
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
  overlay (ci.yml:335-370), `kubeconform -strict` with **no** `-ignore-missing-schemas`
  (ci.yml:416-419), and `trivy config` hard-failing on **MEDIUM+** against the
  *rendered* output (ci.yml:433-438). The workflow itself is least-privilege
  (`permissions: contents: read`, ci.yml:9-10).
- **Denial of service / drift** — ApplicationSet `syncPolicy` runs `selfHeal` +
  `prune` with a bounded retry/backoff (every default ApplicationSet's
  syncPolicy, e.g. addons-observability.yaml), so manual drift is reverted and a
  transient sync failure retries rather than wedging.
- **Residual** — CI proves manifests *render, schema-validate, and scan clean*; it
  does not prove they are *correct policy*. Branch protection + human PR review is
  the control that a malicious-but-valid change must pass, and that lives in GitHub
  settings, not this repo. CI has no cluster, so first-party CRDs
  (Platform/Tenant/ModelGateway/BudgetPolicy, Grafana) are schema-skipped
  (the skip list in scripts/kubeconform-scan.sh) and validated only against the
  real webhook out-of-band.

## 3. Image supply chain  (`policies/kyverno/supply-chain/`, `scripts/check-image-verification.py`, `scripts/check-digest-rewrite.sh`)

- **Spoofing / Tampering of a workload image** — a hand-pushed, branch-built or
  altered `ghcr.io/nanohype/*` image. Mitigated: `verify-images` is an
  ImageValidatingPolicy (`policies.kyverno.io/v1`) scoped to `ghcr.io/nanohype/*`
  that requires (`required: true`) both a keyless Cosign signature and an SPDX SBOM
  attestation (in-toto type `https://spdx.dev/Document`), each from the GitHub
  Actions OIDC issuer with an anchored, org-scoped `subjectRegExp` bound to a
  `release.ya?ml` workflow on `refs/tags/`, and checked against the Rekor
  transparency log. Kyverno verifies a Sigstore bundle referrer (cosign v3) when
  the image carries one and reads the legacy `.sig`/`.att` tags only when it
  carries none. Base is `validationActions: [Audit]`; the **staging and
  production overlays patch it to `[Deny]`**, blocking a failed verification at
  admission. It matches Pods, and the `pods/ephemeralcontainers` subresource
  through which `kubectl debug` adds a container, and it generates no rule for
  pod controllers (`autogen.podControllers.controllers: []`), so a Deployment
  whose template names a failing image is admitted and its pods are refused.
- **Repudiation of a weakened policy** — `kyverno test` verifies real signatures
  (policies/kyverno/tests/kyverno-test.yaml), so it proves the release identity
  admits a release-signed image and refuses a branch-signed one, but an identity
  weakened in a way both fixtures still satisfy passes it. The structural gate
  `check-image-verification.py` closes that hole on the base and on each
  supply-chain overlay as kustomize renders it, since a cluster installs the
  overlay: it fails the build if `required`, `mutateDigest` or `verifyDigest`
  flips, the issuer changes, the subjectRegExp is anything but the one release
  identity the gate holds (`SUBJECT_REGEXP`, which its unit tests check against
  accepted and refused certificate subjects), an attestor brings a root bundle,
  log key or transparency log of its own or switches the log off, the SPDX
  attestation stops being required, either validation differs from the
  expression the gate holds, compared whole, the scope narrows from
  `ghcr.io/nanohype/*`, admission-time evaluation is switched off, an image
  extractor shadows a container field, the ephemeral-container subresource
  stops being matched, a rule is generated for pod controllers, the namespace
  exclusion grows past the system namespaces, or a tier's `validationActions`
  departs from its environment's (`[Audit]` in development, `[Deny]` in staging
  and production) — run in CI (job `kyverno`).
- **Pinning** — `mutateDigest: true` in the base: admission resolves each matched
  tag to the digest it verified and rewrites the pod spec to it, at every tier,
  because an ImageValidatingPolicy pins under Audit as well as Deny.
  `verifyDigest: true` then refuses any matched image that reaches validation
  without a digest, so a pin that did not happen is a verification failure rather
  than a tag the kubelet resolves again at pull. `check-policy-validity.py` asserts
  both fields on every rendered overlay.

  That pinning is EXECUTED under real admission: `scripts/check-digest-rewrite.sh`
  (CI job `digest-rewrite`) brings up kind, installs the pinned Kyverno chart with
  this catalog's values, applies each rendered supply-chain overlay, and requires a
  tag-only signed pod to come back pinned to `@sha256` in its init, main and
  ephemeral containers, a Deployment of the same tag to be stored with its
  template as written while the pod its ReplicaSet creates comes back pinned,
  and a branch-signed pod and ephemeral container to be denied wherever the
  overlay says Deny. The Kyverno CLI cannot establish this: it runs the
  validating path only, never the mutating webhook that writes the pin. The
  template is left alone because ArgoCD compares it with git: a pin written there
  is drift on every sync, which selfHeal and admission would rewrite in turn.

- **Residual** — third-party images (anything outside `ghcr.io/nanohype/*`) are
  unmatched and pass unsigned — their trust is the upstream registry's, not this
  policy's. The four system namespaces (`kube-system`, `kube-public`,
  `kube-node-lease`, `kyverno`) are excluded, so a nanohype image placed there is
  not verified.

  A gate exercises a signing format only through a fixture signed in it. The
  release and branch-signed fixtures under `policies/kyverno/tests/` carry
  cosign's legacy `.sig`/`.att` format (`cosign tree <image>` lists the tags and
  any bundle referrer), so both gates above decide on Kyverno's legacy path, and
  bundle verification rests on Kyverno's implementation with no fixture here
  behind it. A release signed in the bundle format, pinned beside the legacy
  fixtures, is what puts that path under the same gates.

## 4. Admission / pod security  (`policies/kyverno/{best-practices,pod-security-standards}/`)

- **Elevation of privilege** — a root or unconstrained pod. Mitigated by Kyverno
  ClusterPolicies: `runAsNonRoot: true` (require-non-root.yaml), CPU + memory
  limits (require-resource-limits.yaml), required probes and
  limits (require-resource-limits.yaml:52-57,90-95), required probes and the
  the five-label org tier — `app.kubernetes.io/name`, `managed-by`, `component`,
  `platform.nanohype.dev/environment`, `platform.nanohype.dev/team`
  (require-probes.yaml, require-labels.yaml:88-92).
  Base is `Audit`; each group's **production overlay patches every ClusterPolicy to
  `Enforce`** — both `best-practices/overlays/production/kustomization.yaml:8-14`
  (require-labels, require-probes) and
  `pod-security-standards/overlays/production/kustomization.yaml:8-14`
  (require-non-root, require-resource-limits).
  `kyverno test` proves each rule passes a compliant and fails a violating resource
  (ci.yml:76-77), and `trivy config` MEDIUM+ backstops the rendered manifests. The
  **policy-admission** gate (`ci.yml` job `policy-admission`,
  `scripts/check-policy-admission.py`) renders the whole addon fleet into its
  real destination namespaces and runs `kyverno apply` against the Enforce overlay,
  so an addon landing in a namespace the policies neither exclude nor let it satisfy
  fails at PR time instead of being denied at admission on a vended Enforce cluster;
  it also asserts all four exclusion lists stay identical, that every namespace the
  fleet lands a workload in is on that list, and — via a deliberately non-compliant
  canary every rule must deny — that the run evaluated anything at all.
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
  pasted into a values file does not merge. gitleaks is pattern- and
  entropy-based, so a novel secret format it has no rule for can still slip; a
  fork handling real secrets should pair it with GitHub push-protection and
  narrow its allowlist to the repo's known example values.

## 6. Agent platform governance  (`addons/ai-platform/`, `dashboards/base/alerting/agent-platform.yaml`)

- **Elevation of privilege (an over-privileged LLM)** — there is no bundled agent
  runtime to over-privilege. Agents are Deployments running the tenant's own image
  under the tenant ServiceAccount, so an agent holds exactly the tenant's grants and
  nothing more, and its actions appear in the audit log under the tenant's identity.
  The catalog ships no cluster-admin-bound tools ServiceAccount and no admin-token
  MCP that a values flag could switch back on. That is the point of omitting a
  bundled runtime rather than shipping one with its dangerous options defaulted
  off: a surface that does not exist needs no refusal, and a refusal is only safe
  for as long as everyone keeps making it correctly.
  Model access is an explicit `allowedModels` allowlist, not a family
  wildcard (platform.yaml:35-37), and operator sessions cap at 1h (:41).
- **Denial of service (runaway spend)** — a two-tier budget with
  `killSwitchEnabled: true` and `alertThresholdsPercent: [50,80,100]`
  (platform.yaml:50-52). Grafana **paging** alerts fire the instant the kill-switch
  stamps (agent-platform.yaml:49-70), when a budget crosses its cap (:108,165), and
  when evals regress or go stale (:224,284), each linking the recovery runbook
  (docs/runbooks/ai-platform-budget-killswitch.md).
- **Residual** — this repo only **declares** the `BudgetPolicy` / `Platform` /
  `ModelGateway` CRs and the alert rules. The *enforcement* — measuring spend,
  suspending a Platform, revoking IRSA — is the eks-agent-platform operator (a
  separate repo). The alert PromQL is untestable in CI (KSM CRDs are schema-skipped)
  and correct only if each selector matches the series KSM emits.

## 7. Multi-tenancy  (`catalog/druid/chart/templates/role.yaml`)

- **Elevation of privilege / cross-tenant reach** — one tenant reaching another's
  workloads. Mitigated: each tenant deploy is expected to land in its own
  `druid-<name>` namespace, and the tenant chart's Role is namespace-scoped with
  **enumerated verbs, never `"*"`** so a new API verb does not silently widen the
  grant (role.yaml:14-20). Kyverno admission (boundaries 3-4) applies fleet-wide
  across tenant namespaces.
- **Residual** — namespace + RBAC scoping is soft isolation on shared nodes; it is
  **not** a NetworkPolicy or node-level boundary. Per-tenant IAM isolation
  (Pod Identity, one role per tenant) is minted by **landing-zone**, not this repo —
  a cross-repo dependency a fork must keep intact.

## 8. Denial of service / availability  (`catalog/druid/`)

- **Denial of service** — a node drain or rolling upgrade taking a stateful role
  fully offline. Mitigated: one PodDisruptionBudget per long-running druid role
  (poddisruptionbudget.yaml:9-11) and soft topology spread across zones
  (_helpers.tpl:481-492). The resource-limits ClusterPolicy (boundary 4) caps
  noisy-neighbor consumption.
- **Residual** — HA is per-role and single-cluster: PDBs self-gate on `replicas>1`,
  topology spread is `ScheduleAnyway` (advisory, not hard), and there is no
  cross-region or cross-cluster failover in the catalog. Regional resilience is a
  substrate/landing-zone concern.

## What this model excludes

- **The running cluster and its substrate** — EKS control plane, node security,
  Terraform state, org guardrails: owned by the
  [landing-zone threat model](https://github.com/nanohype/landing-zone/blob/main/docs/threat-model.md).
- **Per-tenant IAM** — IRSA/Pod Identity role minting and the agent-iam boundary
  are provisioned by landing-zone; this catalog only *consumes* the role ARNs.
- **Agent-platform enforcement logic** — the budget reconciler, kill-switch
  suspension, and admission webhook live in the eks-agent-platform operator repo;
  this catalog declares the CRs and the alerts, not the controller that acts on them.
- **Sigstore infrastructure** — Fulcio, Rekor and the GitHub OIDC issuer are
  trusted as published; CI exercises verification against them over the network
  (jobs `kyverno` and `digest-rewrite`) but does not model their compromise.
- **Application-layer threats inside tenant workloads** (druid, agent code).
