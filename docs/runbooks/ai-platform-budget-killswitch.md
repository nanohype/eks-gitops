# AI Platform — Budget, Kill-Switch, and Model Access

Operational runbook for the AI platform's cost controls and model-access
guardrails. The behavior here is enforced by the `eks-agent-platform` operator;
this doc describes what the operator actually does so on-call can read a status,
predict what will happen, and recover a suspended platform.

The manifests live in `addons/ai-platform/agent-platform/base/platform.yaml`
(the `Tenant`, `Platform`, `BudgetPolicy`, and `ModelGateway` CRs).

## The two-tier budget

Cost is bounded at two levels:

| CR | Field | Scope |
|----|-------|-------|
| `Tenant` (`platform.nanohype.dev`) | `spec.aggregateMonthlyBudgetUsd` | ceiling across every Platform the tenant owns |
| `BudgetPolicy` (`governance.nanohype.dev`) | `spec.monthlyUsd` | per-Platform cap, referenced by `spec.platformRef` |

A `BudgetPolicy` also carries `killSwitchEnabled` and
`alertThresholdsPercent` (e.g. `[50, 80, 100]`).

## How spend is measured

The budget reconciler computes month-to-date spend as the **sum of two
sources**:

1. **CUR-tagged spend** (Athena, month-to-date) — the authoritative billed
   number, partitioned and therefore lagging.
2. **In-flight invocation cost** (CloudWatch, trailing 24h) — covers the CUR
   partition lag so a spike in the last day still counts.

`percentOfBudget = (curSpend + inflightSpend) / monthlyUsd`.

Two degradation paths are deliberate and non-fatal:

- **Dev/test** (no cost-pipeline outputs in SSM) → Athena is "not configured",
  CUR falls back to `0`, and only the CloudWatch in-flight number is used.
- **CloudWatch outage** → the in-flight portion zeroes out; the (stale) Athena
  CUR value is still used rather than blocking the whole reconcile.

The current reading is written to `BudgetPolicy.status`:
`currentSpendUsd`, `percentOfBudget`, `lastReconciled`, and a
`BudgetReconciled` condition.

## Alerts vs. the kill-switch — different thresholds

**These are not the same number.** Alerts fire at the configured
`alertThresholdsPercent`; the kill-switch fires much later, at a hard **120%**.

| Event | Trigger | Effect |
|-------|---------|--------|
| Alert | crossing a value in `alertThresholdsPercent` **upward** (e.g. 50→80) | `BudgetReconciled` condition reason `ThresholdCrossed`, message names the threshold. Advisory — nothing is suspended. |
| Kill-switch | `percentOfBudget >= 120` **and** `killSwitchEnabled` **and** not already fired | fires once; suspends the platform (below) |

The alert only fires on an upward crossing relative to the last recorded
`status.percentOfBudget`, so a steady-state reconcile at 85% does not re-alert
every tick.

## What the kill-switch actually does

When the threshold is met the operator publishes **one** EventBridge event and
records that it fired:

- Event bus: the operator's configured kill-switch bus
  (`KillSwitchEventBusName`; empty ⇒ **log-only mode**, see below).
- Event: `source = governance.nanohype.dev/budget`, `detail-type = BudgetBreach`,
  detail carries `platformId`, `namespace`, `budgetPolicy`, `monthlyUsd`,
  `currentSpendUsd`, `percentOfBudget`, `severity: critical`.
- `BudgetPolicy.status.killSwitchFiredAt` is stamped and the
  `BudgetReconciled` condition flips to `False` / reason `KillSwitchFired`.

The terraform-managed bus has a rule targeting a **suspension Step Functions
state machine**, which:

1. flips `Platform.status.phase` → `Suspended`,
2. revokes the platform's IRSA permissions, and
3. scales its AgentFleets to zero.

Mechanically, suspension is driven by a **`suspended` tag on the tenant IAM
role**: while that tag is present the operator skips reattaching the role's
baseline managed policy, so the role keeps its identity but loses its grants.
The Platform then reports:

- `status.phase: Suspended`, `status.suspendedAt`, `status.suspendedReason`
- condition `Suspended = True`, reason `KillSwitchActive`
- new AgentSandbox sessions are torn down (reason `PlatformSuspended`)

**Log-only mode:** if no kill-switch bus is configured, the operator does *not*
suspend anything — it only records the `KillSwitchFired` status condition. Ops
alerting fires from the condition. Use this in environments without the
governance EventBridge/SFN wiring.

## Recovery — un-suspending a platform

The kill-switch fires **once** (`killSwitchFiredAt == nil` guard), so recovery
is a deliberate, auditable action, not an automatic reset:

1. **Deal with the spend.** Either the month rolls over (spend resets) or raise
   `BudgetPolicy.spec.monthlyUsd` (and the `Tenant.spec.aggregateMonthlyBudgetUsd`
   if that ceiling is also hit). Confirm the new headroom against
   `status.currentSpendUsd`.
2. **Remove the `suspended` tag** from the tenant IAM role. On the next Platform
   reconcile the operator sees `Suspended: false`, sets `phase: Ready`, clears
   `suspendedAt`/`suspendedReason`, and reattaches the baseline policy. IRSA
   grants and AgentFleet scaling come back with it.
3. **Re-arm the kill-switch:** clear `BudgetPolicy.status.killSwitchFiredAt`
   (e.g. `kubectl patch --subresource=status`). Until this is cleared the
   switch will not fire again even if spend climbs.

Verify recovery: `Platform.status.phase == Ready`, `Suspended` condition gone,
and a fresh AgentSandbox session schedules.

## Model access — allowlist and routing

Two independent controls bound which models an agent can reach. **Neither is
optional guardrail decoration — an agent cannot invoke a model absent from
both.**

- **`Platform.spec.identity`** is the IAM allowlist and the tighter of the two
  controls. Set *either* `allowedModels` (explicit model IDs — preferred) *or*
  `allowedModelFamilies` (a whole family); the admission webhook enforces they
  are mutually exclusive. Prefer `allowedModels`: a family allowlist admits
  every future model in that family automatically. This renders a
  bedrock-model-scoping IAM policy; when scoped, the Platform reports
  `ModelAccessScoped = True`.

- **`ModelGateway.spec.routes`** (`agents.nanohype.dev`) maps a logical route
  name (`reason`, `cheap`, …) to a `modelId` and a `rateLimit` (requests/min).
  Routes are how callers select a model by intent; the allowlist is what makes
  a route *permitted*.

**To add a model** you must touch **both**: add the `modelId` to
`Platform.spec.identity.allowedModels`, then add a `ModelGateway` route for it.
Adding only a route leaves the model IAM-denied; adding only the allowlist entry
leaves callers with no route to select it.

## Quick status reference

```bash
# Budget state for a platform
kubectl get budgetpolicy <name> -o jsonpath='{.status}'
#   currentSpendUsd, percentOfBudget, killSwitchFiredAt, conditions

# Is a platform suspended, and why?
kubectl get platform <name> -o jsonpath='{.status.phase} {.status.suspendedReason}'

# Model access scoping + suspension conditions
kubectl get platform <name> -o jsonpath='{range .status.conditions[*]}{.type}={.reason} {end}'
```
