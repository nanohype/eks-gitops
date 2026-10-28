#!/usr/bin/env bash
# Unified kubeconform gate — the SINGLE source of truth for the strict schema
# scan and its skip list, shared by `task scan` (local) and CI so a clean tree
# never passes one and fails the other. Native kinds resolve from
# yannh/kubernetes-json-schema and CRD kinds from the datreeio CRDs-catalog, each
# read at the commit pinned below. There is deliberately no
# -ignore-missing-schemas: a kind neither source knows fails the build until it
# gets a schema or an explicit skip below.
#
# Usage: kubeconform-scan.sh <path> [<path> ...]
#   KUBECONFORM_SKIP  override the skip list (the appset scan passes "" — the
#                     ApplicationSet schema is in the datreeio catalog and needs
#                     no skip).
#   KUBECONFORM_CACHE if set, cache downloaded schemas there (CI sets it).
set -euo pipefail

# First-party / by-design-partial CRDs kubeconform cannot resolve, kept here in
# ONE place so local and CI agree:
#   Grafana — the external Grafana CR ships spec.external.url empty by design (the
#     dashboards ApplicationSet injects the per-cluster Amazon Managed Grafana URL
#     via its cluster generator); the catalog schema is stricter than upstream
#     (requires tenantNamespace, which upstream does not).
#   Platform,Tenant,ModelGateway,BudgetPolicy,AgentFleet,EvalSuite — the
#     platform's own CRDs (platform.nanohype.dev, agents.nanohype.dev,
#     governance.nanohype.dev). Their schemas live in eks-agent-platform and are
#     published to no public catalog, so neither schema-location resolves them.
#     They are validated against the real webhook with `kubectl apply
#     --dry-run=server` out-of-band — a strictly stronger gate than a JSON-schema
#     match (it caught identity.allowedModels / allowedModelFamilies being
#     mutually exclusive, which no schema encodes). CI has no cluster, so the
#     skip stands here and scripts/check-platform-crs.py (CI job platform-crs)
#     validates these kinds against the CRDs the pinned operator chart ships.
DEFAULT_SKIP="Grafana,Platform,Tenant,ModelGateway,BudgetPolicy,AgentFleet,EvalSuite"
SKIP="${KUBECONFORM_SKIP-$DEFAULT_SKIP}"

# Both schema catalogs are read at a pinned commit, never at a branch head. Each
# is a repository that moves on its own schedule, so read at a branch the verdict
# is a function of the day the scan ran: a schema that stops compiling upstream
# fails every environment with no change here, and the fix arrives the same way.
# Pinned, a catalog moves as a Renovate pull request that bumps the ref and runs
# this scan against it. Each `# renovate:` line is read by the git-refs
# customManager in renovate.json, which owns the ref on the line below it.
# renovate: datasource=git-refs depName=yannh/kubernetes-json-schema packageName=https://github.com/yannh/kubernetes-json-schema branch=master
K8S_SCHEMA_REF="89a35a5e9a1412a692a2603d79c3786f602238a4"
# renovate: datasource=git-refs depName=datreeio/CRDs-catalog packageName=https://github.com/datreeio/CRDs-catalog branch=main
CRD_CATALOG_REF="3eb90d47aba8d61919d4419dd38301536e32a94b"

# kubeconform's `default` schema location, with the branch replaced by the pin.
K8S_SCHEMAS="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/${K8S_SCHEMA_REF}/{{ .NormalizedKubernetesVersion }}-standalone{{ .StrictSuffix }}/{{ .ResourceKind }}{{ .KindSuffix }}.json"
CRD_SCHEMAS="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRD_CATALOG_REF}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

# kubeconform decides whether anything was validated at all, so its absence is
# a refusal and not a finding. Without this, `exec` fails with 127 and a raw
# shell message: non-zero, so CI does stop, but the status is the same shape a
# schema violation produces and the sentence names no tool to install.
if ! command -v kubeconform >/dev/null 2>&1; then
  echo "Cannot run: kubeconform is not on PATH. No manifest was validated —"
  echo "that is different from every manifest validating. Install it (CI pins"
  echo "the version in the env block at the top of .github/workflows/ci.yml)."
  exit 2
fi

args=(-strict -summary -schema-location "$K8S_SCHEMAS" -schema-location "$CRD_SCHEMAS")
[ -n "${KUBECONFORM_CACHE:-}" ] && args+=(-cache "$KUBECONFORM_CACHE")
[ -n "$SKIP" ] && args+=(-skip "$SKIP")

# kubeconform's output is captured so the summary can be read below, and it is
# printed before its status is acted on. Under `set -e` an assignment from a
# failing command substitution exits on the spot, so the status is collected with
# `||` instead: a rejected manifest has to reach the log with the line naming it,
# or the job fails with nothing to read. On failure the refs are printed too,
# because a schema that changed between catalog pins fails an unchanged manifest
# and the two read the same.
rc=0
out="$(kubeconform "${args[@]}" "$@" 2>&1)" || rc=$?
printf '%s\n' "$out"
if [ "$rc" -ne 0 ]; then
  echo "FAIL  kubeconform exited $rc. Schemas were read from"
  echo "      yannh/kubernetes-json-schema@${K8S_SCHEMA_REF} and"
  echo "      datreeio/CRDs-catalog@${CRD_CATALOG_REF}."
  exit "$rc"
fi

# A floor on what was VALIDATED. kubeconform exits 0 over an empty target and
# prints "0 resource found in 0 file", which is the same status a clean tree
# gets — so a renamed directory, a wrong argument or a rendered/ that was never
# written all report success. The summary is what says whether anything was read.

found="$(printf '%s' "$out" | sed -n 's/.*Summary: \([0-9][0-9]*\) resource.*/\1/p' | head -1)"
if [ -z "$found" ]; then
  echo "Cannot run: kubeconform printed no summary, so how many resources it read"
  echo "is unknown. A pass here would report the same thing as a clean tree."
  exit 2
fi
if [ "$found" -eq 0 ]; then
  echo "FAIL  kubeconform validated 0 resources under: $*"
  echo "      Nothing was schema-checked, which is not the same as everything being"
  echo "      valid. Check the path — a renamed directory or an unrendered target"
  echo "      reports exactly this."
  exit 2
fi
exit 0
