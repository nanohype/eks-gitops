#!/usr/bin/env bash
# Unified kubeconform gate — the SINGLE source of truth for the strict schema
# scan and its skip list, shared by `task scan` (local) and CI so a clean tree
# never passes one and fails the other. Native kinds resolve from the default
# kubernetes-json-schema location; CRD kinds resolve from the datreeio
# CRDs-catalog. There is deliberately no -ignore-missing-schemas: a kind neither
# source knows fails the build until it gets a schema or an explicit skip below.
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
#     mutually exclusive, which no schema encodes). CI has no cluster, so this
#     skip records the gap rather than pretending the schema resolved.
DEFAULT_SKIP="Grafana,Platform,Tenant,ModelGateway,BudgetPolicy,AgentFleet,EvalSuite"
SKIP="${KUBECONFORM_SKIP-$DEFAULT_SKIP}"

DATREE='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

args=(-strict -summary -schema-location default -schema-location "$DATREE")
[ -n "${KUBECONFORM_CACHE:-}" ] && args+=(-cache "$KUBECONFORM_CACHE")
[ -n "$SKIP" ] && args+=(-skip "$SKIP")

exec kubeconform "${args[@]}" "$@"
