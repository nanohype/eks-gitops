#!/usr/bin/env bash
#
# Deploy-time placeholder audit.
#
# Some values in this catalog reference identifiers that only exist once the
# cloud substrate is provisioned: IAM role ARNs (written against the stand-in
# account 000000000000) and Amazon Managed Prometheus / Grafana workspace ids
# (ws-PLACEHOLDER, g-PLACEHOLDER). Helm and Kustomize render these literals
# without complaint, so a forgotten substitution passes every build and only
# fails once a pod starts in a real cluster — the most expensive place to learn
# a value was never wired.
#
# This audit pins the known placeholders in .placeholder-baseline and fails on
# any drift:
#   - a NEW placeholder that is not in the baseline (substitute it at deploy
#     time or source it from the substrate; do not commit the literal), or
#   - a baseline entry whose placeholder is GONE (delete the stale line so the
#     baseline keeps telling the truth).
# As the catalog moves identifiers onto EKS Pod Identity and provisioner-sourced
# values, the baseline shrinks; when it is empty no placeholder may appear
# anywhere.
#
# Usage:
#   scripts/check-placeholders.sh            audit the tree; exit 1 on drift
#   scripts/check-placeholders.sh --update   rewrite .placeholder-baseline from the tree

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

baseline=".placeholder-baseline"

# Emit "<path><TAB><kind>" for every tracked YAML carrying a placeholder. The
# record is keyed on the file and the kind of placeholder, never a line number,
# so unrelated edits never churn the baseline.
scan() {
  git ls-files -z -- '*.yaml' '*.yml' | while IFS= read -r -d '' f; do
    grep -qE 'arn:aws:iam::000000000000:role/' "$f"   && printf '%s\t%s\n' "$f" 'irsa-role-arn'
    grep -qE 'ws-PLACEHOLDER|workspaces/PLACEHOLDER' "$f" && printf '%s\t%s\n' "$f" 'amp-workspace-id'
    grep -qE 'g-PLACEHOLDER' "$f"                      && printf '%s\t%s\n' "$f" 'amg-workspace-id'
    true
  done | sort -u
}

current="$(scan)"

if [[ "${1:-}" == "--update" ]]; then
  {
    echo "# Known deploy-time placeholders, acknowledged by scripts/check-placeholders.sh."
    echo "# Each line is '<path><TAB><kind>'. Remove a line when its placeholder is"
    echo "# substituted by a real, provisioner-sourced value. See the script header."
    printf '%s\n' "$current"
  } > "$baseline"
  echo "Wrote $(printf '%s\n' "$current" | grep -c . ) acknowledged placeholders to $baseline"
  exit 0
fi

acknowledged="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$baseline" 2>/dev/null | sort -u || true)"

introduced="$(comm -23 <(printf '%s\n' "$current") <(printf '%s\n' "$acknowledged") | grep -c . || true)"
stale="$(comm -13 <(printf '%s\n' "$current") <(printf '%s\n' "$acknowledged") | grep -c . || true)"

if [[ "$introduced" -eq 0 && "$stale" -eq 0 ]]; then
  remaining="$(printf '%s\n' "$acknowledged" | grep -c . || true)"
  echo "Placeholder audit clean — $remaining acknowledged, 0 introduced, 0 stale."
  exit 0
fi

if [[ "$introduced" -gt 0 ]]; then
  echo "New deploy-time placeholders that are not in $baseline:"
  comm -23 <(printf '%s\n' "$current") <(printf '%s\n' "$acknowledged") | sed 's/^/  + /'
  echo "  -> substitute these at deploy time (e.g. EKS Pod Identity, a provisioner output);"
  echo "     do not commit the literal. If a stand-in is unavoidable, add it to $baseline."
fi
if [[ "$stale" -gt 0 ]]; then
  echo "Stale $baseline entries whose placeholder is gone:"
  comm -13 <(printf '%s\n' "$current") <(printf '%s\n' "$acknowledged") | sed 's/^/  - /'
  echo "  -> delete these lines from $baseline."
fi
exit 1
