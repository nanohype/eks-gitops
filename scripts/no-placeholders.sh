#!/usr/bin/env bash
# Zero-placeholder gate — fail if an unfilled "fill-me" sentinel appears in
# applied deploy configuration (Helm values, kustomize, ArgoCD manifests,
# terragrunt/tofu inputs). Every per-environment value must render from its
# source of truth, never sit in the repo as a placeholder waiting to be
# hand-edited before deploy.
#
# NOT sentinels (intentional public-repo conventions, deliberately unmatched):
#   - example.com domains
#   - the 111111111111 / 222222222222 fake AWS account ids
#   - Azure subscription/tenant GUID placeholders (xxxxxxxx-…)
# Excluded by path: docs (prose, not applied config — *.md isn't scanned),
# examples, test fixtures, and vendored copies.
set -uo pipefail

# "changeit" is the JVM keystore default password — a well-known credential,
# gated here like any other fill-me sentinel.
# Floor on the corpus size, well below the real count so ordinary additions and
# deletions never trip it. It exists to catch the glob matching nothing at all.
MIN_FILES=100

SENTINELS='PLACEHOLDER|REPLACE_ME|REPLACEME|CHANGEME|CHANGE_ME|changeit|FILL_ME|FILLME|TODO_FILL|TO_BE_FILLED|<FILL|<YOUR_|<ACCOUNT_ID>|<FLEET_ACCOUNT'

# grep's exit codes are three-valued: 0 found, 1 none found, >=2 the search
# itself failed. Discarding stderr and reading only the captured text collapses
# the third case into the second, so a pattern grep cannot compile reports as a
# clean tree. Keep the diagnostic and branch on the status.
err=$(mktemp)
hits=$(grep -rnE "$SENTINELS" . \
  --include='*.yaml' --include='*.yml' --include='*.tf' --include='*.hcl' \
  --include='*.tfvars' --include='*.json' \
  --exclude='*.example' \
  --exclude-dir='.git' --exclude-dir='.terraform' --exclude-dir='.terragrunt-cache' \
  --exclude-dir='node_modules' --exclude-dir='examples' --exclude-dir='testdata' \
  --exclude-dir='test' --exclude-dir='vendor' \
  2>"$err")
status=$?
diag=$(cat "$err"); rm -f "$err"

if [ "$status" -ge 2 ]; then
  echo "Placeholder scan did not run (grep exited $status):"
  echo "$diag"
  echo
  echo "A search that could not run is not a clean tree. Fix the pattern or the"
  echo "path arguments in scripts/no-placeholders.sh and re-run."
  exit 2
fi

if [ -n "$hits" ]; then
  echo "Unfilled placeholder sentinel(s) found in deploy config:"
  echo "$hits"
  echo
  echo "Deploy config must render from its source of truth, not carry a fill-me"
  echo "placeholder. If a path is a legitimate opt-in template, add it to the"
  echo "exclude list in scripts/no-placeholders.sh."
  exit 1
fi

# The scan is only evidence if it read something. A path or include-glob that
# matches no file exits 1 exactly as a clean tree does, so assert the corpus
# rather than inferring it from silence.
scanned=$(grep -rlE '.' . \
  --include='*.yaml' --include='*.yml' --include='*.tf' --include='*.hcl' \
  --include='*.tfvars' --include='*.json' \
  --exclude='*.example' \
  --exclude-dir='.git' --exclude-dir='.terraform' --exclude-dir='.terragrunt-cache' \
  --exclude-dir='node_modules' --exclude-dir='examples' --exclude-dir='testdata' \
  --exclude-dir='test' --exclude-dir='vendor' 2>/dev/null | wc -l | tr -d ' ')

if [ "$scanned" -lt "$MIN_FILES" ]; then
  echo "Placeholder scan covered $scanned file(s), fewer than the $MIN_FILES this"
  echo "repo is known to carry. The include globs or exclude list no longer match"
  echo "the tree, so a pass here would prove nothing."
  exit 2
fi

echo "✓ no placeholder sentinels across $scanned deploy-config file(s)"
