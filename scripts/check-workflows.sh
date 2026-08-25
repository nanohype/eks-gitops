#!/usr/bin/env bash
# Static analysis of the GitHub Actions workflows, offline.
#
# This repo ships no package manifest. Every third-party thing it executes is an
# action or a downloaded release binary named in .github/workflows/, so the
# workflows ARE its dependency surface — the place a supply-chain check belongs
# is here rather than alongside a lockfile that does not exist.
#
# --offline is what makes the verdict a function of the commit under test. With
# network access zizmor resolves action metadata upstream, so the same tree can
# pass today and fail tomorrow for a reason no commit introduced, and a security
# gate whose result depends on when it ran cannot be reasoned about.
#
# MEDIUM is the threshold, matching the `trivy config` gate over rendered output
# so one severity floor governs both scanners. Informational findings are
# reported and do not block: the ones this tree carries are template expansions
# of `needs.<job>.result`, whose value is one of four literals GitHub writes.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOWS="${1:-$ROOT/.github/workflows}"

if ! command -v zizmor >/dev/null 2>&1; then
  echo "zizmor is not on PATH. Install it with:"
  echo "  pip install --require-hashes -r requirements.txt"
  echo "requirements.txt is the single pinned source; CI installs the same file."
  exit 2
fi

# Assert the corpus. A path that matches no workflow exits clean, exactly as a
# tree with nothing wrong does, so the count is checked rather than inferred
# from a quiet run.
count=$(find "$WORKFLOWS" -maxdepth 1 -name '*.yml' -o -maxdepth 1 -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')
if [ "$count" -lt 1 ]; then
  echo "Found no workflow files under $WORKFLOWS — nothing was scanned, and a pass"
  echo "here would report the same thing as a clean tree."
  exit 2
fi

echo "Scanning $count workflow file(s) with $(zizmor --version)"
zizmor --offline --min-severity medium --format plain "$WORKFLOWS"
status=$?

if [ "$status" -ne 0 ]; then
  echo
  echo "  A workflow finding at MEDIUM or above blocks. The common ones and their"
  echo "  fixes: artipacked -> set 'persist-credentials: false' on the checkout;"
  echo "  template-injection -> pass the expansion through 'env:' instead of"
  echo "  interpolating it into a script body."
  exit 1
fi

echo "✓ $count workflow file(s) clean at MEDIUM and above"
