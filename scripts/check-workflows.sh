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
# so one severity floor governs both scanners. Low and informational findings
# are reported and do not block: the ones this tree carries are template
# expansions of `needs.<job>.result` (a value GitHub writes from four literals),
# concurrency limits, and one undocumented-permissions note.
#
# --persona=auditor is load-bearing and is a DIFFERENT AXIS from severity. Under
# the default persona the excessive-permissions audit DOES NOT RUN AT ALL, so a
# workflow-level `id-token: write` — which lets any job added later mint an OIDC
# token and assume a deploy role, with no diff that looks like a permission
# change — passes silently. Demonstrated: a planted workflow-level id-token
# grant exits 0 under the default persona and 14 under auditor.
#
# This tree carries no id-token grant and all three workflows are
# `contents: read`, so the setting changes no verdict today. It changes which
# question is being asked.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOWS="${1:-$ROOT/.github/workflows}"

# The gate asserts its own precondition rather than assuming it. zizmor's audit
# set changes between releases — 1.29.0 runs an `unpinned-tools` audit 1.16.3
# does not — so the same tree gets different verdicts from different versions.
# A gate that accepts whatever is on PATH reports on an unknown rule set, and a
# green run then means "some version found nothing".
WANT_ZIZMOR="$(sed -n 's/^zizmor==\([0-9][^ \\]*\).*/\1/p' "$ROOT/requirements.txt" | head -1)"

# An unresolvable pin FAILS rather than skipping the version check. Guarding the
# comparison with `[ -n "$WANT_ZIZMOR" ]` made an unreadable requirements.txt
# silently delete the check: a wrong zizmor then passed, because the authority
# the gate compares against had gone missing and the gate carried on without it.
# Absence of an authority is a refusal, never a permissive default.
if [ -z "$WANT_ZIZMOR" ]; then
  echo "Cannot run: no zizmor==<version> pin found in $ROOT/requirements.txt."
  echo "That pin is the authority this gate compares PATH against; without it the"
  echo "version check would silently not happen and any zizmor would pass."
  exit 2
fi

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

have_zizmor="$(zizmor --version 2>/dev/null | awk '{print $NF}')"
if [ "$have_zizmor" != "$WANT_ZIZMOR" ]; then
  echo "zizmor on PATH is $have_zizmor but requirements.txt pins $WANT_ZIZMOR."
  echo "Different releases run different audits, so this run would report on a"
  echo "rule set the lockfile does not describe. Install the pinned version:"
  echo "  pip install --require-hashes -r requirements.txt"
  exit 2
fi

echo "Scanning $count workflow file(s) with zizmor $have_zizmor (pinned)"
zizmor --offline --persona=auditor --min-severity=medium --format plain "$WORKFLOWS"
status=$?

# A bare non-zero conflates two different facts. zizmor exits 14 when it audited
# the workflows and found something, and 3 when the run itself failed — no
# inputs collected, a file it could not parse. Printing the finding remedy for
# the second case tells an operator to fix a `persist-credentials` line in a
# file that never parsed, which costs them a search that cannot succeed.
if [ "$status" -eq 14 ]; then
  echo
  echo "  A workflow finding at MEDIUM or above blocks. The common ones and their"
  echo "  fixes: artipacked -> set 'persist-credentials: false' on the checkout;"
  echo "  template-injection -> pass the expansion through 'env:' instead of"
  echo "  interpolating it into a script body."
  exit 1
fi

if [ "$status" -ne 0 ]; then
  echo
  echo "  zizmor exited $status without completing an audit, so the workflows were"
  echo "  NOT checked — this is not a clean result. Its own output above says what"
  echo "  went wrong; the usual cause is a workflow file that does not parse."
  exit 2
fi

# Report the tier just BELOW the threshold on the passing line. A gate that
# prints only "clean at MEDIUM and above" lets `ok` read as nothing-found, when
# what it means is nothing-found-at-the-tier-we-block-on. The count is what
# stops that reading.
#
# zizmor exits non-zero whenever it has findings at all, so its status here says
# nothing about severity and is deliberately not read — the summary line it
# prints is the operand.
audit_out=$(zizmor --offline --persona=auditor --format plain "$WORKFLOWS" 2>&1)
below=$(printf '%s\n' "$audit_out" | sed -n 's/^\([0-9][0-9]*\) findings.*/\1/p' | tail -1)
[ -n "$below" ] || below="an unknown number of"

echo "✓ $count workflow file(s) clean at MEDIUM and above"
echo "  $below low/informational finding(s) sit below the threshold — reported, not"
echo "  blocking. See them with:"
echo "    zizmor --offline --persona=auditor $WORKFLOWS"
