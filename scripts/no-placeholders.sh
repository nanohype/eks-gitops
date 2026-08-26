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

# A count is an operand, and an absent or failed producer yields an EMPTY one,
# not a zero. `[ "" -lt 100 ]` exits 2 with "integer expected", and an `if`
# reads exit 2 as false — so the floor is not failed, it is SKIPPED, and
# execution continues to the pass. The floor that exists to prove this gate
# examined something is removed by the same absence it exists to survive.
#
# Asserting the operand is a digit string is direction-independent: it does not
# depend on which way any particular comparison runs, so a later edit that flips
# a threshold cannot silently turn a safe default into the passing value.
require_count() {
  case "$2" in
    "" ) echo "Cannot run: $1 produced no count — its producer did not run. An"
         echo "undetermined count is not a count of zero, and a floor that cannot"
         echo "evaluate is a floor that did not run."
         exit 2 ;;
    *[!0-9]* ) echo "Cannot run: $1 produced a non-numeric count ($2)."
         exit 2 ;;
  esac
}


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
# SCOPE: the files this repository OWNS, from git ls-files — not a filesystem
# walk. CI checks sibling repositories and downloaded tools into the same
# workspace, and a walk grades those too. A sentinel found in a neighbour is a
# correct finding that stops the wrong seat: this one cannot fix it.
#
# The file list is built first and its own status checked, so a failure to
# enumerate is distinguishable from an empty tree.
files=$(mktemp); err=$(mktemp)
trap 'rm -f "$files" "$err"' EXIT

# git DEFINES the population this gate scans, which puts it above the tools a
# gate merely runs: with it absent the file list is empty and the empty-corpus
# floor below does stop the run — but it reports "nothing matched the scanned
# extensions", sending the reader to the extension list instead of to the tool
# nobody installed. Asserting it by name is what makes the sentence true.
if ! command -v git >/dev/null 2>&1; then
  echo "Cannot run: git is not on PATH. This gate scans the tracked set, so"
  echo "without git the population is unknown — which is not an empty one."
  exit 2
fi

# grep runs in BOTH halves of this gate: it filters the population below and it
# produces the verdict at the scan. The verdict half survives its absence on its
# own — that status is read directly and 127 is >= 2, the did-not-run branch. The
# enumeration half does not: an absent grep empties the file list, the
# empty-corpus floor fires, and its sentence blames the extension globs while the
# real cause is a tool nobody installed. Naming it here is what makes every
# message downstream true.
if ! command -v grep >/dev/null 2>&1; then
  echo "Cannot run: grep is not on PATH. It both selects the files this gate"
  echo "scans and produces the verdict, so nothing was searched — which is not"
  echo "the same as finding nothing."
  exit 2
fi

git ls-files -z 2>"$err" \
  | tr '\0' '\n' \
  | grep -E '\.(yaml|yml|tf|hcl|tfvars|json)$' \
  | grep -vE '\.example$|(^|/)(examples|testdata|test|vendor|node_modules)/' \
  > "$files"
enum=("${PIPESTATUS[@]}")

# The enumeration is a four-stage pipeline and its status was never read, so
# every way it can fail arrived at the emptiness test below as "no files" —
# indistinguishable from a tree that genuinely holds none. git's status is the
# one that matters: grep exiting 1 means the filters selected nothing, which the
# floor below already reports, but git failing means the population is unknown.
if [ "${enum[0]}" -ne 0 ]; then
  echo "Cannot run: git ls-files exited ${enum[0]} while enumerating the tracked set."
  printf '%s\n' "$(cat "$err")" | sed 's/^/    /'
  echo "The population could not be determined, which is not the same as it being empty."
  exit 2
fi

if [ ! -s "$files" ]; then
  echo "Placeholder scan enumerated no files to scan."
  echo "$(cat "$err")"
  echo
  echo "git ls-files returned nothing matching the scanned extensions. This is"
  echo "not a clean tree — it is a scan that never ran."
  exit 2
fi

scanned=$(wc -l < "$files" | tr -d ' ')
require_count "the scanned-file count" "$scanned"

# grep's exit codes are three-valued: 0 found, 1 none found, >=2 the search
# itself failed. Reading only the captured text collapses the third case into
# the second, so a pattern grep cannot compile would report a clean tree. The
# status is taken from grep directly, with no pipe between.
# Read into an array and pass the paths to grep directly. NOT `xargs`: its
# status is its own, not grep's, so the three-valued reading above would be
# lost — and `xargs -a` is a GNU extension that BSD xargs rejects outright,
# which made this gate scan zero files and report a clean tree on a macOS seat
# while working in CI. A plain indexed array is bash 3.2 syntax; only
# ASSOCIATIVE arrays need bash 4.
scan_files=()
while IFS= read -r line; do
  [ -n "$line" ] && scan_files+=("$line")
done < "$files"

hits=$(grep -nE "$SENTINELS" "${scan_files[@]}" 2>"$err")
status=$?
diag=$(cat "$err")

if [ "$status" -ge 2 ]; then
  echo "Placeholder scan did not run (grep exited $status):"
  echo "$diag"
  echo
  echo "A search that could not run is not a clean tree. Fix the pattern in"
  echo "scripts/no-placeholders.sh and re-run."
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

# The scan is only evidence if it read something. A tracked set that stops
# matching the extensions exits exactly as a clean tree does, so the count is
# asserted rather than inferred from silence.
if [ "$scanned" -lt "$MIN_FILES" ]; then
  echo "Placeholder scan covered $scanned file(s), fewer than the $MIN_FILES this"
  echo "repo is known to carry. The include globs or exclude list no longer match"
  echo "the tree, so a pass here would prove nothing."
  exit 2
fi

echo "✓ no placeholder sentinels across $scanned deploy-config file(s)"
