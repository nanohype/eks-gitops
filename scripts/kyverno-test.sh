#!/usr/bin/env bash
# `kyverno test` with a floor on what it ran.
#
# The CLI exits 0 over a directory holding no tests, printing "No test yamls
# available" — the same status a passing suite gets. A renamed directory, a
# narrowed path or a fixture set that stopped matching all report success, and
# this is the job that stands behind every Kyverno policy in the catalog.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS="${1:-policies/kyverno/tests}"

# A floor on tests EXECUTED. Set under what the suite holds, so it catches
# "matched almost nothing" rather than one case being retired.
MIN_TESTS=24

if ! command -v kyverno >/dev/null 2>&1; then
  echo "Cannot run: kyverno is not on PATH. No policy was tested — that is"
  echo "different from every policy passing."
  exit 2
fi

# A count is an operand, and an absent producer yields an EMPTY one, not a zero.
# `[ "" -gt 0 ]` exits 2 with "integer expected", and an `if` reads exit 2 as
# false — so the check is not failed, it is SKIPPED, and execution falls through
# to the pass.
require_count() {
  case "$2" in
    "" ) echo "Cannot run: $1 produced no count — its producer did not run. An"
         echo "undetermined count is not a count of zero."
         exit 2 ;;
    *[!0-9]* ) echo "Cannot run: $1 produced a non-numeric count ($2)."
         exit 2 ;;
  esac
}

cd "$ROOT"
out="$(kyverno test "$TESTS" 2>&1)"
rc=$?
printf '%s\n' "$out"
[ "$rc" -ne 0 ] && exit "$rc"

# A policy the engine REJECTS is reported as "Invalid Policy", and a rejected
# policy skips every rule — which is what every row expecting a skip asserts. The
# CLI counts those rows as passes, so a variable expression Kyverno will not
# accept prints the same summary as a suite that evaluated everything. Only rows
# asserting a patched resource notice; a test file made of skips asserts nothing
# at all.
invalid="$(printf '%s' "$out" | grep -c 'Invalid Policy')"
require_count "the invalid-policy scan" "$invalid"
if [ "$invalid" -gt 0 ]; then
  echo "FAIL  kyverno reported $invalid result(s) against a policy it will not accept."
  echo "      A rejected policy skips every rule, which satisfies every expected"
  echo "      skip in the suite — the run below passed without evaluating anything."
  exit 1
fi

ran="$(printf '%s' "$out" | sed -n 's/^Test Summary: \([0-9][0-9]*\) tests passed.*/\1/p' | head -1)"
if [ -z "$ran" ]; then
  echo "Cannot run: kyverno printed no test summary, so how many tests ran is"
  echo "unknown. A pass here would report the same thing as a passing suite."
  exit 2
fi
if [ "$ran" -lt "$MIN_TESTS" ]; then
  echo "FAIL  $ran Kyverno test(s) ran under $TESTS, below the floor of $MIN_TESTS."
  echo "      Almost nothing was tested, which is not the same as every policy"
  echo "      behaving. Check the path — a renamed directory reports exactly this."
  exit 2
fi
exit 0
