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

# Runs of the suite a transport failure may cost before the run is reported as
# one that could not verify, and the seconds the Nth repeat waits (N * PAUSE).
ATTEMPTS=3
PAUSE=5

# The seconds one run of the suite may take before GNU timeout sends it TERM,
# and the seconds after that TERM a run still going is given before timeout
# sends it KILL. A read the registry, the TUF mirror or Rekor stops answering
# partway through can hold the CLI for as long as the connection stays open, so
# a run that does not finish inside RUN_TIMEOUT counts as a transport failure
# like any other, whichever signal ended it. Every attempt at both, with the
# probes and pauses around them, fits inside the kyverno job's timeout-minutes,
# so the job ends on this script's diagnostic rather than on the runner's;
# scripts/tests/test_kyverno_test.py holds the two together.
RUN_TIMEOUT=240
KILL_TIMEOUT=10

# Decides what a run on the image-verification path established: whether an
# endpoint answered, whether a run decided its rows, and whether to run the suite
# again. It holds the one transport-failure pattern, which
# scripts/check-digest-rewrite.sh reads through too.
VERDICTS="$ROOT/scripts/verdicts.py"

if ! command -v kyverno >/dev/null 2>&1; then
  echo "Cannot run: kyverno is not on PATH. No policy was tested — that is"
  echo "different from every policy passing."
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Cannot run: python3 is not on PATH, so what a run of the suite established"
  echo "cannot be decided. No policy was tested."
  exit 2
fi

# GNU coreutils' timeout, which macOS ships under neither name: Homebrew's
# coreutils installs it as gtimeout.
TIMEOUT_CMD="$(command -v timeout || command -v gtimeout)"
if [ -z "$TIMEOUT_CMD" ]; then
  echo "Cannot run: neither timeout nor gtimeout is on PATH, so a run stalled on a"
  echo "read could hold this job until the runner ends it. On macOS,"
  echo "\`brew install coreutils\` installs gtimeout."
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

cd "$ROOT" || { echo "Cannot run: $ROOT cannot be entered."; exit 2; }

# An ImageValidatingPolicy row matching a ghcr.io/nanohype image verifies a
# real signature: Kyverno reads the image, its signature and attestation from
# the registry, the Sigstore trusted root from its TUF mirror, and checks each
# entry against Rekor. A transport failure on that path decides such a row for
# a reason the policy did not, and verdicts.py names the two ways it reaches the
# table. Only the verifier's log names the second, which is why the suite runs
# with --detailed-results (the message column) and -v 1 (the log).
#
# So the three are reached first, and each run is handed to verdicts.py, which
# reads one carrying a transport failure anywhere, or one RUN_TIMEOUT ended, as
# a run that decided none of its image-verification rows. It is run again, up to
# ATTEMPTS times, and a transport failure in every attempt exits 2: a run that
# could not verify, not a regression and not a pass. A run carrying none is
# decided on what the policies did: a failing row exits 1.
if grep -rqs --include='kyverno-test.yaml' 'isImageValidatingPolicy: true' "$TESTS"; then
  command -v curl >/dev/null 2>&1 \
    || { echo "Cannot run: curl is not on PATH, so the registry and Sigstore cannot be reached first."; exit 2; }
  for endpoint in https://ghcr.io/v2/ https://tuf-repo-cdn.sigstore.dev/timestamp.json \
                  https://rekor.sigstore.dev/api/v1/log; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$endpoint" 2>/dev/null)"
    python3 "$VERDICTS" endpoint --url="$endpoint" --status="$code" || exit 2
  done
fi

attempt=1
while :; do
  out="$("$TIMEOUT_CMD" -k "$KILL_TIMEOUT" "$RUN_TIMEOUT" kyverno test "$TESTS" --detailed-results -v 1 2>&1)"
  rc=$?
  said="$(printf '%s\n' "$out" | python3 "$VERDICTS" kyverno-run --status="$rc" \
            --attempt="$attempt" --attempts="$ATTEMPTS" --seconds="$RUN_TIMEOUT")"
  # verdicts.py's status: 0 decided, 4 run again, 2 could not verify. No
  # interpreter failure exits 0 or 4, so any other status is a run nothing
  # decided either.
  case "$?" in
    0) break ;;
    4) printf '%s\n' "$said"
       sleep $((attempt * PAUSE))
       attempt=$((attempt + 1)) ;;
    *) printf '%s\n' "$out"
       echo
       printf '%s\n' "${said:-Cannot run: scripts/verdicts.py could not read attempt $attempt.}"
       exit 2 ;;
  esac
done
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
