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

# A transport failure as the image-verification path words one: Go's HTTP
# client, go-containerregistry reading the registry, the Sigstore TUF client
# fetching the trusted root, and the Rekor client. Matched case-insensitively.
TRANSPORT_FAILURE='dial tcp|no such host|i/o timeout|connection refused|connection reset|broken pipe|TLS handshake timeout|context deadline exceeded|Client\.Timeout exceeded|unexpected EOF|tuf: failed to download|unexpected status code (429|5[0-9][0-9])|toomanyrequests|\]\[(429|5[0-9][0-9])\]'

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

# An ImageValidatingPolicy row matching a ghcr.io/nanohype image verifies a
# real signature: Kyverno reads the image, its signature and attestation from
# the registry, the Sigstore trusted root from its TUF mirror, and checks each
# entry against Rekor. A transport failure on that path reaches the table two
# ways. Reading the image fails the row as "got error", with the transport error
# as its message. Anything after that is counted as a signature that did not
# verify, so the row reports the policy's own message: a row expecting a pass
# fails and a row expecting a fail passes, neither for a reason the policy
# decided. Only the verifier's log names that cause, which is why the suite runs
# with --detailed-results (the message column) and -v 1 (the log).
#
# So the three are reached first, and a run whose output carries a transport
# failure anywhere has not decided its image-verification rows either way. It
# is run again, up to ATTEMPTS times, and a transport failure in every attempt
# exits 2: a run that could not verify, not a regression and not a pass. A run
# carrying none is decided on what the policies did: a failing row exits 1.
if grep -rqs --include='kyverno-test.yaml' 'isImageValidatingPolicy: true' "$TESTS"; then
  command -v curl >/dev/null 2>&1 \
    || { echo "Cannot run: curl is not on PATH, so the registry and Sigstore cannot be reached first."; exit 2; }
  for endpoint in https://ghcr.io/v2/ https://tuf-repo-cdn.sigstore.dev/timestamp.json \
                  https://rekor.sigstore.dev/api/v1/log; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$endpoint" 2>/dev/null)"
    case "$code" in
      2??|401) ;;
      *) echo "Cannot run: $endpoint answered '${code:-nothing}', so the image-verification"
         echo "rows would decide on an unreachable registry or log rather than on a signature."
         exit 2 ;;
    esac
  done
fi

attempt=1
while :; do
  out="$(kyverno test "$TESTS" --detailed-results -v 1 2>&1)"
  rc=$?
  # Each failing line from shortly before its first transport phrase, with the
  # colour codes and the log prefix cut away, and each distinct one once.
  transport="$(printf '%s\n' "$out" | sed "s/$(printf '\033')\[[0-9;]*m//g" \
    | grep -oiE ".{0,60}($TRANSPORT_FAILURE).*" | cut -c1-240 | awk '!seen[$0]++' | head -3)"
  [ -z "$transport" ] && break
  if [ "$attempt" -ge "$ATTEMPTS" ]; then
    printf '%s\n' "$out"
    echo
    echo "Cannot run: all $ATTEMPTS runs met a transport failure on the image-verification"
    echo "path, so no image-verification row above was decided by a signature. The last:"
    printf '%s\n' "$transport" | sed 's/^/      /'
    exit 2
  fi
  echo "Attempt $attempt of $ATTEMPTS met a transport failure, so its image-verification"
  echo "rows decided nothing; running the suite again:"
  printf '%s\n' "$transport" | sed 's/^/      /'
  sleep $((attempt * PAUSE))
  attempt=$((attempt + 1))
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
