# shellcheck shell=bash
# What a transport failure on the image-verification path looks like, sourced
# by the two gates that read that path's errors: scripts/kyverno-test.sh out of
# the Kyverno CLI's table and log, and scripts/check-digest-rewrite.sh out of the
# API server's refusal and the admission controller's log. Both read the same
# verifier, so a phrase only one of them knows is an outage that one reports as
# a run that could not verify and the other as a verdict on a signature.

# Go's HTTP client, go-containerregistry reading the registry, the Sigstore TUF
# client fetching the trusted root, and the Rekor client. Matched
# case-insensitively.
TRANSPORT_FAILURE='dial tcp|no such host|i/o timeout|connection refused|connection reset|broken pipe|TLS handshake timeout|context deadline exceeded|Client\.Timeout exceeded|unexpected EOF|tuf: failed to download|unexpected status code (429|5[0-9][0-9])|toomanyrequests|\]\[(429|5[0-9][0-9])\]'

# Standard input with the terminal colour codes cut away. The verifier logs
# through zerolog's console writer, which colours field names and values.
uncoloured() {
  sed "s/$(printf '\033')\[[0-9;]*m//g"
}

# Each line of standard input that names a transport failure, from shortly
# before its first transport phrase, each distinct one once and at most three:
# what a diagnostic quotes. Prints nothing when the input names none.
transport_failures() {
  uncoloured | grep -oiE ".{0,60}($TRANSPORT_FAILURE).*" | cut -c1-240 \
    | awk '!seen[$0]++' | head -3
}
