#!/usr/bin/env bash
# Execute the digest rewrite the enforcing tier depends on, and read the result.
#
# WHY THIS EXISTS
#
# `mutateDigest: true` is the whole reason the enforcing tier enforces.
# Verification resolves a tag to a digest at admission; the kubelet resolves the
# same tag again at pull time. Pinning at admission is what stops anyone who can
# move a tag between those two moments from running an unverified image under a
# policy reporting success.
#
# In this repository that guarantee was a field value other files read, never a
# behaviour anything ran. Three checks touch the field and all three read
# rendered YAML: `kyverno test` loads only base policies, where the field is
# false because Kyverno rejects true under an Audit failure action;
# check-image-verification.py declines to assert it and delegates the pairing;
# check-policy-validity.py asserts Enforce implies true, then applies its probe
# pod, whose image is outside `ghcr.io/nanohype/*` so the rule never matches.
#
# The rendition carrying `mutateDigest: true` was under no test at all. A change
# that keeps the field and breaks the rewrite — an exclude block growing over a
# workload namespace, a Kyverno upgrade altering the verifyImages mutation path —
# leaves every YAML reading exactly as it does today.
#
# WHAT THIS RUNS
#
# The ENFORCING rendition, rendered here rather than committed, against a pod
# written the way the catalog writes one: with a tag. The pod's image is a real
# signed release, so verification runs end to end and the mutation runs behind
# it — this exercises the path rather than a model of it.
#
# HOW THE RESULT IS OBSERVED, and why it is read out of a report.
#
# The Kyverno CLI offers no machine-readable channel carrying the object a
# verifyImages mutation admitted. Three were tried. `kyverno test`'s
# `patchedResources` is compared against EVERY engine response for the rule, and
# a verifyImages rule produces two — one holding the resource as submitted and
# one holding it mutated — so one comparison always diffs whichever file is
# supplied, and supplying both produces a cross product with two failures.
# `kyverno apply -o` writes a file for mutate rules and leaves it empty for this
# one. The JSON policy report carries the verdict and the message and not the
# object.
#
# What remains is the CLI's own detailed report, which prints the admitted
# object. That is text, and text is the weaker reading — but it fails in the
# safe direction: the assertion is that a specific reference token appears, so a
# report that stops printing it, or wraps it, or renames the column, makes the
# token absent and this gate red. It cannot go quiet.
#
# NEEDS THE NETWORK, and that is not incidental. Keyless verification reaches
# the registry for the manifest and Rekor for the transparency-log entry, which
# is the round trip admission makes. Offline the CLI reports a verification
# failure rather than a clean result, which is why the two are told apart below
# instead of both reading as a rewrite that stopped happening.
#
# WHAT IT DOES NOT ESTABLISH
#
# That a cluster admits what the CLI admits. The engine is the same code and the
# policy is the rendered one, and no environment reachable from this repository
# runs an API server — so this is the strongest observation available here and
# it is not an admission-time proof.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="$ROOT/policies/kyverno/tests/supply-chain-digest"

# Every overlay that turns the rewrite on. Enumerated from the tree rather than
# named here: an overlay added later is one more tier depending on a step, and
# it has to be executed by something too.
mapfile -t OVERLAYS < <(
  grep -rl 'verifyImages/0/mutateDigest' "$ROOT/policies/kyverno" --include='kustomization.yaml' \
    | xargs -n1 dirname | sort
)

if [ "${#OVERLAYS[@]}" -eq 0 ]; then
  echo "Cannot run: no overlay in policies/kyverno patches mutateDigest, so the"
  echo "rendition this executes does not exist. That is a tree this gate cannot"
  echo "read, not a rewrite that works."
  exit 2
fi

for tool in kyverno kustomize; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Cannot run: $tool is not on PATH. The rewrite was not executed — that is"
    echo "different from it having happened."
    exit 2
  fi
done

if [ ! -f "$SUITE/pod.yaml" ]; then
  echo "Cannot run: $SUITE/pod.yaml does not exist, so there is no pod to admit."
  exit 2
fi

# The reference the fixture submits, read out of the fixture rather than
# repeated here. A tag, and asserted to be one: a digest-pinned fixture needs no
# rewrite, so it would satisfy every check below against a policy with the
# rewrite turned off — which is the state this gate exists to detect.
TAGGED="$(grep -oE 'ghcr\.io/nanohype/[a-z0-9./-]+:[A-Za-z0-9][A-Za-z0-9._-]*' "$SUITE/pod.yaml" | head -1)"
if [ -z "$TAGGED" ]; then
  echo "Cannot run: $SUITE/pod.yaml carries no tagged ghcr.io/nanohype image, so"
  echo "the rule under test does not match it and nothing would be rewritten."
  exit 2
fi
if printf '%s' "$TAGGED" | grep -q '@sha256:'; then
  echo "Cannot run: $SUITE/pod.yaml is pinned by digest already. The rewrite would"
  echo "be a no-op and this would pass over a policy that had stopped doing it."
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

fail=0
for overlay in "${OVERLAYS[@]}"; do
  rel="${overlay#"$ROOT"/}"
  dir="$WORK/$(printf '%s' "$rel" | tr '/' '_')"
  mkdir -p "$dir"
  if ! kustomize build "$overlay" > "$dir/policy.yaml" 2>"$dir/err"; then
    echo "Cannot run: $rel does not render — $(head -1 "$dir/err")"
    exit 2
  fi
  cp "$SUITE/pod.yaml" "$dir/"
  # The expected patch is the pod AS SUBMITTED, and that direction is what makes
  # the reading non-circular. `kyverno test` compares it against every engine
  # response; the mutated one differs, so the report prints the object the engine
  # produced. A digest in that output can only have come from the engine — an
  # expectation carrying the digest would have the report echo the fixture back.
  cat > "$dir/kyverno-test.yaml" <<TEST
apiVersion: cli.kyverno.io/v1alpha1
kind: Test
metadata:
  name: digest-rewrite
policies:
  - policy.yaml
resources:
  - pod.yaml
results:
  - policy: verify-images
    rule: verify-ghcr-nanohype
    resources:
      - eks-agent-platform/signed-operator
    kind: Pod
    result: pass
    patchedResources: pod.yaml
TEST

  out="$(cd "$dir" && kyverno test . --registry --detailed-results 2>&1 \
           | sed 's/\x1b\[[0-9;]*m//g')"

  # A verification that could not REACH the registry or Rekor is not a rewrite
  # that did not happen. They are different facts about different systems, so
  # they are told apart here rather than both reading as a policy that stopped
  # pinning.
  if printf '%s' "$out" | grep -qiE 'failed to verify image|no such host|i/o timeout|connection refused|context deadline'; then
    echo "Cannot run: $rel — the image could not be verified, so the rewrite never"
    echo "ran and this observed nothing:"
    printf '%s\n' "$out" | grep -iE 'failed to verify image|no such host|i/o timeout|connection refused|context deadline' \
      | head -2 | cut -c1-160 | sed 's/^/      /'
    exit 2
  fi

  # The verification must have PASSED, because a rewrite behind a failed
  # verification is a rewrite that never had a digest to write.
  if printf '%s' "$out" | grep -qE 'Fail +\| +(Ok|Want)'; then
    fail=1
    echo "  FAIL  $rel did not verify $TAGGED, so no digest was resolved to write."
    printf '%s\n' "$out" | tail -6 | cut -c1-160 | sed 's/^/        /'
    continue
  fi

  # And the admitted object must carry the digest joined to the tag it was
  # verified from. One token, so a report that wraps or renames around it makes
  # this absent rather than true.
  if printf '%s' "$out" | tr -s ' ' | grep -q "image: $TAGGED@sha256:"; then
    echo "  ok    $rel admits the pod carrying the digest verification resolved"
    continue
  fi
  fail=1
  echo "  FAIL  $rel verified $TAGGED and admitted it with no digest attached."
  echo "        Verification and execution then resolve the tag separately, and"
  echo "        anyone able to move it between those two moments runs an"
  echo "        unverified image under a policy reporting success."
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "The enforcing tier's guarantee is that the admitted spec carries the digest"
  echo "the signature was checked against. It does not."
  exit 1
fi

echo "✓ ${#OVERLAYS[@]} enforcing overlay(s) rewrite a tagged image to the digest"
echo "  verification resolved — executed against the registry and the transparency"
echo "  log, not read off the rendered field"
