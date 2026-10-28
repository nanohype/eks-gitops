#!/usr/bin/env bash
# Admit pods through a real API server running the catalog's Kyverno, and read
# back what was admitted.
#
# WHAT THIS GUARDS
#
# verify-images pins every ghcr.io/nanohype/* tag to the digest it verified
# (`mutateDigest: true`). Verification resolves a tag at admission and the
# kubelet resolves it again at pull; the pin is what stops anyone able to move
# the tag between those two moments from running an unverified image under a
# passing policy.
#
# The pin is written by Kyverno's MUTATING webhook. The Kyverno CLI evaluates an
# ImageValidatingPolicy through the validating path only, so `kyverno test` and
# `kyverno apply` never execute it: under `verifyDigest: true` a tag-only pod
# simply fails there. A field can read true in every rendered overlay while the
# rewrite has stopped happening — a Kyverno upgrade changing the mutation path,
# a webhook that no longer registers — and only an admission request sees it.
#
# WHAT THIS RUNS
#
# A kind cluster on the node image ci.yml pins (KIND_NODE_IMAGE), Kyverno from
# the chart and values the kyverno appset element names, and then, for each
# rendered supply-chain overlay in turn:
#
#   * the signed fixture, written with a tag, must be admitted carrying that tag
#     joined to an @sha256 digest — at every tier, because the pin does not
#     depend on the validation action;
#   * the branch-signed fixture must be DENIED with the policy's identity
#     message wherever the overlay's validationActions include Deny, and
#     admitted (audited) where they do not.
#
# NEEDS THE NETWORK AND DOCKER. Kyverno inside the cluster reaches the registry
# for the manifest and Rekor for the transparency-log entry, which is the round
# trip production admission makes. A denial whose message is a network failure
# exits 2: it is a verification that never ran, not a rewrite that stopped.
#
# Exit 0: every overlay pinned the tag and decided the identity as its action
# says. Exit 1: one did not. Exit 2: the run could not establish either.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="$ROOT/policies/kyverno/tests/supply-chain-digest"
GROUP="$ROOT/policies/kyverno/supply-chain"
APPSET="$ROOT/applicationsets/addons-security.yaml"
CI="$ROOT/.github/workflows/ci.yml"
POLICY=verify-images
IDENTITY_MESSAGE="image is not signed by a nanohype release workflow"

cannot_run() {
  printf '%s\n' "Cannot run: $*"
  exit 2
}

# ── The tree first, so an absent corpus refuses before any cluster exists ──

OVERLAYS=()
for d in "$GROUP"/overlays/*/; do
  [ -f "$d/kustomization.yaml" ] && OVERLAYS+=("${d%/}")
done
if [ "${#OVERLAYS[@]}" -eq 0 ]; then
  cannot_run "no overlay under ${GROUP#"$ROOT"/}/overlays, so there is no rendition
of $POLICY to admit anything through. That is a tree this gate cannot read, not a
rewrite that works."
fi

for f in pod.yaml branch-signed.yaml; do
  [ -f "$SUITE/$f" ] || cannot_run "$SUITE/$f does not exist, so there is no pod to admit."
done

# The reference the signed fixture submits, read out of the fixture. A tag, and
# asserted to be one: a digest-pinned fixture needs no rewrite and would pass
# against a policy with the rewrite turned off.
TAGGED="$(sed -n 's/^ *image: *\(ghcr\.io\/nanohype\/[^ ]*\) *$/\1/p' "$SUITE/pod.yaml" | head -1)"
if [ -z "$TAGGED" ] || ! printf '%s' "$TAGGED" | grep -qE ':[A-Za-z0-9][A-Za-z0-9._-]*$'; then
  cannot_run "$SUITE/pod.yaml carries no tagged ghcr.io/nanohype image, so the policy
does not match it and nothing would be rewritten."
fi
if printf '%s' "$TAGGED" | grep -q '@sha256:'; then
  cannot_run "$SUITE/pod.yaml is pinned by digest already. The rewrite would be a
no-op and this would pass over a policy that had stopped doing it."
fi

[ -f "$APPSET" ] || cannot_run "$APPSET does not exist, so the Kyverno chart pin is unknown."
[ -f "$CI" ] || cannot_run "$CI does not exist, so the pinned kind node image is unknown."

for tool in kind kubectl helm kustomize docker python3; do
  command -v "$tool" >/dev/null 2>&1 \
    || cannot_run "$tool is not on PATH. No pod was admitted — that is different
from the rewrite having happened."
done

# The chart coordinates the catalog installs, read from the appset element.
read -r CHART_REPO CHART_VERSION ADDON_PATH < <(python3 - "$APPSET" <<'PY'
import sys, yaml
for doc in yaml.safe_load_all(open(sys.argv[1])):
    def walk(n):
        if isinstance(n, dict):
            if n.get("chart") == "kyverno" and n.get("chartVersion"):
                print(n["chartRepo"], n["chartVersion"], n["path"])
                sys.exit(0)
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
    walk(doc)
PY
)
[ -n "${CHART_VERSION:-}" ] || cannot_run "$APPSET names no kyverno chart element."
VALUES=("$ROOT/$ADDON_PATH/values.yaml" "$ROOT/$ADDON_PATH/values-production.yaml")
for v in "${VALUES[@]}"; do
  [ -f "$v" ] || cannot_run "$v does not exist, so Kyverno would install with values the catalog does not ship."
done

NODE_IMAGE="${KIND_NODE_IMAGE:-$(sed -n 's/^  KIND_NODE_IMAGE: *\([^ ]*\) *$/\1/p' "$CI" | head -1)}"
case "$NODE_IMAGE" in
  *@sha256:*) ;;
  *) cannot_run "KIND_NODE_IMAGE is '$NODE_IMAGE', not a digest-pinned image. The node
image is part of what this run asserts against, so an unpinned one is refused." ;;
esac

# ── The cluster ──────────────────────────────────────────────────────────

WORK="$(mktemp -d)"
CLUSTER="digest-rewrite-$$"
export KUBECONFIG="$WORK/kubeconfig"
cleanup() {
  kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "── kind $NODE_IMAGE, kyverno chart $CHART_VERSION"
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 180s >"$WORK/kind.log" 2>&1 \
  || { tail -20 "$WORK/kind.log"; cannot_run "kind could not create the cluster."; }

helm_args=()
for v in "${VALUES[@]}"; do helm_args+=(-f "$v"); done
helm install kyverno kyverno --repo "$CHART_REPO" --version "$CHART_VERSION" \
    --namespace kyverno --create-namespace "${helm_args[@]}" \
    --wait --timeout 10m >"$WORK/helm.log" 2>&1 \
  || { tail -20 "$WORK/helm.log"; cannot_run "Kyverno $CHART_VERSION did not install."; }

# The namespaces the fixtures name.
for f in "$SUITE"/*.yaml; do
  ns="$(sed -n 's/^  namespace: *\([^ ]*\) *$/\1/p' "$f" | head -1)"
  [ -n "$ns" ] && kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done

# The API server's refusal, with the checkout path elided so the reason fits.
show_err() {
  sed -e "s#$ROOT/##g" -e 's/^/        /' "$WORK/err" | cut -c1-240
}

network_failure() {
  grep -qiE 'no such host|i/o timeout|connection refused|context deadline|TLS handshake|unexpected status code 5[0-9][0-9]|toomanyrequests'
}

fail=0
checked=0
for overlay in "${OVERLAYS[@]}"; do
  rel="${overlay#"$ROOT"/}"
  rendered="$WORK/$(basename "$overlay").yaml"
  kustomize build "$overlay" >"$rendered" 2>"$WORK/err" \
    || cannot_run "$rel does not render — $(head -1 "$WORK/err")"
  actions="$(python3 - "$rendered" "$POLICY" <<'PY'
import sys, yaml
for doc in yaml.safe_load_all(open(sys.argv[1])):
    if doc and doc.get("kind") == "ImageValidatingPolicy" and doc["metadata"]["name"] == sys.argv[2]:
        print(",".join(doc["spec"].get("validationActions") or []))
        sys.exit(0)
sys.exit(1)
PY
)" || cannot_run "$rel renders no ImageValidatingPolicy named $POLICY."

  kubectl apply --server-side -f "$rendered" >/dev/null 2>"$WORK/err" \
    || cannot_run "the API server refused $rel — $(head -1 "$WORK/err")"
  if ! kubectl wait --for=jsonpath='{.status.conditionStatus.ready}'=true \
        "imagevalidatingpolicy/$POLICY" --timeout=180s >/dev/null 2>"$WORK/err"; then
    kubectl get "imagevalidatingpolicy/$POLICY" -o jsonpath='{.status}' 2>/dev/null; echo
    cannot_run "$rel: Kyverno never reported $POLICY ready, so its webhooks may not be
registered and an admitted pod would prove nothing."
  fi

  echo "── $rel (validationActions: $actions)"

  # The tag, rewritten. The admitted object is the API server's response to the
  # create, so the digest in it can only have been written by admission.
  if admitted="$(kubectl create -f "$SUITE/pod.yaml" -o jsonpath='{.spec.containers[0].image}' 2>"$WORK/err")"; then
    kubectl delete -f "$SUITE/pod.yaml" --wait=false >/dev/null 2>&1
    if printf '%s' "$admitted" | grep -qE "^$(printf '%s' "$TAGGED" | sed 's/[.]/\\./g')@sha256:[0-9a-f]{64}$"; then
      echo "  ok    admitted $TAGGED as $admitted"
    else
      fail=1
      echo "  FAIL  admitted $TAGGED as '$admitted', with no digest joined to the tag."
      echo "        Verification and execution then resolve the tag separately, and"
      echo "        anyone able to move it between those two moments runs an"
      echo "        unverified image under a policy reporting success."
    fi
  elif network_failure <"$WORK/err"; then
    show_err
    cannot_run "$rel could not reach the registry or Rekor, so the signed pod was never
verified and nothing was observed about the rewrite."
  else
    fail=1
    echo "  FAIL  denied the release-signed $TAGGED, so no digest was written:"
    show_err
  fi

  # The identity, decided. Deny refuses it; Audit admits and reports it.
  if kubectl create -f "$SUITE/branch-signed.yaml" -o name >/dev/null 2>"$WORK/err"; then
    kubectl delete -f "$SUITE/branch-signed.yaml" --wait=false >/dev/null 2>&1
    case ",$actions," in
      *,Deny,*)
        fail=1
        echo "  FAIL  admitted a branch-signed image under Deny." ;;
      *) echo "  ok    admitted the branch-signed image under $actions (reported, not blocked)" ;;
    esac
  elif grep -qF "$IDENTITY_MESSAGE" "$WORK/err"; then
    case ",$actions," in
      *,Deny,*) echo "  ok    denied the branch-signed image: $IDENTITY_MESSAGE" ;;
      *) fail=1
         echo "  FAIL  denied the branch-signed image under $actions, which reports and does not block." ;;
    esac
  elif network_failure <"$WORK/err"; then
    show_err
    cannot_run "$rel could not reach the registry or Rekor for the branch-signed image."
  else
    fail=1
    echo "  FAIL  the branch-signed image was refused for a reason other than its identity:"
    show_err
  fi

  kubectl delete -f "$rendered" --wait=true >/dev/null 2>&1
  checked=$((checked + 1))
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "verify-images' guarantee is that the admitted spec carries the digest the"
  echo "signature was checked against, and that a tier with Deny refuses an identity"
  echo "the policy does not trust. Under real admission, that did not hold."
  exit 1
fi

echo "✓ $checked overlay(s) of $POLICY pin a tagged image to the digest admission"
echo "  verified and decide a foreign identity as their validationActions say —"
echo "  executed through a real API server, the registry and the transparency log"
