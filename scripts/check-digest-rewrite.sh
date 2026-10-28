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
#     joined to an @sha256 digest in its init container and its main container
#     — at every tier, because the pin does not depend on the validation action;
#   * the same tag added to that pod as an ephemeral container, the request
#     `kubectl debug` makes through the pods/ephemeralcontainers subresource,
#     must come back pinned too, and the branch-signed image added the same way
#     must be decided as the branch-signed pod below is;
#   * a Deployment of the same tag must be stored with its pod template as
#     written, and the pod its ReplicaSet creates must come back pinned. ArgoCD
#     compares the stored template with git, so a pin written there is drift on
#     every sync; the policy generates no rule for pod controllers, and this is
#     where that is observed;
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

for f in pod.yaml deployment.yaml branch-signed.yaml; do
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
# Every image the fixtures submit is that one tag: the pod's init and main
# containers, and the Deployment's template. Another reference in either would
# be a pin this run reads without having checked it was a tag.
for f in pod.yaml deployment.yaml; do
  others="$(sed -n 's/^ *image: *\([^ ]*\) *$/\1/p' "$SUITE/$f" | grep -vxF "$TAGGED")"
  [ -z "$others" ] || cannot_run "$SUITE/$f names $others beside $TAGGED, so its pin
would be read off a reference this run never established is a tag."
done
[ "$(grep -c '^ *image: ' "$SUITE/pod.yaml")" -eq 2 ] \
  || cannot_run "$SUITE/pod.yaml does not carry the tag in exactly one init container and
one container, so the init field's pin would go unobserved."
POD="$(sed -n 's/^  name: *\([^ ]*\) *$/\1/p' "$SUITE/pod.yaml" | head -1)"
POD_NS="$(sed -n 's/^  namespace: *\([^ ]*\) *$/\1/p' "$SUITE/pod.yaml" | head -1)"
[ -n "$POD" ] && [ -n "$POD_NS" ] \
  || cannot_run "$SUITE/pod.yaml names no pod and namespace to add an ephemeral container to."
FOREIGN="$(sed -n 's/^ *image: *\(ghcr\.io\/nanohype\/[^ ]*@sha256:[0-9a-f]\{64\}\) *$/\1/p' "$SUITE/branch-signed.yaml" | head -1)"
[ -n "$FOREIGN" ] \
  || cannot_run "$SUITE/branch-signed.yaml carries no digest-pinned ghcr.io/nanohype image."
DEPLOYMENT="$(sed -n 's/^  name: *\([^ ]*\) *$/\1/p' "$SUITE/deployment.yaml" | head -1)"
DEPLOYMENT_NS="$(sed -n 's/^  namespace: *\([^ ]*\) *$/\1/p' "$SUITE/deployment.yaml" | head -1)"
[ -n "$DEPLOYMENT" ] && [ -n "$DEPLOYMENT_NS" ] \
  || cannot_run "$SUITE/deployment.yaml names no Deployment and namespace to read back."

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

# The tag joined to a digest, and nothing else.
TAGGED_RE="$(printf '%s' "$TAGGED" | sed 's/[.]/\\./g')"
pinned() {
  printf '%s' "$1" | grep -qE "^${TAGGED_RE}@sha256:[0-9a-f]{64}$"
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
  if admitted="$(kubectl create -f "$SUITE/pod.yaml" -o jsonpath='{.spec.initContainers[0].image} {.spec.containers[0].image}' 2>"$WORK/err")"; then
    read -r admitted_init admitted_main <<<"$admitted"
    for pair in "init container:${admitted_init:-}" "container:${admitted_main:-}"; do
      field="${pair%%:*}"; image="${pair#*:}"
      if pinned "$image"; then
        echo "  ok    admitted $TAGGED in the $field as $image"
      else
        fail=1
        echo "  FAIL  admitted $TAGGED in the $field as '$image', with no digest joined"
        echo "        to the tag. Verification and execution then resolve the tag"
        echo "        separately, and anyone able to move it between those two moments"
        echo "        runs an unverified image under a policy reporting success."
      fi
    done

    # The ephemeral containers, through the subresource that alone adds them.
    if ephemeral="$(kubectl patch pod "$POD" -n "$POD_NS" --subresource=ephemeralcontainers \
          --type=strategic -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"pinned\",\"image\":\"$TAGGED\"}]}}" \
          -o jsonpath='{.spec.ephemeralContainers[0].image}' 2>"$WORK/err")"; then
      if pinned "$ephemeral"; then
        echo "  ok    admitted $TAGGED as an ephemeral container as $ephemeral"
      else
        fail=1
        echo "  FAIL  admitted $TAGGED as an ephemeral container as '$ephemeral', with"
        echo "        no digest joined to the tag."
      fi
    elif network_failure <"$WORK/err"; then
      show_err
      cannot_run "$rel could not reach the registry or Rekor for the ephemeral container."
    else
      fail=1
      echo "  FAIL  refused the release-signed $TAGGED as an ephemeral container:"
      show_err
    fi
    if kubectl patch pod "$POD" -n "$POD_NS" --subresource=ephemeralcontainers \
          --type=strategic -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"foreign\",\"image\":\"$FOREIGN\"}]}}" \
          -o name >/dev/null 2>"$WORK/err"; then
      case ",$actions," in
        *,Deny,*)
          fail=1
          echo "  FAIL  admitted a branch-signed ephemeral container under Deny." ;;
        *) echo "  ok    admitted a branch-signed ephemeral container under $actions (reported, not blocked)" ;;
      esac
    elif grep -qF "$IDENTITY_MESSAGE" "$WORK/err"; then
      case ",$actions," in
        *,Deny,*) echo "  ok    denied a branch-signed ephemeral container: $IDENTITY_MESSAGE" ;;
        *) fail=1
           echo "  FAIL  denied a branch-signed ephemeral container under $actions, which reports and does not block." ;;
      esac
    elif network_failure <"$WORK/err"; then
      show_err
      cannot_run "$rel could not reach the registry or Rekor for the branch-signed ephemeral container."
    else
      fail=1
      echo "  FAIL  the branch-signed ephemeral container was refused for a reason other than its identity:"
      show_err
    fi
    kubectl delete -f "$SUITE/pod.yaml" --wait=true --timeout=120s >/dev/null 2>&1
  elif network_failure <"$WORK/err"; then
    show_err
    cannot_run "$rel could not reach the registry or Rekor, so the signed pod was never
verified and nothing was observed about the rewrite."
  else
    fail=1
    echo "  FAIL  denied the release-signed $TAGGED, so no digest was written:"
    show_err
  fi

  # The Deployment, stored as git wrote it; the pod it creates, pinned. A pod
  # left from an earlier overlay would answer for this one, so none may remain.
  kubectl wait --for=delete pod -n "$DEPLOYMENT_NS" -l "app.kubernetes.io/name=$DEPLOYMENT" \
    --timeout=120s >/dev/null 2>&1
  if stored="$(kubectl create -f "$SUITE/deployment.yaml" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>"$WORK/err")"; then
    if [ "$stored" = "$TAGGED" ]; then
      echo "  ok    stored the Deployment's pod template as written ($TAGGED)"
    else
      fail=1
      echo "  FAIL  stored the Deployment's pod template as '$stored', not as written."
      echo "        ArgoCD compares that template with git, so every nanohype workload"
      echo "        it syncs reads as drift, and selfHeal and admission rewrite it in turn."
    fi
    created=""
    for _ in $(seq 1 60); do
      created="$(kubectl get pod -n "$DEPLOYMENT_NS" -l "app.kubernetes.io/name=$DEPLOYMENT" \
        -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null)"
      [ -n "$created" ] && break
      sleep 2
    done
    if [ -z "$created" ]; then
      kubectl get events -n "$DEPLOYMENT_NS" --field-selector reason=FailedCreate \
        -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' >"$WORK/err" 2>&1
      if network_failure <"$WORK/err"; then
        show_err
        cannot_run "$rel could not reach the registry or Rekor for the Deployment's pod."
      fi
      fail=1
      echo "  FAIL  the Deployment's ReplicaSet created no pod within 120s:"
      show_err
    elif pinned "$created"; then
      echo "  ok    admitted the Deployment's pod as $created"
    else
      fail=1
      echo "  FAIL  admitted the Deployment's pod as '$created', with no digest joined"
      echo "        to the tag. A controller-created pod is the one that runs, and it"
      echo "        must carry the digest admission verified."
    fi
    kubectl delete -f "$SUITE/deployment.yaml" --cascade=foreground --wait=true \
      --timeout=120s >/dev/null 2>&1
  elif network_failure <"$WORK/err"; then
    show_err
    cannot_run "$rel could not reach the registry or Rekor for the Deployment."
  else
    fail=1
    echo "  FAIL  refused the Deployment of the release-signed $TAGGED:"
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
echo "  verified in the init, main and ephemeral container fields and in a"
echo "  controller's pod, leave the controller's template as written, and decide a"
echo "  foreign identity in a pod and in an ephemeral container as their"
echo "  validationActions say — executed through a real API server, the registry"
echo "  and the transparency log"
