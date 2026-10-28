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
# for the manifest, the Sigstore TUF mirror for the trusted root and Rekor for
# the transparency-log entry, which is the round trip production admission
# makes. A refusal whose cause the run cannot establish exits 2: a transport
# failure on that path, an admission controller log that cannot be read, or the
# identity message with no verifier line behind it. Each is a verification
# whose outcome is unknown, not a rewrite that stopped and not an identity
# decided.
#
# Every step is bounded: each API request by REQUEST_TIMEOUT, each wait by its
# own *_TIMEOUT, and kind and helm by GNU timeout, so a step that stops
# answering ends on this script's diagnostic.
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

# Seconds one API request may take. A create reaching verify-images' mutating
# and validating webhooks can take a minute, since the API server gives a
# webhook at most 30s, and the API server answers any non-streaming request
# inside its own one-minute deadline. This sits above both: it ends only a
# request whose connection stopped answering, and every other request returns
# the server's own answer.
REQUEST_TIMEOUT=90
# Seconds kind's control plane, and Kyverno's report that the policy is ready,
# may take.
READY_TIMEOUT=180
# Seconds an object may take to go once deleted.
DELETE_TIMEOUT=120
# Seconds the Deployment's ReplicaSet may take to create its pod.
CREATE_TIMEOUT=120
# Seconds kind may take to pull the node image and create or delete the cluster,
# and helm to fetch the chart and install it.
KIND_TIMEOUT=600
HELM_TIMEOUT=600
# Seconds a step GNU timeout ended is given to stop before it is killed.
KILL_TIMEOUT=10

# The admission controller's pods, which run the verifier: the chart labels them
# with this component, and this run installs the chart as release kyverno.
VERIFIER_NS=kyverno
VERIFIER_PODS="app.kubernetes.io/instance=kyverno,app.kubernetes.io/component=admission-controller"
# The message Kyverno's cosign verifier logs every failed verification under,
# through logr's Error, which no verbosity setting suppresses.
VERIFIER_FAILED="image verification failed"
# Seconds the verifier's log is read from before a request was sent, because
# `date +%s` truncates both ends of the window to the second. An earlier
# request's transport failure inside that slack can only turn a decision into a
# run that could not decide.
LOG_SLACK=5

# shellcheck source=transport-failure.sh
. "$ROOT/scripts/transport-failure.sh"

cannot_run() {
  printf '%s\n' "Cannot run: $*"
  exit 2
}

# The API server's refusal, with the checkout path elided so the reason fits.
show_err() {
  sed -e "s#$ROOT/##g" -e 's/^/        /' "$WORK/err" | cut -c1-240
}

# kubectl, every request bounded by REQUEST_TIMEOUT. Each call in this script
# goes through here.
kube() {
  kubectl --request-timeout="${REQUEST_TIMEOUT}s" "$@"
}

# The moment a request goes to the API server, taken before it is sent.
mark_sent() {
  sent="$(date +%s)"
}

# The verifier's lines among what every admission-controller replica logged
# from LOG_SLACK seconds before the request marked $sent until this read,
# uncoloured, into $WORK/log. That window holds the request's own line, because
# a failed verification is logged before the refusal returns, and any line
# another request logged inside it: one naming a transport failure can only end
# the run as one that could not decide, and any other one shows the log read is
# the verifier's.
#
# Only the verifier's lines are kept: the controller's webhook server logs its
# own connection errors to the same stream (a TLS handshake error as the API
# server drops a connection), and those name no verification. Given a selector,
# kubectl logs prints ten lines a pod unless --tail says otherwise, and a
# selector matching no pod prints nothing and exits 0; an identity refusal is
# decided only beside a verifier line for that reason. A log that cannot be
# read, inside REQUEST_TIMEOUT or at all, leaves a refusal's cause unknown, so
# the run cannot decide it.
read_verifier_log() {
  if kube logs -n "$VERIFIER_NS" -l "$VERIFIER_PODS" --tail=-1 \
       --since="$(( $(date +%s) - sent + LOG_SLACK ))s" >"$WORK/log.raw" 2>"$WORK/log.err"; then
    uncoloured <"$WORK/log.raw" | grep -F "$VERIFIER_FAILED" >"$WORK/log"
    return 0
  fi
  sed 's/^/        /' "$WORK/log.err" | cut -c1-240
  cannot_run "$rel: the admission controller's log could not be read, so whether a
refusal was the policy deciding or an outage on the verification path is unknown."
}

# A refusal, in $WORK/err, ends the run unless its cause is established. $1
# names what was refused. Every refusal this script decides comes through here
# first, so one rule holds on every path, and the verifier's log it reads is
# always the one read for this refusal.
#
# The cluster states a refusal's cause in the same two places the Kyverno CLI
# does for scripts/kyverno-test.sh. Reading the image failing refuses the
# request with the transport error as the API server's message. A failure after
# that — fetching the Sigstore trusted root, a Rekor lookup, the signature's
# manifest — is counted as a signature that did not verify, so the refusal
# carries the policy's own identity message and only the verifier's log names
# the cause. Both are read, through the one pattern scripts/transport-failure.sh
# holds for both gates.
#
# So a refusal carrying the identity message is decided only beside at least
# one verifier line. A failed verification always logs one, so with none the
# log read is not the verifier's, and its silence says nothing about whether
# the identity or an outage refused the request.
require_known_cause() {
  local cause
  cause="$(transport_failures <"$WORK/err")"
  if [ -z "$cause" ]; then
    read_verifier_log
    cause="$(transport_failures <"$WORK/log")"
  fi
  if [ -n "$cause" ]; then
    show_err
    printf '%s\n' "$cause" | sed 's/^/        /'
    cannot_run "$rel could not reach the registry, the Sigstore trusted root or Rekor for $1."
  fi
  if grep -qF "$IDENTITY_MESSAGE" "$WORK/err" && [ ! -s "$WORK/log" ]; then
    show_err
    cannot_run "$rel refused $1 with the identity message, but the admission
controller's log carries no '$VERIFIER_FAILED' line, so whether the identity or
an outage refused it is unknown."
  fi
  return 0
}

# A release-signed submission refused, in $WORK/err: a FAIL once the cause is
# established. $1 names what was refused and $2 says what the refusal means.
refused_release_signed() {
  require_known_cause "$1"
  fail=1
  echo "  FAIL  $2:"
  show_err
}

# A foreign identity, decided: an overlay whose validationActions include Deny
# refuses it with the policy's identity message, and any other admits it and
# reports it. $1 names what was submitted and $2 is "admitted" or "refused";
# the refusal is in $WORK/err and the overlay's actions in $actions. A refusal
# for a reason other than the identity is a FAIL.
decide_foreign() {
  local what="$1" outcome="$2"
  if [ "$outcome" = admitted ]; then
    case ",$actions," in
      *,Deny,*) fail=1
                echo "  FAIL  admitted $what under Deny." ;;
      *) echo "  ok    admitted $what under $actions (reported, not blocked)" ;;
    esac
    return 0
  fi
  require_known_cause "$what"
  if ! grep -qF "$IDENTITY_MESSAGE" "$WORK/err"; then
    fail=1
    echo "  FAIL  $what was refused for a reason other than its identity:"
    show_err
    return 0
  fi
  case ",$actions," in
    *,Deny,*) echo "  ok    denied $what: $IDENTITY_MESSAGE" ;;
    *) fail=1
       echo "  FAIL  denied $what under $actions, which reports and does not block." ;;
  esac
}

# Deletes what the remaining arguments name and waits for it to go. Anything
# still present after DELETE_TIMEOUT ends the run, because the next step would
# meet it: a pod of the same name refused as already existing reads as a tier
# denying a signed image, and a policy of the same name leaves which overlay
# decides the next admissions unknown. $1 names it.
delete_within() {
  local what="$1"
  shift
  kube delete "$@" --wait=true --timeout="${DELETE_TIMEOUT}s" >/dev/null 2>"$WORK/err" \
    || cannot_run "$rel: $what was not deleted within ${DELETE_TIMEOUT}s — $(head -1 "$WORK/err")"
}

# The tag joined to a digest, and nothing else.
pinned() {
  local tagged_re
  tagged_re="$(printf '%s' "$TAGGED" | sed 's/[.]/\\./g')"
  printf '%s' "$1" | grep -qE "^${tagged_re}@sha256:[0-9a-f]{64}$"
}

# The overlay rendered at $rendered, applied, and reported ready by Kyverno: an
# admission before that would not establish its webhooks are registered.
install_policy() {
  kube apply --server-side -f "$rendered" >/dev/null 2>"$WORK/err" \
    || cannot_run "the API server refused $rel — $(head -1 "$WORK/err")"
  if ! kube wait --for=jsonpath='{.status.conditionStatus.ready}'=true \
        "imagevalidatingpolicy/$POLICY" --timeout="${READY_TIMEOUT}s" >/dev/null 2>"$WORK/err"; then
    kube get "imagevalidatingpolicy/$POLICY" -o jsonpath='{.status}' 2>/dev/null; echo
    cannot_run "$rel: Kyverno never reported $POLICY ready, so its webhooks may not be
registered and an admitted pod would prove nothing."
  fi
}

# The overlay's policy, gone before the next overlay applies one of the same name.
retire_policy() {
  delete_within "its policy" -f "$rendered"
}

# The tag, rewritten, in the signed pod's init and main containers. The admitted
# object is the API server's response to the create, so the digest in it can
# only have been written by admission. The admitted pod is where the ephemeral
# containers are added, and it is deleted after them: the next overlay creates
# the same pod.
check_signed_pod() {
  local admitted admitted_init admitted_main pair field image
  mark_sent
  if ! admitted="$(kube create -f "$SUITE/pod.yaml" -o jsonpath='{.spec.initContainers[0].image} {.spec.containers[0].image}' 2>"$WORK/err")"; then
    refused_release_signed "the signed pod" "denied the release-signed $TAGGED, so no digest was written"
    return 0
  fi
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
  check_signed_ephemeral
  check_foreign_ephemeral
  delete_within "the signed pod" -f "$SUITE/pod.yaml"
}

# The signed tag as an ephemeral container, through the subresource that alone
# adds one, pinned.
check_signed_ephemeral() {
  local ephemeral
  mark_sent
  if ephemeral="$(kube patch pod "$POD" -n "$POD_NS" --subresource=ephemeralcontainers \
        --type=strategic -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"pinned\",\"image\":\"$TAGGED\"}]}}" \
        -o jsonpath='{.spec.ephemeralContainers[0].image}' 2>"$WORK/err")"; then
    if pinned "$ephemeral"; then
      echo "  ok    admitted $TAGGED as an ephemeral container as $ephemeral"
    else
      fail=1
      echo "  FAIL  admitted $TAGGED as an ephemeral container as '$ephemeral', with"
      echo "        no digest joined to the tag."
    fi
  else
    refused_release_signed "the signed ephemeral container" \
      "refused the release-signed $TAGGED as an ephemeral container"
  fi
}

# The branch-signed image as an ephemeral container, decided as the
# branch-signed pod is.
check_foreign_ephemeral() {
  local outcome=refused
  mark_sent
  kube patch pod "$POD" -n "$POD_NS" --subresource=ephemeralcontainers \
      --type=strategic -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"foreign\",\"image\":\"$FOREIGN\"}]}}" \
      -o name >/dev/null 2>"$WORK/err" && outcome=admitted
  decide_foreign "the branch-signed ephemeral container" "$outcome"
}

# The Deployment, stored as git wrote it; the pod it creates, pinned. A pod
# left from an earlier overlay would answer for this one, so none may remain:
# the wait bounds how long one may take to go, and the listing after it is what
# establishes that none is left. The wait's own status is not read, because a
# selector matching nothing is not a failure to delete.
check_deployment() {
  local left stored created deadline
  kube wait --for=delete pod -n "$DEPLOYMENT_NS" -l "app.kubernetes.io/name=$DEPLOYMENT" \
    --timeout="${DELETE_TIMEOUT}s" >/dev/null 2>&1
  left="$(kube get pod -n "$DEPLOYMENT_NS" -l "app.kubernetes.io/name=$DEPLOYMENT" \
    -o name 2>"$WORK/err")" \
    || cannot_run "$rel: the Deployment's pods could not be listed — $(head -1 "$WORK/err")"
  [ -z "$left" ] || cannot_run "$rel: $left from an earlier overlay was still present after
${DELETE_TIMEOUT}s, so it would answer for this overlay's Deployment."
  mark_sent
  if ! stored="$(kube create -f "$SUITE/deployment.yaml" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>"$WORK/err")"; then
    refused_release_signed "the Deployment" "refused the Deployment of the release-signed $TAGGED"
    return 0
  fi
  if [ "$stored" = "$TAGGED" ]; then
    echo "  ok    stored the Deployment's pod template as written ($TAGGED)"
  else
    fail=1
    echo "  FAIL  stored the Deployment's pod template as '$stored', not as written."
    echo "        ArgoCD compares that template with git, so every nanohype workload"
    echo "        it syncs reads as drift, and selfHeal and admission rewrite it in turn."
  fi
  created=""
  deadline=$(( $(date +%s) + CREATE_TIMEOUT ))
  while :; do
    created="$(kube get pod -n "$DEPLOYMENT_NS" -l "app.kubernetes.io/name=$DEPLOYMENT" \
      -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null)"
    [ -n "$created" ] && break
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 2
  done
  if [ -z "$created" ]; then
    # The ReplicaSet's refusals are its FailedCreate events.
    kube get events -n "$DEPLOYMENT_NS" --field-selector reason=FailedCreate \
      -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' >"$WORK/err" 2>"$WORK/events.err" \
      || cannot_run "$rel: the Deployment's events could not be read — $(head -1 "$WORK/events.err")"
    refused_release_signed "the Deployment's pod" \
      "the Deployment's ReplicaSet created no pod within ${CREATE_TIMEOUT}s"
  elif pinned "$created"; then
    echo "  ok    admitted the Deployment's pod as $created"
  else
    fail=1
    echo "  FAIL  admitted the Deployment's pod as '$created', with no digest joined"
    echo "        to the tag. A controller-created pod is the one that runs, and it"
    echo "        must carry the digest admission verified."
  fi
  delete_within "the Deployment" -f "$SUITE/deployment.yaml" --cascade=foreground
}

# The identity, decided. Deny refuses it; Audit admits and reports it.
check_foreign_pod() {
  mark_sent
  if kube create -f "$SUITE/branch-signed.yaml" -o name >/dev/null 2>"$WORK/err"; then
    decide_foreign "the branch-signed image" admitted
    delete_within "the branch-signed pod" -f "$SUITE/branch-signed.yaml"
  else
    decide_foreign "the branch-signed image" refused
  fi
}

# Sourced, this file defines the functions above and runs nothing, so
# scripts/tests/test_digest_rewrite.py can decide a verdict without a cluster.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
  return 0
fi

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
# GNU coreutils' timeout bounds kind and helm, whose own flags bound their waits
# but not the image pull or the chart fetch before them. macOS ships it under
# neither name: Homebrew's coreutils installs it as gtimeout.
TIMEOUT_CMD="$(command -v timeout || command -v gtimeout)"
[ -n "$TIMEOUT_CMD" ] \
  || cannot_run "neither timeout nor gtimeout is on PATH, so kind and helm would run
unbounded. On macOS, \`brew install coreutils\` installs gtimeout."

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
  "$TIMEOUT_CMD" -k "$KILL_TIMEOUT" "$KIND_TIMEOUT" \
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "── kind $NODE_IMAGE, kyverno chart $CHART_VERSION"
"$TIMEOUT_CMD" -k "$KILL_TIMEOUT" "$KIND_TIMEOUT" \
    kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait "${READY_TIMEOUT}s" \
    >"$WORK/kind.log" 2>&1 \
  || { tail -20 "$WORK/kind.log"; cannot_run "kind could not create the cluster."; }

helm_args=()
for v in "${VALUES[@]}"; do helm_args+=(-f "$v"); done
"$TIMEOUT_CMD" -k "$KILL_TIMEOUT" "$HELM_TIMEOUT" \
    helm install kyverno kyverno --repo "$CHART_REPO" --version "$CHART_VERSION" \
    --namespace kyverno --create-namespace "${helm_args[@]}" \
    --wait --timeout "${HELM_TIMEOUT}s" >"$WORK/helm.log" 2>&1 \
  || { tail -20 "$WORK/helm.log"; cannot_run "Kyverno $CHART_VERSION did not install."; }

# The namespaces the fixtures name.
for f in "$SUITE"/*.yaml; do
  ns="$(sed -n 's/^  namespace: *\([^ ]*\) *$/\1/p' "$f" | head -1)"
  [ -n "$ns" ] || continue
  kube create namespace "$ns" --dry-run=client -o yaml | kube apply -f - >/dev/null 2>"$WORK/err" \
    || cannot_run "the namespace $ns could not be created — $(head -1 "$WORK/err")"
done

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

  install_policy
  echo "── $rel (validationActions: $actions)"
  check_signed_pod
  check_deployment
  check_foreign_pod
  retire_policy
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
