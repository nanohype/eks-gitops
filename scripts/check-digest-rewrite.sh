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
# failure on that path, on the API server's call to the admission webhook or on
# kubectl's request to the API server, each named as the one it was; an
# admission controller log that cannot be read; or the identity message with no
# verifier line behind it. Each is a verification whose outcome is unknown, not
# a rewrite that stopped and not an identity decided.
#
# This script makes the requests and reads what came back; scripts/verdicts.py
# decides what each answer means, the pin, the identity and a refusal's cause,
# with the one transport-failure pattern scripts/kyverno-test.sh reads through
# too. scripts/tests/test_verdicts.py holds those decisions without a cluster.
#
# Every step is bounded, each on its own: a request that returns an answer by
# REQUEST_TIMEOUT, a wait by its own *_TIMEOUT under a GNU timeout above it, and
# kind and helm by GNU timeout. A step that stops answering ends on this
# script's diagnostic.
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
VERDICTS="$ROOT/scripts/verdicts.py"

# Seconds one kubectl request that returns an answer may take: a create, get,
# patch or apply, or a read of the verifier's log. A create reaching
# verify-images' mutating and validating webhooks can take a minute, since the
# API server gives each webhook at most 30s, and the API server answers every
# such request but the log read inside its own one-minute deadline; the log
# read is minutes of one controller's log at most. This sits above both, so a
# request the server is still working on gets the server's answer, and one
# whose connection stopped answering ends here.
#
# kubectl's --request-timeout is client-go's http.Client.Timeout, which covers
# the whole exchange, a watch's stream included: it ends a watch connection at
# that many seconds whether or not the connection is answering. A wait
# therefore never runs under it; kube_wait bounds it instead.
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
# Seconds the verifier's log is read from before a request was sent, because
# `date +%s` truncates both ends of the window to the second. An earlier
# request's transport failure inside that slack can only turn a decision into a
# run that could not decide.
LOG_SLACK=5

cannot_run() {
  printf '%s\n' "Cannot run: $*"
  exit 2
}

# What a status from scripts/verdicts.py means here: $1 is the status and $2 the
# question it answered. A finding sets fail, and a run that could not decide ends
# here. No interpreter failure exits 0, 3 or 4, so a traceback, or a python3
# that did not start, ends the run as one that could not decide.
act_on() {
  case "$1" in
    0) ;;
    3) fail=1 ;;
    2) exit 2 ;;
    *) cannot_run "scripts/verdicts.py exited $1 answering $2, so no verdict was reached." ;;
  esac
}

# scripts/verdicts.py's answer to the question its arguments ask, acted on.
verdict() {
  python3 "$VERDICTS" "$@"
  act_on "$?" "$1"
}

# A verdict on the request mark_sent marked, whose refusal, when it was refused,
# is in $WORK/err. Every refusal this script decides comes through here, so one
# rule holds on every path: verdicts.py establishes its cause first, from the
# refusal and, where the refusal does not name one, from the verifier's log read
# for it. It asks for that log by exiting 4 rather than being handed it, so a
# request kubectl got no answer for is never followed by a read of a log no
# admission wrote to.
decide() {
  local rc
  local -a args=("$@" --overlay="$rel" --root="$ROOT" --request-timeout="$REQUEST_TIMEOUT"
                 --refusal="$WORK/err")
  python3 "$VERDICTS" "${args[@]}"
  rc=$?
  if [ "$rc" -eq 4 ]; then
    read_verifier_log
    python3 "$VERDICTS" "${args[@]}" --log="$WORK/log"
    rc=$?
  fi
  act_on "$rc" "$1"
}

# The remaining arguments, run under GNU timeout: TERM after $1 seconds, and a
# kill KILL_TIMEOUT seconds after that to a command still going. A command the
# bound ended has written nothing that says so, so the line verdicts.py words
# for it goes to standard error, where the caller's diagnostic reads it.
bounded() {
  local seconds="$1" rc
  shift
  "$TIMEOUT_CMD" -k "$KILL_TIMEOUT" "$seconds" "$@"
  rc=$?
  python3 "$VERDICTS" bound --command="$1" --status="$rc" --seconds="$seconds" >&2
  return "$rc"
}

# kubectl for a request that returns an answer, bounded by REQUEST_TIMEOUT.
# Every kubectl call in this script goes through here or through kube_wait.
kube() {
  kubectl --request-timeout="${REQUEST_TIMEOUT}s" "$@"
}

# kubectl for a command that waits, `wait` or `delete --wait`. $1 is the wait's
# own bound in seconds, handed to it as --timeout, which cancels the watch the
# wait reads. Under --request-timeout each watch connection would also end at
# REQUEST_TIMEOUT, answering or not, and the wait would run its course only by
# kubectl reopening its watch. So it runs without one, and GNU timeout bounds
# the command as a whole REQUEST_TIMEOUT above its own bound: room for the
# requests it sends before its wait begins, so the wait's own diagnostic comes
# first, and a connection that stops answering still ends.
kube_wait() {
  local seconds="$1"
  shift
  bounded "$(( seconds + REQUEST_TIMEOUT ))" kubectl "$@" --timeout="${seconds}s"
}

# The moment a request goes to the API server, taken before it is sent.
mark_sent() {
  sent="$(date +%s)"
}

# What every admission-controller replica logged from LOG_SLACK seconds before
# the request marked $sent until this read, into $WORK/log. That window holds
# the request's own line, because a failed verification is logged before the
# refusal returns, and any line another request logged inside it: one naming a
# transport failure can only end the run as one that could not decide, and any
# other verifier line shows the log read is the verifier's. verdicts.py keeps
# the verifier's lines and sets the controller's own aside.
#
# Given a selector, kubectl logs prints ten lines a pod unless --tail says
# otherwise, and a selector matching no pod prints nothing and exits 0; an
# identity refusal is decided only beside a verifier line for that reason. A log
# that cannot be read, inside REQUEST_TIMEOUT or at all, leaves a refusal's cause
# unknown, so the run cannot decide it.
read_verifier_log() {
  if kube logs -n "$VERIFIER_NS" -l "$VERIFIER_PODS" --tail=-1 \
       --since="$(( $(date +%s) - sent + LOG_SLACK ))s" >"$WORK/log" 2>"$WORK/log.err"; then
    return 0
  fi
  sed 's/^/        /' "$WORK/log.err" | cut -c1-240
  cannot_run "$rel: the admission controller's log could not be read, so whether a
refusal was the policy deciding or an outage on the verification path is unknown."
}

# Deletes what the remaining arguments name and waits for it to go. Anything
# still present after DELETE_TIMEOUT ends the run, because the next step would
# meet it: a pod of the same name refused as already existing reads as a tier
# denying a signed image, and a policy of the same name leaves which overlay
# decides the next admissions unknown. $1 names it.
delete_within() {
  local what="$1"
  shift
  kube_wait "$DELETE_TIMEOUT" delete "$@" --wait=true >/dev/null 2>"$WORK/err" \
    || cannot_run "$rel: $what was not deleted within ${DELETE_TIMEOUT}s — $(head -1 "$WORK/err")"
}

# The overlay rendered at $rendered, applied, and reported ready by Kyverno: an
# admission before that would not establish its webhooks are registered.
install_policy() {
  kube apply --server-side -f "$rendered" >/dev/null 2>"$WORK/err" \
    || cannot_run "the API server refused $rel — $(head -1 "$WORK/err")"
  if ! kube_wait "$READY_TIMEOUT" wait --for=jsonpath='{.status.conditionStatus.ready}'=true \
        "imagevalidatingpolicy/$POLICY" >/dev/null 2>"$WORK/err"; then
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
  local admitted admitted_init admitted_main
  mark_sent
  if ! admitted="$(kube create -f "$SUITE/pod.yaml" -o jsonpath='{.spec.initContainers[0].image} {.spec.containers[0].image}' 2>"$WORK/err")"; then
    decide release-signed --what="the signed pod" \
      --means="denied the release-signed $TAGGED, so no digest was written"
    return 0
  fi
  read -r admitted_init admitted_main <<<"$admitted"
  verdict pinned --site=init-container --tagged="$TAGGED" --image="${admitted_init:-}"
  verdict pinned --site=container --tagged="$TAGGED" --image="${admitted_main:-}"
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
    verdict pinned --site=ephemeral-container --tagged="$TAGGED" --image="$ephemeral"
  else
    decide release-signed --what="the signed ephemeral container" \
      --means="refused the release-signed $TAGGED as an ephemeral container"
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
  decide foreign-identity --what="the branch-signed ephemeral container" \
    --outcome="$outcome" --actions="$actions"
}

# The Deployment, stored as git wrote it; the pod it creates, pinned. A pod
# left from an earlier overlay would answer for this one, so none may remain:
# the wait bounds how long one may take to go, and the listing after it is what
# establishes that none is left. The wait's own status is not read, because a
# selector matching nothing is not a failure to delete.
check_deployment() {
  local left stored created deadline
  kube_wait "$DELETE_TIMEOUT" wait --for=delete pod -n "$DEPLOYMENT_NS" \
    -l "app.kubernetes.io/name=$DEPLOYMENT" >/dev/null 2>&1
  left="$(kube get pod -n "$DEPLOYMENT_NS" -l "app.kubernetes.io/name=$DEPLOYMENT" \
    -o name 2>"$WORK/err")" \
    || cannot_run "$rel: the Deployment's pods could not be listed — $(head -1 "$WORK/err")"
  [ -z "$left" ] || cannot_run "$rel: $left from an earlier overlay was still present after
${DELETE_TIMEOUT}s, so it would answer for this overlay's Deployment."
  mark_sent
  if ! stored="$(kube create -f "$SUITE/deployment.yaml" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>"$WORK/err")"; then
    decide release-signed --what="the Deployment" \
      --means="refused the Deployment of the release-signed $TAGGED"
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
    decide release-signed --what="the Deployment's pod" \
      --means="the Deployment's ReplicaSet created no pod within ${CREATE_TIMEOUT}s"
  else
    verdict pinned --site=deployment-pod --tagged="$TAGGED" --image="$created"
  fi
  delete_within "the Deployment" -f "$SUITE/deployment.yaml" --cascade=foreground
}

# The identity, decided. Deny refuses it; Audit admits and reports it.
check_foreign_pod() {
  mark_sent
  if kube create -f "$SUITE/branch-signed.yaml" -o name >/dev/null 2>"$WORK/err"; then
    decide foreign-identity --what="the branch-signed image" --outcome=admitted \
      --actions="$actions"
    delete_within "the branch-signed pod" -f "$SUITE/branch-signed.yaml"
  else
    decide foreign-identity --what="the branch-signed image" --outcome=refused \
      --actions="$actions"
  fi
}

# The cluster, on the pinned node image. kind's --wait bounds the control
# plane's readiness and not the node image pull before it, so GNU timeout
# bounds the command as a whole.
create_cluster() {
  bounded "$KIND_TIMEOUT" kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" \
      --wait "${READY_TIMEOUT}s" >"$WORK/kind.log" 2>&1 \
    || { tail -20 "$WORK/kind.log"; cannot_run "kind could not create the cluster."; }
}

# Kyverno, from the chart and values the catalog installs. helm's --timeout
# bounds its wait for the release and not the chart fetch before it, so GNU
# timeout bounds the command as a whole.
install_kyverno() {
  local helm_args=() v
  for v in "${VALUES[@]}"; do helm_args+=(-f "$v"); done
  bounded "$HELM_TIMEOUT" helm install kyverno kyverno --repo "$CHART_REPO" \
      --version "$CHART_VERSION" --namespace kyverno --create-namespace "${helm_args[@]}" \
      --wait --timeout "${HELM_TIMEOUT}s" >"$WORK/helm.log" 2>&1 \
    || { tail -20 "$WORK/helm.log"; cannot_run "Kyverno $CHART_VERSION did not install."; }
}

# Sourced, this file defines the functions above and runs nothing, so
# scripts/tests/test_digest_rewrite.py can drive each step without a cluster.
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
# GNU coreutils' timeout, which bounded runs kind, helm and every kubectl wait
# under. macOS ships it under neither name: Homebrew's coreutils installs it as
# gtimeout.
TIMEOUT_CMD="$(command -v timeout || command -v gtimeout)"
[ -n "$TIMEOUT_CMD" ] \
  || cannot_run "neither timeout nor gtimeout is on PATH, so kind, helm and the waits
would run unbounded. On macOS, \`brew install coreutils\` installs gtimeout."

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
  bounded "$KIND_TIMEOUT" kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" \
    >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "── kind $NODE_IMAGE, kyverno chart $CHART_VERSION"
create_cluster
install_kyverno

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
