#!/usr/bin/env bash
# Re-verify every Tier-1 claim with the tool's OWN exit status.
#
# No pipe stands between a command and the status read from it. Every earlier
# reading that went through `| tail` or `| grep` and then `${PIPESTATUS[0]}`
# printed an EMPTY STRING under zsh, where the array is `pipestatus` and is
# 1-indexed. Those readings measured nothing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
SP="$(mktemp -d)"

# Backups live OUTSIDE $SP, and that placement is the whole fix. This harness
# plants defects in TRACKED files and restores them afterwards, so between mut
# and res the only copy of a file's original content is the backup. Keeping that
# copy inside the directory the cleanup removes meant the teardown destroyed the
# means of restoration: interrupt the run in that window — a timeout is enough —
# and the trap fired, deleted the scratch dir, and left a planted defect in the
# working tree with nothing able to put it back.
#
# The recovery in practice was `git checkout --`, which works only because these
# victims happen to be tracked. That is luck, not design, and it does not cover a
# harness that mutates something untracked.
BK="$(mktemp -d)"
OUT=$SP/rv.out

# Every file mutated this run, so restoration does not depend on reaching the
# matching `res` call.
MUT_FILES=()

_slot() { printf '%s' "$1" | tr '/' '_'; }

# Back a file up before mutating it. The first mutation of a file wins: a second
# mut on the same path must not overwrite the pristine copy with a mutated one.
mut() {
  local f="$1" s
  s="$(_slot "$f")"
  [ -e "$BK/$s" ] || cp "$f" "$BK/$s"
  case " ${MUT_FILES[*]:-} " in
    *" $f "*) ;;
    *) MUT_FILES+=("$f") ;;
  esac
}

# Idempotent by construction: restoring from the pristine copy is repeatable, so
# an explicit res followed by the trap's sweep is a no-op rather than a conflict.
# Also recreates a file the harness DELETED, which one case does.
res() {
  local f="$1" s
  s="$(_slot "$f")"
  [ -e "$BK/$s" ] && cp "$BK/$s" "$f"
  return 0
}

# Files this harness CREATES rather than edits. mut/res restore a tracked file
# from a backup taken before the edit; a file that did not exist has no backup,
# and leaving one behind after an interrupt makes the next run measure a tree
# nobody wrote. So creation is registered and the same trap removes it.
NEW_FILES=()
add_file() { NEW_FILES+=("$1"); }
drop_file() { rm -f "$1"; }

restore_all() {
  local f
  for f in "${NEW_FILES[@]:-}"; do [ -n "$f" ] && rm -f "$f"; done
  NEW_FILES=()
  [ "${#MUT_FILES[@]}" -eq 0 ] && return 0
  for f in "${MUT_FILES[@]}"; do res "$f"; done
}

# Restore BEFORE removing anything, and on the signals a timeout or a Ctrl-C
# actually sends — not EXIT alone, which a killed shell never reaches for TERM.
cleanup() { restore_all; rm -rf "$SP" "$BK"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
pass=0; fail=0

# run <want> <label> <cmd...>
#
# 126 and 127 EXACTLY are "not executable" and "not found" — the tool never ran.
# Scoring either as a rejection is the crash-scores-as-catch defect wearing a
# shell costume, and the first draft of this harness did exactly that: an
# off-by-one shift ate the command name and five 127s were reported as green
# rejections.
#
# Only those two. A first draft of the fix rejected everything at or above 126
# and then misread `task`'s own aggregate failure code, 201, as a missing
# binary — a harness rule too broad is its own kind of wrong answer.
run() {
  local want="$1" label="$2"; shift 2
  "$@" >"$OUT" 2>&1
  local rc=$?
  if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
    printf "  HARNESS %-50s rc=%s — the tool did not run; this is not a verdict\n" "$label" "$rc"
    sed -n '1,3p' "$OUT" | sed 's/^/          /'
    fail=$((fail+1)); return
  fi
  # grep answers four ways: 0 matched, 1 definitely did not, >=2 the search
  # itself failed, 127 absent. An `if grep` has two branches, so everything
  # above 1 lands in the did-not-match one and an absent grep would delete this
  # crash check silently — the check that exists because a gate which CRASHES
  # exits non-zero and is otherwise indistinguishable from one that rejected the
  # tree. Require the definite outcome; treat anything else as harness failure
  # and name the status.
  grep -qE "Traceback \(most recent call last\)|^panic: " "$OUT"
  local grc=$?
  if [ "$grc" -eq 0 ]; then
    printf "  HARNESS %-50s rc=%s — CRASHED, not rejected\n" "$label" "$rc"
    fail=$((fail+1)); return
  elif [ "$grc" -ne 1 ]; then
    printf "  HARNESS %-50s crash-scan itself failed (grep exited %s); no verdict\n" "$label" "$grc"
    fail=$((fail+1)); return
  fi
  # On a FAIL the captured output is the only thing that can name a cause: the
  # branch itself carries a label and an integer, and `run 0 "task validate"`
  # fronts an aggregate of parallel gates where rc=1 does not say which one
  # rejected. $OUT is truncated by the next `run` and removed by the EXIT trap,
  # so a status printed without it is the last chance to know why.
  if [ "$want" = "nonzero" ]; then
    if [ "$rc" -ne 0 ]; then printf "  ok    %-52s rc=%s\n" "$label" "$rc"; pass=$((pass+1));
    else printf "  FAIL  %-52s rc=0 (wanted non-zero)\n" "$label"; sed 's/^/          /' "$OUT"; fail=$((fail+1)); fi
  else
    if [ "$rc" -eq "$want" ]; then printf "  ok    %-52s rc=%s\n" "$label" "$rc"; pass=$((pass+1));
    else printf "  FAIL  %-52s rc=%s (wanted %s)\n" "$label" "$rc" "$want"; sed 's/^/          /' "$OUT"; fail=$((fail+1)); fi
  fi
}

echo "── Clean tree: every gate must ACCEPT ──"
run 0 "task validate" task validate
run 0 "controls floor" ./scripts/tests/controls.py
run 0 "check-workflows.sh (zizmor)" ./scripts/check-workflows.sh
run 0 "check-image-pins.py" ./scripts/check-image-pins.py

# The same tree under the other helm stream shape. Some helm builds write the
# OCI pull report to stdout, where it lands in the manifest stream the gate
# parses and every OCI-sourced chart puts its own coordinates there; some write
# it to stderr, where nothing sees it. A gate reading one only is green on the
# machine that renders and red in the job that installs the other build, with
# nothing in the tree different — which is not a verdict about the tree.
#
# Reproduced rather than described: a shim runs the real helm and folds stderr
# into stdout, with a cold OCI cache, because helm reports nothing on a hit.
mkdir -p "$SP/oldhelm"
REAL_HELM="$(command -v helm)"
cat > "$SP/oldhelm/helm" <<SHIM
#!/usr/bin/env bash
exec "$REAL_HELM" "\$@" 2>&1
SHIM
chmod +x "$SP/oldhelm/helm"
run 0 "image-pins: a helm reporting OCI pulls on stdout" \
  env "PATH=$SP/oldhelm:$PATH" \
      "HELM_CACHE_HOME=$SP/oldhelm/cache" \
      "HELM_CONFIG_HOME=$SP/oldhelm/config" \
      "HELM_DATA_HOME=$SP/oldhelm/data" \
  ./scripts/check-image-pins.py
run 0 "check-renovate-coverage.py" ./scripts/check-renovate-coverage.py
run 0 "check-ai-config.py" ./scripts/check-ai-config.py
run 0 "check-alert-severity-routes.py" ./scripts/check-alert-severity-routes.py
run 0 "check-env-coverage.py" ./scripts/check-env-coverage.py
run 0 "check-burn-rate-budgets.py" ./scripts/check-burn-rate-budgets.py
run 0 "check-named-things.py" ./scripts/check-named-things.py
run 0 "check-policy-validity.py" ./scripts/check-policy-validity.py
run 0 "no-placeholders.sh" ./scripts/no-placeholders.sh
run 0 "check-platform-crs --self-test" ./scripts/check-platform-crs.py --self-test
run 0 "check-chart-deprecation --self-test" ./scripts/check-chart-deprecation.py --self-test
run 0 "kyverno test" kyverno test policies/kyverno/tests
run 0 "check-digest-rewrite.sh" ./scripts/check-digest-rewrite.sh
run 0 "gitleaks dir (CI invocation)" gitleaks dir . --redact
run 0 "yamllint" yamllint -c .yamllint.yaml .

echo
echo "── Known-bad fed in: every gate must REJECT ──"



F=addons/security/kyverno/values.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("""test:
  image:
    tag: v1.18.2
""","").replace("""  image:
    tag: v1.18.2
""","",1)
assert m!=s and "tag: v1.18.2" not in m, "mutation did not land"
p.write_text(m)
PY
run nonzero "image-pins: unpinned readiness-checker" ./scripts/check-image-pins.py
res $F

# What the gate cannot read is not therefore absent, and the two ways it can
# fail to read are two verdicts. A reference the classifier cannot place is a
# chart that rendered and a question this gate owes an answer to; a chart that
# did not render leaves the fleet's image set unknown.
#
# The digest form is the one the gate's own remediation recommends. Written with
# no tag it matched neither tag alternative, so the whole reference yielded only
# its `sha256:<hex>` tail — a single-segment shape a declaration by that name
# passed over.
F=addons/networking/external-dns/values.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
a="podAnnotations:\n"
assert a in s, "podAnnotations anchor not found"
ref="ghcr.io/example/probe-worker@sha256:" + "9f8e" + "a"*60
m=s.replace(a, a + f'  probe/image: "{ref}"\n', 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print(f"   planted {ref[:52]}...")
PY
run nonzero "image-pins: a digest-only reference nothing declares" ./scripts/check-image-pins.py
res $F

# A chart that contributes no images and is DECLARED to contribute none, so the
# per-chart floor passes over it and the unrendered verdict is what is being
# read. Any other chart would be caught by the floor first, which would score
# this probe green for a reason it did not plant.
F=addons/ai-platform/envoy-ai-gateway-crds/values.yaml; mut $F
printf '\nbroken: [unclosed\n' >> $F
echo "   planted unparseable values for a chart declared imageless"
run nonzero "image-pins: a chart that did not render cannot report a clean fleet" ./scripts/check-image-pins.py
res $F

F=applicationsets/addons-agent-operator.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("oci://ghcr.io/nanohype/eks-agent-platform/charts/operator",
            "oci://ghcr.io/nanohype/eks-agent-platform/charts",1)
assert m!=s, "mutation did not land"
p.write_text(m)
PY
run nonzero "renovate-coverage: tidied OCI repoURL" ./scripts/check-renovate-coverage.py
res $F

# Coverage is REACH, not attribution. A manager on enabledManagers is one
# Renovate runs; managerFilePatterns decides which files it opens. Pointing one
# manager at a path this repo does not have is valid config that opens nothing —
# the schema passes, no lookup is attempted so the Dependency Dashboard reports
# nothing, and the only symptom is a version that stops moving. Each of these
# repoints ONE manager: repointing them all at once is a failure any pooled
# check would also catch, while repointing one leaves every other manager
# matching, which is the shape a pooled check reports as covered.
F=renovate.json; mut $F
python3 - "$F" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text())
c["pip-compile"]["managerFilePatterns"]=["/^locks/requirements\\.txt$/"]
p.write_text(json.dumps(c,indent=2)+"\n")
print("   pip-compile ->", c["pip-compile"]["managerFilePatterns"])
PY
run nonzero "renovate-coverage: pip-compile reaches no file" ./scripts/check-renovate-coverage.py
res $F

F=renovate.json; mut $F
python3 - "$F" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text())
c["customManagers"][0]["managerFilePatterns"]=["/^nowhere/[^/]+$/"]
p.write_text(json.dumps(c,indent=2)+"\n")
print("   customManagers[0] ->", c["customManagers"][0]["managerFilePatterns"])
PY
run nonzero "renovate-coverage: one customManager reaches no file" ./scripts/check-renovate-coverage.py
res $F

# A manager resting on the default shipped inside the Renovate package. The
# record scripts/renovate-manager-defaults.json holds is what makes these
# provable offline, and configuring one is how a repo narrows what it reads.
F=renovate.json; mut $F
python3 - "$F" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text())
c["github-actions"]={"managerFilePatterns":["/^workflows/[^/]+\\.ya?ml$/"]}
p.write_text(json.dumps(c,indent=2)+"\n")
print("   github-actions ->", c["github-actions"]["managerFilePatterns"])
PY
run nonzero "renovate-coverage: github-actions narrowed off .github/workflows" ./scripts/check-renovate-coverage.py
res $F

# The naturally-shaped one: no config edit at all. A job installs a second
# lockfile, two pins are derived from it, and the pip-compile pattern that
# reaches requirements.txt reaches nothing else.
F=.github/workflows/ci.yml; mut $F
add_file requirements-dev.txt
printf 'pytest==8.4.2\nhypothesis==6.140.3\n' > requirements-dev.txt
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
a="          pip install --require-hashes -r requirements.txt"
assert a in s, "install step anchor not found"
m=s.replace(a, a+"\n          pip install -r requirements-dev.txt", 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   added: pip install -r requirements-dev.txt")
PY
run nonzero "renovate-coverage: a second lockfile no pattern reaches" ./scripts/check-renovate-coverage.py
drop_file requirements-dev.txt
res $F

# A version file for a runtime nobody wrote a reader for. Recognised by shape,
# so it is SEEN and unattributable — which is a different answer from absent and
# exits 2 rather than passing over it. Ruby because this repository installs no
# Ruby: every runtime with a reader is one a workflow here resolves, so a probe
# has to name one that is not.
F=.github/workflows/ci.yml; mut $F
add_file .ruby-version
printf '3.4.1\n' > .ruby-version
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
a="      - name: No unfilled placeholders in deploy config\n"
assert a in s, "step anchor not found"
step=("      - name: Probe ruby setup\n"
      "        uses: ruby/setup-ruby@v1\n"
      "        with:\n"
      "          ruby-version-file: .ruby-version\n\n")
m=s.replace(a, step+a, 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   added: a setup-ruby step reading .ruby-version")
PY
run 2 "renovate-coverage: a version file for an unread runtime" ./scripts/check-renovate-coverage.py
drop_file .ruby-version
res $F

# The refusal, kept as its own probe because it is the one that holds when
# everything else is unavailable. scripts/check-renovate-defaults.mjs needs the
# Renovate package, which this repository does not vendor — so here it can
# resolve nothing, and the answer must be EXACTLY 2. Exit 0 would be a green run
# over nothing compared; exit 1 would call it a defect in a tree it never read.
run 2 "renovate-defaults: nothing resolved is a refusal, not a verdict" \
  node scripts/check-renovate-defaults.mjs

# The Node the renovate-coverage job installs is read from .node-version, and
# the coverage gate derives a pin from it. Delete the file the workflow names
# and what that step installs is unknown, which is not the same as unpinned.
F=.node-version; mut $F; rm -f $F
run 2 "renovate-coverage: the version file a setup step names is gone" \
  ./scripts/check-renovate-coverage.py
res $F

F=addons/ai-platform/agent-platform/base/platform.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("      modelId: us.anthropic.claude-sonnet-5",
            "      modelId: global.anthropic.claude-sonnet-5",1)
assert m!=s and "global.anthropic" in m, "mutation did not land"
p.write_text(m)
PY
run nonzero "ai-config: global. geo prefix" ./scripts/check-ai-config.py
res $F

# A rule labelled to page is asking for a human to be woken, and Grafana keeps
# that promise by matching the label against a route. Relabelled to a severity
# the tree does not route, the rule still parses, still evaluates and still
# changes state in the alert list — and falls to the root receiver instead of
# the destination it asked for. The rule and the policy never name each other,
# so nothing else in this tree can see it.
F=dashboards/base/alerting/agent-operator.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("        severity: page\n", "        severity: urgent\n", 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   relabelled one rule severity: page -> urgent")
PY
run nonzero "alert-severity-routes: a severity the tree does not route" \
  ./scripts/check-alert-severity-routes.py
res $F

# The other direction, and the one that rots: a destination nothing reaches.
F=dashboards/base/alerting/notification-policy.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("      - receiver: platform-page\n", "      - receiver: platform-paige\n", 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   misspelled the receiver one route delivers to")
PY
run nonzero "alert-severity-routes: a route to a contact point nobody declares" \
  ./scripts/check-alert-severity-routes.py
res $F

# The routing tree stops being delivered without moving, being edited, or
# failing to render. Every earlier check here still passes on this tree: the
# rules are labelled, the routes match, the contact points are declared. What a
# cluster receives is the rule groups and nothing to match them against.
F=dashboards/base/kustomization.yaml; mut $F
python3 - "$F" <<'PYX'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("  - alerting/notification-policy.yaml\n", "", 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   dropped the notification policy from the kustomization's resources")
PYX
run nonzero "alert-severity-routes: the routing tree stops shipping" \
  ./scripts/check-alert-severity-routes.py
res $F

# The number an on-call reads first. The expression stays correct and only the
# sentence changes, which is every rule-level validation's blind spot.
F=dashboards/base/alerting/agent-operator.yaml; mut $F
python3 - "$F" <<'PYX'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("budget burning slowest (10% in 3d)", "budget burning (100% over 3d)", 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   claimed the 3d tier consumes the whole budget")
PYX
run nonzero "burn-rate-budgets: a summary claiming a budget its expression does not spend" \
  ./scripts/check-burn-rate-budgets.py
res $F

# The other term, and the one that lives outside the alerting directory. The
# dashboard is unedited and still renders; it is simply no longer in the
# kustomization's resources. The rules ship and burn, the panel measuring what
# they burn against does not, and every figure is then anchored to a document no
# cluster receives.
F=dashboards/base/kustomization.yaml; mut $F
python3 - "$F" <<'PYZ'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("  - platform/agent-operator.yaml\n", "", 1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   dropped the panel measuring the objective from the kustomization")
PYZ
run nonzero "burn-rate-budgets: the panel measuring the objective stops shipping" \
  ./scripts/check-burn-rate-budgets.py
res $F

F=addons/bootstrap/cert-manager/values-hub.yaml; mut $F; rm -f $F
run nonzero "env-coverage: deleted hub delta" ./scripts/check-env-coverage.py
res $F

F=policies/kyverno/best-practices/base/require-labels.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("apiVersion: kyverno.io/v1","apiVersion: kyverno.io/vBOGUS",1)
assert m!=s, "mutation did not land"
p.write_text(m)
PY
run nonzero "policy-validity: kyverno discards the policy" ./scripts/check-policy-validity.py
res $F

F=docs/runbooks/troubleshooting.md; mut $F
printf '\nRun `task nonexistent-target-probe`.\n' >> $F
run nonzero "named-things: fabricated task target" ./scripts/check-named-things.py
res $F

# Planted in a TRACKED file, and restored after. An untracked probe file used
# to work and stopped the moment no-placeholders was scoped to `git ls-files`:
# the gate correctly ignored it, and this harness read that correct behaviour as
# the gate failing to reject. A fixture outside the population its gate examines
# tests nothing and reports a defect that is not there.
F=addons/operations/karpenter/values-development.yaml; mut $F
printf '\nrvProbe: REPLACE_ME\n' >> $F
run nonzero "no-placeholders: planted sentinel" ./scripts/no-placeholders.sh
res $F

# Assembled at run time rather than written as a literal. Committing a
# credential-shaped string makes the repo's own secret scan fail on the file
# that tests the secret scan — which is exactly what happened on the first
# attempt, caught by gitleaks in this same harness.
leak="ghp_$(printf '%s' '016C6e7Ab2Cd3Ef4Gh5Ij6Kl7Mn8Op9Qr0St1Uv')"
printf 'k = "%s"\n' "$leak" > ./rv-leak.yaml
run nonzero "gitleaks: planted GitHub PAT" gitleaks dir . --redact
rm -f ./rv-leak.yaml

printf 'a: 1\na: 2\nb: 3   \n' > ./rv-lint.yaml
run nonzero "yamllint: duplicate key + trailing space" yamllint -c .yamllint.yaml .
rm -f ./rv-lint.yaml

mkdir -p $SP/tbad
cat > $SP/tbad/bad.yaml <<'YAML'
apiVersion: v1
kind: Pod
metadata: {name: bad}
spec:
  hostNetwork: true
  containers:
    - name: c
      image: nginx:latest
      securityContext: {privileged: true, runAsUser: 0}
YAML
run nonzero "trivy config: privileged pod" trivy config --exit-code 1 --severity MEDIUM,HIGH,CRITICAL --quiet $SP/tbad

mkdir -p $SP/wbad/.github/workflows
cat > $SP/wbad/.github/workflows/bad.yml <<'YAML'
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
YAML
run nonzero "zizmor: unpinned action" ./scripts/check-workflows.sh $SP/wbad/.github/workflows

# renovate-config-validator is deliberately absent from this harness: it runs
# through `npx --package renovate`, which fetches the whole Renovate package and
# takes minutes. It is a CI-only gate, and this harness is meant to be runnable.
# Its rejection was proven by hand once (an invalid regex in a matchString ->
# rc=1) and that proof is recorded in the report, not re-run here.

F=policies/kyverno/networking/base/inject-adopt-lb-subnets.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=s.replace("alb.ingress.kubernetes.io/subnets","alb.ingress.kubernetes.io/subnets-MUT",1)
assert m!=s, "mutation did not land"
p.write_text(m)
PY
run nonzero "kyverno test: mutated injected annotation" kyverno test policies/kyverno/tests
res $F

# The digest rewrite is the whole reason the enforcing tier enforces, and it was
# a field value other files read rather than a behaviour anything ran. Turned
# off in the overlay, every gate that reads rendered YAML still passes: the
# field is gone, so nothing asserts it is true, and the pod is admitted with the
# tag it arrived with. Only executing the policy sees it.
F=policies/kyverno/supply-chain/overlays/production/kustomization.yaml; mut $F
python3 - "$F" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
m=re.sub(r'(path: /spec/rules/0/verifyImages/0/mutateDigest\n\s+value: )true', r'\1false', s, count=1)
assert m!=s, "mutation did not land"
p.write_text(m)
print("   production overlay: mutateDigest -> false")
PY
run nonzero "digest-rewrite: the enforcing tier stops pinning" ./scripts/check-digest-rewrite.sh
res $F

echo
echo "── Restored tree must be clean again ──"
run 0 "task validate (post)" task validate

echo
echo "RESULT pass=$pass fail=$fail"

# The harness owes the same assertion it demands of the gates: with every `run`
# line deleted it would report pass=0 fail=0 and exit 0, which is a green run
# over nothing checked.
MIN_CHECKS=44
total=$((pass + fail))
if [ "$total" -lt "$MIN_CHECKS" ]; then
  echo "FAIL  ran $total check(s), under the floor of $MIN_CHECKS — this harness"
  echo "      verified almost nothing, which is not the same as everything passing."
  exit 2
fi

[ "$fail" -eq 0 ]
