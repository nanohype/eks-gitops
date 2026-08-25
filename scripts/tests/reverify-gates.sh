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
trap 'rm -rf "$SP"' EXIT
OUT=$SP/rv.out
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
  if grep -qE "Traceback \(most recent call last\)|^panic: " "$OUT"; then
    printf "  HARNESS %-50s rc=%s — CRASHED, not rejected\n" "$label" "$rc"
    fail=$((fail+1)); return
  fi
  if [ "$want" = "nonzero" ]; then
    if [ "$rc" -ne 0 ]; then printf "  ok    %-52s rc=%s\n" "$label" "$rc"; pass=$((pass+1));
    else printf "  FAIL  %-52s rc=0 (wanted non-zero)\n" "$label"; fail=$((fail+1)); fi
  else
    if [ "$rc" -eq "$want" ]; then printf "  ok    %-52s rc=%s\n" "$label" "$rc"; pass=$((pass+1));
    else printf "  FAIL  %-52s rc=%s (wanted %s)\n" "$label" "$rc" "$want"; fail=$((fail+1)); fi
  fi
}

echo "── Clean tree: every gate must ACCEPT ──"
run 0 "task validate" task validate
run 0 "controls floor" ./scripts/tests/controls.py
run 0 "check-workflows.sh (zizmor)" ./scripts/check-workflows.sh
run 0 "check-image-pins.py" ./scripts/check-image-pins.py
run 0 "check-renovate-coverage.py" ./scripts/check-renovate-coverage.py
run 0 "check-ai-config.py" ./scripts/check-ai-config.py
run 0 "check-env-coverage.py" ./scripts/check-env-coverage.py
run 0 "check-named-things.py" ./scripts/check-named-things.py
run 0 "check-policy-validity.py" ./scripts/check-policy-validity.py
run 0 "no-placeholders.sh" ./scripts/no-placeholders.sh
run 0 "check-platform-crs --self-test" ./scripts/check-platform-crs.py --self-test
run 0 "check-chart-deprecation --self-test" ./scripts/check-chart-deprecation.py --self-test
run 0 "kyverno test" kyverno test policies/kyverno/tests
run 0 "gitleaks dir (CI invocation)" gitleaks dir . --redact
run 0 "yamllint" yamllint -c .yamllint.yaml .

echo
echo "── Known-bad fed in: every gate must REJECT ──"

mut() { cp "$1" "$SP/rv.bak"; }
res() { cp "$SP/rv.bak" "$1"; }

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

echo
echo "── Restored tree must be clean again ──"
run 0 "task validate (post)" task validate

echo
echo "RESULT pass=$pass fail=$fail"

# The harness owes the same assertion it demands of the gates: with every `run`
# line deleted it would report pass=0 fail=0 and exit 0, which is a green run
# over nothing checked.
MIN_CHECKS=25
total=$((pass + fail))
if [ "$total" -lt "$MIN_CHECKS" ]; then
  echo "FAIL  ran $total check(s), under the floor of $MIN_CHECKS — this harness"
  echo "      verified almost nothing, which is not the same as everything passing."
  exit 2
fi

[ "$fail" -eq 0 ]
