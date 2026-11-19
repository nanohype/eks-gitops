#!/usr/bin/env bash
# Registers every AWS account id and IAM ARN in the named environment variables
# with the GitHub Actions runner's log masker, before anything else in the job
# prints.
#
# WHY THIS EXISTS
#
# The repository is public, and so are its Actions logs. The workflows read AWS
# account ids and role ARNs: deploy.yml and destroy.yml DEPLOY_ROLE_ARN and
# DEPLOY_ACCOUNT_ID, ci.yml's plan job AWS_ROLE_ARN and TERRAGRUNT_ACCOUNT_ID,
# e2e.yml E2E_AWS_ROLE_ARN, drift.yml a JSON map of plan role ARNs.
#
# A GitHub Actions VARIABLE is never masked. The runner prints it in the env
# block of every step that receives it, and an action prints it among its
# inputs, before any step of the job has had a chance to mask anything. So each
# of those values is a SECRET on the GitHub Environment its job declares: the
# runner masks a secret's value as a whole, from the first line of the job.
#
# It does not mask a PART of one. The account id inside a role ARN, a role ARN
# taken out of a JSON map, the state bucket <account_id>-<region>-tfstate in a
# terragrunt error, an ARN in an AWS AccessDenied message: each would print in
# the clear. So each job's first step that receives one of these secrets runs
# this script as its first command, and every id and ARN is masked from the
# next line on, for the rest of the job: later output in that step, and every
# later step's env block, action inputs and output. Masks are per job, so each
# job that reads one runs it.
#
# WHAT IT MASKS, in every named value
#
#   - every twelve-digit window of every run of twelve or more digits, whether
#     or not the value is well formed: an id in a malformed value is still an
#     id, and an id inside a longer run is masked at whatever offset it starts.
#   - every IAM ARN (arn:aws:iam::<twelve digits>:<resource>), whole.
#   - when the value is JSON (drift.yml's role map), the same two in every key
#     and string after JSON decoding, so an ARN written with escapes is masked
#     in the form an action prints it. Only this pass needs jq: without it the
#     raw-text masks are registered and then the script refuses (exit 1).
#
# All of it happens before any refusal below is printed. It prints nothing but
# `::add-mask::` commands and, on refusal, `::error` annotations that name the
# variable and never any part of its value.
#
# WHAT IT REFUSES (exit 1)
#
#   - a value that spans more than one line, after leading and trailing
#     whitespace is trimmed. The runner masks each line of a multi-line secret
#     on its own, so a pretty-printed JSON map registers `{` and `}` as secrets
#     and every brace in the log turns to `***`; and a role ARN or account id
#     that carries a second line is not one. Store it on one line (`jq -c` for
#     a JSON value).
#   - an unset, empty or whitespace-only value, unless --optional is given.
#     --optional is for a caller that decides what an absent value means itself:
#     ci.yml's plan job skips when its pair is unset, and deploy.yml and
#     destroy.yml report each missing value with the environment it belongs on.
#
# USAGE
#
#   mask-aws-ids.sh NAME...              every NAME must be set
#   mask-aws-ids.sh --optional NAME...   an unset NAME is passed over
#   mask-aws-ids.sh --self-test          run the built-in cases (synthetic ids
#                                        only) against this script itself
#
# NAME is the name of an environment variable, never a value: a workflow passes
# the secret through the step's env map and names it here, so the value is
# never part of a command line. Exit 2 is a usage error.
#
# The self-test is what keeps this script honest. It is the only thing keeping
# account ids out of the public logs, and an edit that weakens it (a narrower
# id pattern, a refusal moved ahead of the masks, a stray echo) would otherwise
# pass every other gate and first show itself as ids in a log. ci.yml's
# workflow-id-masking job runs it on every pull request, and
# scripts/check-workflow-id-masking.py holds the other half: that every
# workflow runs this as the first command of the first step, in each job, that
# receives such a secret.
#
# drift.yml (until it is folded onto this script; see docs/threat-model.md)
# runs scripts/mask-drift-role-map.sh, which does the same for its one map.
# `mask-aws-ids.sh DRIFT_PLAN_ROLE_ARNS` is the drop-in replacement: required,
# single-line, every id at every offset in keys and values, every role ARN
# whole, ids masked before a refusal.
set -euo pipefail

# An IAM ARN, up to the first character no ARN resource carries (a quote, a
# backslash, whitespace). Anchored on the account segment, so a malformed
# resource part still masks the whole ARN-shaped run.
ARN_PATTERN='arn:aws:iam::[0-9]{12}:[A-Za-z0-9+=,.@_/:-]+'

usage() {
  echo "::error title=mask-aws-ids.sh usage::usage: mask-aws-ids.sh [--optional] NAME... | --self-test (NAME is an environment variable name)"
  exit 2
}

self_test() {
  local script tmp failures=0 cases=0
  script="${BASH_SOURCE[0]}"
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064 # expand now: tmp is fixed for this run
  trap "rm -rf '$tmp'" RETURN

  # run_case NAME EXPECTED_EXIT ENV-ASSIGNMENTS... -- ARGS...: runs the script
  # under `env -i` with only PATH and the given assignments, so nothing from
  # this shell's environment can stand in for a value under test. Leaves stdout
  # in $tmp/out and stderr in $tmp/err for the expectations after it.
  run_case() {
    local name=$1 want=$2 got=0
    shift 2
    local assigns=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
      assigns+=("$1")
      shift
    done
    [ "$#" -gt 0 ] && shift
    cases=$((cases + 1))
    env -i PATH="$PATH" ${assigns[@]+"${assigns[@]}"} bash "$script" "$@" >"$tmp/out" 2>"$tmp/err" || got=$?
    if [ "$got" -ne "$want" ]; then
      echo "FAIL [$name]: exit $got, want $want" >&2
      failures=$((failures + 1))
    fi
    if [ -s "$tmp/err" ]; then
      echo "FAIL [$name]: wrote to stderr" >&2
      failures=$((failures + 1))
    fi
    # Nothing but mask commands and error annotations.
    if grep -vqE '^::add-mask::|^::error( title=[^:]*)?::' "$tmp/out"; then
      echo "FAIL [$name]: printed a line that is neither ::add-mask:: nor ::error" >&2
      failures=$((failures + 1))
    fi
    # No error annotation carries an id or an ARN.
    if grep -E '^::error' "$tmp/out" | grep -qE '[0-9]{12}|arn:aws'; then
      echo "FAIL [$name]: an ::error line carries a twelve-digit run or an ARN" >&2
      failures=$((failures + 1))
    fi
  }
  expect_mask() {
    if ! grep -qxF "::add-mask::$2" "$tmp/out"; then
      echo "FAIL [$1]: no ::add-mask:: for a value that must be masked" >&2
      failures=$((failures + 1))
    fi
  }
  expect_count() {
    local got
    got=$(grep -cE "$2" "$tmp/out") || true
    if [ "$got" -ne "$3" ]; then
      echo "FAIL [$1]: $got line(s) matching $2, want $3" >&2
      failures=$((failures + 1))
    fi
  }
  expect_absent() {
    if grep -qF -- "$2" "$tmp/out"; then
      echo "FAIL [$1]: the output carries text it must never print" >&2
      failures=$((failures + 1))
    fi
  }
  # The masks come first and the refusal last, so the refusal is printed with
  # every id already registered.
  expect_masks_then_error() {
    if [ "$(head -n 1 "$tmp/out" | cut -c1-12)" != "::add-mask::" ] ||
      [ "$(tail -n 1 "$tmp/out" | cut -c1-7)" != "::error" ]; then
      echo "FAIL [$1]: the masks must come first and the refusal last" >&2
      failures=$((failures + 1))
    fi
  }

  # Synthetic ids only. None is an account anyone holds.
  local id1=222233334444 id2=555566667777
  local arn1="arn:aws:iam::${id1}:role/github-actions-deploy"
  local arn2="arn:aws:iam::${id2}:role/github-actions-plan"

  # deploy.yml: a role ARN and the account id it names.
  run_case deploy-pair 0 "DEPLOY_ROLE_ARN=$arn1" "DEPLOY_ACCOUNT_ID=$id1" -- DEPLOY_ROLE_ARN DEPLOY_ACCOUNT_ID
  expect_mask deploy-pair "$id1"
  expect_mask deploy-pair "$arn1"
  expect_count deploy-pair '^::add-mask::' 2
  expect_count deploy-pair '^::error' 0

  # Two accounts across two values: each id and each ARN, once.
  run_case two-accounts 0 "A_ROLE_ARN=$arn1" "B_ROLE_ARN=$arn2" -- A_ROLE_ARN B_ROLE_ARN
  expect_mask two-accounts "$id1"
  expect_mask two-accounts "$id2"
  expect_mask two-accounts "$arn1"
  expect_mask two-accounts "$arn2"
  expect_count two-accounts '^::add-mask::' 4

  # A trailing newline (gh secret set reading a file) is not a second line.
  run_case trailing-newline 0 "E2E_AWS_ROLE_ARN=$arn2"$'\n' -- E2E_AWS_ROLE_ARN
  expect_mask trailing-newline "$id2"
  expect_mask trailing-newline "$arn2"
  expect_count trailing-newline '^::error' 0

  # ci.yml's plan job on an unconfigured repository: nothing set, nothing to do.
  run_case optional-unset 0 -- --optional AWS_ROLE_ARN TERRAGRUNT_ACCOUNT_ID
  expect_count optional-unset '.' 0

  run_case optional-half 0 "TERRAGRUNT_ACCOUNT_ID=$id1" -- --optional AWS_ROLE_ARN TERRAGRUNT_ACCOUNT_ID
  expect_mask optional-half "$id1"
  expect_count optional-half '^::add-mask::' 1
  expect_count optional-half '^::error' 0

  run_case required-unset 1 -- E2E_AWS_ROLE_ARN
  expect_count required-unset '^::error' 1
  expect_count required-unset '^::add-mask::' 0

  run_case required-empty 1 "DEPLOY_ROLE_ARN=" -- DEPLOY_ROLE_ARN
  expect_count required-empty '^::error' 1

  run_case required-whitespace 1 $'DEPLOY_ROLE_ARN= \n\t ' -- DEPLOY_ROLE_ARN
  expect_count required-whitespace '^::error' 1

  # Several refusals are all reported, after every mask.
  run_case two-refusals 1 "A_ROLE_ARN=$arn1"$'\n'"x" -- A_ROLE_ARN B_ACCOUNT_ID
  expect_mask two-refusals "$id1"
  expect_count two-refusals '^::error' 2
  expect_masks_then_error two-refusals

  # A multi-line value is refused, and its ids are masked BEFORE the refusal,
  # optional or not.
  run_case multi-line 1 $'DRIFT_PLAN_ROLE_ARNS={\n  "network": "arn:aws:iam::313131313131:role/github-actions-plan"\n}' -- DRIFT_PLAN_ROLE_ARNS
  expect_mask multi-line 313131313131
  expect_mask multi-line arn:aws:iam::313131313131:role/github-actions-plan
  expect_count multi-line '^::error' 1
  expect_masks_then_error multi-line

  run_case multi-line-optional 1 "AWS_ROLE_ARN=$arn2"$'\n'"$arn1" -- --optional AWS_ROLE_ARN
  expect_mask multi-line-optional "$id1"
  expect_mask multi-line-optional "$id2"
  expect_count multi-line-optional '^::error' 1
  expect_masks_then_error multi-line-optional

  run_case carriage-return 1 $'DEPLOY_ACCOUNT_ID=414141414141\r1' -- DEPLOY_ACCOUNT_ID
  expect_mask carriage-return 414141414141
  expect_count carriage-return '^::error' 1

  # An id at any offset inside a longer digit run: every twelve-digit window.
  local long=314159265358979323846264 i
  run_case long-run 0 "TERRAGRUNT_ACCOUNT_ID=x${long}y" -- TERRAGRUNT_ACCOUNT_ID
  for ((i = 0; i + 12 <= ${#long}; i++)); do
    expect_mask long-run "${long:i:12}"
  done
  expect_count long-run '^::add-mask::' 13

  # drift.yml's role map: ids in keys and values, each role ARN whole.
  run_case role-map 0 "DRIFT_PLAN_ROLE_ARNS={\"workload-staging\":\"$arn1\",\"444455556666\":\"$arn2\"}" -- DRIFT_PLAN_ROLE_ARNS
  expect_mask role-map "$id1"
  expect_mask role-map "$id2"
  expect_mask role-map 444455556666
  expect_mask role-map "$arn1"
  expect_mask role-map "$arn2"
  expect_count role-map '^::add-mask::' 5
  expect_count role-map '^::error' 0

  # An ARN written with JSON escapes is masked in its decoded form too, the form
  # configure-aws-credentials would print it in.
  run_case json-escaped 0 'DRIFT_PLAN_ROLE_ARNS={"network":"arn:aws:iam::616161616161:role\/github-actions-plan"}' -- DRIFT_PLAN_ROLE_ARNS
  expect_mask json-escaped 616161616161
  expect_mask json-escaped arn:aws:iam::616161616161:role/github-actions-plan

  # Every IAM ARN, not only roles, and an id in a value that is not JSON.
  run_case not-json 0 "X_ROLE_ARN=see arn:aws:iam::717171717171:user/someone and 818181818181" -- X_ROLE_ARN
  expect_mask not-json 717171717171
  expect_mask not-json 818181818181
  expect_mask not-json arn:aws:iam::717171717171:user/someone
  expect_count not-json '^::add-mask::' 3

  # The value itself is never printed, even where it holds no id to mask.
  run_case never-echoed 0 "X_ACCOUNT_ID=not-an-id-SENTINEL-value" -- X_ACCOUNT_ID
  expect_absent never-echoed SENTINEL
  expect_count never-echoed '.' 0
  run_case never-echoed-refusal 1 $'X_ACCOUNT_ID=SENTINEL\nSENTINEL' -- X_ACCOUNT_ID
  expect_absent never-echoed-refusal SENTINEL
  expect_count never-echoed-refusal '^::error' 1

  # Without jq, the raw-text masks are still registered, before the refusal.
  local nojq="$tmp/nojq-bin" tool
  mkdir -p "$nojq"
  for tool in bash grep sort; do
    ln -s "$(command -v "$tool")" "$nojq/$tool"
  done
  run_case no-jq 1 "PATH=$nojq" "DEPLOY_ROLE_ARN=$arn1" "DEPLOY_ACCOUNT_ID=$id1" -- DEPLOY_ROLE_ARN DEPLOY_ACCOUNT_ID
  expect_mask no-jq "$id1"
  expect_mask no-jq "$arn1"
  expect_count no-jq '^::add-mask::' 2
  expect_count no-jq '^::error' 1
  expect_masks_then_error no-jq

  # Usage errors.
  run_case no-names 2 --
  run_case only-flag 2 -- --optional
  run_case bad-name 2 -- 'DEPLOY_ROLE_ARN;echo'
  run_case unknown-flag 2 -- --mask-everything DEPLOY_ROLE_ARN

  if [ "$failures" -ne 0 ]; then
    echo "mask-aws-ids self-test FAILED: $failures assertion(s) over $cases case(s)" >&2
    return 1
  fi
  if [ "$cases" -lt 20 ]; then
    echo "mask-aws-ids self-test ran only $cases case(s); refusing to report a pass" >&2
    return 1
  fi
  echo "mask-aws-ids self-test passed ($cases cases)."
}

if [ "${1-}" = "--self-test" ]; then
  [ "$#" -eq 1 ] || usage
  self_test
  exit $?
fi

optional=false
if [ "${1-}" = "--optional" ]; then
  optional=true
  shift
fi
[ "$#" -gt 0 ] || usage
for name in "$@"; do
  [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || usage
done

# The masks for one text: every twelve-digit window of every run of twelve or
# more digits, and every IAM ARN whole, one per line.
masks_in() {
  {
    printf '%s' "$1" | grep -oE '[0-9]{12,}' | while IFS= read -r run; do
      for ((i = 0; i + 12 <= ${#run}; i++)); do
        printf '%s\n' "${run:i:12}"
      done
    done
    printf '%s' "$1" | grep -oE "$ARN_PATTERN"
  } | sort -u
}

# Registers each line of $1 not registered already.
registered=""
register() {
  local mask
  [ -n "$1" ] || return 0
  while IFS= read -r mask; do
    case $'\n'"$registered" in
      *$'\n'"$mask"$'\n'*) continue ;;
    esac
    echo "::add-mask::${mask}"
    registered+="$mask"$'\n'
  done <<<"$1"
}

# Every value, trimmed of leading and trailing whitespace: one text the two
# patterns run over.
corpus=""
for name in "$@"; do
  raw="${!name-}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  [ -n "$raw" ] || continue
  corpus+="$raw"$'\n'
done

# Masks first: they need no parse, no validity and nothing but grep, and they
# must all be registered before any refusal is printed.
register "$(masks_in "$corpus")"

# Then the same over every key and string of each value that is JSON, after
# decoding, so an ARN written with escapes is masked in the form an action
# prints it. This pass alone needs jq; without it the step stops, with every
# mask above already registered.
if ! command -v jq >/dev/null 2>&1; then
  echo "::error title=jq is not installed::mask-aws-ids.sh needs jq to read JSON values. Every account id and ARN in their raw text is masked; their JSON-decoded forms are not, so this step stops here."
  exit 1
fi
decoded_corpus=""
for name in "$@"; do
  raw="${!name-}"
  [ -n "${raw//[[:space:]]/}" ] || continue
  if decoded=$(printf '%s' "$raw" | jq -r '.. | (strings, (objects | keys[]))' 2>/dev/null); then
    decoded_corpus+="$decoded"$'\n'
  fi
done
register "$(masks_in "$decoded_corpus")"

# Then the refusals, every one of them, naming the variable and nothing of its
# value.
failed=0
for name in "$@"; do
  raw="${!name-}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  if [ -z "$raw" ]; then
    if [ "$optional" = false ]; then
      echo "::error title=${name} is not set::${name} is unset or empty. It is a secret on the GitHub Environment this job declares, and this step cannot run without it (see docs/operations.md)."
      failed=1
    fi
    continue
  fi
  case "$raw" in
    *$'\n'* | *$'\r'*)
      echo "::error title=${name} spans several lines::${name} holds more than one line. The runner masks each line of a multi-line secret separately, and no account id or role ARN spans lines. Store it on one line (pipe a JSON value through jq -c; see docs/operations.md)."
      failed=1
      ;;
  esac
done
exit "$failed"
