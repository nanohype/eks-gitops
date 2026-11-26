#!/usr/bin/env bash
# The command every workflow's mask step runs first, in each job that receives an
# AWS account id or role ARN as a secret:
#
#   bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" [--optional] NAME...
#
# It registers every account id and IAM ARN in the named environment variables
# with the runner's log masker, before anything else in the job prints.
# scripts/mask-aws-ids.py does that work and holds what it masks, what it refuses
# and its self-test (`mask-aws-ids.sh --self-test`).
# scripts/check-workflow-id-masking.py holds every workflow to running this as
# the first command of the first step, in each job, that receives such a secret.
#
# Without python3 nothing is masked, so the step stops here, printing only an
# error annotation, and the job stops with it.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "::error title=python3 is not installed::mask-aws-ids.sh runs scripts/mask-aws-ids.py, so without python3 nothing is masked and this step stops here."
  exit 1
fi
exec python3 "$(dirname "${BASH_SOURCE[0]}")/mask-aws-ids.py" "$@"
