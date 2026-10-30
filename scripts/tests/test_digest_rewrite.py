"""Unit tests for the steps scripts/check-digest-rewrite.sh takes, and what each concludes.

The script admits a signed pod, its ephemeral containers, a Deployment and a
branch-signed pod through each rendered supply-chain overlay, on a kind cluster
that only CI brings up. Each of those steps is a function, and sourcing the
script defines them without running anything. These source it and hand each
step the answers an overlay can give: admitted or refused, under Deny or Audit,
and refused for the policy's identity message, a transport failure, or another
reason.

A transport failure inside verification refuses with the policy's own message,
and only the verifier's log names it, so a refusal is also decided on what the
admission controller logged. Stubs named kubectl, date and sleep, first on PATH,
stand in for the cluster and the clock: kubectl answers each call from files
named for it and records the call, and the clock moves only when a request is
sent or the script sleeps. Stubs named timeout, kind and helm record what runs
under a bound and what the bound was.

Each step hands what it read to scripts/verdicts.py, which decides it, and
scripts/tests/test_verdicts.py holds each decision on its own. These hold every
step to the decision it reaches through the script: what the script asks, and
what it reads before and after asking. scripts/kyverno-test.sh hands its runs
to the same module, so both gates read transport failures through one pattern.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml
from gateloader import load
from shellgate import ESC, identity_message, setting, verifier_line

verdicts = load("verdicts")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check-digest-rewrite.sh"
KYVERNO_TEST = ROOT / "scripts" / "kyverno-test.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"

IDENTITY = identity_message()

REQUEST_TIMEOUT = setting(SCRIPT, "REQUEST_TIMEOUT")
READY_TIMEOUT = setting(SCRIPT, "READY_TIMEOUT")
DELETE_TIMEOUT = setting(SCRIPT, "DELETE_TIMEOUT")
CREATE_TIMEOUT = setting(SCRIPT, "CREATE_TIMEOUT")
KIND_TIMEOUT = setting(SCRIPT, "KIND_TIMEOUT")
HELM_TIMEOUT = setting(SCRIPT, "HELM_TIMEOUT")
KILL_TIMEOUT = setting(SCRIPT, "KILL_TIMEOUT")

# What the main body reads out of the fixtures, the appset and ci.yml, set by
# hand: a tag, a foreign image pinned by digest, and the cluster and chart.
TAGGED = "ghcr.io/nanohype/x:1.0.0"
FOREIGN = f"ghcr.io/nanohype/x@sha256:{'0' * 64}"
PINNED = f"{TAGGED}@sha256:{'a' * 64}"
CHART_VERSION = "0.0.0"

PRELUDE = f"""
source "$1" || exit 99
WORK="$2" rel=overlays/tier actions="$3" fail=0 rendered="$2/policy.yaml"
TAGGED={TAGGED} FOREIGN={FOREIGN}
POD=signed POD_NS=workloads DEPLOYMENT=signed-deployment DEPLOYMENT_NS=workloads
TIMEOUT_CMD="$2/bin/timeout" CLUSTER=digest-rewrite-test NODE_IMAGE=kindest/node@sha256:{'b' * 64}
CHART_REPO=https://kyverno.github.io/kyverno CHART_VERSION={CHART_VERSION} VALUES=("$2/values.yaml")
"""

# The clock's reading when a run starts, and the seconds it moves across each
# create or patch: a request the API server takes that long to answer.
START = 1000
STEP = 10

# The wait for the Deployment's pod, shortened where the length of the wait is
# not what a test reads: each poll is a few stub processes.
SHORT_CREATE_TIMEOUT = 4

# Bash builtins only, so it answers the same whatever else is on PATH. A call is
# keyed by its subcommand and what it names: the fixture a -f reads, the
# ephemeral container a patch adds, and which listing a get makes. The key's
# answer is the files under answers/ named for it, holding what the call prints,
# what it writes to stderr and the status it exits with. Each call is recorded
# with the clock's reading when it was made.
KUBECTL = r"""#!BASH
work='WORK'
sub="" base="" prev=""
for a in "$@"; do
  [ "$prev" = -f ] && { base="${a##*/}"; base="${base%.yaml}"; }
  case "$a" in -*) ;; *) [ -n "$sub" ] || sub="$a" ;; esac
  prev="$a"
done
case "$sub $* " in
  "patch "*'"name":"pinned"'*) key=patch-pinned ;;
  "patch "*'"name":"foreign"'*) key=patch-foreign ;;
  "get "*" events "*) key=get-events ;;
  "get "*" -o name "*) key=get-pods ;;
  "get "*" pod "*) key=get-pod ;;
  *) key="$sub${base:+-$base}" ;;
esac
{ printf '%s\x1f' "$(<"$work/now")" "$key" "$@"; printf '\n'; } >>"$work/calls"
answer="$work/answers/$key"
[ -f "$answer.out" ] && printf '%s\n' "$(<"$answer.out")"
[ -f "$answer.err" ] && printf '%s\n' "$(<"$answer.err")" >&2
case "$sub" in
  create|patch) echo "$(( $(<"$work/now") + STEP ))" >"$work/now" ;;
esac
[ -f "$answer.rc" ] && exit "$(<"$answer.rc")"
exit 0
"""

# GNU timeout's shape, `timeout [OPTION]... DURATION COMMAND...`. What precedes
# the command is recorded as the bounds it was given, with the command after
# them. answers/timeout-<command>.rc stands for the bound ending that command:
# the stub exits with it and runs nothing.
TIMEOUT = r"""#!BASH
work='WORK'
bounds=()
while [ "$#" -gt 0 ]; do
  case "$1" in kubectl|kind|helm) break ;; esac
  bounds+=("$1"); shift
done
{ printf '%s\x1f' "${bounds[@]}" "$@"; printf '\n'; } >>"$work/bounded"
[ -f "$work/answers/timeout-$1.rc" ] && exit "$(<"$work/answers/timeout-$1.rc")"
exec "$@"
"""

# kind and helm, answering every call with success.
TOOL = r"""#!BASH
exit 0
"""

DATE = r"""#!BASH
printf '%s\n' "$(<'WORK/now')"
"""

SLEEP = r"""#!BASH
echo "$(( $(<'WORK/now') + $1 ))" >'WORK/now'
"""


def log(error: str) -> str:
    """A verifier line as the admission controller writes it, naming the image."""
    return verifier_line(error, f"image=ghcr.io/nanohype/x@sha256:{'0' * 64}")


def kubectl_said(message: str, reason: str = "Forbidden") -> str:
    """What kubectl writes for an answer the API server sent, carrying `message`."""
    return f"Error from server ({reason}): {message}"


def replicaset_said(message: str) -> str:
    """The FailedCreate event the ReplicaSet writes when the API server refuses its pod."""
    return f"Error creating: {message}"


# The API server's refusal under the policy's identity message, and as kubectl
# reports it.
IDENTITY_REFUSAL = (f'admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
                    f"Policy verify-images failed: {IDENTITY}")
DENIED = kubectl_said(IDENTITY_REFUSAL)

MISMATCH = log("failed to verify cosign signatures: no matching signatures: none of the "
               "expected identities matched what was in the certificate")

# Three outages on the verification path, each worded only one way the shared
# pattern knows: the Sigstore trusted root, Rekor, and the registry.
TUF = log('failed to build cosign verification opts: tuf: failed to download 17.root.json: '
          'Get \\"https://tuf-repo-cdn.sigstore.dev/17.root.json\\": http2: server sent '
          'GOAWAY and closed the connection')
REKOR_503 = log("failed to verify cosign signatures: [POST /api/v1/log/entries/retrieve][503] "
                "searchLogQueryDefault")
# What the webhook server logs as the API server drops a connection, into the
# same stream as the verifier.
DROPPED = (f"2026-01-01T00:00:00Z {ESC}[31mERR{ESC}[0m github.com/kyverno/kyverno/pkg/logging/"
           "log.go:184 > http: TLS handshake error from 10.244.0.1:53422: read tcp "
           "10.244.0.5:9443->10.244.0.1:53422: read: connection reset by peer logger=server")

# Reading the image failed, so the API server's refusal carries the transport
# error: the registry throttling, and the registry's host not resolving.
REGISTRY_429 = ('admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
                "Policy verify-images error: failed to get imagedata: GET https://ghcr.io/v2/"
                "nanohype/x/manifests/sha256:0: unexpected status code 429 Too Many Requests")
REGISTRY_UNRESOLVED = ('admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
                       'Policy verify-images error: failed to get imagedata: Get '
                       '"https://ghcr.io/v2/": dial tcp: lookup ghcr.io: i/o timeout')

# kubectl's own request ending at its --request-timeout, before the API server
# answered: no "Error from server", because no answer came.
NO_ANSWER = ('error: error when creating "pod.yaml": Post "https://127.0.0.1:6443/api/v1/'
             'namespaces/workloads/pods?fieldManager=kubectl-create&timeout=90s": context '
             "deadline exceeded (Client.Timeout exceeded while awaiting headers)")

# The API server getting no answer from Kyverno's admission webhook.
WEBHOOK_UNANSWERED = kubectl_said(
    'Internal error occurred: failed calling webhook "ivpol.validate.kyverno.svc-fail": '
    'failed to call webhook: Post "https://kyverno-svc.kyverno.svc:443/validate/fail?'
    'timeout=10s": context deadline exceeded', reason="InternalError")

VERIFIER_OUTAGE = ("Cannot run: overlays/tier could not reach the registry, the Sigstore "
                   "trusted root or Rekor")
UNKNOWN_CAUSE = ("with the identity message, but the admission\ncontroller's log carries no "
                 "'image verification failed' line")


def no_answer_for(what: str) -> str:
    return (f"Cannot run: overlays/tier: kubectl's request for {what} ended with no answer from "
            f"the API server:\nits {REQUEST_TIMEOUT}s bound passed or its connection failed.")


def shared_pattern() -> str:
    return verdicts.TRANSPORT_FAILURE.pattern


def literal_phrases(pattern: str) -> list[str]:
    """The alternatives of the pattern that are plain phrases, unescaped."""
    alternatives, depth, current = [], 0, ""
    for ch in pattern:
        if ch == "|" and depth == 0:
            alternatives.append(current)
            current = ""
            continue
        depth += {"(": 1, ")": -1}.get(ch, 0)
        current += ch
    alternatives.append(current)
    return [re.sub(r"\\(.)", r"\1", a) for a in alternatives
            if not re.search(r"(?<!\\)[(\[]", a)]


def executable_lines(text: str) -> list[str]:
    """The lines of a shell script that run: every line but a comment."""
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def own_phrases(text: str, phrases: list[str]) -> list[str]:
    """The phrases a script's code words itself, whatever its comments say."""
    code = "\n".join(executable_lines(text)).lower()
    return [phrase for phrase in phrases if phrase.lower() in code]


def seconds(argv: list[str], flag: str) -> int | None:
    """The seconds `flag=<n>s` gives in argv, or None where argv does not carry it."""
    for arg in argv:
        found = re.fullmatch(rf"{re.escape(flag)}=(\d+)s", arg)
        if found:
            return int(found.group(1))
    return None


class AGateRun(unittest.TestCase):
    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        self.bash = bash
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        (self.work / "answers").mkdir()
        (self.work / "now").write_text(f"{START}\n")
        for name, body in (("kubectl", KUBECTL), ("date", DATE), ("sleep", SLEEP),
                           ("timeout", TIMEOUT), ("kind", TOOL), ("helm", TOOL)):
            stub = self.bin / name
            stub.write_text(body.replace("BASH", bash, 1).replace("WORK", str(self.work))
                            .replace("STEP", str(STEP)))
            stub.chmod(0o755)

    def answer(self, key: str, out: str | None = None, err: str | None = None,
               rc: int = 0) -> None:
        """What the kubectl call keyed `key` prints, writes to stderr and exits with."""
        for suffix, value in (("out", out), ("err", err), ("rc", str(rc) if rc else None)):
            if value is not None:
                (self.work / "answers" / f"{key}.{suffix}").write_text(value)

    def run_gate(self, body: str, actions: str = "Deny") -> tuple[int, str]:
        """Source the script, run `body` against the stubs, and report fail."""
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        proc = subprocess.run([self.bash, "-c", f'{PRELUDE}{body}\necho "fail=$fail"\n',
                               "bash", str(SCRIPT), str(self.work), actions],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(proc.returncode, 99, proc.stderr)
        return proc.returncode, proc.stdout + proc.stderr

    def calls(self) -> list[tuple[int, str, list[str]]]:
        """Each kubectl call: the clock when it was made, its key and its argv."""
        path = self.work / "calls"
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            clock, key, *argv = line.split("\x1f")[:-1]
            out.append((int(clock), key, argv))
        return out

    def calls_to(self, key: str) -> list[list[str]]:
        return [argv for _, k, argv in self.calls() if k == key]

    def bounded(self) -> list[tuple[list[str], list[str]]]:
        """Each command run under timeout: the bounds it was given, and the command."""
        path = self.work / "bounded"
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            fields = line.split("\x1f")[:-1]
            at = next(i for i, f in enumerate(fields) if f in ("kubectl", "kind", "helm"))
            out.append((fields[:at], fields[at:]))
        return out

    def assert_cannot_run(self, rc: int, said: str, cause: str,
                          headline: str = VERIFIER_OUTAGE) -> None:
        self.assertEqual(rc, 2, said)
        self.assertIn(headline, said)
        self.assertIn(cause, said)
        self.assertNotIn("ok    denied", said)
        self.assertNotIn("fail=", said)

    def assert_cause_unknown(self, rc: int, said: str, what: str) -> None:
        self.assertEqual(rc, 2, said)
        self.assertIn(f"Cannot run: overlays/tier refused {what} {UNKNOWN_CAUSE}", said)
        self.assertNotIn("FAIL", said)
        self.assertNotIn("fail=", said)

    def admit_signed_pod(self, init: str = PINNED, main: str = PINNED) -> None:
        """The signed pod and its ephemeral container admitted, the foreign one denied."""
        self.answer("create-pod", out=f"{init} {main}")
        self.answer("patch-pinned", out=PINNED)
        self.answer("patch-foreign", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)


class DecidingARefusal(AGateRun):
    def decide(self, actions: str, outcome: str, err: str = "", verifier_log: str = "",
               logs_rc: int = 0, logs_err: str | None = None) -> tuple[int, str]:
        """The branch-signed pod admitted, or refused with `err`, under `actions`."""
        if outcome == "refused":
            self.answer("create-branch-signed", err=err, rc=1)
        self.answer("logs", out=verifier_log, err=logs_err, rc=logs_rc)
        return self.run_gate("check_foreign_pod", actions)


class DecidingAForeignIdentity(DecidingARefusal):
    def test_sourcing_the_script_runs_nothing(self):
        proc = subprocess.run([self.bash, "-c", f'source "{SCRIPT}"; echo sourced'],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "sourced\n")

    def test_admitted_under_deny_fails(self):
        rc, said = self.decide("Deny", "admitted")
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  admitted the branch-signed image under Deny.", said)
        self.assertIn("fail=1", said)
        self.assertEqual(self.calls_to("logs"), [], "an admission is decided on no log")

    def test_admitted_under_audit_is_reported_not_blocked(self):
        rc, said = self.decide("Audit", "admitted")
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    admitted the branch-signed image under Audit", said)
        self.assertIn("fail=0", said)
        self.assertEqual(len(self.calls_to("delete-branch-signed")), 1, self.calls())

    def test_denied_for_its_identity_under_deny_passes(self):
        rc, said = self.decide("Deny", "refused", DENIED, MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    denied the branch-signed image:", said)
        self.assertIn("fail=0", said)

    def test_deny_among_several_actions_still_blocks(self):
        rc, said = self.decide("Deny,Audit", "admitted")
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  admitted the branch-signed image under Deny.", said)
        self.assertIn("fail=1", said)

    def test_denied_for_its_identity_under_audit_fails(self):
        rc, said = self.decide("Audit", "refused", DENIED, MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  denied the branch-signed image under Audit, which reports", said)
        self.assertIn("fail=1", said)

    def test_refused_for_a_transport_failure_cannot_run(self):
        rc, said = self.decide("Deny", "refused", kubectl_said(REGISTRY_UNRESOLVED))
        self.assert_cannot_run(rc, said, "i/o timeout")

    def test_refused_for_another_reason_fails_and_shows_it(self):
        rc, said = self.decide("Deny", "refused",
                               kubectl_said('pods "vi-branch-signed" already exists',
                                            reason="AlreadyExists"),
                               MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  the branch-signed image was refused for a reason other than its "
                      "identity", said)
        self.assertIn("already exists", said)
        self.assertIn("fail=1", said)


class AnOutageBehindTheIdentityMessage(DecidingARefusal):
    """Verification counts an outage as a signature that did not verify.

    The refusal then carries the policy's identity message, which under Deny is
    exactly what a correct denial says; only the verifier's log tells them apart.
    """

    def test_a_trusted_root_that_could_not_be_fetched_is_not_a_denial(self):
        rc, said = self.decide("Deny", "refused", DENIED, TUF)
        self.assert_cannot_run(rc, said, "tuf: failed to download 17.root.json")
        self.assertNotIn(ESC, said)

    def test_a_rekor_5xx_is_not_a_denial(self):
        rc, said = self.decide("Deny", "refused", DENIED, "\n".join([MISMATCH, REKOR_503]))
        self.assert_cannot_run(rc, said, "[503]")

    def test_a_registry_429_refusal_cannot_run(self):
        rc, said = self.decide("Deny", "refused", kubectl_said(REGISTRY_429), MISMATCH)
        self.assert_cannot_run(rc, said, "unexpected status code 429")

    def test_a_log_that_cannot_be_read_decides_no_refusal(self):
        rc, said = self.decide("Deny", "refused", DENIED, MISMATCH, logs_rc=1,
                               logs_err="error: the server could not find the requested resource")
        self.assertEqual(rc, 2, said)
        self.assertIn("Cannot run: overlays/tier: the admission controller's log could not be "
                      "read", said)
        self.assertIn("could not find the requested resource", said)
        self.assertNotIn("ok    denied", said)

    def test_a_log_read_that_times_out_decides_no_refusal(self):
        """A read the request timeout ended is a log that could not be read."""
        rc, said = self.decide("Deny", "refused", DENIED, MISMATCH, logs_rc=1,
                               logs_err="Unable to connect to the server: net/http: request "
                                        "canceled (Client.Timeout exceeded while awaiting "
                                        "headers)")
        self.assertEqual(rc, 2, said)
        self.assertIn("the admission controller's log could not be read", said)
        self.assertIn("Client.Timeout exceeded", said)
        self.assertNotIn("could not reach the registry", said)
        self.assertNotIn("ok    denied", said)

    def test_a_log_without_the_verifiers_line_decides_no_denial(self):
        """A selector matching no pod reads an empty log, and exits 0."""
        rc, said = self.decide("Deny", "refused", DENIED, "")
        self.assert_cause_unknown(rc, said, "the branch-signed image")
        self.assertNotIn("ok    denied", said)

    def test_a_log_without_the_verifiers_line_decides_no_audit_verdict(self):
        rc, said = self.decide("Audit", "refused", DENIED, "")
        self.assert_cause_unknown(rc, said, "the branch-signed image")

    def test_a_connection_the_webhook_server_dropped_is_not_the_verifiers(self):
        """The controller's own log lines share the stream and name no verification."""
        rc, said = self.decide("Deny", "refused", DENIED, "\n".join([DROPPED, MISMATCH]))
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    denied the branch-signed image:", said)
        self.assertIn("fail=0", said)

    def test_the_log_is_read_whole_from_every_admission_controller_replica(self):
        self.decide("Deny", "refused", DENIED, MISMATCH)
        logs = self.calls_to("logs")
        self.assertEqual(len(logs), 1, self.calls())
        argv = logs[0]
        self.assertEqual(argv[0], f"--request-timeout={REQUEST_TIMEOUT}s")
        self.assertEqual(argv[1:4], ["logs", "-n", "kyverno"])
        selector = argv[argv.index("-l") + 1].split(",")
        self.assertEqual(sorted(selector), ["app.kubernetes.io/component=admission-controller",
                                            "app.kubernetes.io/instance=kyverno"])
        self.assertIn("--tail=-1", argv)
        self.assertEqual(len([a for a in argv if a.startswith("--since=")]), 1, argv)


class WhereATransportFailureHappened(DecidingARefusal):
    """A transport failure in the refusal is named by the link it broke.

    kubectl's own request to the API server, the API server's call to Kyverno's
    webhook, and the verifier's reads of the registry, the Sigstore trusted root
    and Rekor each leave a run that cannot decide, for a different reason.
    """

    def test_a_request_kubectl_got_no_answer_for_is_not_the_registry(self):
        rc, said = self.decide("Deny", "refused", NO_ANSWER, MISMATCH)
        self.assert_cannot_run(rc, said, "Client.Timeout exceeded",
                               headline=no_answer_for("the branch-signed image"))
        self.assertNotIn("could not reach the registry", said)
        self.assertEqual(self.calls_to("logs"), [], "no admission ran to log anything")

    def test_a_webhook_the_api_server_got_no_answer_from_is_not_the_registry(self):
        rc, said = self.decide("Deny", "refused", WEBHOOK_UNANSWERED, MISMATCH)
        self.assert_cannot_run(rc, said, "failed calling webhook",
                               headline="Cannot run: overlays/tier: the API server got no "
                                        "answer from Kyverno's admission webhook for the "
                                        "branch-signed image.")
        self.assertNotIn("could not reach the registry", said)

    def test_a_signed_pod_kubectl_got_no_answer_for_is_not_the_registry(self):
        """The release-signed path names it by the same rule."""
        self.answer("create-pod", err=NO_ANSWER, rc=1)
        rc, said = self.run_gate("check_signed_pod")
        self.assert_cannot_run(rc, said, "Client.Timeout exceeded",
                               headline=no_answer_for("the signed pod"))
        self.assertNotIn("FAIL", said)

    def test_a_deployments_pod_the_registry_throttled_cannot_run(self):
        """The ReplicaSet's event carries the API server's answer, as kubectl's error does."""
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-events", out=replicaset_said(REGISTRY_429))
        self.answer("logs", out=MISMATCH)
        rc, said = self.run_gate(f"CREATE_TIMEOUT={SHORT_CREATE_TIMEOUT}\ncheck_deployment")
        self.assert_cannot_run(rc, said, "unexpected status code 429")
        self.assertIn("for the Deployment's pod.", said)


class ARefusedReleaseSignedSubmission(AGateRun):
    """A release-signed submission refused is decided on the rule a foreign one is.

    A refusal carrying the identity message with no verifier line behind it
    leaves its cause unknown on every path, whichever step made the request.
    With the verifier's line, the refusal is the policy's, and a release-signed
    image refused is a FAIL.
    """

    def refuse_signed_pod(self, verifier_log: str) -> tuple[int, str]:
        self.answer("create-pod", err=DENIED, rc=1)
        self.answer("logs", out=verifier_log)
        return self.run_gate("check_signed_pod")

    def refuse_signed_ephemeral(self, verifier_log: str) -> tuple[int, str]:
        self.answer("patch-pinned", err=DENIED, rc=1)
        self.answer("logs", out=verifier_log)
        return self.run_gate("check_signed_ephemeral")

    def refuse_deployment(self, verifier_log: str) -> tuple[int, str]:
        self.answer("create-deployment", err=DENIED, rc=1)
        self.answer("logs", out=verifier_log)
        return self.run_gate("check_deployment")

    def refuse_deployments_pod(self, verifier_log: str,
                               create_timeout: int | None = SHORT_CREATE_TIMEOUT
                               ) -> tuple[int, str]:
        """The Deployment stored; its ReplicaSet refused, as its FailedCreate events say."""
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-events", out=replicaset_said(IDENTITY_REFUSAL))
        self.answer("logs", out=verifier_log)
        shorten = "" if create_timeout is None else f"CREATE_TIMEOUT={create_timeout}\n"
        return self.run_gate(f"{shorten}check_deployment")

    def test_a_signed_pod_refused_with_no_verifier_line_cannot_decide(self):
        rc, said = self.refuse_signed_pod("")
        self.assert_cause_unknown(rc, said, "the signed pod")

    def test_a_signed_pod_the_verifier_refused_fails(self):
        rc, said = self.refuse_signed_pod(MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn(f"FAIL  denied the release-signed {TAGGED}, so no digest was written:",
                      said)
        self.assertIn("fail=1", said)

    def test_a_signed_ephemeral_container_refused_with_no_verifier_line_cannot_decide(self):
        rc, said = self.refuse_signed_ephemeral("")
        self.assert_cause_unknown(rc, said, "the signed ephemeral container")

    def test_a_signed_ephemeral_container_the_verifier_refused_fails(self):
        rc, said = self.refuse_signed_ephemeral(MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn(f"FAIL  refused the release-signed {TAGGED} as an ephemeral container:",
                      said)
        self.assertIn("fail=1", said)

    def test_a_deployment_refused_with_no_verifier_line_cannot_decide(self):
        rc, said = self.refuse_deployment("")
        self.assert_cause_unknown(rc, said, "the Deployment")

    def test_a_deployment_the_verifier_refused_fails(self):
        rc, said = self.refuse_deployment(MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn(f"FAIL  refused the Deployment of the release-signed {TAGGED}:", said)
        self.assertIn("fail=1", said)

    def test_a_deployments_pod_refused_with_no_verifier_line_cannot_decide(self):
        rc, said = self.refuse_deployments_pod("")
        self.assert_cause_unknown(rc, said, "the Deployment's pod")

    def test_a_deployments_pod_the_verifier_refused_fails(self):
        rc, said = self.refuse_deployments_pod(MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn(f"FAIL  the Deployment's ReplicaSet created no pod within "
                      f"{SHORT_CREATE_TIMEOUT}s:", said)
        self.assertIn(IDENTITY, said)
        self.assertIn("fail=1", said)
        self.assertEqual(len(self.calls_to("delete-deployment")), 1, self.calls())

    def test_a_deployments_pod_is_waited_for_until_the_bound_and_no_longer(self):
        self.refuse_deployments_pod(MISMATCH, create_timeout=None)
        polls = [clock for clock, key, _ in self.calls() if key == "get-pod"]
        self.assertGreater(len(polls), 1, self.calls())
        self.assertGreaterEqual(polls[-1] - polls[0], CREATE_TIMEOUT)
        self.assertLess(polls[-1] - polls[0], CREATE_TIMEOUT + STEP)


class TheLogWindow(AGateRun):
    """Each request is marked before it is sent, and its log read from before the mark.

    The clock moves STEP seconds across each create or patch. A window opening at
    or after the second the request was sent can miss the line the verifier
    logged as it refused it, and every decision on a refusal reads that line.
    """

    def assert_window_opens_before(self, request: str) -> None:
        calls = self.calls()
        sent = [clock for clock, key, _ in calls if key == request]
        self.assertEqual(len(sent), 1, calls)
        reads = [(clock, argv) for clock, key, argv in calls if key == "logs"]
        self.assertEqual(len(reads), 1, calls)
        clock, argv = reads[0]
        since = [a for a in argv if a.startswith("--since=")]
        self.assertEqual(len(since), 1, argv)
        window = re.fullmatch(r"--since=(\d+)s", since[0])
        self.assertIsNotNone(window, since[0])
        assert window is not None
        self.assertLess(clock - int(window.group(1)), sent[0],
                        f"the log was read from {clock - int(window.group(1))}, and the "
                        f"request was sent at {sent[0]}")

    def test_the_signed_pods_window_opens_before_its_create(self):
        self.answer("create-pod", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_signed_pod")
        self.assert_window_opens_before("create-pod")

    def test_the_signed_ephemeral_containers_window_opens_before_its_patch(self):
        self.answer("patch-pinned", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_signed_ephemeral")
        self.assert_window_opens_before("patch-pinned")

    def test_the_branch_signed_ephemeral_containers_window_opens_before_its_patch(self):
        self.answer("patch-foreign", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_foreign_ephemeral")
        self.assert_window_opens_before("patch-foreign")

    def test_the_deployments_window_opens_before_its_create(self):
        self.answer("create-deployment", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_deployment")
        self.assert_window_opens_before("create-deployment")

    def test_the_deployments_pods_window_opens_before_the_deployment_was_created(self):
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-events", out=replicaset_said(IDENTITY_REFUSAL))
        self.answer("logs", out=MISMATCH)
        self.run_gate(f"CREATE_TIMEOUT={SHORT_CREATE_TIMEOUT}\ncheck_deployment")
        self.assert_window_opens_before("create-deployment")

    def test_the_branch_signed_pods_window_opens_before_its_create(self):
        self.answer("create-branch-signed", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_foreign_pod")
        self.assert_window_opens_before("create-branch-signed")


class AnAdmittedSignedPod(AGateRun):
    def test_pinned_in_every_field_passes(self):
        self.admit_signed_pod()
        rc, said = self.run_gate("check_signed_pod")
        self.assertEqual(rc, 0, said)
        self.assertIn(f"ok    admitted {TAGGED} in the init container as {PINNED}", said)
        self.assertIn(f"ok    admitted {TAGGED} in the container as {PINNED}", said)
        self.assertIn(f"ok    admitted {TAGGED} as an ephemeral container as {PINNED}", said)
        self.assertIn("ok    denied the branch-signed ephemeral container:", said)
        self.assertIn("fail=0", said)
        self.assertEqual(len(self.calls_to("delete-pod")), 1, self.calls())

    def test_a_tag_left_unpinned_fails(self):
        self.admit_signed_pod(init=TAGGED)
        rc, said = self.run_gate("check_signed_pod")
        self.assertEqual(rc, 0, said)
        self.assertIn(f"FAIL  admitted {TAGGED} in the init container as '{TAGGED}'", said)
        self.assertIn("fail=1", said)

    def test_a_pin_verdicts_py_could_not_decide_is_no_verdict(self):
        """An interpreter failing ends the run as one that could not decide."""
        python3 = self.bin / "python3"
        python3.write_text(f"#!{self.bash}\nexit 1\n")
        python3.chmod(0o755)
        self.admit_signed_pod()
        rc, said = self.run_gate("check_signed_pod")
        self.assertEqual(rc, 2, said)
        self.assertIn("Cannot run: scripts/verdicts.py exited 1 answering pinned, so no "
                      "verdict was reached.", said)
        self.assertNotIn("fail=", said)


class DeletingWhatTheNextStepWouldMeet(AGateRun):
    """An object still present after DELETE_TIMEOUT ends the run."""

    def test_a_policy_not_deleted_in_time_cannot_run(self):
        self.answer("delete-policy", rc=1,
                    err="error: timed out waiting for the condition on "
                        "imagevalidatingpolicies/verify-images")
        rc, said = self.run_gate("retire_policy")
        self.assertEqual(rc, 2, said)
        self.assertIn(f"Cannot run: overlays/tier: its policy was not deleted within "
                      f"{DELETE_TIMEOUT}s — error: timed out waiting", said)
        self.assertNotIn("fail=", said)

    def test_a_policy_is_deleted_and_waited_for(self):
        rc, said = self.run_gate("retire_policy")
        self.assertEqual(rc, 0, said)
        deletes = self.calls_to("delete-policy")
        self.assertEqual(len(deletes), 1, self.calls())
        self.assertIn("--wait=true", deletes[0])
        self.assertIn(f"--timeout={DELETE_TIMEOUT}s", deletes[0])

    def test_an_admitted_signed_pod_not_deleted_in_time_cannot_run(self):
        self.admit_signed_pod()
        self.answer("delete-pod", rc=1, err="error: timed out waiting for the condition")
        rc, said = self.run_gate("check_signed_pod")
        self.assertEqual(rc, 2, said)
        self.assertIn(f"Cannot run: overlays/tier: the signed pod was not deleted within "
                      f"{DELETE_TIMEOUT}s", said)


class EachWaitRunsToItsOwnTimeout(AGateRun):
    """A wait's own --timeout ends it, and nothing below that ends it first.

    kubectl's --request-timeout ends every connection a wait opens, its watch
    included, so one below the wait's own --timeout would cut the watch before
    the wait's bound. A wait is bounded from outside instead: GNU timeout,
    REQUEST_TIMEOUT above its own bound.
    """

    def run_every_wait(self) -> list[list[str]]:
        """One overlay's steps, every wait among them; the waits' argv."""
        self.admit_signed_pod()
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-pod", out=PINNED)
        self.answer("create-branch-signed", err=DENIED, rc=1)
        rc, said = self.run_gate("install_policy\ncheck_signed_pod\ncheck_deployment\n"
                                 "check_foreign_pod\nretire_policy")
        self.assertEqual(rc, 0, said)
        self.assertIn("fail=0", said)
        waits = [(key, argv) for _, key, argv in self.calls()
                 if "wait" in argv or "--wait=true" in argv]
        self.assertEqual(sorted(key for key, _ in waits),
                         ["delete-deployment", "delete-pod", "delete-policy", "wait", "wait"],
                         self.calls())
        return [argv for _, argv in waits]

    def test_no_wait_is_given_a_request_timeout_below_its_own(self):
        for argv in self.run_every_wait():
            with self.subTest(argv=argv):
                own = seconds(argv, "--timeout")
                self.assertIsNotNone(own, f"the wait carries no --timeout of its own: {argv}")
                assert own is not None
                request = seconds(argv, "--request-timeout")
                if request is not None:
                    self.assertGreaterEqual(request, own,
                                            f"--request-timeout={request}s would end the "
                                            f"wait's watch before its own {own}s")

    def test_each_wait_runs_under_gnu_timeout_above_its_own(self):
        waits = self.run_every_wait()
        bounded = {tuple(command): bounds for bounds, command in self.bounded()}
        for argv in waits:
            with self.subTest(argv=argv):
                own = seconds(argv, "--timeout")
                expected = (READY_TIMEOUT if "imagevalidatingpolicy/verify-images" in argv
                            else DELETE_TIMEOUT)
                self.assertEqual(own, expected)
                self.assertEqual(bounded.get(("kubectl", *argv)),
                                 ["-k", str(KILL_TIMEOUT), str(expected + REQUEST_TIMEOUT)])

    def test_a_wait_the_bound_ended_says_so(self):
        self.answer("timeout-kubectl", rc=124)
        rc, said = self.run_gate("retire_policy")
        self.assertEqual(rc, 2, said)
        self.assertIn(f"Cannot run: overlays/tier: its policy was not deleted within "
                      f"{DELETE_TIMEOUT}s — kubectl did not finish within "
                      f"{DELETE_TIMEOUT + REQUEST_TIMEOUT}s, so GNU timeout ended it.", said)


class KindAndHelmRunUnderTheirBounds(AGateRun):
    """kind's --wait and helm's --timeout leave the image pull and chart fetch unbounded."""

    def test_kind_creates_the_cluster_under_its_bound(self):
        rc, said = self.run_gate("create_cluster")
        self.assertEqual(rc, 0, said)
        [(bounds, command)] = self.bounded()
        self.assertEqual(bounds, ["-k", str(KILL_TIMEOUT), str(KIND_TIMEOUT)])
        self.assertEqual(command[:3], ["kind", "create", "cluster"])
        self.assertEqual(command[command.index("--wait") + 1], f"{READY_TIMEOUT}s")

    def test_helm_installs_kyverno_under_its_bound(self):
        rc, said = self.run_gate("install_kyverno")
        self.assertEqual(rc, 0, said)
        [(bounds, command)] = self.bounded()
        self.assertEqual(bounds, ["-k", str(KILL_TIMEOUT), str(HELM_TIMEOUT)])
        self.assertEqual(command[:4], ["helm", "install", "kyverno", "kyverno"])
        self.assertEqual(command[command.index("--timeout") + 1], f"{HELM_TIMEOUT}s")

    def test_a_cluster_the_bound_ended_says_so(self):
        self.answer("timeout-kind", rc=124)
        rc, said = self.run_gate("create_cluster")
        self.assertEqual(rc, 2, said)
        self.assertIn(f"kind did not finish within {KIND_TIMEOUT}s, so GNU timeout ended it.",
                      said)
        self.assertIn("Cannot run: kind could not create the cluster.", said)

    def test_an_install_the_bound_killed_says_so(self):
        self.answer("timeout-helm", rc=137)
        rc, said = self.run_gate("install_kyverno")
        self.assertEqual(rc, 2, said)
        self.assertIn("helm was killed before it finished.", said)
        self.assertIn(f"Cannot run: Kyverno {CHART_VERSION} did not install.", said)


class EveryStepIsBounded(unittest.TestCase):
    """The job's timeout sits above the bound the script puts on each step.

    Each step is held to it on its own, so one step that stalls ends on the
    script's diagnostic rather than on the runner cancelling the job. The
    bounds are not summed: a run in which several steps each stall to their
    bound can outlast the job.
    """

    TEXT = SCRIPT.read_text()

    def test_every_kubectl_call_goes_through_a_bounded_wrapper(self):
        """Every line naming kubectl, other than as a possessive in a message."""
        calls = [line.strip() for line in executable_lines(self.TEXT)
                 if re.search(r"(?<![\w-])kubectl(?![\w'-])", line)
                 and not line.lstrip().startswith("for tool in ")]
        self.assertEqual(calls, [
            'kubectl --request-timeout="${REQUEST_TIMEOUT}s" "$@"',
            'bounded "$(( seconds + REQUEST_TIMEOUT ))" kubectl "$@" --timeout="${seconds}s"',
        ])

    def test_every_wait_goes_through_the_wait_wrapper(self):
        """A wait sent through kube would run under --request-timeout."""
        for line in executable_lines(self.TEXT):
            with self.subTest(line=line.strip()):
                self.assertNotRegex(line, r"(?<![\w-])kube\s+(wait|delete)\b")

    def test_each_steps_bound_is_under_the_jobs_timeout(self):
        bounds = {name: int(value) for name, value
                  in re.findall(r"^([A-Z_]+_TIMEOUT)=(\d+)$", self.TEXT, re.M)}
        self.assertIn("REQUEST_TIMEOUT", bounds)
        self.assertIn("KILL_TIMEOUT", bounds)
        request, kill = bounds.pop("REQUEST_TIMEOUT"), bounds.pop("KILL_TIMEOUT")
        job = yaml.safe_load(CI.read_text())["jobs"]["digest-rewrite"]
        self.assertIn("./scripts/check-digest-rewrite.sh",
                      [step.get("run") for step in job["steps"]])
        # The longest any one step under a bound runs: a wait, REQUEST_TIMEOUT
        # above its own bound and a kill's grace after that; kind or helm, the
        # bound and the grace; the wait for the Deployment's pod, the bound and
        # the request under way when it passes.
        for name, value in bounds.items():
            with self.subTest(bound=name):
                self.assertLess(value + request + kill, job["timeout-minutes"] * 60)
        for line in executable_lines(self.TEXT):
            with self.subTest(line=line.strip()):
                self.assertNotRegex(line, r'--(request-)?timeout[= ]"?\d|--wait "?\d')


class OneTransportPattern(unittest.TestCase):
    """Both gates hand what they read to scripts/verdicts.py, which holds the one pattern."""

    ASKS = re.compile(r'^VERDICTS="\$ROOT/scripts/verdicts\.py"$', re.M)

    def test_both_gates_ask_verdicts(self):
        for gate in (SCRIPT, KYVERNO_TEST):
            with self.subTest(gate=gate.name):
                text = gate.read_text()
                self.assertRegex(text, self.ASKS)
                self.assertIn('python3 "$VERDICTS" ', "\n".join(executable_lines(text)))

    def test_no_gate_words_a_transport_failure_of_its_own(self):
        phrases = literal_phrases(shared_pattern())
        self.assertIn("tuf: failed to download", phrases)
        self.assertIn("no such host", phrases)
        for gate in (SCRIPT, KYVERNO_TEST):
            with self.subTest(gate=gate.name):
                self.assertEqual(own_phrases(gate.read_text(), phrases), [])
                self.assertNotRegex(gate.read_text(), r"(?m)^\s*TRANSPORT_FAILURE=")

    def test_no_gate_decides_on_a_message_of_its_own(self):
        """The messages a refusal is decided on are verdicts.py's, and nowhere else."""
        for gate in (SCRIPT, KYVERNO_TEST):
            with self.subTest(gate=gate.name):
                self.assertEqual(own_phrases(gate.read_text(), [verdicts.IDENTITY_MESSAGE,
                                                                verdicts.VERIFIER_FAILED]), [])

    def test_a_phrase_in_code_is_a_pattern_of_its_own_and_one_in_a_comment_is_not(self):
        phrases = literal_phrases(shared_pattern())
        text = ("# A connection reset by peer is the API server dropping one.\n"
                "classify() { grep -iE 'no such host|i/o timeout'; }\n")
        self.assertEqual(own_phrases(text, phrases), ["no such host", "i/o timeout"])


if __name__ == "__main__":
    unittest.main()
