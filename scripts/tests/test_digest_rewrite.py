"""Unit tests for the verdicts scripts/check-digest-rewrite.sh reaches.

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
sent or the script sleeps.

The same transport failures are classified by scripts/kyverno-test.sh, and both
gates read them through the one pattern scripts/transport-failure.sh holds.
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

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check-digest-rewrite.sh"
KYVERNO_TEST = ROOT / "scripts" / "kyverno-test.sh"
SHARED = ROOT / "scripts" / "transport-failure.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"

IDENTITY = re.search(r'^IDENTITY_MESSAGE="([^"]+)"$', SCRIPT.read_text(), re.M)


def _setting(name: str) -> int:
    """A numeric setting the script makes, read from the script."""
    found = re.search(rf"^{name}=(\d+)$", SCRIPT.read_text(), re.M)
    assert found, f"{SCRIPT.name} sets no {name}"
    return int(found.group(1))


REQUEST_TIMEOUT = _setting("REQUEST_TIMEOUT")
DELETE_TIMEOUT = _setting("DELETE_TIMEOUT")
CREATE_TIMEOUT = _setting("CREATE_TIMEOUT")

# What the main body reads out of the fixtures, set by hand: a tag, and a
# foreign image pinned by digest.
TAGGED = "ghcr.io/nanohype/x:1.0.0"
FOREIGN = f"ghcr.io/nanohype/x@sha256:{'0' * 64}"
PINNED = f"{TAGGED}@sha256:{'a' * 64}"

PRELUDE = f"""
source "$1" || exit 99
WORK="$2" rel=overlays/tier actions="$3" fail=0 rendered="$2/policy.yaml"
TAGGED={TAGGED} FOREIGN={FOREIGN}
POD=signed POD_NS=workloads DEPLOYMENT=signed-deployment DEPLOYMENT_NS=workloads
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

DATE = r"""#!BASH
printf '%s\n' "$(<'WORK/now')"
"""

SLEEP = r"""#!BASH
echo "$(( $(<'WORK/now') + $1 ))" >'WORK/now'
"""

ESC = "\033"


def log(error: str) -> str:
    """A verifier ERR line as the admission controller writes it, coloured."""
    return (f"2026-01-01T00:00:00Z {ESC}[31mERR{ESC}[0m github.com/kyverno/kyverno/pkg/image/"
            f"verifiers/ivpol/cosign/verifier.go:281 > image verification failed "
            f"{ESC}[36merror={ESC}[0m{ESC}[31m\"{error}\"{ESC}[0m attestor=release "
            f"image=ghcr.io/nanohype/x@sha256:{'0' * 64}")


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

REGISTRY_429 = ('admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
                "Policy verify-images error: failed to get imagedata: GET https://ghcr.io/v2/"
                "nanohype/x/manifests/sha256:0: unexpected status code 429 Too Many Requests")

UNKNOWN_CAUSE = ("with the identity message, but the admission\ncontroller's log carries no "
                 "'image verification failed' line")


def shared_pattern() -> str:
    found = re.search(r"^TRANSPORT_FAILURE='([^']+)'$", SHARED.read_text(), re.M)
    assert found, f"{SHARED.name} sets no TRANSPORT_FAILURE"
    return found.group(1)


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


class AGateRun(unittest.TestCase):
    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        self.bash = bash
        self.assertIsNotNone(IDENTITY, f"{SCRIPT.name} sets no IDENTITY_MESSAGE")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        (self.work / "answers").mkdir()
        (self.work / "now").write_text(f"{START}\n")
        for name, body in (("kubectl", KUBECTL), ("date", DATE), ("sleep", SLEEP)):
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

    def denied(self) -> str:
        assert IDENTITY is not None
        return (f'admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
                f"Policy verify-images failed: {IDENTITY.group(1)}")

    def assert_cannot_run(self, rc: int, said: str, cause: str) -> None:
        self.assertEqual(rc, 2, said)
        self.assertIn("Cannot run: overlays/tier could not reach the registry, the Sigstore "
                      "trusted root or Rekor", said)
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
        self.answer("patch-foreign", err=self.denied(), rc=1)
        self.answer("logs", out=MISMATCH)


class DecidingARefusal(AGateRun):
    def decide(self, actions: str, outcome: str, err: str = "", verifier_log: str = "",
               logs_rc: int = 0, logs_err: str | None = None) -> tuple[int, str]:
        (self.work / "err").write_text(err)
        self.answer("logs", out=verifier_log, err=logs_err, rc=logs_rc)
        return self.run_gate(f'mark_sent\ndecide_foreign "the branch-signed image" {outcome}',
                             actions)


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

    def test_admitted_under_audit_is_reported_not_blocked(self):
        rc, said = self.decide("Audit", "admitted")
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    admitted the branch-signed image under Audit", said)
        self.assertIn("fail=0", said)

    def test_denied_for_its_identity_under_deny_passes(self):
        rc, said = self.decide("Deny", "refused", self.denied(), MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    denied the branch-signed image:", said)
        self.assertIn("fail=0", said)

    def test_deny_among_several_actions_still_blocks(self):
        rc, said = self.decide("Deny,Audit", "admitted")
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  admitted the branch-signed image under Deny.", said)
        self.assertIn("fail=1", said)

    def test_denied_for_its_identity_under_audit_fails(self):
        rc, said = self.decide("Audit", "refused", self.denied(), MISMATCH)
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  denied the branch-signed image under Audit, which reports", said)
        self.assertIn("fail=1", said)

    def test_refused_for_a_transport_failure_cannot_run(self):
        rc, said = self.decide("Deny", "refused",
                               "Get https://ghcr.io/v2/: dial tcp: i/o timeout")
        self.assert_cannot_run(rc, said, "i/o timeout")

    def test_refused_for_another_reason_fails_and_shows_it(self):
        rc, said = self.decide("Deny", "refused", 'pods "vi-branch-signed" already exists',
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
        rc, said = self.decide("Deny", "refused", self.denied(), TUF)
        self.assert_cannot_run(rc, said, "tuf: failed to download 17.root.json")
        self.assertNotIn(ESC, said)

    def test_a_rekor_5xx_is_not_a_denial(self):
        rc, said = self.decide("Deny", "refused", self.denied(), "\n".join([MISMATCH, REKOR_503]))
        self.assert_cannot_run(rc, said, "[503]")

    def test_a_registry_429_refusal_cannot_run(self):
        rc, said = self.decide("Deny", "refused", REGISTRY_429, MISMATCH)
        self.assert_cannot_run(rc, said, "unexpected status code 429")

    def test_a_log_that_cannot_be_read_decides_no_refusal(self):
        rc, said = self.decide("Deny", "refused", self.denied(), MISMATCH, logs_rc=1,
                               logs_err="error: the server could not find the requested resource")
        self.assertEqual(rc, 2, said)
        self.assertIn("Cannot run: overlays/tier: the admission controller's log could not be "
                      "read", said)
        self.assertIn("could not find the requested resource", said)
        self.assertNotIn("ok    denied", said)

    def test_a_log_read_that_times_out_decides_no_refusal(self):
        """A read the request timeout ended is a log that could not be read."""
        rc, said = self.decide("Deny", "refused", self.denied(), MISMATCH, logs_rc=1,
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
        rc, said = self.decide("Deny", "refused", self.denied(), "")
        self.assert_cause_unknown(rc, said, "the branch-signed image")
        self.assertNotIn("ok    denied", said)

    def test_a_log_without_the_verifiers_line_decides_no_audit_verdict(self):
        rc, said = self.decide("Audit", "refused", self.denied(), "")
        self.assert_cause_unknown(rc, said, "the branch-signed image")

    def test_a_connection_the_webhook_server_dropped_is_not_the_verifiers(self):
        """The controller's own log lines share the stream and name no verification."""
        rc, said = self.decide("Deny", "refused", self.denied(), "\n".join([DROPPED, MISMATCH]))
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    denied the branch-signed image:", said)
        self.assertIn("fail=0", said)

    def test_the_log_is_read_whole_from_every_admission_controller_replica(self):
        self.decide("Deny", "refused", self.denied(), MISMATCH)
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


class ARefusedReleaseSignedSubmission(AGateRun):
    """A release-signed submission refused is decided on the rule a foreign one is.

    A refusal carrying the identity message with no verifier line behind it
    leaves its cause unknown on every path, whichever step made the request.
    With the verifier's line, the refusal is the policy's, and a release-signed
    image refused is a FAIL.
    """

    def refuse_signed_pod(self, verifier_log: str) -> tuple[int, str]:
        self.answer("create-pod", err=self.denied(), rc=1)
        self.answer("logs", out=verifier_log)
        return self.run_gate("check_signed_pod")

    def refuse_signed_ephemeral(self, verifier_log: str) -> tuple[int, str]:
        self.answer("patch-pinned", err=self.denied(), rc=1)
        self.answer("logs", out=verifier_log)
        return self.run_gate("check_signed_ephemeral")

    def refuse_deployment(self, verifier_log: str) -> tuple[int, str]:
        self.answer("create-deployment", err=self.denied(), rc=1)
        self.answer("logs", out=verifier_log)
        return self.run_gate("check_deployment")

    def refuse_deployments_pod(self, verifier_log: str,
                               create_timeout: int | None = SHORT_CREATE_TIMEOUT
                               ) -> tuple[int, str]:
        """The Deployment stored; its ReplicaSet refused, as its FailedCreate events say."""
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-events", out=f"Error creating: {self.denied()}")
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
        assert IDENTITY is not None
        self.assertIn(IDENTITY.group(1), said)
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
        seconds = re.fullmatch(r"--since=(\d+)s", since[0])
        self.assertIsNotNone(seconds, since[0])
        assert seconds is not None
        self.assertLess(clock - int(seconds.group(1)), sent[0],
                        f"the log was read from {clock - int(seconds.group(1))}, and the "
                        f"request was sent at {sent[0]}")

    def test_the_signed_pods_window_opens_before_its_create(self):
        self.answer("create-pod", err=self.denied(), rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_signed_pod")
        self.assert_window_opens_before("create-pod")

    def test_the_signed_ephemeral_containers_window_opens_before_its_patch(self):
        self.answer("patch-pinned", err=self.denied(), rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_signed_ephemeral")
        self.assert_window_opens_before("patch-pinned")

    def test_the_branch_signed_ephemeral_containers_window_opens_before_its_patch(self):
        self.answer("patch-foreign", err=self.denied(), rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_foreign_ephemeral")
        self.assert_window_opens_before("patch-foreign")

    def test_the_deployments_window_opens_before_its_create(self):
        self.answer("create-deployment", err=self.denied(), rc=1)
        self.answer("logs", out=MISMATCH)
        self.run_gate("check_deployment")
        self.assert_window_opens_before("create-deployment")

    def test_the_deployments_pods_window_opens_before_the_deployment_was_created(self):
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-events", out=f"Error creating: {self.denied()}")
        self.answer("logs", out=MISMATCH)
        self.run_gate(f"CREATE_TIMEOUT={SHORT_CREATE_TIMEOUT}\ncheck_deployment")
        self.assert_window_opens_before("create-deployment")

    def test_the_branch_signed_pods_window_opens_before_its_create(self):
        self.answer("create-branch-signed", err=self.denied(), rc=1)
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


class EveryStepIsBounded(unittest.TestCase):
    """The job's timeout sits above every bound the script puts on a step.

    A step that stalls then ends on the script's diagnostic rather than on the
    runner cancelling the job.
    """

    TEXT = SCRIPT.read_text()

    def test_every_kubectl_call_goes_through_the_bounded_wrapper(self):
        calls = [line.strip() for line in executable_lines(self.TEXT)
                 if re.search(r"(?<![\w-])kubectl(?![\w-])", line)
                 and not line.lstrip().startswith("for tool in ")]
        self.assertEqual(calls, ['kubectl --request-timeout="${REQUEST_TIMEOUT}s" "$@"'])

    def test_every_bound_is_named_and_under_the_jobs_timeout(self):
        bounds = {name: int(value) for name, value
                  in re.findall(r"^([A-Z_]+_TIMEOUT)=(\d+)$", self.TEXT, re.M)}
        self.assertIn("REQUEST_TIMEOUT", bounds)
        job = yaml.safe_load(CI.read_text())["jobs"]["digest-rewrite"]
        self.assertIn("./scripts/check-digest-rewrite.sh",
                      [step.get("run") for step in job["steps"]])
        for name, seconds in bounds.items():
            with self.subTest(bound=name):
                self.assertLess(seconds, job["timeout-minutes"] * 60)
        for line in executable_lines(self.TEXT):
            with self.subTest(line=line.strip()):
                self.assertNotRegex(line, r'--(request-)?timeout[= ]"?\d|--wait "?\d')


class OneTransportPattern(unittest.TestCase):
    """Both gates read the verifier's errors through scripts/transport-failure.sh."""

    SOURCE = re.compile(r'^\. "\$ROOT/scripts/transport-failure\.sh"$', re.M)

    def test_both_gates_source_the_shared_pattern(self):
        for gate in (SCRIPT, KYVERNO_TEST):
            with self.subTest(gate=gate.name):
                self.assertRegex(gate.read_text(), self.SOURCE)

    def test_no_gate_words_a_transport_failure_of_its_own(self):
        phrases = literal_phrases(shared_pattern())
        self.assertIn("tuf: failed to download", phrases)
        self.assertIn("no such host", phrases)
        for gate in (SCRIPT, KYVERNO_TEST):
            with self.subTest(gate=gate.name):
                self.assertEqual(own_phrases(gate.read_text(), phrases), [])
                self.assertNotRegex(gate.read_text(), r"(?m)^\s*TRANSPORT_FAILURE=")

    def test_a_phrase_in_code_is_a_pattern_of_its_own_and_one_in_a_comment_is_not(self):
        phrases = literal_phrases(shared_pattern())
        text = ("# A connection reset by peer is the API server dropping one.\n"
                "classify() { grep -iE 'no such host|i/o timeout'; }\n")
        self.assertEqual(own_phrases(text, phrases), ["no such host", "i/o timeout"])


if __name__ == "__main__":
    unittest.main()
