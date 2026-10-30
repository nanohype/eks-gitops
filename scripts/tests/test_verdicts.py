"""Unit tests for scripts/verdicts.py, every verdict on the image-verification path.

scripts/kyverno-test.sh and scripts/check-digest-rewrite.sh run the commands
and hand what came back to verdicts.py, which decides what it means. These hold
each decision on its own, on the shapes the verifier, the API server, kubectl
and GNU timeout produce: the transport failures that decide nothing, the
refusals whose cause is or is not established, the pin, the foreign identity,
and the statuses the shell scripts act on. scripts/tests/test_kyverno_test.py
and scripts/tests/test_digest_rewrite.py hold the scripts to these decisions.

The file sits at 100% of its lines and branches in scripts/tests/run.py,
because a branch on this path that no test reaches is a verdict nothing proves.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from gateloader import load
from shellgate import ESC, identity_message, verifier_line

verdicts = load("verdicts")
gatelib = load("gatelib")

SCRIPT = pathlib.Path(verdicts.__file__)

TAGGED = "ghcr.io/nanohype/x:1.0.0"
DIGEST = f"sha256:{'a' * 64}"
PINNED = f"{TAGGED}@{DIGEST}"
ROOT = "/checkout/eks-gitops"

IDENTITY_REFUSAL = ('Error from server (Forbidden): admission webhook "ivpol.validate.kyverno.'
                    'svc-fail" denied the request: Policy verify-images failed: '
                    f"{verdicts.IDENTITY_MESSAGE}")
MISMATCH = verifier_line("failed to verify cosign signatures: no matching signatures: none of "
                         "the expected identities matched what was in the certificate")
TUF = verifier_line('failed to build cosign verification opts: tuf: failed to download '
                    '17.root.json: Get "https://tuf-repo-cdn.sigstore.dev/17.root.json": http2: '
                    'server sent GOAWAY and closed the connection')
# What the webhook server logs as the API server drops a connection, into the
# same stream as the verifier, naming a transport failure and no verification.
DROPPED = (f"2026-01-01T00:00:00Z {ESC}[31mERR{ESC}[0m github.com/kyverno/kyverno/pkg/logging/"
           "log.go:184 > http: TLS handshake error from 10.244.0.1:53422: read tcp "
           "10.244.0.5:9443->10.244.0.1:53422: read: connection reset by peer logger=server")
NO_ANSWER = ('error: error when creating "pod.yaml": Post "https://127.0.0.1:6443/api/v1/'
             'namespaces/workloads/pods": context deadline exceeded (Client.Timeout exceeded '
             "while awaiting headers)")
WEBHOOK_UNANSWERED = ('Error from server (InternalError): Internal error occurred: failed '
                      'calling webhook "ivpol.validate.kyverno.svc-fail": failed to call webhook: '
                      'Post "https://kyverno-svc.kyverno.svc:443/validate/fail?timeout=10s": '
                      "context deadline exceeded")
REGISTRY_429 = ('Error from server (Forbidden): admission webhook "ivpol.validate.kyverno.'
                'svc-fail" denied the request: Policy verify-images error: failed to get '
                "imagedata: GET https://ghcr.io/v2/nanohype/x/manifests/sha256:0: unexpected "
                "status code 429 Too Many Requests")
ALREADY_EXISTS = 'Error from server (AlreadyExists): pods "vi-branch-signed" already exists'
# A warning the API server returned with its answer, which kubectl writes on a
# line of its own ahead of the error.
PSA_WARNING = ('Warning: would violate PodSecurity "restricted:latest": '
               'allowPrivilegeEscalation != false (container "x" must set '
               "securityContext.allowPrivilegeEscalation=false)")

# One line per alternative of the pattern, each naming only that alternative, in
# the words the client that writes it uses.
TRANSPORT = {
    "dial tcp": 'Get "https://ghcr.io/v2/": dial tcp 140.82.112.33:443: connect: network down',
    "no such host": "lookup ghcr.io on 127.0.0.53:53: no such host",
    "i/o timeout": "read udp 10.0.0.2:41234->10.0.0.1:53: i/o timeout",
    "connection refused": "connect: connection refused",
    "connection reset": "read: connection reset by peer",
    "broken pipe": "write: broken pipe",
    "TLS handshake timeout": "net/http: TLS handshake timeout",
    "context deadline exceeded": "Post \"https://rekor.sigstore.dev\": context deadline exceeded",
    "Client.Timeout exceeded": "net/http: request canceled (Client.Timeout exceeded while "
                               "awaiting headers)",
    "unexpected EOF": "GET https://ghcr.io/v2/nanohype/x/blobs/sha256:0: unexpected EOF",
    "tuf: failed to download": "tuf: failed to download 17.root.json",
    "unexpected status code 429": "GET https://ghcr.io/v2/: unexpected status code 429 Too Many "
                                  "Requests",
    "unexpected status code 5xx": "GET https://ghcr.io/v2/: unexpected status code 502 Bad "
                                  "Gateway",
    "toomanyrequests": "TOOMANYREQUESTS: retry-after: 1s",
    "][429]": "[POST /api/v1/log/entries/retrieve][429] searchLogQueryDefault",
    "][5xx]": "[POST /api/v1/log/entries/retrieve][503] searchLogQueryDefault",
}

# What the verification path writes that is no transport failure, and must not
# read as one.
NOT_TRANSPORT = {
    "an identity mismatch": "no matching signatures: none of the expected identities matched",
    "a 404": "GET https://ghcr.io/v2/: unexpected status code 404 Not Found",
    "a Rekor 404": "[POST /api/v1/log/entries/retrieve][404] searchLogQueryNotFound",
    "a refusal under the identity message": IDENTITY_REFUSAL,
    "an object that already exists": ALREADY_EXISTS,
}


def refusal(text: str, log: str | None = None, what: str = "the signed pod"):
    return verdicts.Refusal(what=what, overlay="overlays/tier", root=ROOT, request_timeout=90,
                            text=text, log=log)


def run(*argv: str, stdin: bytes = b"") -> tuple[int, str]:
    """main(argv), with `stdin` piped in: the status and what it printed."""
    out = io.StringIO()
    piped = io.TextIOWrapper(io.BytesIO(stdin))
    with contextlib.redirect_stdout(out), mock.patch.object(verdicts.sys, "stdin", piped):
        status = verdicts.main(list(argv))
    return status, out.getvalue()


class TheStatuses(unittest.TestCase):
    """What the shell scripts act on, and what no failure of the interpreter produces."""

    def test_each_verdict_is_a_status_of_its_own(self):
        statuses = [verdicts.HOLDS, verdicts.CANNOT_RUN, verdicts.FINDING, verdicts.AGAIN]
        self.assertEqual(len(set(statuses)), 4, statuses)

    def test_could_not_decide_is_the_status_every_gate_shares(self):
        self.assertEqual(verdicts.CANNOT_RUN, gatelib.CANNOT_RUN)

    def test_a_traceback_reads_as_no_verdict(self):
        """Python exits 1 for an uncaught exception; no verdict is 1."""
        self.assertNotIn(1, (verdicts.HOLDS, verdicts.FINDING, verdicts.AGAIN))

    def test_a_call_that_cannot_be_parsed_could_not_decide(self):
        for argv in (["no-such-question"], ["pinned", "--site=container"], []):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    verdicts.main(argv)
                self.assertEqual(raised.exception.code, verdicts.CANNOT_RUN)

    def test_run_as_a_script_it_exits_with_the_verdict(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "pinned", "--site=container",
                               f"--tagged={TAGGED}", f"--image={TAGGED}"],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, verdicts.FINDING, proc.stderr)
        self.assertIn(f"FAIL  admitted {TAGGED} in the container as '{TAGGED}'", proc.stdout)


class ReadingLines(unittest.TestCase):
    def test_a_final_newline_ends_the_last_line(self):
        self.assertEqual(verdicts.lines_of("a\nb\n"), ["a", "b"])

    def test_a_last_line_without_a_newline_is_a_line(self):
        self.assertEqual(verdicts.lines_of("a\nb"), ["a", "b"])

    def test_an_empty_line_inside_is_kept(self):
        self.assertEqual(verdicts.lines_of("a\n\nb\n"), ["a", "", "b"])

    def test_nothing_is_no_lines(self):
        self.assertEqual(verdicts.lines_of(""), [])

    def test_colour_codes_are_cut_away(self):
        self.assertEqual(verdicts.uncoloured(f"{ESC}[36merror={ESC}[0m{ESC}[1;31mx{ESC}[0m"),
                         "error=x")


class ATransportFailure(unittest.TestCase):
    def test_each_phrase_is_one(self):
        for phrase, line in TRANSPORT.items():
            with self.subTest(phrase=phrase):
                self.assertEqual(verdicts.transport_failures(line), [line])

    def test_each_example_names_one_phrase_alone(self):
        """So each phrase is held by a line nothing else in the pattern reads."""
        alternatives = split_alternatives(verdicts.TRANSPORT_FAILURE.pattern)
        self.assertEqual(len(alternatives), len(TRANSPORT) - 2,
                         "a phrase in the pattern carries no example here, or an example "
                         "names no phrase; the 429 and 5xx forms of a status share one")
        for phrase, line in TRANSPORT.items():
            with self.subTest(phrase=phrase):
                matching = [a for a in alternatives
                            if re.search(a, line, re.IGNORECASE)]
                self.assertEqual(len(matching), 1, matching)

    def test_case_is_ignored(self):
        self.assertTrue(verdicts.transport_failures("NO SUCH HOST"))

    def test_what_is_no_transport_failure_is_not_one(self):
        for name, line in NOT_TRANSPORT.items():
            with self.subTest(name=name):
                self.assertEqual(verdicts.transport_failures(line), [])

    def test_a_line_is_quoted_from_shortly_before_its_first_phrase(self):
        line = "x" * 100 + " dial tcp: lookup ghcr.io: no such host"
        [quoted] = verdicts.transport_failures(line)
        self.assertEqual(quoted, line[line.index("dial tcp") - verdicts.CONTEXT:])

    def test_a_phrase_near_the_start_is_quoted_from_the_start(self):
        line = "Get x: dial tcp: refused"
        self.assertEqual(verdicts.transport_failures(line), [line])

    def test_a_quoted_line_is_cut_to_its_width(self):
        [quoted] = verdicts.transport_failures("no such host " + "y" * 500)
        self.assertEqual(len(quoted), verdicts.WIDTH)

    def test_its_colour_is_cut_away_before_it_is_read(self):
        [quoted] = verdicts.transport_failures(TUF)
        self.assertNotIn(ESC, quoted)
        self.assertIn("tuf: failed to download 17.root.json", quoted)

    def test_a_line_seen_twice_is_quoted_once(self):
        line = TRANSPORT["no such host"]
        self.assertEqual(verdicts.transport_failures(f"{line}\n{line}\n"), [line])

    def test_at_most_three_distinct_lines_are_quoted(self):
        lines = [TRANSPORT[p] for p in ("dial tcp", "broken pipe", "unexpected EOF",
                                        "toomanyrequests")]
        self.assertEqual(verdicts.transport_failures("\n".join(lines)), lines[:3])

    def test_lines_naming_none_are_skipped(self):
        line = TRANSPORT["broken pipe"]
        self.assertEqual(verdicts.transport_failures(f"fine\n{line}\nfine"), [line])


def split_alternatives(pattern: str) -> list[str]:
    """The top-level alternatives of `pattern`, as patterns of their own."""
    alternatives, depth, current = [], 0, ""
    for i, ch in enumerate(pattern):
        escaped = i > 0 and pattern[i - 1] == "\\"
        if ch == "|" and depth == 0 and not escaped:
            alternatives.append(current)
            current = ""
            continue
        if not escaped:
            depth += {"(": 1, ")": -1}.get(ch, 0)
        current += ch
    alternatives.append(current)
    return alternatives


class ABound(unittest.TestCase):
    def test_a_command_its_term_ended_did_not_finish(self):
        self.assertEqual(verdicts.ended_by_bound("kind", verdicts.TIMED_OUT, 600),
                         "kind did not finish within 600s, so GNU timeout ended it.")

    def test_a_command_its_kill_ended_was_killed(self):
        self.assertEqual(verdicts.ended_by_bound("helm", verdicts.KILLED, 600),
                         "helm was killed before it finished.")

    def test_a_command_that_ended_on_its_own_is_not_named(self):
        for status in (0, 1, 2, 125, 126, 127, 143):
            with self.subTest(status=status):
                self.assertEqual(verdicts.ended_by_bound("kubectl", status, 90), "")

    def test_the_statuses_are_gnu_timeouts(self):
        self.assertEqual((verdicts.TIMED_OUT, verdicts.KILLED), (124, 128 + 9))

    def test_asked_it_prints_the_sentence(self):
        self.assertEqual(run("bound", "--command=kind", "--status=124", "--seconds=600"),
                         (verdicts.HOLDS, "kind did not finish within 600s, so GNU timeout "
                                          "ended it.\n"))

    def test_asked_about_a_command_that_finished_it_prints_nothing(self):
        self.assertEqual(run("bound", "--command=kind", "--status=0", "--seconds=600"),
                         (verdicts.HOLDS, ""))


class AnEndpoint(unittest.TestCase):
    def test_a_success_or_the_registrys_challenge_answered(self):
        for status in ("200", "204", "401"):
            with self.subTest(status=status):
                self.assertEqual(verdicts.endpoint("https://ghcr.io/v2/", status),
                                 (verdicts.HOLDS, []))

    def test_anything_else_did_not(self):
        for status in ("503", "429", "404", "403", "000", "2000", "20"):
            with self.subTest(status=status):
                verdict, said = verdicts.endpoint("https://ghcr.io/v2/", status)
                self.assertEqual(verdict, verdicts.CANNOT_RUN)
                self.assertIn(f"Cannot run: https://ghcr.io/v2/ answered '{status}'", said[0])

    def test_no_status_at_all_answered_nothing(self):
        status, said = run("endpoint", "--url=https://rekor.sigstore.dev/api/v1/log",
                           "--status=")
        self.assertEqual(status, verdicts.CANNOT_RUN)
        self.assertIn("answered 'nothing', so the image-verification\nrows would decide on an "
                      "unreachable registry or log rather than on a signature.", said)


CLEAN = "│ 15 │ verify-images │ Pass │ Ok │ success │\nTest Summary: 33 tests passed"


class AKyvernoRun(unittest.TestCase):
    def test_one_naming_no_transport_failure_is_decided_on_its_rows(self):
        for status in (0, 1):
            with self.subTest(status=status):
                self.assertEqual(verdicts.kyverno_run(CLEAN, status, 1, 3, 240),
                                 (verdicts.HOLDS, []))

    def test_a_failure_behind_the_policys_message_is_run_again(self):
        verdict, said = verdicts.kyverno_run(f"{CLEAN}\n{TUF}", 1, 1, 3, 240)
        self.assertEqual(verdict, verdicts.AGAIN)
        self.assertEqual(said[0], "Attempt 1 of 3 met a transport failure, so its "
                                  "image-verification")
        self.assertEqual(said[1], "rows decided nothing; running the suite again:")
        self.assertTrue(said[2].startswith("      "), said)
        self.assertIn("tuf: failed to download", said[2])

    def test_the_last_attempt_could_not_verify(self):
        verdict, said = verdicts.kyverno_run(TRANSPORT["no such host"], 1, 3, 3, 240)
        self.assertEqual(verdict, verdicts.CANNOT_RUN)
        self.assertEqual(said[0], "Cannot run: all 3 runs met a transport failure on the "
                                  "image-verification")
        self.assertEqual(said[2], f"      {TRANSPORT['no such host']}")

    def test_an_attempt_past_the_last_could_not_verify_either(self):
        verdict, _ = verdicts.kyverno_run(TRANSPORT["no such host"], 1, 4, 3, 240)
        self.assertEqual(verdict, verdicts.CANNOT_RUN)

    def test_a_run_its_bound_ended_is_run_again_whatever_it_printed(self):
        verdict, said = verdicts.kyverno_run(CLEAN, verdicts.TIMED_OUT, 1, 3, 240)
        self.assertEqual(verdict, verdicts.AGAIN)
        self.assertEqual(said[2:], ["      kyverno test did not finish within 240s, so GNU "
                                    "timeout ended it."])

    def test_a_run_killed_is_run_again_whatever_it_printed(self):
        verdict, said = verdicts.kyverno_run(CLEAN, verdicts.KILLED, 2, 3, 240)
        self.assertEqual(verdict, verdicts.AGAIN)
        self.assertEqual(said[2:], ["      kyverno test was killed before it finished."])

    def test_a_bound_ending_the_last_run_is_named_and_not_its_output(self):
        verdict, said = verdicts.kyverno_run(TRANSPORT["broken pipe"], verdicts.KILLED, 3, 3,
                                             240)
        self.assertEqual(verdict, verdicts.CANNOT_RUN)
        self.assertEqual(said[2:], ["      kyverno test was killed before it finished."])

    def test_asked_it_reads_the_run_on_standard_input(self):
        status, said = run("kyverno-run", "--status=1", "--attempt=1", "--attempts=3",
                           "--seconds=240", stdin=f"{CLEAN}\n{TUF}\n".encode())
        self.assertEqual(status, verdicts.AGAIN)
        self.assertIn("tuf: failed to download 17.root.json", said)

    def test_bytes_that_are_not_utf8_are_read_rather_than_refused(self):
        status, said = run("kyverno-run", "--status=1", "--attempt=3", "--attempts=3",
                           "--seconds=240", stdin=b"\xff\xfe dial tcp: refused\n")
        self.assertEqual(status, verdicts.CANNOT_RUN)
        self.assertIn("�� dial tcp: refused", said)


class TheVerifiersLines(unittest.TestCase):
    def test_a_failed_verification_is_the_verifiers(self):
        self.assertEqual(verdicts.verifier_lines(MISMATCH), [verdicts.uncoloured(MISMATCH)])

    def test_the_controllers_own_errors_are_not(self):
        self.assertEqual(verdicts.verifier_lines(f"{DROPPED}\n{MISMATCH}\n"),
                         [verdicts.uncoloured(MISMATCH)])

    def test_the_fixtures_line_is_one_the_verifier_writes(self):
        """Both shell gates' tests build the verifier's line from shellgate.py."""
        self.assertIn(verdicts.VERIFIER_FAILED, verifier_line("x"))


class TheIdentityMessage(unittest.TestCase):
    def test_it_is_the_policys(self):
        """A refusal is decided on the message; a copy that drifts decides none."""
        self.assertEqual(verdicts.IDENTITY_MESSAGE, identity_message())


class ARefusalsCause(unittest.TestCase):
    def assert_cannot_run(self, verdict, headline: str, cause: str) -> None:
        """The refusal, then the line naming its cause, then the link it broke."""
        status, said = verdict
        self.assertEqual(status, verdicts.CANNOT_RUN, said)
        self.assertEqual(len(said), 3, said)
        self.assertTrue(said[0].startswith("        Error from server")
                        or said[0].startswith("        error:"), said)
        self.assertTrue(said[1].startswith(verdicts.INDENT), said)
        self.assertIn(cause, said[1])
        self.assertEqual(said[2], f"Cannot run: {headline}")

    def test_a_request_kubectl_got_no_answer_for_reads_no_log(self):
        self.assert_cannot_run(
            verdicts.refusal_cause(refusal(NO_ANSWER)),
            "overlays/tier: kubectl's request for the signed pod ended with no answer from the "
            "API server:\nits 90s bound passed or its connection failed.",
            "Client.Timeout exceeded")

    def test_a_webhook_the_api_server_got_no_answer_from(self):
        self.assert_cannot_run(
            verdicts.refusal_cause(refusal(WEBHOOK_UNANSWERED)),
            "overlays/tier: the API server got no answer from Kyverno's admission webhook for "
            "the signed pod.",
            "context deadline exceeded")

    def test_a_registry_the_verifier_could_not_read(self):
        self.assert_cannot_run(
            verdicts.refusal_cause(refusal(REGISTRY_429)),
            "overlays/tier could not reach the registry, the Sigstore trusted root or Rekor for "
            "the signed pod.",
            "unexpected status code 429")

    def test_the_replicasets_refusal_carries_an_answer(self):
        events = ("Error creating: pods is forbidden: exceeded quota\n"
                  "Error creating: " + REGISTRY_429.split(": ", 1)[1])
        status, said = verdicts.refusal_cause(refusal(events, what="the Deployment's pod"))
        self.assertEqual(status, verdicts.CANNOT_RUN)
        self.assertIn("could not reach the registry", said[-1])

    def test_an_answer_after_kubectls_warnings_is_an_answer(self):
        """kubectl writes each warning the API server returned ahead of its error."""
        text = f"{PSA_WARNING}\n{REGISTRY_429}"
        status, said = verdicts.refusal_cause(refusal(text))
        self.assertEqual(status, verdicts.CANNOT_RUN, said)
        self.assertEqual(said[-1], "Cannot run: overlays/tier could not reach the registry, the "
                                   "Sigstore trusted root or Rekor for the signed pod.")

    def test_a_refusal_naming_none_asks_for_the_verifiers_log(self):
        self.assertEqual(verdicts.refusal_cause(refusal(IDENTITY_REFUSAL)),
                         (verdicts.AGAIN, []))

    def test_an_outage_behind_the_identity_message_is_not_a_denial(self):
        self.assert_cannot_run(
            verdicts.refusal_cause(refusal(IDENTITY_REFUSAL, f"{MISMATCH}\n{TUF}")),
            "overlays/tier could not reach the registry, the Sigstore trusted root or Rekor for "
            "the signed pod.",
            "tuf: failed to download 17.root.json")

    def test_an_identity_refusal_with_no_verifier_line_is_of_unknown_cause(self):
        for log in ("", DROPPED):
            with self.subTest(log=log):
                status, said = verdicts.refusal_cause(refusal(IDENTITY_REFUSAL, log))
                self.assertEqual(status, verdicts.CANNOT_RUN)
                self.assertEqual(said[-1], (
                    "Cannot run: overlays/tier refused the signed pod with the identity message, "
                    "but the admission\ncontroller's log carries no 'image verification failed' "
                    "line, so whether the identity or\nan outage refused it is unknown."))
                self.assertIn(f"        {IDENTITY_REFUSAL}", said)

    def test_an_identity_refusal_beside_the_verifiers_line_is_the_policys(self):
        self.assertEqual(verdicts.refusal_cause(refusal(IDENTITY_REFUSAL, f"{DROPPED}\n{MISMATCH}")),
                         (verdicts.HOLDS, []))

    def test_another_refusal_needs_no_verifier_line(self):
        self.assertEqual(verdicts.refusal_cause(refusal(ALREADY_EXISTS, "")),
                         (verdicts.HOLDS, []))

    def test_a_refusal_is_shown_without_the_checkouts_path_and_cut_to_width(self):
        text = f'error: the path "{ROOT}/policies/x.yaml" does not exist ' + "z" * 400
        [shown] = verdicts.shown(refusal(text))
        self.assertTrue(shown.startswith('        error: the path "policies/x.yaml"'), shown)
        self.assertEqual(len(shown), verdicts.WIDTH)


class ARefusedReleaseSignedSubmission(unittest.TestCase):
    MEANS = f"denied the release-signed {TAGGED}, so no digest was written"

    def test_the_policys_refusal_is_a_finding(self):
        status, said = verdicts.release_signed_refused(refusal(IDENTITY_REFUSAL, MISMATCH),
                                                       self.MEANS)
        self.assertEqual(status, verdicts.FINDING)
        self.assertEqual(said, [f"  FAIL  {self.MEANS}:", f"        {IDENTITY_REFUSAL}"])

    def test_one_of_unknown_cause_is_not(self):
        status, said = verdicts.release_signed_refused(refusal(IDENTITY_REFUSAL, ""), self.MEANS)
        self.assertEqual(status, verdicts.CANNOT_RUN)
        self.assertNotIn("FAIL", "\n".join(said))

    def test_its_log_is_asked_for_before_it_is_decided(self):
        self.assertEqual(verdicts.release_signed_refused(refusal(IDENTITY_REFUSAL), self.MEANS),
                         (verdicts.AGAIN, []))


class AForeignIdentity(unittest.TestCase):
    WHAT = "the branch-signed image"

    def decide(self, admitted: bool, actions: str, text: str = "", log: str | None = None):
        return verdicts.foreign_identity(refusal(text, log, self.WHAT), admitted, actions)

    def test_admitted_under_deny_is_a_finding(self):
        self.assertEqual(self.decide(True, "Deny"),
                         (verdicts.FINDING, [f"  FAIL  admitted {self.WHAT} under Deny."]))

    def test_admitted_under_deny_among_others_is_a_finding(self):
        self.assertEqual(self.decide(True, "Audit,Deny")[0], verdicts.FINDING)

    def test_admitted_under_audit_holds_and_is_reported(self):
        self.assertEqual(self.decide(True, "Audit"), (verdicts.HOLDS, [
            f"  ok    admitted {self.WHAT} under Audit (reported, not blocked)"]))

    def test_an_action_merely_containing_deny_does_not_block(self):
        self.assertEqual(self.decide(True, "Audit,NoDeny")[0], verdicts.HOLDS)

    def test_denied_for_its_identity_under_deny_holds(self):
        self.assertEqual(self.decide(False, "Deny", IDENTITY_REFUSAL, MISMATCH), (verdicts.HOLDS, [
            f"  ok    denied {self.WHAT}: {verdicts.IDENTITY_MESSAGE}"]))

    def test_denied_for_its_identity_under_audit_is_a_finding(self):
        self.assertEqual(self.decide(False, "Audit", IDENTITY_REFUSAL, MISMATCH), (
            verdicts.FINDING,
            [f"  FAIL  denied {self.WHAT} under Audit, which reports and does not block."]))

    def test_refused_for_another_reason_is_a_finding_that_shows_it(self):
        self.assertEqual(self.decide(False, "Deny", ALREADY_EXISTS, MISMATCH), (
            verdicts.FINDING,
            [f"  FAIL  {self.WHAT} was refused for a reason other than its identity:",
             f"        {ALREADY_EXISTS}"]))

    def test_refused_for_a_transport_failure_could_not_decide(self):
        self.assertEqual(self.decide(False, "Deny", REGISTRY_429)[0], verdicts.CANNOT_RUN)

    def test_a_refusal_asks_for_its_log_before_it_is_decided(self):
        self.assertEqual(self.decide(False, "Deny", IDENTITY_REFUSAL), (verdicts.AGAIN, []))


class AskedAboutARefusal(unittest.TestCase):
    """The refusal and the log arrive as files, whatever bytes the shell wrote."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)

    def file(self, name: str, content: bytes) -> str:
        path = self.dir / name
        path.write_bytes(content)
        return str(path)

    def ask(self, *argv: str, log: bytes | None = None) -> tuple[int, str]:
        context = ["--overlay=overlays/tier", f"--root={ROOT}", "--request-timeout=90",
                   f"--refusal={self.file('err', IDENTITY_REFUSAL.encode() + b'\xff')}"]
        if log is not None:
            context.append(f"--log={self.file('log', log)}")
        return run(*argv, *context)

    def test_without_the_log_it_asks_for_it(self):
        self.assertEqual(self.ask("release-signed", "--what=the signed pod", "--means=refused"),
                         (verdicts.AGAIN, ""))

    def test_with_the_log_a_release_signed_refusal_is_a_finding(self):
        status, said = self.ask("release-signed", "--what=the signed pod", "--means=refused",
                                log=MISMATCH.encode())
        self.assertEqual(status, verdicts.FINDING)
        self.assertEqual(said, f"  FAIL  refused:\n        {IDENTITY_REFUSAL}�\n")

    def test_a_foreign_identity_refused_under_deny_holds(self):
        status, said = self.ask("foreign-identity", "--what=the branch-signed image",
                                "--outcome=refused", "--actions=Deny", log=MISMATCH.encode())
        self.assertEqual(status, verdicts.HOLDS)
        self.assertIn("ok    denied the branch-signed image:", said)

    def test_a_foreign_identity_admitted_under_deny_is_a_finding(self):
        status, said = self.ask("foreign-identity", "--what=the branch-signed image",
                                "--outcome=admitted", "--actions=Deny")
        self.assertEqual(status, verdicts.FINDING)
        self.assertEqual(said, "  FAIL  admitted the branch-signed image under Deny.\n")


class APin(unittest.TestCase):
    def test_the_tag_joined_to_a_digest_is_pinned(self):
        self.assertTrue(verdicts.pinned(TAGGED, PINNED))

    def test_what_is_not_the_tag_joined_to_a_digest_is_not(self):
        for name, image in {
            "the tag alone": TAGGED,
            "nothing": "",
            "a short digest": f"{TAGGED}@sha256:{'a' * 63}",
            "a long digest": f"{TAGGED}@sha256:{'a' * 65}",
            "an upper-case digest": f"{TAGGED}@sha256:{'A' * 64}",
            "another algorithm": f"{TAGGED}@sha512:{'a' * 64}",
            "the digest alone": f"ghcr.io/nanohype/x@{DIGEST}",
            "another tag": f"ghcr.io/nanohype/x:1.0.1@{DIGEST}",
            "a dot read as any character": f"ghcr.io/nanohype/x:1x0x0@{DIGEST}",
            "a prefix": f"evil/{PINNED}",
            "a suffix": f"{PINNED}x",
            "a second line": f"{TAGGED}\n{PINNED}",
        }.items():
            with self.subTest(name=name):
                self.assertFalse(verdicts.pinned(TAGGED, image))

    def test_each_site_names_where_the_pin_was_read(self):
        for site, subject in {"init-container": f"{TAGGED} in the init container",
                              "container": f"{TAGGED} in the container",
                              "ephemeral-container": f"{TAGGED} as an ephemeral container",
                              "deployment-pod": "the Deployment's pod"}.items():
            with self.subTest(site=site):
                self.assertEqual(verdicts.pin(site, TAGGED, PINNED),
                                 (verdicts.HOLDS, [f"  ok    admitted {subject} as {PINNED}"]))
                status, said = verdicts.pin(site, TAGGED, TAGGED)
                self.assertEqual(status, verdicts.FINDING)
                self.assertEqual(said[0], f"  FAIL  admitted {subject} as '{TAGGED}', with no "
                                          f"digest joined to the tag.")

    def test_a_tag_resolved_twice_says_what_that_costs(self):
        _, said = verdicts.pin("container", TAGGED, TAGGED)
        self.assertIn("runs an unverified image", "\n".join(said))

    def test_a_controller_pod_says_it_is_the_one_that_runs(self):
        _, said = verdicts.pin("deployment-pod", TAGGED, TAGGED)
        self.assertIn("A controller-created pod is the one that runs", "\n".join(said))

    def test_asked_it_answers_with_the_verdict(self):
        self.assertEqual(run("pinned", "--site=ephemeral-container", f"--tagged={TAGGED}",
                             f"--image={PINNED}"),
                         (verdicts.HOLDS, f"  ok    admitted {TAGGED} as an ephemeral container "
                                          f"as {PINNED}\n"))

    def test_asked_about_an_image_that_looks_like_a_flag_it_still_answers(self):
        status, _ = run("pinned", "--site=container", f"--tagged={TAGGED}", "--image=-x")
        self.assertEqual(status, verdicts.FINDING)


if __name__ == "__main__":
    unittest.main()
