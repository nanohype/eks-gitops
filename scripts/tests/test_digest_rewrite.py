"""Unit tests for the verdict scripts/check-digest-rewrite.sh reaches on a refusal.

The script admits a branch-signed pod and a branch-signed ephemeral container
through each rendered supply-chain overlay, on a kind cluster that only CI
brings up. What it concludes from the API server's answer is one function,
decide_foreign, and sourcing the script defines it without running anything.
These source it and hand it each answer an overlay can get: admitted or
refused, under Deny or Audit, and refused for the policy's identity message, a
transport failure, or another reason.

A transport failure inside verification refuses with the policy's own message,
and only the verifier's log names it, so a refusal is also decided on what the
admission controller logged. A stub named kubectl, first on PATH, answers the
log read with a scripted log and records the arguments it was given.

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

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check-digest-rewrite.sh"
KYVERNO_TEST = ROOT / "scripts" / "kyverno-test.sh"
SHARED = ROOT / "scripts" / "transport-failure.sh"

IDENTITY = re.search(r'^IDENTITY_MESSAGE="([^"]+)"$', SCRIPT.read_text(), re.M)

DECIDE = """
source "$1" || exit 99
WORK="$2" rel=overlays/tier actions="$3" fail=0
mark_sent
decide_foreign "the branch-signed image" "$4"
echo "fail=$fail"
"""

# Bash builtins only, so it answers the same whatever else is on PATH.
KUBECTL = """#!{bash}
printf '%s\\0' "$@" > '{work}/kubectl.argv'
[ -f '{work}/kyverno.log' ] && printf '%s\\n' "$(<'{work}/kyverno.log')"
[ -f '{work}/kubectl.rc' ] || exit 0
echo 'error: the server could not find the requested resource' >&2
exit "$(<'{work}/kubectl.rc')"
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


class DecidingARefusal(unittest.TestCase):
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
        kubectl = self.bin / "kubectl"
        kubectl.write_text(KUBECTL.format(bash=bash, work=self.work))
        kubectl.chmod(0o755)

    def decide(self, actions: str, outcome: str, err: str = "", verifier_log: str = "",
               kubectl_rc: int = 0) -> tuple[int, str]:
        (self.work / "err").write_text(err)
        (self.work / "kyverno.log").write_text(verifier_log)
        if kubectl_rc:
            (self.work / "kubectl.rc").write_text(str(kubectl_rc))
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        proc = subprocess.run([self.bash, "-c", DECIDE, "bash", str(SCRIPT), str(self.work),
                               actions, outcome], capture_output=True, text=True, env=env,
                              timeout=30)
        self.assertNotEqual(proc.returncode, 99, proc.stderr)
        return proc.returncode, proc.stdout + proc.stderr

    def kubectl_argv(self) -> list[str]:
        path = self.work / "kubectl.argv"
        return path.read_text().split("\0")[:-1] if path.exists() else []

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

    def test_refused_for_a_network_failure_cannot_run(self):
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
        rc, said = self.decide("Deny", "refused", self.denied(), MISMATCH, kubectl_rc=1)
        self.assertEqual(rc, 2, said)
        self.assertIn("Cannot run: overlays/tier: the admission controller's log could not be "
                      "read", said)
        self.assertIn("could not find the requested resource", said)
        self.assertNotIn("ok    denied", said)

    def test_a_log_without_the_verifiers_line_decides_no_denial(self):
        """A selector matching no pod reads an empty log, and exits 0."""
        rc, said = self.decide("Deny", "refused", self.denied(), "")
        self.assertEqual(rc, 2, said)
        self.assertIn("carries no 'image verification failed' line", said)
        self.assertNotIn("ok    denied", said)

    def test_a_connection_the_webhook_server_dropped_is_not_the_verifiers(self):
        """The controller's own log lines share the stream and name no verification."""
        rc, said = self.decide("Deny", "refused", self.denied(), "\n".join([DROPPED, MISMATCH]))
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    denied the branch-signed image:", said)
        self.assertIn("fail=0", said)

    def test_the_log_is_read_whole_from_every_admission_controller_replica(self):
        self.decide("Deny", "refused", self.denied(), MISMATCH)
        argv = self.kubectl_argv()
        self.assertEqual(argv[:3], ["logs", "-n", "kyverno"])
        selector = argv[argv.index("-l") + 1].split(",")
        self.assertEqual(sorted(selector), ["app.kubernetes.io/component=admission-controller",
                                            "app.kubernetes.io/instance=kyverno"])
        self.assertIn("--tail=-1", argv)
        since = [a for a in argv if a.startswith("--since=")]
        self.assertEqual(len(since), 1, argv)
        slack = re.search(r"^LOG_SLACK=(\d+)$", SCRIPT.read_text(), re.M)
        assert slack is not None
        self.assertRegex(since[0], r"^--since=\d+s$")
        self.assertGreaterEqual(int(since[0][len("--since="):-1]), int(slack.group(1)))


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
            text = gate.read_text().lower()
            for phrase in phrases:
                with self.subTest(gate=gate.name, phrase=phrase):
                    self.assertNotIn(phrase.lower(), text)
            with self.subTest(gate=gate.name):
                self.assertNotRegex(gate.read_text(), r"(?m)^\s*TRANSPORT_FAILURE=")


if __name__ == "__main__":
    unittest.main()
