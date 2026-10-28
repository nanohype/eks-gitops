"""Unit tests for scripts/kyverno-test.sh, run against a scripted kyverno.

The verify-images rows verify real signatures, so a transport failure on the
registry, the Sigstore TUF mirror or Rekor reaches the suite's table. Reading
the image fails a row as "got error" with the transport error as its message;
anything after that is counted as a signature that did not verify, so the row
carries the policy's own message and only the verifier's log names the cause.
The script classifies a run by both, repeats one that met a transport failure,
and exits 2 when every attempt did. A run that met none is decided on its rows.

These run the real script with stubs named kyverno, curl and sleep first on
PATH, and the few tools it reads output with linked beside them, so a kyverno
installed on the machine cannot answer in the stub's place. Each kyverno call
prints the next scripted run and records the arguments it was given.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "kyverno-test.sh"

# The tools the script runs besides the three stubbed ones.
TOOLS = ("grep", "sed", "head", "cut", "awk", "dirname")


def _attempts() -> int:
    """How many runs the script makes, read from the script."""
    found = re.search(r"^ATTEMPTS=(\d+)$", SCRIPT.read_text(), re.M)
    assert found, f"{SCRIPT.name} sets no ATTEMPTS"
    return int(found.group(1))


ATTEMPTS = _attempts()

# Bash builtins only: the PATH the script runs under holds nothing else.
KYVERNO = """#!{bash}
n=0; [ -f '{bin}/calls' ] && n=$(<'{bin}/calls')
n=$((n + 1)); echo "$n" > '{bin}/calls'
printf '%s\\0' "$@" > '{bin}/argv'$n
printf '%s\\n' "$(<'{bin}/run'$n.out)"
exit "$(<'{bin}/run'$n.rc)"
"""

CURL = """#!{bash}
printf '%s\\n' "${{@: -1}}" >> '{bin}/curled'
printf '%s' "$(<'{bin}/curl.code')"
"""

SLEEP = """#!{bash}
printf '%s\\n' "$1" >> '{bin}/slept'
"""

ESC = "\033"


def row(n: int, resource: str, result: str, reason: str, message: str) -> str:
    return (f"│ {n:<3}│ verify-images │ verify-images │ v1/Pod/workloads/{resource:<24}│ "
            f"{result:<6}│ {reason:<22}│ {message} │")


def log(error: str) -> str:
    """A verifier ERR line at -v 1, coloured the way the CLI writes it."""
    return (f"2026-01-01T00:00:00Z {ESC}[31mERR{ESC}[0m github.com/kyverno/kyverno/pkg/image/"
            f"verifiers/ivpol/cosign/verifier.go:281 > image verification failed "
            f"{ESC}[36merror={ESC}[0m{ESC}[31m\"{error}\"{ESC}[0m attestor=release")


IDENTITY = "image is not signed by a nanohype release workflow"
MISMATCH = log("failed to verify cosign signatures: no matching signatures: none of the "
               "expected identities matched what was in the certificate")
SUMMARY_OK = "Test Summary: 33 tests passed and 0 tests failed"
SUMMARY_FAILED = "Test Summary: 31 tests passed and 2 tests failed"

CLEAN = ("\n".join([row(15, "vi-signed", "Pass", "Ok", "success"),
                    row(18, "vi-branch-signed", "Pass", "Ok", IDENTITY),
                    MISMATCH, SUMMARY_OK]), 0)

# The policy refused a release-signed image, on a network that answered.
REFUSED = ("\n".join([row(15, "vi-signed", "Fail", "Want pass, got fail", IDENTITY),
                      MISMATCH, SUMMARY_FAILED, "Error: 2 tests failed"]), 1)

# The policy does not evaluate, for a reason of its own.
CEL_ERROR = ("\n".join([row(15, "vi-signed", "Fail", "Want pass, got error",
                            "failed to evaluate policy: undeclared reference to 'imagez'"),
                        SUMMARY_FAILED, "Error: 2 tests failed"]), 1)

# Reading the image failed, so the row is an error carrying the transport error.
GOT_ERROR = ("\n".join([row(15, "vi-signed", "Fail", "Want pass, got error",
                            'failed to evaluate policy: Get "https://ghcr.io/v2/": dial tcp: '
                            "lookup ghcr.io: no such host"),
                        SUMMARY_FAILED, "Error: 2 tests failed"]), 1)

# The trusted root could not be fetched, which verification counts as a
# signature that did not verify: the row carries the policy's own message.
SWALLOWED = ("\n".join([row(15, "vi-signed", "Fail", "Want pass, got fail", IDENTITY),
                        log('failed to build cosign verification opts: tuf: failed to download '
                            '17.root.json: Get \\"https://tuf-repo-cdn.sigstore.dev/17.root.json'
                            '\\": net/http: TLS handshake timeout'),
                        SUMMARY_FAILED, "Error: 2 tests failed"]), 1)

# The same failure under a row expecting a fail: it passes, for the wrong reason.
FALSE_PASS = ("\n".join([row(18, "vi-branch-signed", "Pass", "Ok", IDENTITY),
                         log("failed to verify cosign signatures: [POST /api/v1/log/entries/"
                             "retrieve][503] searchLogQueryDefault"),
                         SUMMARY_OK]), 0)

MARKED = "results:\n  - policy: verify-images\n    isImageValidatingPolicy: true\n"


class KyvernoTestScript(unittest.TestCase):
    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        self.bash = bash
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.bin = pathlib.Path(tmp.name) / "bin"
        self.bin.mkdir()
        for tool in TOOLS:
            found = shutil.which(tool)
            if found is None:
                self.skipTest(f"{tool} is not on PATH")
            (self.bin / tool).symlink_to(found)
        self.stub("curl", CURL)
        self.stub("sleep", SLEEP)
        (self.bin / "curl.code").write_text("200")
        self.tests = pathlib.Path(tmp.name) / "tests"
        self.tests.mkdir()
        (self.tests / "kyverno-test.yaml").write_text(MARKED)

    def stub(self, name: str, body: str) -> None:
        exe = self.bin / name
        exe.write_text(body.format(bash=self.bash, bin=self.bin))
        exe.chmod(0o755)

    def run_script(self, *runs: tuple[str, int], kyverno: bool = True) -> tuple[int, str]:
        if kyverno:
            self.stub("kyverno", KYVERNO)
        # The last scripted run answers every attempt after it.
        for n in range(1, ATTEMPTS + 1):
            out, rc = runs[min(n, len(runs)) - 1] if runs else ("", 0)
            (self.bin / f"run{n}.out").write_text(out)
            (self.bin / f"run{n}.rc").write_text(str(rc))
        env = {"PATH": str(self.bin), "HOME": str(self.bin)}
        proc = subprocess.run([self.bash, str(SCRIPT), str(self.tests)], capture_output=True,
                              text=True, env=env, timeout=60)
        return proc.returncode, proc.stdout + proc.stderr

    def calls(self) -> int:
        path = self.bin / "calls"
        return int(path.read_text()) if path.exists() else 0

    def slept(self) -> list[str]:
        path = self.bin / "slept"
        return path.read_text().split() if path.exists() else []


class ARunThatMetNoTransportFailure(KyvernoTestScript):
    """Decided on what the policies did, on the first attempt."""

    def test_a_clean_run_passes_once(self):
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.calls(), 1)
        self.assertEqual(self.slept(), [])
        self.assertIn(SUMMARY_OK, said)

    def test_a_refused_signature_is_a_regression_and_runs_once(self):
        rc, said = self.run_script(REFUSED)
        self.assertEqual(rc, 1, said)
        self.assertEqual(self.calls(), 1)
        self.assertIn("Want pass, got fail", said)
        self.assertNotIn("transport failure", said)

    def test_an_evaluation_error_of_the_policy_is_a_regression(self):
        rc, said = self.run_script(CEL_ERROR)
        self.assertEqual(rc, 1, said)
        self.assertEqual(self.calls(), 1)

    def test_the_suite_is_asked_for_the_reasons_it_is_classified_by(self):
        """The message column carries a got-error cause, the -v 1 log the rest."""
        self.run_script(CLEAN)
        argv = (self.bin / "argv1").read_text().split("\0")[:-1]
        self.assertEqual(argv[0], "test")
        self.assertIn("--detailed-results", argv)
        self.assertIn("-v", argv)
        self.assertEqual(argv[argv.index("-v") + 1], "1")


class ARunThatMetATransportFailure(KyvernoTestScript):
    """Decided nothing about the image-verification rows, whatever they reported."""

    def test_one_that_clears_is_run_again(self):
        rc, said = self.run_script(GOT_ERROR, CLEAN)
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.calls(), 2)
        self.assertEqual(self.slept(), ["5"])
        self.assertIn("Attempt 1 of 3 met a transport failure", said)
        self.assertIn("no such host", said)

    def test_one_behind_the_policy_message_is_not_a_regression(self):
        """The row reads as a refused signature; the verifier's log says otherwise."""
        rc, said = self.run_script(SWALLOWED)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 3)
        self.assertEqual(self.slept(), ["5", "10"])
        self.assertIn("Cannot run: all 3 runs met a transport failure", said)
        self.assertIn("TLS handshake timeout", said)
        self.assertNotIn(ESC, said.split("Cannot run:")[1])

    def test_an_expected_failure_it_produced_is_not_a_pass(self):
        rc, said = self.run_script(FALSE_PASS)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 3)
        self.assertIn("[503]", said)

    def test_a_regression_after_one_clears_is_still_a_regression(self):
        rc, said = self.run_script(SWALLOWED, REFUSED)
        self.assertEqual(rc, 1, said)
        self.assertEqual(self.calls(), 2)


class TheEndpointsAreReachedFirst(KyvernoTestScript):
    def test_every_endpoint_on_the_verification_path_is_probed(self):
        self.run_script(CLEAN)
        curled = (self.bin / "curled").read_text().split()
        self.assertEqual(curled, ["https://ghcr.io/v2/",
                                  "https://tuf-repo-cdn.sigstore.dev/timestamp.json",
                                  "https://rekor.sigstore.dev/api/v1/log"])

    def test_an_endpoint_that_does_not_answer_cannot_run_and_tests_nothing(self):
        (self.bin / "curl.code").write_text("503")
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 0)
        self.assertIn("answered '503'", said)

    def test_a_suite_with_no_image_verification_row_probes_nothing(self):
        (self.tests / "kyverno-test.yaml").write_text("results: []\n")
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 0, said)
        self.assertFalse((self.bin / "curled").exists())


class WhatTheTableMustCarry(KyvernoTestScript):
    def test_a_policy_the_engine_rejected(self):
        out, _ = CLEAN
        rc, said = self.run_script((out + "\n│ 3 │ x │ x │ Pass │ Invalid Policy │", 0))
        self.assertEqual(rc, 1, said)
        self.assertIn("a policy it will not accept", said)

    def test_a_run_below_the_floor(self):
        rc, said = self.run_script(("Test Summary: 3 tests passed and 0 tests failed", 0))
        self.assertEqual(rc, 2, said)
        self.assertIn("below the floor", said)

    def test_a_run_with_no_summary_cannot_run(self):
        rc, said = self.run_script(("No test yamls available", 0))
        self.assertEqual(rc, 2, said)
        self.assertIn("printed no test summary", said)

    def test_no_kyverno_cannot_run(self):
        rc, said = self.run_script(kyverno=False)
        self.assertEqual(rc, 2, said)
        self.assertIn("kyverno is not on PATH", said)


if __name__ == "__main__":
    unittest.main()
