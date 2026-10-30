"""Unit tests for scripts/kyverno-test.sh, run against a scripted kyverno.

The verify-images rows verify real signatures, so a transport failure on the
registry, the Sigstore TUF mirror or Rekor reaches the suite's table. Reading
the image fails a row as "got error" with the transport error as its message;
anything after that is counted as a signature that did not verify, so the row
carries the policy's own message and only the verifier's log names the cause.
The script bounds each run in time and hands it to scripts/verdicts.py, which
classifies it by both and counts one that does not finish as a transport
failure too. The script repeats a run that met a transport failure, and exits 2
when every attempt did. A run that met none is decided on its rows.

scripts/tests/test_verdicts.py holds each of those decisions on its own. These
hold the script to them: they run the real script with stubs named kyverno,
timeout, curl and sleep first on PATH, and the interpreter and the few tools it
reads output with linked beside them, so a kyverno installed on the machine
cannot answer in the stub's place. Each kyverno call prints the next scripted
run and records the arguments it was given; the timeout stub records the bounds
and runs what it was handed, so a scripted run exiting 124 or 137 is what
timeout reports for a run it ended or killed.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml
from shellgate import ESC, identity_message, setting, verifier_line

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "kyverno-test.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"

# The tools the script runs besides the stubbed ones and python3.
TOOLS = ("grep", "sed", "head", "dirname")

# The endpoints the script reaches before running the suite, in order.
ENDPOINTS = ["https://ghcr.io/v2/", "https://tuf-repo-cdn.sigstore.dev/timestamp.json",
             "https://rekor.sigstore.dev/api/v1/log"]


ATTEMPTS = setting(SCRIPT, "ATTEMPTS")
PAUSE = setting(SCRIPT, "PAUSE")
RUN_TIMEOUT = setting(SCRIPT, "RUN_TIMEOUT")
KILL_TIMEOUT = setting(SCRIPT, "KILL_TIMEOUT")

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

# GNU timeout's shape, `timeout [OPTION]... DURATION COMMAND...`, under either
# name. What precedes the command is recorded as the bounds it was given.
TIMEOUT = """#!{bash}
bounds=()
while [ "$#" -gt 0 ] && [ "$1" != kyverno ]; do bounds+=("$1"); shift; done
printf '%s\\n' "${{bounds[*]}}" >> '{bin}/bounds'
exec "$@"
"""

def row(n: int, resource: str, result: str, reason: str, message: str) -> str:
    return (f"│ {n:<3}│ verify-images │ verify-images │ v1/Pod/workloads/{resource:<24}│ "
            f"{result:<6}│ {reason:<22}│ {message} │")


IDENTITY = identity_message()
MISMATCH = verifier_line("failed to verify cosign signatures: no matching signatures: none of "
                         "the expected identities matched what was in the certificate")
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
                        verifier_line('failed to build cosign verification opts: tuf: failed '
                                      'to download 17.root.json: Get \\"https://tuf-repo-cdn.'
                                      'sigstore.dev/17.root.json\\": net/http: TLS handshake '
                                      'timeout'),
                        SUMMARY_FAILED, "Error: 2 tests failed"]), 1)

# The same failure under a row expecting a fail: it passes, for the wrong reason.
FALSE_PASS = ("\n".join([row(18, "vi-branch-signed", "Pass", "Ok", IDENTITY),
                         verifier_line("failed to verify cosign signatures: [POST /api/v1/log/"
                                       "entries/retrieve][503] searchLogQueryDefault"),
                         SUMMARY_OK]), 0)

# The registry throttling the signature's manifest read, behind the policy's message.
THROTTLED = ("\n".join([row(15, "vi-signed", "Fail", "Want pass, got fail", IDENTITY),
                        verifier_line("failed to verify cosign signatures: GET https://ghcr.io/"
                                      "v2/nanohype/x/manifests/sha256-0.sig: unexpected status "
                                      "code 429 Too Many Requests"),
                        SUMMARY_FAILED, "Error: 2 tests failed"]), 1)

# A run timeout ended partway through its table.
CUT_OFF = (row(15, "vi-signed", "Pass", "Ok", "success"), 124)

# A run still going KILL_TIMEOUT after that, which timeout killed.
KILLED = (row(15, "vi-signed", "Pass", "Ok", "success"), 137)

# What timeout is handed before the command it bounds.
BOUNDS = f"-k {KILL_TIMEOUT} {RUN_TIMEOUT}"

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
        # The interpreter running these tests, which scripts/verdicts.py runs under.
        (self.bin / "python3").symlink_to(sys.executable)
        self.stub("curl", CURL)
        self.stub("sleep", SLEEP)
        self.stub("timeout", TIMEOUT)
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

    def bounds(self) -> list[str]:
        path = self.bin / "bounds"
        return path.read_text().splitlines() if path.exists() else []


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

    def test_a_throttled_registry_behind_the_policy_message_is_not_a_regression(self):
        rc, said = self.run_script(THROTTLED)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 3)
        self.assertIn("unexpected status code 429", said)

    def test_a_regression_after_one_clears_is_still_a_regression(self):
        rc, said = self.run_script(SWALLOWED, REFUSED)
        self.assertEqual(rc, 1, said)
        self.assertEqual(self.calls(), 2)


class ARunThatDoesNotFinish(KyvernoTestScript):
    """A read that stops answering holds the CLI; the bound ends it as a transport failure."""

    def test_each_run_is_sent_term_at_the_bound_and_killed_after_the_grace(self):
        self.run_script(GOT_ERROR, CLEAN)
        self.assertEqual(self.bounds(), [BOUNDS] * 2)

    def test_one_cut_off_is_run_again(self):
        rc, said = self.run_script(CUT_OFF, CLEAN)
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.calls(), 2)
        self.assertIn(f"kyverno test did not finish within {RUN_TIMEOUT}s", said)

    def test_one_killed_is_run_again(self):
        rc, said = self.run_script(KILLED, CLEAN)
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.calls(), 2)
        self.assertIn("kyverno test was killed before it finished", said)

    def test_one_killed_every_time_cannot_run(self):
        rc, said = self.run_script(KILLED)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), ATTEMPTS)
        self.assertIn("killed before it finished", said.split("Cannot run:")[1])

    def test_one_cut_off_every_time_cannot_run(self):
        rc, said = self.run_script(CUT_OFF)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), ATTEMPTS)
        self.assertIn(f"Cannot run: all {ATTEMPTS} runs met a transport failure", said)
        self.assertIn(f"did not finish within {RUN_TIMEOUT}s", said.split("Cannot run:")[1])

    def test_gtimeout_bounds_the_run_where_timeout_is_absent(self):
        """macOS ships neither name, and Homebrew's coreutils installs this one."""
        (self.bin / "timeout").unlink()
        self.stub("gtimeout", TIMEOUT)
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.bounds(), [BOUNDS])

    def test_no_bound_cannot_run_and_tests_nothing(self):
        (self.bin / "timeout").unlink()
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 0)
        self.assertIn("neither timeout nor gtimeout is on PATH", said)

    def test_every_attempt_fits_inside_the_jobs_timeout(self):
        """The job ends on the script's diagnostic, not on the runner cancelling it.

        The worst case is every probe taking its whole --max-time, every attempt
        outlasting its bound and the grace after it until it is killed, and
        every pause between them.
        """
        probe = re.search(r"--max-time (\d+)", SCRIPT.read_text())
        self.assertIsNotNone(probe, f"{SCRIPT.name} bounds no endpoint probe")
        assert probe is not None
        worst = (len(ENDPOINTS) * int(probe.group(1)) + ATTEMPTS * (RUN_TIMEOUT + KILL_TIMEOUT)
                 + PAUSE * sum(range(1, ATTEMPTS)))
        job = yaml.safe_load(CI.read_text())["jobs"]["kyverno"]
        self.assertIn("./scripts/kyverno-test.sh policies/kyverno/tests",
                      [step.get("run") for step in job["steps"]])
        self.assertLess(worst, job["timeout-minutes"] * 60)


class TheEndpointsAreReachedFirst(KyvernoTestScript):
    def test_every_endpoint_on_the_verification_path_is_probed(self):
        self.run_script(CLEAN)
        curled = (self.bin / "curled").read_text().split()
        self.assertEqual(curled, ENDPOINTS)

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


class WhatDecidesARun(KyvernoTestScript):
    """scripts/verdicts.py decides each run, so a run it could not decide is undecided."""

    def test_no_python_cannot_run_and_tests_nothing(self):
        (self.bin / "python3").unlink()
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 0)
        self.assertIn("python3 is not on PATH", said)

    def test_a_verdict_that_could_not_be_reached_is_not_a_pass(self):
        """An interpreter failing reads as a run nothing decided, never as a decided one."""
        (self.bin / "python3").unlink()
        self.stub("python3", "#!{bash}\ncat >/dev/null\nexit 1\n")
        (self.tests / "kyverno-test.yaml").write_text("results: []\n")
        rc, said = self.run_script(CLEAN)
        self.assertEqual(rc, 2, said)
        self.assertEqual(self.calls(), 1)
        self.assertIn("Cannot run: scripts/verdicts.py could not read attempt 1.", said)
        self.assertIn(SUMMARY_OK, said, "the run's own output is shown")


if __name__ == "__main__":
    unittest.main()
