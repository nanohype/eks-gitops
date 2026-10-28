"""Unit tests for the verdict scripts/check-digest-rewrite.sh reaches on a foreign identity.

The script admits a branch-signed pod and a branch-signed ephemeral container
through each rendered supply-chain overlay, on a kind cluster that only CI
brings up. What it concludes from the API server's answer is one function,
decide_foreign, and sourcing the script defines it without running anything.
These source it and hand it each answer an overlay can get: admitted or
refused, under Deny or Audit, and refused for the policy's identity message, a
network failure, or another reason.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check-digest-rewrite.sh"

IDENTITY = re.search(r'^IDENTITY_MESSAGE="([^"]+)"$', SCRIPT.read_text(), re.M)

DECIDE = """
source "$1" || exit 99
WORK="$2" rel=overlays/tier actions="$3" fail=0
decide_foreign "the branch-signed image" "$4"
echo "fail=$fail"
"""


class DecidingAForeignIdentity(unittest.TestCase):
    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        self.bash = bash
        self.assertIsNotNone(IDENTITY, f"{SCRIPT.name} sets no IDENTITY_MESSAGE")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)

    def decide(self, actions: str, outcome: str, err: str = "") -> tuple[int, str]:
        (self.work / "err").write_text(err)
        proc = subprocess.run([self.bash, "-c", DECIDE, "bash", str(SCRIPT), str(self.work),
                               actions, outcome], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 99, proc.stderr)
        return proc.returncode, proc.stdout + proc.stderr

    def denied(self) -> str:
        assert IDENTITY is not None
        return (f'admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
                f"Policy verify-images failed: {IDENTITY.group(1)}")

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
        rc, said = self.decide("Deny", "refused", self.denied())
        self.assertEqual(rc, 0, said)
        self.assertIn("ok    denied the branch-signed image:", said)
        self.assertIn("fail=0", said)

    def test_deny_among_several_actions_still_blocks(self):
        rc, said = self.decide("Deny,Audit", "admitted")
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  admitted the branch-signed image under Deny.", said)
        self.assertIn("fail=1", said)

    def test_denied_for_its_identity_under_audit_fails(self):
        rc, said = self.decide("Audit", "refused", self.denied())
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  denied the branch-signed image under Audit, which reports", said)
        self.assertIn("fail=1", said)

    def test_refused_for_a_network_failure_cannot_run(self):
        rc, said = self.decide("Deny", "refused",
                               "Get https://ghcr.io/v2/: dial tcp: i/o timeout")
        self.assertEqual(rc, 2, said)
        self.assertIn("Cannot run: overlays/tier could not reach the registry or Rekor", said)
        self.assertNotIn("fail=", said)

    def test_refused_for_another_reason_fails_and_shows_it(self):
        rc, said = self.decide("Deny", "refused", 'pods "vi-branch-signed" already exists')
        self.assertEqual(rc, 0, said)
        self.assertIn("FAIL  the branch-signed image was refused for a reason other than its "
                      "identity", said)
        self.assertIn("already exists", said)
        self.assertIn("fail=1", said)


if __name__ == "__main__":
    unittest.main()
