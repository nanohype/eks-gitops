"""Unit tests for scripts/kubeconform-scan.sh, run against a scripted kubeconform.

The script captures kubeconform's output to read the summary, so what reaches
the log on a rejection is the script's doing rather than kubeconform's. These
run the real script with a stub named kubeconform first on PATH, and hold what
a reader of a failed CI job depends on: the scan output naming the manifest, the
status kubeconform exited with, and the two catalog commits the run read. The stub
records the arguments it was given, so the commits printed are held to be the
commits kubeconform was pointed at.
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
SCRIPT = ROOT / "scripts" / "kubeconform-scan.sh"

STUB = """#!{bash}
printf '%s\\0' "$@" > '{argv}'
printf '%s\\n' {lines}
exit {status}
"""


def _ref(name: str) -> str:
    """The commit the script pins a schema catalog to, read from the script."""
    found = re.search(rf'^{name}="([0-9a-f]{{40}})"$', SCRIPT.read_text(), re.M)
    assert found, f"{SCRIPT.name} pins no {name}"
    return found.group(1)


class WhatTheScanLeavesInTheLog(unittest.TestCase):
    """Every way the scan exits non-zero leaves the log something to act on."""

    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        self.bash = bash
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.bin = pathlib.Path(tmp.name)
        # Only the directories of the tools the script calls, so a kubeconform
        # installed beside them cannot answer in the stub's place.
        tools = {pathlib.Path(p).parent for p in
                 (shutil.which(t) for t in ("sed", "head")) if p}
        self.path = os.pathsep.join([str(self.bin), *sorted(map(str, tools))])
        for d in tools:
            if (d / "kubeconform").exists():
                self.skipTest(f"a real kubeconform sits in {d}, which the script needs")

    def scan(self, *lines: str, status: int = 0, stub: bool = True):
        if stub:
            quoted = " ".join("'" + line.replace("'", "'\\''") + "'" for line in lines)
            exe = self.bin / "kubeconform"
            exe.write_text(STUB.format(bash=self.bash, argv=self.bin / "argv", lines=quoted,
                                       status=status))
            exe.chmod(0o755)
        env = {"PATH": self.path, "HOME": str(self.bin)}
        proc = subprocess.run([self.bash, str(SCRIPT), "rendered/"], capture_output=True,
                              text=True, env=env, timeout=60)
        return proc.returncode, proc.stdout + proc.stderr

    def assert_refs(self, said: str):
        self.assertIn("Schema catalogs pinned for this run:", said)
        self.assertIn(f"yannh/kubernetes-json-schema@{_ref('K8S_SCHEMA_REF')}", said)
        self.assertIn(f"datreeio/CRDs-catalog@{_ref('CRD_CATALOG_REF')}", said)

    def test_a_rejected_manifest_reaches_the_log_with_the_refs(self):
        """The status is collected with `||`, so `set -e` cannot exit before the print."""
        rejected = "rendered/bad.yaml - ConfigMap rv is invalid: got number, want string"
        rc, said = self.scan(rejected,
                             "Summary: 1 resource found in 1 file - Valid: 0, Invalid: 1",
                             status=1)
        self.assertEqual(rc, 1, said)
        self.assertIn(rejected, said)
        self.assertIn("FAIL  kubeconform exited 1.", said)
        self.assertLess(said.index(rejected), said.index("Schema catalogs pinned"))
        self.assert_refs(said)

    def test_a_status_other_than_1_is_passed_through(self):
        rc, said = self.scan("Get https://raw.githubusercontent.com/...: timeout", status=3)
        self.assertEqual(rc, 3, said)
        self.assertIn("FAIL  kubeconform exited 3.", said)
        self.assert_refs(said)

    def test_a_scan_that_validated_nothing_names_the_refs_too(self):
        rc, said = self.scan("Summary: 0 resource found in 0 file - Valid: 0, Invalid: 0")
        self.assertEqual(rc, 2, said)
        self.assertIn("validated 0 resources", said)
        self.assert_refs(said)

    def test_a_scan_with_no_summary_cannot_run(self):
        rc, said = self.scan("something other than a summary")
        self.assertEqual(rc, 2, said)
        self.assertIn("printed no summary", said)

    def test_no_kubeconform_cannot_run(self):
        rc, said = self.scan(stub=False)
        self.assertEqual(rc, 2, said)
        self.assertIn("kubeconform is not on PATH", said)

    def test_kubeconform_reads_only_the_pinned_catalogs(self):
        rc, said = self.scan("Summary: 3 resources found in 2 files - Valid: 3, Invalid: 0")
        self.assertEqual(rc, 0, said)
        argv = (self.bin / "argv").read_text().split("\0")[:-1]
        locations = [argv[i + 1] for i, a in enumerate(argv) if a == "-schema-location"]
        self.assertEqual(len(locations), 2, argv)
        k8s = f"/yannh/kubernetes-json-schema/{_ref('K8S_SCHEMA_REF')}/"
        crds = f"/datreeio/CRDs-catalog/{_ref('CRD_CATALOG_REF')}/"
        self.assertEqual([k8s in loc for loc in locations], [True, False], locations)
        self.assertEqual([crds in loc for loc in locations], [False, True], locations)
        self.assertNotIn("default", locations)

    def test_a_clean_scan_passes_without_the_refs(self):
        rc, said = self.scan("Summary: 3 resources found in 2 files - Valid: 3, Invalid: 0")
        self.assertEqual(rc, 0, said)
        self.assertNotIn("Schema catalogs pinned", said)


if __name__ == "__main__":
    unittest.main()
