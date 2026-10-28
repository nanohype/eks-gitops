"""Unit tests for the policy-validity gate's reading of what Kyverno said.

The gate renders every policy overlay and hands each to `kyverno apply`, whose
exit status says nothing: it exits 0 over a policy it discarded and over one it
rejected. The verdict is read out of the output instead, and every branch below
is a way that output can look like success while a policy did not load.

It also holds every rendered ImageValidatingPolicy to the digest pin, which
Kyverno accepts either way. That half is on the signature-verification path.

kustomize and kyverno are replaced by a stub answering the way each one does,
so nothing here reaches a tool or the network.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-policy-validity")

IVPOL = {"apiVersion": "policies.kyverno.io/v1", "kind": "ImageValidatingPolicy",
         "metadata": {"name": "verify-images"},
         "spec": {"validationConfigurations": {"mutateDigest": True, "verifyDigest": True}}}
CPOL = {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
        "metadata": {"name": "require-labels"},
        "spec": {"rules": [{"name": "a"}, {"name": "b"}]}}


def render(*docs) -> str:
    return yaml.safe_dump_all(docs)


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["tool"], returncode, stdout, stderr)


APPLIED = "Applying 3 policy rule(s) to 1 resource(s)...\npass: 0, fail: 0, warn: 0, error: 0, skip: 3\n"


class Tools:
    """Stands in for subprocess.run, answering by the command's first word."""

    def __init__(self, kustomize=None, kyverno=None) -> None:
        self.kustomize = kustomize or completed(stdout=render(CPOL, IVPOL))
        self.kyverno = kyverno or completed(stdout=APPLIED)

    def __call__(self, cmd, **_):
        return self.kustomize if cmd[0] == "kustomize" else self.kyverno


class TheDigestPin(unittest.TestCase):
    """Valid Kyverno either way, so this gate is the one that refuses it."""

    def setUp(self):
        gate.failures.clear()

    def tearDown(self):
        gate.failures.clear()

    def test_both_fields_true_pass(self):
        gate._check_pins_digest("o", render(CPOL, IVPOL, None))
        self.assertEqual(gate.failures, [])

    def test_an_absent_field_reads_as_the_crd_default(self):
        doc = {**IVPOL, "spec": {}}
        gate._check_pins_digest("o", render(doc))
        self.assertEqual(gate.failures, [])

    def test_either_field_false_is_a_failure(self):
        for field in ("mutateDigest", "verifyDigest"):
            with self.subTest(field=field):
                gate.failures.clear()
                cfg = {"mutateDigest": True, "verifyDigest": True, field: False}
                gate._check_pins_digest("o", render({**IVPOL, "spec": {
                    "validationConfigurations": cfg}}))
                self.assertEqual(len(gate.failures), 1)
                self.assertIn(f"sets {field} False", gate.failures[0])


class CountingRules(unittest.TestCase):
    """The count Kyverno's load line is compared against."""

    def test_a_clusterpolicy_counts_its_rules_and_a_cel_policy_counts_one(self):
        self.assertEqual(gate.rules_in(render(CPOL, IVPOL, {"kind": "ConfigMap"}, None)), 3)

    def test_a_policy_with_no_rules_counts_none(self):
        self.assertEqual(gate.rules_in(render({"kind": "Policy", "spec": {}})), 0)

    def test_a_scalar_document_is_not_a_policy(self):
        self.assertEqual(gate.rules_in("--- just a string\n"), 0)


class TheRun(unittest.TestCase):
    """main() over a policy tree in a temporary directory, with stubbed tools."""

    def setUp(self):
        gate.failures.clear()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.policies = self.root / "policies" / "kyverno"

    def tearDown(self):
        gate.failures.clear()

    def overlays(self, groups=("supply-chain",), envs=gate.ENVS):
        for group in groups:
            for env in envs:
                d = self.policies / group / "overlays" / env
                d.mkdir(parents=True)
                (d / "kustomization.yaml").write_text("resources: []\n")

    def run_main(self, tools=None):
        buf = io.StringIO()
        with mock.patch.object(gate, "ROOT", self.root), \
             mock.patch.object(gate, "POLICIES", self.policies), \
             mock.patch.object(gate.gatelib, "require"), \
             mock.patch.object(gate.subprocess, "run", tools or Tools()), \
             contextlib.redirect_stdout(buf):
            code = gate.main()
        return code, buf.getvalue()

    def test_every_overlay_accepted_passes(self):
        self.overlays()
        code, out = self.run_main()
        self.assertEqual(code, 0, out)
        self.assertIn("3 rendered overlays (1 groups x 3 environments)", out)

    def test_no_overlay_is_not_a_clean_run(self):
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("found no policy overlays", out)

    def test_an_environment_with_no_overlay_fails(self):
        self.overlays(envs=("development", "production"))
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("['staging']", out)

    def test_an_overlay_directory_without_a_kustomization_is_not_an_overlay(self):
        self.overlays()
        (self.policies / "supply-chain" / "overlays" / "notes").mkdir()
        (self.policies / "supply-chain" / "overlays" / "README.md").write_text("x\n")
        code, out = self.run_main()
        self.assertEqual(code, 0, out)

    def failing(self, says, **tools):
        self.overlays()
        code, out = self.run_main(Tools(**tools))
        self.assertEqual(code, 1, out)
        self.assertIn(says, out)

    def test_a_render_failure(self):
        self.failing("kustomize build failed", kustomize=completed(1, stderr="no base"))

    def test_an_empty_render(self):
        self.failing("rendered to nothing", kustomize=completed(stdout="\n"))

    def test_no_rule_count_printed(self):
        self.failing("printed no rule count", kyverno=completed(stdout="error: 0\n"))

    def test_fewer_rules_loaded_than_rendered(self):
        self.failing("loaded only 1",
                     kyverno=completed(stdout="Applying 1 policy rule(s) to 1 resource(s)\n"))

    def test_zero_rules_loaded_from_a_render_carrying_none(self):
        self.failing("loaded 0 policy rules",
                     kustomize=completed(stdout=render({"kind": "ConfigMap"})),
                     kyverno=completed(stdout="Applying 0 policy rule(s) to 1 resource(s)\n"))

    def test_a_validation_message_on_stderr(self):
        self.failing("Kyverno rejects this policy",
                     kyverno=completed(stdout=APPLIED,
                                       stderr="spec.x: Invalid value: true: not allowed\n"))

    def test_an_error_count_in_the_summary(self):
        self.failing("kyverno reported errors: pass: 0, fail: 0, warn: 0, error: 1",
                     kyverno=completed(stdout="Applying 3 policy rule(s) to 1 resource(s)\n"
                                              "pass: 0, fail: 0, warn: 0, error: 1, skip: 3\n"))

    def test_an_error_count_with_no_summary_line_reports_the_output(self):
        self.failing("kyverno reported errors: Applying 3",
                     kyverno=completed(stdout="Applying 3 policy rule(s) to 1 resource(s)\n"))

    def test_an_imagevalidatingpolicy_that_stops_pinning(self):
        unpinned = {**IVPOL, "spec": {"validationConfigurations": {"mutateDigest": False}}}
        self.failing("sets mutateDigest False",
                     kustomize=completed(stdout=render(CPOL, unpinned)))


if __name__ == "__main__":
    unittest.main()
