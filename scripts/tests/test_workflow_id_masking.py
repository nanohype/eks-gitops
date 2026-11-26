"""The vendored account-id gate and mask script, run as this repository runs them.

scripts/check-workflow-id-masking.py, scripts/mask-aws-ids.sh and the core that
script runs, scripts/mask-aws-ids.py, are nanohype/landing-zone's, byte for
byte, and scripts/vendored.json records the commit and digest of each. Their
tests are their own self-tests: the gate's plants every case
scripts/workflow-id-masking.toml lists against this repository's workflows, and
every rule's built-in shapes, policy refusals, floor shortfalls, vendored-record
failures and exit statuses; the mask core's runs its own cases. These run both in
this process, so the coverage run measures the vendored code, and require the
gate to pass the tree as it is.

A vendored file is held by its digest, not by this repository's formatter: ruff
would re-lay it, and the copy would then no longer be the bytes recorded. So each
vendored Python file is excluded from ruff, and the last case here holds that
exclusion to the record, in both directions.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tomllib
import unittest

from gateloader import load

gate = load("check-workflow-id-masking")
mask = load("mask-aws-ids")

ROOT = pathlib.Path(__file__).resolve().parents[2]


def quiet(fn, *args, **kwargs) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = fn(*args, **kwargs)
    return code, out.getvalue()


class TheTree(unittest.TestCase):
    def test_every_workflow_reads_its_ids_as_this_repository_requires(self):
        code, out = quiet(gate.main_check, ROOT)
        self.assertEqual(code, 0, out)
        self.assertIn("vendored file(s), each the bytes scripts/vendored.json records", out)


class TheSelfTests(unittest.TestCase):
    def test_the_gate_rejects_every_case_the_policy_plants(self):
        code, out = quiet(gate.self_test)
        self.assertEqual(code, 0, out[-4000:])
        self.assertIn("check-workflow-id-masking self-test passed", out)

    def test_the_mask_core_masks_every_case_it_carries(self):
        code, out = quiet(mask.self_test)
        self.assertEqual(code, 0, out[-4000:])
        self.assertIn("mask-aws-ids self-test passed", out)


class TheVendoredFiles(unittest.TestCase):
    def test_ruff_excludes_exactly_the_vendored_python(self):
        record = json.loads((ROOT / "scripts/vendored.json").read_text())
        vendored = {rel for rel in record if rel.endswith(".py")}
        ruff = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["ruff"]
        excluded = set(ruff.get("extend-exclude", []))
        self.assertTrue(vendored, "scripts/vendored.json records no Python file")
        self.assertEqual(
            excluded,
            vendored,
            "pyproject.toml's [tool.ruff] extend-exclude must name every vendored Python "
            "file and nothing else: ruff would re-lay a vendored file away from its "
            "recorded bytes, and an exclusion of anything else leaves this repository's "
            "own code unlinted",
        )


if __name__ == "__main__":
    unittest.main()
