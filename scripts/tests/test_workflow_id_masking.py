"""Unit tests for the account-id gate, scripts/check-workflow-id-masking.py.

The repository and its Actions logs are public, and the ECR Public pull role's
ARN carries the account id that owns the role. The gate holds every workflow to
reading such a value as a secret, whole, masked by the vendored
scripts/mask-aws-ids.sh before anything prints, and holds that script to the
bytes scripts/vendored.json records. Its own --self-test plants each forbidden
shape in a copy of the real workflows; these run it, and cover the decisions the
self-test does not reach: the vendored record's every way of being wrong, the
floor, and the exit statuses.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from gateloader import load

gate = load("check-workflow-id-masking")

ROOT = pathlib.Path(__file__).resolve().parents[2]


def quiet(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(*args)
    return code, out.getvalue(), err.getvalue()


class Tree(unittest.TestCase):
    """A copy of the workflows, the mask script and its record."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        (self.root / gate.WORKFLOWS_REL).mkdir(parents=True)
        for p in (ROOT / gate.WORKFLOWS_REL).glob("*.y*ml"):
            shutil.copy(p, self.root / gate.WORKFLOWS_REL / p.name)
        (self.root / "scripts").mkdir()
        for rel in (gate.MASK_SCRIPT, gate.VENDORED_REL):
            shutil.copy(ROOT / rel, self.root / rel)

    def record(self) -> dict:
        return json.loads((self.root / gate.VENDORED_REL).read_text())

    def write_record(self, doc) -> None:
        (self.root / gate.VENDORED_REL).write_text(json.dumps(doc))

    def findings(self) -> list[tuple[str, int, str]]:
        return gate.check(self.root).findings


class TheRealTree(unittest.TestCase):
    def test_the_workflows_as_they_are_pass_and_meet_the_floor(self):
        res = gate.check(ROOT)
        self.assertEqual(res.findings, [])
        self.assertIsNone(gate.floor_problem(res))
        self.assertIn("ECR_PUBLIC_PULL_ROLE_ARN", res.id_names)

    def test_the_self_test_rejects_every_mutation_it_lists(self):
        code, out, err = quiet(gate.self_test)
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count("\nok [") + out.startswith("ok ["),
                         len(gate.MUTATIONS) + len(gate.SCRIPT_MUTATIONS) + 1)

    def test_main_check_reports_a_pass(self):
        code, out, _ = quiet(gate.main_check)
        self.assertEqual(code, 0)
        self.assertIn("OK: ", out)

    def test_the_record_names_landing_zone_and_the_bytes_on_disk(self):
        entry = json.loads((ROOT / gate.VENDORED_REL).read_text())[gate.MASK_SCRIPT]
        self.assertEqual((entry["repo"], entry["path"]),
                         ("nanohype/landing-zone", gate.MASK_SCRIPT))
        self.assertRegex(entry["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(entry["sha256"],
                         hashlib.sha256((ROOT / gate.MASK_SCRIPT).read_bytes()).hexdigest())

    def test_the_repository_secret_is_the_one_the_workflows_read(self):
        self.assertEqual(set(gate.REPOSITORY_LEVEL_IDS), gate.KNOWN_ID_READS)


class TheVendoredRecord(Tree):
    def test_a_clean_copy_passes(self):
        self.assertEqual(self.findings(), [])

    def test_an_edited_script_is_refused_naming_the_source(self):
        script = self.root / gate.MASK_SCRIPT
        script.write_text(script.read_text() + "echo hello\n")
        found = [f for f in self.findings() if f[0] == gate.MASK_SCRIPT]
        self.assertEqual(len(found), 1)
        self.assertIn("nanohype/landing-zone", found[0][2])

    def test_a_missing_script_is_refused(self):
        (self.root / gate.MASK_SCRIPT).unlink()
        found = self.findings()
        self.assertTrue(any(f[0] == gate.MASK_SCRIPT and "not in the tree" in f[2]
                            for f in found), found)

    def test_an_unreadable_record_is_refused(self):
        (self.root / gate.VENDORED_REL).write_text("{not json")
        self.assertTrue(any(f[0] == gate.VENDORED_REL for f in self.findings()))
        (self.root / gate.VENDORED_REL).unlink()
        self.assertTrue(any(f[0] == gate.VENDORED_REL for f in self.findings()))

    def test_an_incomplete_record_is_refused(self):
        for field in ("repo", "path", "commit", "sha256"):
            doc = self.record()
            del doc[gate.MASK_SCRIPT][field]
            self.write_record(doc)
            with self.subTest(missing=field):
                self.assertTrue(any(f[0] == gate.VENDORED_REL and "no complete record" in f[2]
                                    for f in self.findings()))
        for doc in ([], {}, {gate.MASK_SCRIPT: "a string"}):
            self.write_record(doc)
            with self.subTest(record=doc):
                self.assertTrue(any(f[0] == gate.VENDORED_REL for f in self.findings()))


class TheFloor(Tree):
    def test_no_workflows_is_a_scan_that_saw_nothing(self):
        for p in (self.root / gate.WORKFLOWS_REL).glob("*.y*ml"):
            p.unlink()
        problem = gate.floor_problem(gate.check(self.root))
        self.assertIsNotNone(problem)
        self.assertIn("ECR_PUBLIC_PULL_ROLE_ARN", str(problem))

    def test_a_tree_that_stopped_reading_the_secret_is_under_the_floor(self):
        ci = self.root / gate.WORKFLOWS_REL / "ci.yml"
        ci.write_text(ci.read_text().replace("ECR_PUBLIC_PULL_ROLE_ARN", "ECR_PUBLIC_PULL_ROLE"))
        self.assertIsNotNone(gate.floor_problem(gate.check(self.root)))

    def test_main_check_exits_cannot_run_under_the_floor_after_its_findings(self):
        ci = self.root / gate.WORKFLOWS_REL / "ci.yml"
        ci.unlink()
        broken = self.root / gate.MASK_SCRIPT
        broken.write_text("")
        with mock.patch.object(gate, "ROOT", self.root), \
                mock.patch.object(gate, "repo_is_visible", return_value=(True, "")):
            code, out, _ = quiet(gate.main_check)
        self.assertEqual(code, gate.CANNOT_RUN)
        self.assertIn(gate.MASK_SCRIPT, out)
        self.assertIn("Cannot run:", out)

    def test_main_check_exits_one_on_a_finding(self):
        ci = self.root / gate.WORKFLOWS_REL / "ci.yml"
        ci.write_text(ci.read_text().replace(
            "role-to-assume: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}",
            "role-to-assume: ${{ vars.ECR_PUBLIC_PULL_ROLE_ARN }}"))
        with mock.patch.object(gate, "ROOT", self.root), \
                mock.patch.object(gate, "repo_is_visible", return_value=(True, "")):
            code, out, _ = quiet(gate.main_check)
        self.assertEqual(code, 1)
        self.assertIn("::error file=.github/workflows/ci.yml", out)


class TheRepository(unittest.TestCase):
    def test_a_directory_that_is_not_a_checkout_cannot_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, why = gate.repo_is_visible(pathlib.Path(tmp))
            self.assertFalse(ok)
            self.assertIn("git ls-files", why)
            with mock.patch.object(gate, "ROOT", pathlib.Path(tmp)):
                code, out, _ = quiet(gate.main_check)
            self.assertEqual(code, gate.CANNOT_RUN)
            self.assertIn("Cannot run:", out)

    def test_a_checkout_of_only_the_gates_cannot_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "x.py").write_text("")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "scripts/x.py"], cwd=root, check=True)
            ok, why = gate.repo_is_visible(root)
            self.assertFalse(ok)
            self.assertIn("scripts/", why)

    def test_this_checkout_is_visible(self):
        self.assertEqual(gate.repo_is_visible(ROOT), (True, ""))


class TheSelfTestRefuses(Tree):
    def test_a_tree_the_gate_already_rejects(self):
        script = self.root / gate.MASK_SCRIPT
        script.write_text("")
        code, _, err = quiet(gate.self_test, self.root)
        self.assertEqual(code, 1)
        self.assertIn("[unmutated]", err)

    def test_an_anchor_that_no_longer_occurs(self):
        with mock.patch.object(gate, "MUTATIONS",
                               [("gone", "ci.yml", "no such anchor", "x", None, None)]):
            code, _, err = quiet(gate.self_test, self.root)
        self.assertEqual(code, 1)
        self.assertIn("anchor", err)

    def test_a_mutation_the_gate_accepts(self):
        with mock.patch.object(gate, "MUTATIONS",
                               [("harmless", "ci.yml", "name: CI\n", "name: CI \n", None, None)]):
            code, _, err = quiet(gate.self_test, self.root)
        self.assertEqual(code, 1)
        self.assertIn("not rejected", err)

    def test_a_rejection_for_another_rule(self):
        with mock.patch.object(gate, "MUTATIONS", [
                ("wrong rule", "ci.yml", "role-to-assume: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}",
                 "role-to-assume: ${{ vars.ECR_PUBLIC_PULL_ROLE_ARN }}", None,
                 "a message no finding carries")]):
            code, _, err = quiet(gate.self_test, self.root)
        self.assertEqual(code, 1)
        self.assertIn("not the mutated line", err)


class WhatAFindingQuotes(Tree):
    """A finding is an annotation that outlives the diff: it never repeats an id."""

    def test_an_id_is_redacted_and_a_placeholder_kept(self):
        self.assertEqual(gate.redact("arn:aws:iam::222233334444:role/x"),
                         "arn:aws:iam::<account id>:role/x")
        self.assertEqual(gate.redact("x2222333344445y"), "x<account id>y")
        for kept in ("111111111111", "123456789012", "12345678901"):
            self.assertEqual(gate.redact(kept), kept)

    def test_a_quote_is_redacted_before_it_is_cut(self):
        text = "a" * 55 + "222233334444"
        self.assertNotRegex(gate.quote(text, 60), r"[0-9]{5}")
        self.assertEqual(gate.quote(text, 60), repr(("a" * 55 + "<account id>")[:60]))

    def test_a_parse_error_quoting_an_id_is_redacted(self):
        ci = self.root / gate.WORKFLOWS_REL / "ci.yml"
        ci.write_text("jobs: [222233334444\n")
        found = [f for f in self.findings() if f[0].endswith("ci.yml")]
        self.assertTrue(found)
        self.assertFalse(any("222233334444" in f[2] for f in found), found)

    def test_a_parse_error_drops_the_parsers_excerpt(self):
        # PyYAML cuts its excerpt around the column before redact() sees it;
        # here the cut leaves the id's last ten digits, too few to redact.
        ci = self.root / gate.WORKFLOWS_REL / "ci.yml"
        ci.write_text("a:\n          OWNER: x 222233334444 qqqqqqqqqqqqqqqqqqqqq: y\n")
        found = [f for f in self.findings() if f[0].endswith("ci.yml")]
        self.assertEqual(len(found), 1, found)
        self.assertNotIn("2233334444", found[0][2])
        self.assertIn("(line 2, column 54)", found[0][2])

    def test_parse_error_reads_every_part_of_the_error(self):
        self.assertEqual(gate.parse_error(gate.yaml.MarkedYAMLError(problem="p", note="n")),
                         "could not be parsed: p; n")
        self.assertEqual(gate.parse_error(gate.yaml.MarkedYAMLError()),
                         "could not be parsed: MarkedYAMLError")
        self.assertEqual(gate.parse_error(OSError("gone 222233334444")),
                         "could not be parsed: gone <account id>")

    def test_a_planted_ids_head_or_tail_is_a_leak(self):
        findings = [("f", 1, "cut at 22223333"), ("f", 2, "tail 334444"), ("f", 3, "clean")]
        self.assertEqual([f[1] for f in gate.leaked_ids(findings, {"222233334444"})], [1, 2])
        self.assertEqual(gate.leaked_ids([("f", 1, "x 999988887777 y")]),
                         [("f", 1, "x 999988887777 y")])
        self.assertEqual(gate.leaked_ids([("f", 1, "x 123456789012 y")]), [])


class InputNames(Tree):
    """The runner reads an action's inputs upper-cased, so the gate reads them case-blind."""

    def test_with_key_finds_any_spelling(self):
        self.assertEqual(gate.with_key({"Role-To-Assume": "v"}, "role-to-assume"),
                         ("Role-To-Assume", "v"))
        self.assertIsNone(gate.with_key({"other": "v"}, "role-to-assume"))
        self.assertIsNone(gate.with_key(None, "role-to-assume"))

    def test_mask_aws_account_id_in_mixed_case_is_accepted(self):
        ci = self.root / gate.WORKFLOWS_REL / "ci.yml"
        text = ci.read_text()
        self.assertEqual(text.count("          mask-aws-account-id: true\n"), 1)
        ci.write_text(text.replace("          mask-aws-account-id: true\n",
                                   "          Mask-AWS-Account-Id: true\n"))
        self.assertEqual(self.findings(), [])

    def test_numbers_are_read_only_when_asked(self):
        doc = gate.yaml.load("a: 222233334444\n7: b\nc: true\n", Loader=gate.LineLoader)
        self.assertEqual({t for t, _ in gate.strings_with_lines(doc, 1)}, {"a", "b", "c"})
        self.assertEqual({t for t, _ in gate.strings_with_lines(doc, 1, numbers=True)},
                         {"a", "222233334444", "7", "b", "c"})

    def test_a_number_is_read_as_the_text_it_was_written_as(self):
        # YAML 1.1 reads 0-7 digits behind a leading 0 as octal (1402433619).
        doc = gate.yaml.load("a: 012345670123\n012345670123: b\nc: 222_233_334_444\nd: 1.5\n",
                             Loader=gate.LineLoader)
        self.assertEqual(doc["a"], 1402433619)
        texts = {t for t, _ in gate.strings_with_lines(doc, 1, numbers=True)}
        self.assertTrue({"012345670123", "222_233_334_444", "222233334444", "1.5"} <= texts,
                        texts)
        self.assertEqual(gate.number_texts(7), ["7"])


if __name__ == "__main__":
    unittest.main()
