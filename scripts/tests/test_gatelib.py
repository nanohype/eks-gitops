"""Unit tests for the shared gate helpers.

gatelib is loaded by every gate, so a defect here narrows several corpora at
once and each of them reports the same success it always did. The generator
walk had exactly that failure in two gates simultaneously: it returned on the
first list generator, and the count each gate printed was derived from the same
truncated list, so neither could expose its own omission.

The registry client is tested in test_registry; the exit status and the words
a read that failed earns are held here.
"""

import ast
import contextlib
import io
import json
import pathlib
import sys
import unittest
from unittest import mock

from gateloader import load

gatelib = load("gatelib")
registry = load("registry")


def appset(*generators):
    return {"kind": "ApplicationSet", "spec": {"generators": list(generators)}}


def matrix(*inner):
    return {"matrix": {"generators": list(inner)}}


def listgen(*names):
    return {"list": {"elements": [{"appName": n} for n in names]}}


class EveryListGeneratorIsWalked(unittest.TestCase):
    """The defect this helper exists to prevent, stated as a test.

    An ApplicationSet may declare more than one list generator; each contributes
    its own Applications. Returning on the first drops the rest silently.
    """

    def names(self, doc):
        return [e["appName"] for e in gatelib.list_elements(doc)]

    def test_a_single_list_generator(self):
        doc = appset(matrix({"clusters": {}}, listgen("a", "b")))
        self.assertEqual(self.names(doc), ["a", "b"])

    def test_two_matrix_generators_each_with_a_list(self):
        """The shape this catalog already ships."""
        doc = appset(
            matrix({"clusters": {}}, listgen("first")),
            matrix({"clusters": {}}, listgen("second")),
        )
        self.assertEqual(
            self.names(doc),
            ["first", "second"],
            "an element past the first list generator was dropped — the walk "
            "that did this reported a full run over a truncated corpus",
        )

    def test_two_lists_inside_one_matrix(self):
        doc = appset(matrix(listgen("x"), listgen("y")))
        self.assertEqual(self.names(doc), ["x", "y"])

    def test_a_bare_list_generator_outside_a_matrix(self):
        self.assertEqual(self.names(appset(listgen("solo"))), ["solo"])

    def test_generators_without_a_list_contribute_nothing(self):
        doc = appset(matrix({"clusters": {}}, {"git": {}}))
        self.assertEqual(self.names(doc), [])

    def test_a_non_mapping_generator_is_skipped_not_crashed(self):
        """A manifest that parses but nests something odd must not traceback.

        Exit 1 is what these gates use for "the tree is wrong"; an uncaught
        AttributeError is indistinguishable from it by status alone.
        """
        doc = {"spec": {"generators": ["not-a-mapping", matrix(listgen("ok"))]}}
        self.assertEqual(self.names(doc), ["ok"])

    def test_a_non_mapping_element_is_skipped(self):
        doc = {"spec": {"generators": [{"list": {"elements": ["str", {"appName": "ok"}]}}]}}
        self.assertEqual(self.names(doc), ["ok"])

    def test_an_empty_document_yields_nothing(self):
        empties: list[dict[str, object]] = [{}, {"spec": {}}, {"spec": {"generators": []}}]
        for empty in empties:
            self.assertEqual(gatelib.list_elements(empty), [])


class MatrixGeneratorsFlattens(unittest.TestCase):
    """A matrix contributes its inner generators; a bare generator itself."""

    def test_matrix_members_are_yielded_not_the_matrix(self):
        got = list(gatelib.matrix_generators(appset(matrix({"clusters": {}}, listgen("a")))))
        self.assertEqual(len(got), 2)
        self.assertIn("clusters", got[0])
        self.assertIn("list", got[1])

    def test_a_bare_generator_is_yielded_as_itself(self):
        got = list(gatelib.matrix_generators(appset({"clusters": {"selector": {}}})))
        self.assertEqual(len(got), 1)
        self.assertIn("clusters", got[0])

    def test_both_shapes_in_one_document(self):
        doc = appset({"clusters": {}}, matrix(listgen("a"), {"git": {}}))
        self.assertEqual(len(list(gatelib.matrix_generators(doc))), 3)


class TheRealCatalogIsWalkedWhole(unittest.TestCase):
    """Read against the shipped tree, so the corpus cannot shrink unnoticed.

    A count asserted only against a fixture says nothing about the repo. This
    keys on the property instead: every list generator in every ApplicationSet
    contributes, so the total is the sum and not the first.
    """

    def test_every_list_generator_in_the_catalog_contributes(self):
        import pathlib

        import yaml

        root = pathlib.Path(gatelib.__file__).resolve().parent.parent
        appsets = sorted((root / "applicationsets").glob("*.yaml"))
        self.assertTrue(appsets, "no ApplicationSets found — this asserts nothing")

        multi = 0
        for path in appsets:
            doc = yaml.safe_load(path.read_text())
            if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
                continue
            lists = [
                g for g in gatelib.matrix_generators(doc) if (g.get("list") or {}).get("elements")
            ]
            if len(lists) > 1:
                multi += 1
            expected = sum(len(g["list"]["elements"]) for g in lists)
            self.assertEqual(
                len(gatelib.list_elements(doc)),
                expected,
                f"{path.name}: the walk returned fewer elements than its generators declare",
            )
        self.assertGreater(
            multi,
            0,
            "no ApplicationSet declares more than one list generator, so this "
            "suite no longer exercises the case the walk exists for — either the "
            "catalog changed shape or the fixture-only tests above are all that "
            "remain",
        )


class AReadThatFailed(unittest.TestCase):
    """Exit 1 is a finding about a pin; CANNOT_RUN is a fact about the network.

    Collapsing them makes an outage read as a defect in the catalogue, and trains
    readers to re-run a red gate rather than read it. Every gate says the second
    in one set of words, so a reader learns one sentence rather than one per gate.
    """

    REPO = "https://charts.example"

    def test_the_report_names_what_and_why_and_returns_cannot_run(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = gatelib.cannot_read("2 of 5 pinned chart(s)", ["a: HTTP 503", "b: timed out"])
        self.assertEqual(status, gatelib.CANNOT_RUN)
        lines = out.getvalue().splitlines()
        self.assertEqual(
            lines[:3],
            [
                "Cannot run: 2 of 5 pinned chart(s) could not be read:",
                "        a: HTTP 503",
                "        b: timed out",
            ],
        )
        self.assertIn("a fact about the network, not about this repo", lines[3])

    def exit_status(self, answered: bool):
        exc = registry.ChartUnavailable("why", answered=answered)
        with (
            mock.patch.object(registry, "chart_archive", side_effect=exc),
            contextlib.redirect_stdout(io.StringIO()) as out,
            self.assertRaises(SystemExit) as caught,
        ):
            gatelib.chart_archive_or_exit(self.REPO, "c", "1.0.0")
        return caught.exception.code, out.getvalue()

    def test_a_pin_the_registry_ruled_out_exits_1(self):
        code, said = self.exit_status(answered=True)
        self.assertEqual(code, 1)
        self.assertIn(
            f"c 1.0.0: {self.REPO} answered, and its answer rules the pin out — why", said
        )
        self.assertNotIn("Cannot run", said)

    def test_a_chart_that_could_not_be_read_cannot_run(self):
        code, said = self.exit_status(answered=False)
        self.assertEqual(code, gatelib.CANNOT_RUN)
        self.assertIn(
            f"Cannot run: c 1.0.0 from {self.REPO} could not be read:\n        why\n", said
        )

    def test_an_archive_that_is_fetched_is_returned(self):
        archive = pathlib.Path("/cache/c-1.0.0.tgz")
        with mock.patch.object(registry, "chart_archive", return_value=archive):
            self.assertEqual(gatelib.chart_archive_or_exit(self.REPO, "c", "1.0.0"), archive)


class AProgramUnderABound(unittest.TestCase):
    """A program that did not finish decided nothing, so it is CANNOT_RUN, not 1.

    A gate that lets `subprocess.TimeoutExpired` escape exits 1 through the
    traceback, which is the status a finding earns, and a slow renderer or a
    stalled clone then reads as a defect in this repository.
    """

    def outcome(self, cmd, **kwargs):
        with (
            contextlib.redirect_stdout(io.StringIO()) as out,
            self.assertRaises(SystemExit) as caught,
        ):
            gatelib.run(cmd, what="the render", **kwargs)
        return caught.exception.code, out.getvalue()

    def test_a_program_that_finishes_is_returned_with_its_output(self):
        proc = gatelib.run(
            [sys.executable, "-c", "import sys; print('out'); sys.exit(3)"],
            timeout=60,
            what="a probe",
        )
        self.assertEqual((proc.returncode, proc.stdout), (3, "out\n"))

    def test_a_program_that_runs_out_its_bound_cannot_run(self):
        code, said = self.outcome(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2
        )
        self.assertEqual(code, gatelib.CANNOT_RUN)
        self.assertIn("Cannot run: the render did not finish within 0.2s: ", said)
        self.assertIn("time.sleep(30)", said)
        self.assertIn("not the same as nothing being wrong", said)

    def test_a_program_that_cannot_start_cannot_run(self):
        code, said = self.outcome(["no-such-binary-anywhere", "build"], timeout=60)
        self.assertEqual(code, gatelib.CANNOT_RUN)
        self.assertIn("Cannot run: the render could not start: ", said)
        self.assertIn("no-such-binary-anywhere", said)

    def test_the_caller_keeps_the_say_over_capture(self):
        with mock.patch.object(gatelib.subprocess, "run") as run:
            gatelib.run(["tool", pathlib.Path("x")], timeout=5, what="w", capture_output=False)
        run.assert_called_once_with(["tool", "x"], timeout=5, capture_output=False, text=True)


SCRIPTS = pathlib.Path(__file__).resolve().parent.parent

# The files scripts/vendored.json records are landing-zone's bytes, and the gate
# that reads the record fails a copy that differs from it. A call one of them
# leaves unbounded is fixed in landing-zone and re-vendored here, so this reader
# holds the files this repository writes.
VENDORED = set(json.loads((SCRIPTS / "vendored.json").read_text(encoding="utf-8")))

# What a handler can name and still catch subprocess.TimeoutExpired: the class
# itself, a class it derives from, or everything.
CATCHES_EXPIRY = {"TimeoutExpired", "SubprocessError", "Exception", "BaseException"}

RUNNERS = {
    "subprocess.run",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.call",
    "subprocess.Popen",
}


def catches_expiry(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    named = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(ast.unparse(n).rsplit(".", 1)[-1] in CATCHES_EXPIRY for n in named)


def unbounded_calls(source: str) -> list[str]:
    """Each call in `source` that starts a program or reads a URL with no bound.

    A program runs bounded when the call carries `timeout` and sits in a `try`
    that handles `subprocess.TimeoutExpired`, the shape gatelib.run has: by
    naming it, a class it derives from, or no class at all. A URL read is
    bounded when the call carries `timeout`.
    """
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def handles_timeout(node: ast.AST) -> bool:
        while node in parents:
            parent = parents[node]
            if (
                isinstance(parent, ast.Try)
                and node in parent.body
                and any(catches_expiry(handler) for handler in parent.handlers)
            ):
                return True
            node = parent
        return False

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        bounded = any(k.arg == "timeout" for k in node.keywords)
        if (
            name in RUNNERS
            and not (bounded and handles_timeout(node))
            or name.endswith("urlopen")
            and not bounded
        ):
            found.append(f"line {node.lineno}: {name}")
    return found


class EveryProgramAGateRunsIsBounded(unittest.TestCase):
    """gatelib.run is how a gate runs a program; anything else carries its own bound.

    A call with no bound can hold a CI job until the job's own timeout, and one
    whose expiry escapes exits 1, the status a finding earns.
    """

    def test_the_gates_run_programs_only_under_a_bound(self):
        offenders = {
            path.name: calls
            for path in sorted(SCRIPTS.glob("*.py"))
            if f"scripts/{path.name}" not in VENDORED
            and (calls := unbounded_calls(path.read_text(encoding="utf-8")))
        }
        self.assertEqual(offenders, {}, "run these through gatelib.run")

    def test_only_what_the_record_names_is_left_to_its_source(self):
        """The exemption is the record, so it is as narrow as the record is."""
        self.assertTrue(VENDORED, "scripts/vendored.json records no file")
        for rel in sorted(VENDORED):
            with self.subTest(rel=rel):
                self.assertTrue((SCRIPTS.parent / rel).is_file(), f"{rel} is recorded and absent")

    def test_the_reader_sees_an_unbounded_run(self):
        self.assertEqual(
            unbounded_calls("import subprocess\nsubprocess.run(['git', 'ls-files'])\n"),
            ["line 2: subprocess.run"],
        )

    def test_the_reader_sees_a_bound_whose_expiry_escapes(self):
        self.assertEqual(
            unbounded_calls("import subprocess\nsubprocess.run(['git'], timeout=5)\n"),
            ["line 2: subprocess.run"],
        )

    def test_the_reader_sees_an_unbounded_url_read(self):
        self.assertEqual(
            unbounded_calls("import urllib.request\nurllib.request.urlopen('https://x')\n"),
            ["line 2: urllib.request.urlopen"],
        )

    def test_a_handler_for_a_class_the_expiry_derives_from_passes(self):
        for caught in (
            "subprocess.SubprocessError",
            "(OSError, subprocess.SubprocessError)",
            "Exception",
            "BaseException",
        ):
            with self.subTest(caught=caught):
                source = (
                    "import subprocess\n"
                    "try:\n"
                    "    subprocess.run(['git'], timeout=5)\n"
                    f"except {caught}:\n"
                    "    pass\n"
                )
                self.assertEqual(unbounded_calls(source), [])

    def test_a_handler_for_everything_passes(self):
        source = (
            "import subprocess\ntry:\n    subprocess.run(['git'], timeout=5)\nexcept:\n    pass\n"
        )
        self.assertEqual(unbounded_calls(source), [])

    def test_a_handler_for_something_else_lets_the_expiry_escape(self):
        source = (
            "import subprocess\n"
            "try:\n"
            "    subprocess.run(['git'], timeout=5)\n"
            "except (OSError, ValueError):\n"
            "    pass\n"
        )
        self.assertEqual(unbounded_calls(source), ["line 3: subprocess.run"])

    def test_a_bound_whose_expiry_is_handled_passes(self):
        source = (
            "import subprocess\n"
            "try:\n"
            "    subprocess.run(['git'], timeout=5)\n"
            "except subprocess.TimeoutExpired:\n"
            "    pass\n"
        )
        self.assertEqual(unbounded_calls(source), [])


if __name__ == "__main__":
    unittest.main()
