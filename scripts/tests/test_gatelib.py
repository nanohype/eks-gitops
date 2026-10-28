"""Unit tests for the shared gate helpers.

gatelib is loaded by every gate, so a defect here narrows several corpora at
once and each of them reports the same success it always did. The generator
walk had exactly that failure in two gates simultaneously: it returned on the
first list generator, and the count each gate printed was derived from the same
truncated list, so neither could expose its own omission.

The registry client is tested in test_registry; the exit status and the words
a read that failed earns are held here.
"""

import contextlib
import io
import pathlib
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
            self.names(doc), ["first", "second"],
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
        for empty in ({}, {"spec": {}}, {"spec": {"generators": []}}):
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
            lists = [g for g in gatelib.matrix_generators(doc)
                     if (g.get("list") or {}).get("elements")]
            if len(lists) > 1:
                multi += 1
            expected = sum(len(g["list"]["elements"]) for g in lists)
            self.assertEqual(
                len(gatelib.list_elements(doc)), expected,
                f"{path.name}: the walk returned fewer elements than its "
                f"generators declare",
            )
        self.assertGreater(
            multi, 0,
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
        self.assertEqual(lines[:3], ["Cannot run: 2 of 5 pinned chart(s) could not be read:",
                                     "        a: HTTP 503", "        b: timed out"])
        self.assertIn("a fact about the network, not about this repo", lines[3])

    def exit_status(self, answered: bool):
        exc = registry.ChartUnavailable("why", answered=answered)
        with mock.patch.object(registry, "chart_archive", side_effect=exc), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit) as caught:
            gatelib.chart_archive_or_exit(self.REPO, "c", "1.0.0")
        return caught.exception.code, out.getvalue()

    def test_a_pin_the_registry_ruled_out_exits_1(self):
        code, said = self.exit_status(answered=True)
        self.assertEqual(code, 1)
        self.assertIn(f"c 1.0.0: {self.REPO} answered, and its answer rules the pin out — why",
                      said)
        self.assertNotIn("Cannot run", said)

    def test_a_chart_that_could_not_be_read_cannot_run(self):
        code, said = self.exit_status(answered=False)
        self.assertEqual(code, gatelib.CANNOT_RUN)
        self.assertIn(f"Cannot run: c 1.0.0 from {self.REPO} could not be read:\n        why\n",
                      said)

    def test_an_archive_that_is_fetched_is_returned(self):
        archive = pathlib.Path("/cache/c-1.0.0.tgz")
        with mock.patch.object(registry, "chart_archive", return_value=archive):
            self.assertEqual(gatelib.chart_archive_or_exit(self.REPO, "c", "1.0.0"), archive)


if __name__ == "__main__":
    unittest.main()
