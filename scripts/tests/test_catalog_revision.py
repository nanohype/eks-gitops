"""Unit tests for the catalog-revision gate, scripts/check-catalog-revision.py.

cluster-bootstrap stamps `gitops/repo-url` and `gitops/repo-branch` on every
cluster Secret. A source reading its repoURL from the first while pinning a
literal targetRevision runs that child Application at the literal while
app-of-apps runs at the bootstrapped revision, and both report Synced and
Healthy. The gate requires every applied source reading the catalog's URL to
read its revision too, and leaves chart sources, whose targetRevision is a chart
version, alone. These build applicationsets/ trees for each shape and hold the
verdict over them.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-catalog-revision")

URL = "{{ index .metadata.annotations \"gitops/repo-url\" }}"
REVISION = "{{ index .metadata.annotations \"gitops/repo-branch\" }}"


def appset(*sources: dict, single: dict | None = None, name: str = "addons") -> dict:
    spec: dict = {}
    if sources:
        spec["sources"] = list(sources)
    if single is not None:
        spec["source"] = single
    return {"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet",
            "metadata": {"name": name}, "spec": {"template": {"spec": spec}}}


def catalog(revision: str = REVISION) -> dict:
    return {"repoURL": URL, "targetRevision": revision, "ref": "values"}


def chart(version: str = "1.2.3") -> dict:
    return {"repoURL": "https://charts.example.test", "chart": "x", "targetRevision": version}


class Appsets(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.appsets = self.root / "applicationsets"
        self.appsets.mkdir()
        for name, value in (("ROOT", self.root), ("APPSETS", self.appsets)):
            patch = mock.patch.object(gate, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def write(self, name: str, *docs) -> None:
        path = self.appsets / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump_all(docs))

    def check(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), \
                mock.patch("sys.argv", ["check-catalog-revision.py", *argv]):
            rc = gate.main()
        return rc, out.getvalue()


class ACatalogSource(Appsets):
    def test_one_reading_its_revision_passes(self):
        self.write("addons.yaml", appset(chart(), catalog()))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("all 1 catalog source(s) read their revision from gitops/repo-branch", said)

    def test_one_pinning_main_fails(self):
        self.write("addons.yaml", appset(chart(), catalog("main")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("addons.yaml: a source reading gitops/repo-url pins targetRevision: "
                      "'main' instead of reading gitops/repo-branch", said)

    def test_one_with_no_revision_fails(self):
        source = catalog()
        del source["targetRevision"]
        self.write("addons.yaml", appset(single=source))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("pins targetRevision: ''", said)

    def test_a_single_source_is_read_beside_a_list(self):
        self.write("addons.yaml", appset(catalog(), single=catalog("v1.0.0")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("'v1.0.0'", said)

    def test_every_pinned_source_is_named(self):
        self.write("a.yaml", appset(catalog("main"), name="a"))
        self.write("b.yaml", appset(catalog("release"), name="b"))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("a.yaml", said)
        self.assertIn("b.yaml", said)

    def test_list_prints_every_catalog_source_found(self):
        self.write("addons.yaml", appset(chart(), catalog()))
        rc, said = self.check("--list")
        self.assertEqual(rc, 0, said)
        self.assertIn(f"applicationsets/addons.yaml: targetRevision {REVISION!r}", said)


class WhatIsNotACatalogSource(Appsets):
    def test_a_chart_version_is_not_a_catalog_revision(self):
        self.write("addons.yaml", appset(chart("main"), catalog()))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_an_appset_app_of_apps_does_not_apply_is_not_read(self):
        self.write("addons.yaml", appset(catalog()))
        self.write("opt-in/extra.yaml", appset(catalog("main")))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_documents_of_other_kinds_are_not_read(self):
        self.write("addons.yaml", {"kind": "ConfigMap", "spec": {"template": {"spec": {
            "source": catalog("main")}}}}, "text", appset(catalog(), "not-a-source"))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)


class TheCorpus(Appsets):
    def test_no_catalog_source_is_a_broken_gate(self):
        self.write("addons.yaml", appset(chart()))
        rc, said = self.check()
        self.assertEqual(rc, 2, said)
        self.assertIn("no source in applicationsets/ reads the gitops/repo-url annotation", said)

    def test_no_applicationsets_directory_cannot_run(self):
        self.appsets.rmdir()
        rc, said = self.check()
        self.assertEqual(rc, 2, said)
        self.assertIn("no applicationsets/ under", said)

    def test_a_file_that_does_not_parse_is_a_problem(self):
        self.write("addons.yaml", appset(catalog()))
        (self.appsets / "broken.yaml").write_text("kind: [unclosed\n")
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("applicationsets/broken.yaml: not loadable as YAML", said)


if __name__ == "__main__":
    unittest.main()
