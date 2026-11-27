"""Unit tests for scripts/catalog.py, the one render of the catalog's own charts.

Every renderer of a catalog chart goes through this module: CI's validate job,
`task render`, check-serviceaccount-bindings.py and the image gates. These hold
which charts it finds, the command it builds, what a render that fails or hangs
is reported as, and what main() writes and exits with. helm is replaced by a
stub, so no case depends on helm or on the chart tree on disk, except the last
class, which reads the real tree without rendering it.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from gateloader import load

catalog = load("catalog")


class ATree(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name).resolve()
        self.calls: list[tuple[list[str], dict]] = []
        self.answers: dict[str, subprocess.CompletedProcess | Exception] = {}

    def chart(self, name: str, values: bool = True, inputs: bool = True):
        d = self.root / "catalog" / name / "chart"
        d.mkdir(parents=True)
        if values:
            (d.parent / "values.yaml").write_text("{}\n")
        if inputs:
            (d.parent / catalog.TENANT_INPUTS).write_text("{}\n")
        return catalog.CatalogChart(self.root, d)

    def helm(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        answer = self.answers[pathlib.Path(cmd[3]).parent.name]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def stub_helm(self):
        patch = mock.patch.object(catalog.subprocess, "run", self.helm)
        patch.start()
        self.addCleanup(patch.stop)

    def answer(self, name: str, rc: int = 0, out: str = "", err: str = "") -> None:
        self.answers[name] = subprocess.CompletedProcess([], rc, out, err)


class Discovery(ATree):
    def test_every_chart_directory_is_found_in_order(self):
        self.chart("zeta")
        self.chart("alpha")
        self.assertEqual([c.name for c in catalog.discover(self.root)], ["alpha", "zeta"])

    def test_a_file_named_chart_is_not_a_chart(self):
        (self.root / "catalog" / "notes").mkdir(parents=True)
        (self.root / "catalog" / "notes" / "chart").write_text("not a directory\n")
        self.assertEqual(catalog.discover(self.root), [])

    def test_a_tree_with_no_catalog_finds_nothing(self):
        self.assertEqual(catalog.discover(self.root), [])

    def test_a_chart_is_named_for_its_catalog_directory(self):
        c = self.chart("druid")
        self.assertEqual(c.name, "druid")
        self.assertEqual(c.chart, "druid")
        self.assertEqual(c.path, "catalog/druid/chart")
        self.assertEqual(c.namespace, "druid-ci")
        self.assertEqual(
            c.value_files,
            [
                self.root / "catalog" / "druid" / "values.yaml",
                self.root / "catalog" / "druid" / catalog.TENANT_INPUTS,
            ],
        )


class TheCommand(ATree):
    def test_it_renders_the_chart_with_its_values_then_its_inputs_then_the_environment(self):
        c = self.chart("druid")
        self.assertEqual(
            catalog.template_command(c, "staging"),
            [
                "helm",
                "template",
                "ci",
                str(c.chart_dir),
                "--namespace",
                "druid-ci",
                "-f",
                str(c.value_files[0]),
                "-f",
                str(c.value_files[1]),
                "--set",
                "environment=staging",
            ],
        )


class Render(ATree):
    def setUp(self):
        super().setUp()
        self.stub_helm()

    def test_a_chart_that_renders_returns_its_manifests(self):
        c = self.chart("app")
        self.answer("app", out="kind: Pod\n")
        self.assertEqual(catalog.render(c, "development"), "kind: Pod\n")
        ((cmd, kwargs),) = self.calls
        self.assertEqual(cmd, catalog.template_command(c, "development"))
        self.assertEqual(kwargs["timeout"], catalog.RENDER_TIMEOUT)

    def test_missing_inputs_are_named_and_helm_is_not_run(self):
        c = self.chart("app", values=False, inputs=False)
        with self.assertRaises(catalog.RenderFailed) as raised:
            catalog.render(c, "development")
        self.assertIn(
            f"catalog/app/values.yaml, catalog/app/{catalog.TENANT_INPUTS} does not exist",
            str(raised.exception),
        )
        self.assertEqual(self.calls, [])

    def test_a_chart_helm_refuses_is_a_finding_with_helms_words(self):
        c = self.chart("app")
        self.answer("app", rc=1, err="Error: values don't meet the schema\n")
        with self.assertRaises(catalog.RenderFailed) as raised:
            catalog.render(c, "development")
        self.assertEqual(str(raised.exception), "Error: values don't meet the schema")

    def test_a_refusal_on_stdout_alone_is_still_reported(self):
        c = self.chart("app")
        self.answer("app", rc=1, out="Error: on stdout\n")
        with self.assertRaises(catalog.RenderFailed) as raised:
            catalog.render(c, "development")
        self.assertEqual(str(raised.exception), "Error: on stdout")

    def test_helms_words_are_bounded(self):
        c = self.chart("app")
        self.answer("app", rc=1, err="x" * 5000)
        with self.assertRaises(catalog.RenderFailed) as raised:
            catalog.render(c, "development")
        self.assertEqual(len(str(raised.exception)), 1200)

    def test_a_render_that_runs_out_of_time_decided_nothing(self):
        c = self.chart("app")
        self.answers["app"] = subprocess.TimeoutExpired(["helm"], catalog.RENDER_TIMEOUT)
        with self.assertRaises(catalog.CannotRender) as raised:
            catalog.render(c, "development")
        self.assertIn(
            f"ran past the {catalog.RENDER_TIMEOUT}s a render of catalog/app/chart",
            str(raised.exception),
        )


class Main(ATree):
    def setUp(self):
        super().setUp()
        self.stub_helm()
        self.required: list[tuple[str, ...]] = []
        for patch in (
            mock.patch.object(catalog, "ROOT", self.root),
            mock.patch.object(catalog.gatelib, "require", lambda *t: self.required.append(t)),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        # discover() binds ROOT as its default when the module loads, so main's
        # call is pointed at the scratch tree here rather than through ROOT.
        real = catalog.discover
        rediscover = mock.patch.object(catalog, "discover", lambda root=None: real(self.root))
        rediscover.start()
        self.addCleanup(rediscover.stop)
        self.out = str(self.root / "rendered" / "catalog-{name}-chart.yaml")

    def run_main(self, *argv: str) -> tuple[int, str]:
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            rc = catalog.main(list(argv))
        return rc, said.getvalue()

    def test_every_chart_is_written_where_out_names_it(self):
        self.chart("app")
        self.chart("db")
        self.answer("app", out="kind: A\n")
        self.answer("db", out="kind: B\n")
        rc, said = self.run_main("--env", "hub", "--out", self.out)
        self.assertEqual(rc, 0, said)
        rendered = self.root / "rendered"
        self.assertEqual((rendered / "catalog-app-chart.yaml").read_text(), "kind: A\n")
        self.assertEqual((rendered / "catalog-db-chart.yaml").read_text(), "kind: B\n")
        self.assertIn("rendered catalog/app/chart for hub to", said)
        self.assertEqual(self.required, [("helm",)])
        self.assertTrue(all(cmd[-1] == "environment=hub" for cmd, _ in self.calls))

    def test_a_chart_that_fails_fails_the_run_and_the_rest_still_render(self):
        self.chart("app")
        self.chart("db")
        self.answer("app", rc=1, err="Error: broken\n")
        self.answer("db", out="kind: B\n")
        rc, said = self.run_main("--env", "development", "--out", self.out)
        self.assertEqual(rc, 1, said)
        self.assertIn(
            "FAIL  catalog/app/chart did not render for development:\nError: broken", said
        )
        self.assertFalse((self.root / "rendered" / "catalog-app-chart.yaml").exists())
        self.assertTrue((self.root / "rendered" / "catalog-db-chart.yaml").exists())

    def test_a_render_that_runs_out_of_time_cannot_run(self):
        self.chart("app")
        self.chart("db")
        self.answers["app"] = subprocess.TimeoutExpired(["helm"], catalog.RENDER_TIMEOUT)
        rc, said = self.run_main("--env", "development", "--out", self.out)
        self.assertEqual(rc, catalog.gatelib.CANNOT_RUN, said)
        self.assertIn("Cannot run: helm template ran past", said)
        self.assertEqual(len(self.calls), 1, "a run that cannot decide stops there")

    def test_no_chart_cannot_run(self):
        rc, said = self.run_main("--env", "development", "--out", self.out)
        self.assertEqual(rc, catalog.gatelib.CANNOT_RUN, said)
        self.assertIn(f"no chart matched {catalog.CHART_GLOB}", said)

    def test_an_out_path_without_the_chart_name_is_refused(self):
        self.chart("app")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            catalog.main(["--env", "development", "--out", "rendered/all.yaml"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--out must contain {name}", err.getvalue())
        self.assertEqual(self.calls, [])


class TheRealTree(unittest.TestCase):
    """The catalog on disk carries what every render needs, without rendering it."""

    def test_druid_is_in_the_catalog_with_its_values_and_tenant_inputs(self):
        charts = {c.name: c for c in catalog.discover()}
        self.assertIn("druid", charts)
        for chart in charts.values():
            for values in chart.value_files:
                with self.subTest(chart=chart.name, values=values.name):
                    self.assertTrue(values.is_file(), f"{values} does not exist")


if __name__ == "__main__":
    unittest.main()
