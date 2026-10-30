"""Unit tests for the Athena panel-column gate, scripts/check-athena-panel-columns.py.

A CUR export projects a handful of columns, and every other column the CUR
specification names looks plausible in a panel's SQL and fails at query time.
The gate reads each Athena panel's rawSQL out of the committed dashboards and
requires every identifier that could be a column to be one dashboards/cur-columns.txt
delivers. What decides the verdict is which identifiers it reads as columns, so
these hold that reading on the shapes a CUR panel uses, and the verdict over a
dashboard tree built for each case.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-athena-panel-columns")

COLUMNS = ["line_item_unblended_cost", "line_item_usage_start_date", "resource_tags",
           "product_servicecode", "billing_period"]

ATHENA = {"type": "grafana-athena-datasource", "uid": "athena"}
PROMETHEUS = {"type": "prometheus", "uid": "managed-prometheus"}

SPEND = ("SELECT date_trunc('day', line_item_usage_start_date) AS day, "
         "sum(line_item_unblended_cost) AS cost FROM cur "
         "WHERE element_at(resource_tags, 'user_PlatformId') = '$platform' "
         "GROUP BY 1 ORDER BY 1")


def dashboard(*panels: dict) -> dict:
    """A GrafanaDashboard carrying `panels` in its embedded JSON."""
    return {"apiVersion": "grafana.integreatly.org/v1beta1", "kind": "GrafanaDashboard",
            "metadata": {"name": "cost"}, "spec": {"json": json.dumps({"panels": list(panels)})}}


def panel(sql: str, title: str = "Spend", target_ds: dict | None = ATHENA,
          panel_ds: dict | None = None) -> dict:
    target: dict = {"refId": "A", "rawSQL": sql}
    if target_ds is not None:
        target["datasource"] = target_ds
    out: dict = {"title": title, "targets": [target]}
    if panel_ds is not None:
        out["datasource"] = panel_ds
    return out


class ReadingIdentifiers(unittest.TestCase):
    def test_columns_are_read_and_sql_is_not(self):
        self.assertEqual(gate.referenced_identifiers(SPEND),
                         {"line_item_usage_start_date", "line_item_unblended_cost",
                          "resource_tags"})

    def test_a_map_key_in_a_string_is_not_a_column(self):
        self.assertNotIn("user_platformid", gate.referenced_identifiers(SPEND))

    def test_a_function_call_is_not_a_column(self):
        self.assertEqual(gate.referenced_identifiers("SELECT approx_percentile(x, 0.5) FROM cur"),
                         {"x"})

    def test_an_alias_is_not_a_column_wherever_it_is_named(self):
        sql = "SELECT sum(line_item_unblended_cost) AS spend FROM cur ORDER BY spend"
        self.assertEqual(gate.referenced_identifiers(sql), {"line_item_unblended_cost"})

    def test_a_column_the_export_does_not_carry_is_read(self):
        sql = "SELECT bill_billing_period_start_date FROM cur"
        self.assertEqual(gate.referenced_identifiers(sql), {"bill_billing_period_start_date"})

    def test_case_is_folded(self):
        self.assertEqual(gate.referenced_identifiers("select resource_tags from cur"),
                         {"resource_tags"})


class FindingQueries(unittest.TestCase):
    def queries(self, *panels) -> list[tuple[str, str]]:
        return gate.athena_queries({"panels": list(panels)}, pathlib.Path("x.yaml"))

    def test_a_target_on_athena_is_read(self):
        self.assertEqual(self.queries(panel(SPEND)), [("Spend", SPEND)])

    def test_a_target_inheriting_the_panels_athena_datasource_is_read(self):
        self.assertEqual(self.queries(panel(SPEND, target_ds=None, panel_ds=ATHENA)),
                         [("Spend", SPEND)])

    def test_a_target_on_another_datasource_is_not(self):
        self.assertEqual(self.queries(panel(SPEND, target_ds=PROMETHEUS)), [])

    def test_a_target_with_no_sql_is_not(self):
        self.assertEqual(self.queries(panel("  "), {"title": "x", "targets": [{"expr": "up"}]}),
                         [])

    def test_what_is_no_panel_or_target_is_skipped(self):
        self.assertEqual(self.queries("text", {"targets": ["x", panel(SPEND)["targets"][0]]}),
                         [("(untitled)", SPEND)])


class ADashboardTree(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.dashboards = self.root / "dashboards"
        (self.dashboards / "base").mkdir(parents=True)
        self.columns = self.dashboards / "cur-columns.txt"
        self.columns.write_text("# The columns the export delivers.\n\n"
                                + "\n".join(f"{c}  # why" for c in COLUMNS) + "\n")
        for name, value in (("ROOT", self.root), ("DASHBOARD_DIR", self.dashboards),
                            ("COLUMNS_FILE", self.columns)):
            patch = mock.patch.object(gate, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def write(self, *docs, name: str = "base/cost.yaml") -> None:
        (self.dashboards / name).write_text(yaml.safe_dump_all(docs))

    def check(self) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = gate.main()
        return rc, out.getvalue()

    def test_the_contract_is_read_without_its_comments(self):
        self.assertEqual(gate.delivered_columns(), set(COLUMNS))

    def test_panels_naming_only_delivered_columns_pass(self):
        self.write(dashboard(panel(SPEND)))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("1 Athena panel quer(ies) reference only the 5 columns", said)

    def test_a_panel_naming_an_undelivered_column_fails(self):
        self.write(dashboard(panel("SELECT bill_billing_period_start_date FROM cur",
                                   title="Periods")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("panel 'Periods' references 'bill_billing_period_start_date', which the "
                      "CUR table does not deliver", said)

    def test_no_athena_panel_would_pass_vacuously(self):
        self.write(dashboard(panel(SPEND, target_ds=PROMETHEUS)))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("found no Athena panel queries", said)

    def test_an_empty_contract_would_pass_vacuously(self):
        self.columns.write_text("# nothing delivered\n")
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("the CUR column contract is empty", said)

    def test_a_delivered_column_the_gate_subtracts_is_refused(self):
        self.columns.write_text("resource_tags\nyear\ncur\n")
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("the CUR export delivers 'cur', 'year'", said)

    def test_a_missing_contract_is_refused(self):
        self.columns.unlink()
        with self.assertRaises(SystemExit) as raised:
            gate.main()
        self.assertIn("dashboards/cur-columns.txt is missing", str(raised.exception.code))

    def test_a_dashboard_that_does_not_parse_is_refused_rather_than_skipped(self):
        (self.dashboards / "base" / "cost.yaml").write_text("kind: [unclosed\n")
        with self.assertRaises(SystemExit) as raised:
            gate.dashboards()
        self.assertIn("base/cost.yaml is not parseable YAML", str(raised.exception.code))

    def test_embedded_json_that_does_not_parse_is_refused_rather_than_skipped(self):
        broken = dashboard()
        broken["spec"]["json"] = "{not json"
        self.write(broken)
        with self.assertRaises(SystemExit) as raised:
            gate.dashboards()
        self.assertIn("spec.json is not valid JSON", str(raised.exception.code))

    def test_only_dashboards_carrying_json_are_read(self):
        no_json = dashboard()
        del no_json["spec"]["json"]
        self.write({"kind": "ConfigMap"}, no_json, dashboard(panel(SPEND)))
        self.assertEqual(len(gate.dashboards()), 1)


if __name__ == "__main__":
    unittest.main()
