"""Unit tests for the dashboard gate's extractors.

The gate resolves grafana.com ids over the network, so the positive-control
sweep exempts it. Its offline half is where the failures are quiet: a dashboard
is data, so a panel naming a datasource nothing wires renders an error forever
in front of whoever opened the board, and nothing in the sync path reports it.

Every extractor below has the same failure mode: matching less than it should and
comparing an empty set, which passes. The variable regex is where that bites
hardest, because `used - declared` is satisfied by an empty `used` on every
board — so a pattern covering only `${name}` would report nothing while the tree
writes `$name`. TEMPLATE_VAR carries all four of Grafana's spellings and each is
exercised here; check_local_dashboards carries a floor that fails when the whole
corpus declares variables and references none.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import textwrap
import unittest

from gateloader import load

gate = load("validate-dashboards")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


class TemplateVariableReferences(unittest.TestCase):
    """Grafana writes a variable reference four ways; all four must be seen."""

    def test_the_braced_form(self):
        self.assertEqual(gate.template_vars("SELECT ${cost_database}.t"),
                         {"cost_database"})

    def test_the_braced_form_with_a_format_suffix(self):
        self.assertEqual(gate.template_vars("${namespace:csv}"), {"namespace"})

    def test_the_bare_form_every_dashboard_here_uses(self):
        self.assertEqual(gate.template_vars('{namespace="$namespace"}'), {"namespace"})

    def test_the_bracket_form(self):
        self.assertEqual(gate.template_vars("[[tenant]] and [[tenant:csv]]"),
                         {"tenant"})

    def test_grafana_builtins_are_not_reported(self):
        text = "rate(x[$__rate_interval]) offset $__range and $__from to $__to"
        self.assertEqual(gate.template_vars(text), set())

    def test_a_builtin_beside_a_real_variable_leaves_the_real_one(self):
        self.assertEqual(
            gate.template_vars('sum(rate(x{ns="$namespace"}[$__rate_interval]))'),
            {"namespace"})

    def test_every_builtin_in_the_allowlist_is_suppressed(self):
        for name in sorted(gate.GRAFANA_BUILTINS):
            with self.subTest(builtin=name):
                self.assertEqual(gate.template_vars(f"${name}"), set())


class ExtractingTheDashboardBody(unittest.TestCase):
    """Two structurally different failures, told apart so the fix is findable."""

    def manifest(self, body, indent=4):
        pad = " " * indent
        block = "\n".join(f"{pad}  {line}" for line in body.splitlines())
        return (f"kind: GrafanaDashboard\nspec:\n{pad}json: |\n{block}\n")

    def test_a_well_formed_block_parses(self):
        dash, reason = gate.extract_dashboard_json(
            self.manifest(json.dumps({"title": "T", "panels": []}, indent=1)))
        self.assertIsNone(reason)
        self.assertEqual(dash["title"], "T")

    def test_a_manifest_with_no_block_says_so(self):
        dash, reason = gate.extract_dashboard_json("kind: GrafanaDashboard\nspec: {}\n")
        self.assertIsNone(dash)
        self.assertIn("no `json: |` literal block", reason)

    def test_invalid_json_is_reported_as_a_syntax_error_not_a_missing_block(self):
        dash, reason = gate.extract_dashboard_json(self.manifest('{"title": }'))
        self.assertIsNone(dash)
        self.assertIn("not valid JSON", reason)

    def test_the_reported_line_is_one_the_reader_can_open(self):
        """A line number relative to the block sends the reader to the wrong place."""
        text = self.manifest('{\n "title": "T",\n "panels": [ }\n')
        _, reason = gate.extract_dashboard_json(text)
        line = int(reason.rsplit("file line ", 1)[1])
        self.assertLessEqual(line, len(text.splitlines()))
        self.assertGreater(line, 3)

    def test_content_after_the_block_is_not_swallowed(self):
        text = (self.manifest(json.dumps({"title": "T"}))
                + "  instanceSelector:\n    matchLabels:\n      app: grafana\n")
        dash, reason = gate.extract_dashboard_json(text)
        self.assertIsNone(reason)
        self.assertEqual(dash, {"title": "T"})


class DatasourceReferencesInAPanel(unittest.TestCase):
    """Grafana accepts both a bare string and a `{type, uid}` object."""

    def refs(self, node):
        out: list[str] = []
        gate.walk_datasources(node, out)
        return sorted(out)

    def test_a_string_datasource_is_collected(self):
        self.assertEqual(self.refs({"datasource": "athena-cur"}), ["athena-cur"])

    def test_an_object_datasource_yields_its_uid(self):
        self.assertEqual(
            self.refs({"datasource": {"type": "prometheus", "uid": "amp"}}), ["amp"])

    def test_a_datasource_object_with_no_uid_yields_nothing(self):
        self.assertEqual(self.refs({"datasource": {"type": "prometheus"}}), [])

    def test_nested_panels_and_targets_are_reached(self):
        """A collapsed row is a panel whose children hang off a nested list."""
        dash = {"panels": [{"collapsed": True, "panels": [
            {"datasource": "loki", "targets": [{"datasource": {"uid": "tempo"}}]}]}]}
        self.assertEqual(self.refs(dash), ["loki", "tempo"])


class DeclaredVariables(unittest.TestCase):
    def test_names_are_read_off_the_templating_list(self):
        dash = {"templating": {"list": [{"name": "namespace"}, {"name": "tenant"}]}}
        self.assertEqual(gate.declared_template_vars(dash), {"namespace", "tenant"})

    def test_a_dashboard_with_no_templating_block_declares_nothing(self):
        self.assertEqual(gate.declared_template_vars({}), set())
        self.assertEqual(gate.declared_template_vars({"templating": {}}), set())

    def test_a_malformed_entry_is_skipped_rather_than_raising(self):
        dash = {"templating": {"list": ["oops", {"name": 3}, {"name": "ok"}]}}
        self.assertEqual(gate.declared_template_vars(dash), {"ok"})


class LegacyAlertPanels(unittest.TestCase):
    """A grafana.com dashboard carrying legacy alerts is not AMG-saveable."""

    def titles(self, node):
        out: list[str] = []
        gate.alert_panels(node, out)
        return out

    def test_a_top_level_alert_panel_is_found(self):
        self.assertEqual(self.titles({"panels": [{"title": "CPU", "alert": {}}]}),
                         ["CPU"])

    def test_an_alert_inside_a_collapsed_row_is_found(self):
        """A flat scan misses every alert panel a collapsed row contains."""
        dash = {"panels": [{"title": "row", "collapsed": True,
                            "panels": [{"title": "Disk", "alert": {"x": 1}}]}]}
        self.assertEqual(self.titles(dash), ["Disk"])

    def test_a_null_alert_key_is_not_an_alert(self):
        self.assertEqual(self.titles({"panels": [{"title": "CPU", "alert": None}]}), [])

    def test_an_untitled_alert_panel_is_still_reported(self):
        self.assertEqual(self.titles({"panels": [{"alert": {}}]}),
                         ["<untitled panel>"])


class WiredDatasources(unittest.TestCase):
    """Read from the kustomization, not the directory.

    A GrafanaDatasource file that exists but is not in `resources` is never
    applied, so globbing the directory would call a datasource wired when it is
    not — and the panel referencing it would pass the check and fail at view time.
    """

    def tree(self, kustomization: str, files: dict[str, str]):
        root = pathlib.Path(tempfile.mkdtemp())
        base = root / "dashboards" / "base"
        (base / "datasources").mkdir(parents=True)
        (base / "kustomization.yaml").write_text(textwrap.dedent(kustomization))
        for name, body in files.items():
            (base / "datasources" / name).write_text(textwrap.dedent(body))
        return root

    def test_both_the_uid_and_the_name_are_accepted(self):
        root = self.tree(
            """
            resources:
              - datasources/loki.yaml
            """,
            {"loki.yaml": """
             spec:
               datasource:
                 uid: managed-loki
                 name: Loki
             """})
        self.assertEqual(gate.wired_datasource_refs(root), {"managed-loki", "Loki"})

    def test_a_datasource_file_absent_from_resources_is_not_wired(self):
        root = self.tree(
            """
            resources:
              - datasources/loki.yaml
            """,
            {"loki.yaml": "spec:\n  datasource:\n    uid: managed-loki\n",
             "athena.yaml": "spec:\n  datasource:\n    uid: athena-cur\n"})
        self.assertEqual(gate.wired_datasource_refs(root), {"managed-loki"})

    def test_a_tree_with_no_kustomization_wires_nothing(self):
        self.assertEqual(gate.wired_datasource_refs(pathlib.Path(tempfile.mkdtemp())),
                         set())


class TheOfflineVerdict(unittest.TestCase):
    """Each detection, against a tree carrying the violation it names.

    check_local_dashboards is the whole of this gate's offline half, and the only
    thing it produces is a list. Asserting that list is empty on a healthy tree is
    a control against false positives; it is satisfied by every implementation
    that reports nothing, `return []` included. So each detection below is planted
    and the message it produces is named.
    """

    def tree(self, dashboards, wired=("managed-loki",)):
        """A repo root holding a wired datasource and the dashboards given.

        Datasource files carry no `kind: GrafanaDashboard`, so the walk skips
        them — they exist here only to populate the wired set.
        """
        root = pathlib.Path(tempfile.mkdtemp())
        base = root / "dashboards" / "base"
        (base / "datasources").mkdir(parents=True)
        (base / "kustomization.yaml").write_text(
            "resources:\n" + "".join(f"  - datasources/{u}.yaml\n" for u in wired))
        for uid in wired:
            (base / "datasources" / f"{uid}.yaml").write_text(
                f"spec:\n  datasource:\n    uid: {uid}\n")
        (root / "dashboards" / "platform").mkdir(parents=True)
        for name, body in dashboards.items():
            (root / "dashboards" / "platform" / name).write_text(body)
        return root

    def board(self, dash, block=True):
        """A GrafanaDashboard carrying `dash` as its JSON payload."""
        payload = json.dumps(dash, indent=1)
        if not block:
            # A quoted scalar: semantically identical YAML, invisible to the
            # block parser, and every check below silently stops applying.
            return ("kind: GrafanaDashboard\nspec:\n  json: "
                    + json.dumps(payload) + "\n")
        indented = "\n".join("    " + line for line in payload.splitlines())
        return f"kind: GrafanaDashboard\nspec:\n  json: |\n{indented}\n"

    def test_a_healthy_tree_reports_nothing(self):
        """The control against false positives — necessary, and not evidence."""
        root = self.tree({"ok.yaml": self.board({
            "templating": {"list": [{"name": "ns"}]},
            "panels": [{"datasource": "managed-loki",
                        "targets": [{"expr": 'x{namespace="$ns"}'}]}]})})
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_a_panel_naming_an_unwired_datasource_is_reported(self):
        """A dashboard is data: the operator applies it and Grafana discovers the
        missing datasource at view time, in front of whoever opened the board."""
        root = self.tree({"finance.yaml": self.board({
            "panels": [{"datasource": "athena-cur"}]})})
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("panel datasource 'athena-cur' is not wired", problems[0])
        self.assertIn("dashboards/platform/finance.yaml", problems[0])

    def test_a_datasource_chosen_by_a_template_variable_is_not_reported(self):
        root = self.tree({"ok.yaml": self.board({
            "templating": {"list": [{"name": "ds"}]},
            "panels": [{"datasource": "$ds"}]})})
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_an_undeclared_template_variable_is_reported(self):
        """The interpolation expands to nothing and the query is malformed."""
        root = self.tree({"finance.yaml": self.board({
            "panels": [{"datasource": "managed-loki",
                        "targets": [{"rawSql": "SELECT * FROM ${cost_database}.cur"}]}]})})
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("uses $cost_database but declares no such template variable",
                      problems[0])

    def test_a_declared_variable_is_not_reported(self):
        root = self.tree({"ok.yaml": self.board({
            "templating": {"list": [{"name": "cost_database"}]},
            "panels": [{"datasource": "managed-loki",
                        "targets": [{"rawSql": "SELECT * FROM ${cost_database}.cur"}]}]})})
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_a_locally_authored_board_whose_json_cannot_be_read_is_reported(self):
        """Skipping it quietly is how the check reports success having looked at
        nothing: a quoted scalar is identical YAML and invisible to every check."""
        root = self.tree({"quoted.yaml": self.board(
            {"panels": [{"datasource": "athena-cur"}]}, block=False)})
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("dashboard JSON could not be read", problems[0])
        self.assertIn("no `json: |` literal block", problems[0])

    def test_a_grafana_com_board_carrying_no_inline_json_is_not_reported(self):
        """Its content is an id the network checks validate; there is nothing here."""
        root = self.tree({"pulled.yaml":
                          "kind: GrafanaDashboard\nspec:\n  grafanaCom:\n    id: 1860\n"})
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_a_declared_variable_nothing_references_reports_a_broken_parser(self):
        """An empty `used` satisfies `used - declared` on every board, so a regex
        that stops matching turns the check above into a silent no-op."""
        root = self.tree({"ok.yaml": self.board({
            "templating": {"list": [{"name": "ns"}]},
            "panels": [{"datasource": "managed-loki"}]})})
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("not one reference was found", problems[0])
        self.assertIn("TEMPLATE_VAR has stopped matching", problems[0])

    def test_every_detection_is_reported_from_one_pass(self):
        """A verdict that returns on the first problem hides the rest behind a fix."""
        root = self.tree({
            "quoted.yaml": self.board({"panels": []}, block=False),
            "finance.yaml": self.board({
                "panels": [{"datasource": "athena-cur",
                            "targets": [{"rawSql": "FROM ${cost_database}.t"}]}]}),
        })
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 3)

    def test_a_tree_with_no_dashboards_directory_reports_nothing(self):
        """Not a finding: the caller's floor is what refuses an absent corpus."""
        self.assertEqual(
            gate.check_local_dashboards(pathlib.Path(tempfile.mkdtemp())), [])


class TheShippedDashboards(unittest.TestCase):
    """The offline half, over the corpus it actually governs."""

    def test_the_local_checks_find_no_problem_in_the_tree(self):
        self.assertEqual(gate.check_local_dashboards(ROOT), [])

    def test_the_tree_wires_at_least_one_datasource(self):
        """An empty wired set makes every panel reference a reference to nothing —
        which the check would report on all of them, or on none, depending only on
        whether any dashboard names a datasource at all."""
        self.assertTrue(gate.wired_datasource_refs(ROOT))


if __name__ == "__main__":
    unittest.main()
