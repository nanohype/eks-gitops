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

TheGateRunWhole runs the gate end to end over the shipped tree with grafana.com
answered by a fake at urlopen, so every pinned id is resolved, its board's title
compared and its revision read without the network.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import tempfile
import textwrap
import unittest
from collections.abc import Mapping
from unittest import mock

import fakeregistry as fake
from gateloader import load

gate = load("validate-dashboards")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


class TemplateVariableReferences(unittest.TestCase):
    """Grafana writes a variable reference four ways; all four must be seen."""

    def test_the_braced_form(self):
        self.assertEqual(gate.template_vars("SELECT ${cost_database}.t"), {"cost_database"})

    def test_the_braced_form_with_a_format_suffix(self):
        self.assertEqual(gate.template_vars("${namespace:csv}"), {"namespace"})

    def test_the_bare_form_every_dashboard_here_uses(self):
        self.assertEqual(gate.template_vars('{namespace="$namespace"}'), {"namespace"})

    def test_the_bracket_form(self):
        self.assertEqual(gate.template_vars("[[tenant]] and [[tenant:csv]]"), {"tenant"})

    def test_grafana_builtins_are_not_reported(self):
        text = "rate(x[$__rate_interval]) offset $__range and $__from to $__to"
        self.assertEqual(gate.template_vars(text), set())

    def test_a_builtin_beside_a_real_variable_leaves_the_real_one(self):
        self.assertEqual(
            gate.template_vars('sum(rate(x{ns="$namespace"}[$__rate_interval]))'), {"namespace"}
        )

    def test_every_builtin_in_the_allowlist_is_suppressed(self):
        for name in sorted(gate.GRAFANA_BUILTINS):
            with self.subTest(builtin=name):
                self.assertEqual(gate.template_vars(f"${name}"), set())


class ExtractingTheDashboardBody(unittest.TestCase):
    """Two structurally different failures, told apart so the fix is findable."""

    def manifest(self, body, indent=4):
        pad = " " * indent
        block = "\n".join(f"{pad}  {line}" for line in body.splitlines())
        return f"kind: GrafanaDashboard\nspec:\n{pad}json: |\n{block}\n"

    def test_a_well_formed_block_parses(self):
        dash, reason = gate.extract_dashboard_json(
            self.manifest(json.dumps({"title": "T", "panels": []}, indent=1))
        )
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
        text = (
            self.manifest(json.dumps({"title": "T"}))
            + "  instanceSelector:\n    matchLabels:\n      app: grafana\n"
        )
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
        self.assertEqual(self.refs({"datasource": {"type": "prometheus", "uid": "amp"}}), ["amp"])

    def test_grafanas_builtin_datasource_is_not_a_reference(self):
        """The default "Annotations & Alerts" entry names Grafana's own datasource."""
        self.assertEqual(self.refs({"datasource": {"type": "datasource", "uid": "grafana"}}), [])

    def test_a_uid_of_grafana_on_another_type_is_still_collected(self):
        self.assertEqual(
            self.refs({"datasource": {"type": "prometheus", "uid": "grafana"}}), ["grafana"]
        )
        self.assertEqual(self.refs({"datasource": "grafana"}), ["grafana"])

    def test_a_datasource_object_with_no_uid_yields_nothing(self):
        self.assertEqual(self.refs({"datasource": {"type": "prometheus"}}), [])

    def test_nested_panels_and_targets_are_reached(self):
        """A collapsed row is a panel whose children hang off a nested list."""
        dash = {
            "panels": [
                {
                    "collapsed": True,
                    "panels": [
                        {"datasource": "loki", "targets": [{"datasource": {"uid": "tempo"}}]}
                    ],
                }
            ]
        }
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
        self.assertEqual(self.titles({"panels": [{"title": "CPU", "alert": {}}]}), ["CPU"])

    def test_an_alert_inside_a_collapsed_row_is_found(self):
        """A flat scan misses every alert panel a collapsed row contains."""
        dash = {
            "panels": [
                {
                    "title": "row",
                    "collapsed": True,
                    "panels": [{"title": "Disk", "alert": {"x": 1}}],
                }
            ]
        }
        self.assertEqual(self.titles(dash), ["Disk"])

    def test_a_null_alert_key_is_not_an_alert(self):
        self.assertEqual(self.titles({"panels": [{"title": "CPU", "alert": None}]}), [])

    def test_an_untitled_alert_panel_is_still_reported(self):
        self.assertEqual(self.titles({"panels": [{"alert": {}}]}), ["<untitled panel>"])


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
            {
                "loki.yaml": """
             spec:
               datasource:
                 uid: managed-loki
                 name: Loki
             """
            },
        )
        self.assertEqual(gate.wired_datasource_refs(root), {"managed-loki", "Loki"})

    def test_a_datasource_file_absent_from_resources_is_not_wired(self):
        root = self.tree(
            """
            resources:
              - datasources/loki.yaml
            """,
            {
                "loki.yaml": "spec:\n  datasource:\n    uid: managed-loki\n",
                "athena.yaml": "spec:\n  datasource:\n    uid: athena-cur\n",
            },
        )
        self.assertEqual(gate.wired_datasource_refs(root), {"managed-loki"})

    def test_a_tree_with_no_kustomization_wires_nothing(self):
        self.assertEqual(gate.wired_datasource_refs(pathlib.Path(tempfile.mkdtemp())), set())


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
            "resources:\n" + "".join(f"  - datasources/{u}.yaml\n" for u in wired)
        )
        for uid in wired:
            (base / "datasources" / f"{uid}.yaml").write_text(
                f"spec:\n  datasource:\n    uid: {uid}\n"
            )
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
            return "kind: GrafanaDashboard\nspec:\n  json: " + json.dumps(payload) + "\n"
        indented = "\n".join("    " + line for line in payload.splitlines())
        return f"kind: GrafanaDashboard\nspec:\n  json: |\n{indented}\n"

    def test_a_healthy_tree_reports_nothing(self):
        """The control against false positives — necessary, and not evidence."""
        root = self.tree(
            {
                "ok.yaml": self.board(
                    {
                        "templating": {"list": [{"name": "ns"}]},
                        "panels": [
                            {
                                "datasource": "managed-loki",
                                "targets": [{"expr": 'x{namespace="$ns"}'}],
                            }
                        ],
                    }
                )
            }
        )
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_a_panel_naming_an_unwired_datasource_is_reported(self):
        """A dashboard is data: the operator applies it and Grafana discovers the
        missing datasource at view time, in front of whoever opened the board."""
        root = self.tree({"finance.yaml": self.board({"panels": [{"datasource": "athena-cur"}]})})
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("panel datasource 'athena-cur' is not wired", problems[0])
        self.assertIn("dashboards/platform/finance.yaml", problems[0])

    def test_a_datasource_chosen_by_a_template_variable_is_not_reported(self):
        root = self.tree(
            {
                "ok.yaml": self.board(
                    {"templating": {"list": [{"name": "ds"}]}, "panels": [{"datasource": "$ds"}]}
                )
            }
        )
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_an_undeclared_template_variable_is_reported(self):
        """The interpolation expands to nothing and the query is malformed."""
        root = self.tree(
            {
                "finance.yaml": self.board(
                    {
                        "panels": [
                            {
                                "datasource": "managed-loki",
                                "targets": [{"rawSql": "SELECT * FROM ${cost_database}.cur"}],
                            }
                        ]
                    }
                )
            }
        )
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("uses $cost_database but declares no such template variable", problems[0])

    def test_a_declared_variable_is_not_reported(self):
        root = self.tree(
            {
                "ok.yaml": self.board(
                    {
                        "templating": {"list": [{"name": "cost_database"}]},
                        "panels": [
                            {
                                "datasource": "managed-loki",
                                "targets": [{"rawSql": "SELECT * FROM ${cost_database}.cur"}],
                            }
                        ],
                    }
                )
            }
        )
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_a_locally_authored_board_whose_json_cannot_be_read_is_reported(self):
        """Skipping it quietly is how the check reports success having looked at
        nothing: a quoted scalar is identical YAML and invisible to every check."""
        root = self.tree(
            {"quoted.yaml": self.board({"panels": [{"datasource": "athena-cur"}]}, block=False)}
        )
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("dashboard JSON could not be read", problems[0])
        self.assertIn("no `json: |` literal block", problems[0])

    def test_a_grafana_com_board_carrying_no_inline_json_is_not_reported(self):
        """Its content is an id the network checks validate; there is nothing here."""
        root = self.tree(
            {"pulled.yaml": "kind: GrafanaDashboard\nspec:\n  grafanaCom:\n    id: 1860\n"}
        )
        self.assertEqual(gate.check_local_dashboards(root), [])

    def test_a_declared_variable_nothing_references_reports_a_broken_parser(self):
        """An empty `used` satisfies `used - declared` on every board, so a regex
        that stops matching turns the check above into a silent no-op."""
        root = self.tree(
            {
                "ok.yaml": self.board(
                    {
                        "templating": {"list": [{"name": "ns"}]},
                        "panels": [{"datasource": "managed-loki"}],
                    }
                )
            }
        )
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("not one reference was found", problems[0])
        self.assertIn("TEMPLATE_VAR has stopped matching", problems[0])

    def test_every_detection_is_reported_from_one_pass(self):
        """A verdict that returns on the first problem hides the rest behind a fix."""
        root = self.tree(
            {
                "quoted.yaml": self.board({"panels": []}, block=False),
                "finance.yaml": self.board(
                    {
                        "panels": [
                            {
                                "datasource": "athena-cur",
                                "targets": [{"rawSql": "FROM ${cost_database}.t"}],
                            }
                        ]
                    }
                ),
            }
        )
        problems = gate.check_local_dashboards(root)
        self.assertEqual(len(problems), 3)

    def test_a_tree_with_no_dashboards_directory_reports_nothing(self):
        """Not a finding: the caller's floor is what refuses an absent corpus."""
        self.assertEqual(gate.check_local_dashboards(pathlib.Path(tempfile.mkdtemp())), [])


class TheShippedDashboards(unittest.TestCase):
    """The offline half, over the corpus it actually governs."""

    def test_the_local_checks_find_no_problem_in_the_tree(self):
        self.assertEqual(gate.check_local_dashboards(ROOT), [])

    def test_the_tree_wires_at_least_one_datasource(self):
        """An empty wired set makes every panel reference a reference to nothing —
        which the check would report on all of them, or on none, depending only on
        whether any dashboard names a datasource at all."""
        self.assertTrue(gate.wired_datasource_refs(ROOT))


class AnUnreachableGrafanaCom(unittest.TestCase):
    """Every retry failing is CANNOT_RUN: the catalog was not examined, not rejected."""

    def test_an_unreachable_registry_cannot_run(self):
        err = io.StringIO()
        with (
            mock.patch.object(
                gate, "main", side_effect=RuntimeError("x: unreachable after 3 attempts")
            ),
            contextlib.redirect_stderr(err),
        ):
            status = gate.entry()
        self.assertEqual(status, gate.gatelib.CANNOT_RUN)
        self.assertIn("Cannot run: x: unreachable after 3 attempts", err.getvalue())

    def test_a_run_that_reads_everything_returns_its_own_status(self):
        with mock.patch.object(gate, "main", return_value=1):
            self.assertEqual(gate.entry(), 1)


class GrafanaCom:
    """grafana.com's dashboard API as the gate reads it, for the boards given.

    Each board answers its revisions, its metadata naming it and its latest
    revision, and that revision's download carrying its panels. An id with no
    board, a revision that is not the board's, and the metadata or download of
    a board marking it False, answer 404 as grafana.com does; `down` answers
    every request 503.
    """

    PATH = re.compile(rf"{re.escape(gate.API)}/(\d+)(/revisions(?:/(\d+)/download)?)?")

    def __init__(self, boards: dict[int, dict]) -> None:
        self.boards = boards
        self.down = False
        self.urls: list[str] = []

    def urlopen(self, req, timeout=None):
        url = req.full_url
        self.urls.append(url)
        if self.down:
            raise fake.http_error(url, 503)
        match = self.PATH.fullmatch(url)
        board = self.boards.get(int(match.group(1))) if match else None
        if match is None or board is None:
            raise fake.http_error(url, 404)
        if match.group(2) is None and board.get("metadata", True):
            body = {"name": board["name"], "revision": board["revision"]}
        elif match.group(2) is None:
            raise fake.http_error(url, 404)
        elif match.group(3) is None:
            body = {"items": [{"revision": board["revision"]}]}
        elif int(match.group(3)) == board["revision"] and board.get("downloadable", True):
            body = {"panels": board["panels"]}
        else:
            raise fake.http_error(url, 404)
        return fake.served(json.dumps(body).encode())


class TheGateRunWhole(unittest.TestCase):
    """entry() over the shipped tree, with grafana.com answered by GrafanaCom.

    The extractors above hold the offline half. These hold the run: every
    pinned id is asked for its revisions, its metadata and its latest revision,
    each answer reaches the check it decides, and a grafana.com that never
    answers is could-not-run after every retry rather than a dead catalog.
    """

    def setUp(self):
        self.refs = gate.discover(ROOT)
        self.grafana = GrafanaCom(
            {
                gnet_id: {
                    "name": json.loads(f'"{expected}"'),
                    "revision": 7,
                    "panels": [{"title": "Requests", "type": "timeseries"}],
                }
                for gnet_id, _, expected in self.refs
            }
        )
        self.waits: list[float] = []
        for patch in (
            mock.patch.object(gate.urllib.request, "urlopen", self.grafana.urlopen),
            mock.patch.object(gate.time, "sleep", self.waits.append),
            mock.patch.object(gate.sys, "argv", ["validate-dashboards.py"]),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def run_gate(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = gate.entry()
        return status, out.getvalue(), err.getvalue()

    def first(self):
        gnet_id, path, _ = self.refs[0]
        return gnet_id, path.relative_to(ROOT)

    def test_every_pin_resolving_to_its_own_board_passes(self):
        status, out, err = self.run_gate()
        self.assertEqual(status, 0, out + err)
        self.assertGreaterEqual(len(self.refs), gate.MIN_DASHBOARD_REFS)
        self.assertIn(f"all {len(self.refs)} grafana.com dashboards exist", out)
        self.assertEqual(
            len(self.grafana.urls),
            3 * len(self.refs),
            "an id was not asked for its revisions, its metadata and its download",
        )
        self.assertEqual(self.waits, [])

    def test_an_id_grafana_com_no_longer_has_fails_naming_it(self):
        gnet_id, rel = self.first()
        del self.grafana.boards[gnet_id]
        status, out, _ = self.run_gate()
        self.assertEqual(status, 1, out)
        self.assertIn("FAIL — dead grafana.com dashboard id(s):", out)
        self.assertIn(f"{gnet_id}  ({rel})  /revisions -> HTTP 404", out)

    def test_an_id_resolving_to_another_board_fails_naming_both_titles(self):
        gnet_id, rel = self.first()
        self.grafana.boards[gnet_id]["name"] = "AKA SNMP Network"
        status, out, _ = self.run_gate()
        self.assertEqual(status, 1, out)
        self.assertIn("FAIL — grafana.com id(s) that resolve to a different dashboard:", out)
        self.assertIn(f"{gnet_id}  ({rel})  annotation says", out)
        self.assertIn('grafana.com says "AKA SNMP Network"', out)

    def test_a_board_carrying_legacy_alert_panels_fails(self):
        gnet_id, rel = self.first()
        self.grafana.boards[gnet_id]["panels"] = [
            {"title": "Requests", "type": "timeseries"},
            {"title": "Errors", "type": "graph", "alert": {"name": "errors high"}},
        ]
        status, out, _ = self.run_gate()
        self.assertEqual(status, 1, out)
        self.assertIn("FAIL — dashboard(s) carrying legacy panel `alert` blocks:", out)
        self.assertIn(f"{gnet_id}  ({rel})", out)
        self.assertIn("1 alert panel(s): Errors", out)

    def test_a_revision_that_cannot_be_downloaded_is_dead(self):
        gnet_id, rel = self.first()
        self.grafana.boards[gnet_id]["downloadable"] = False
        status, out, _ = self.run_gate()
        self.assertEqual(status, 1, out)
        self.assertIn(f"{gnet_id}  ({rel})  rev 7 download -> HTTP 404", out)

    def test_a_grafana_com_that_stays_down_cannot_run_after_every_retry(self):
        self.grafana.down = True
        gnet_id, _ = self.first()
        status, out, err = self.run_gate()
        self.assertEqual(status, gate.gatelib.CANNOT_RUN, out + err)
        self.assertIn(
            f"Cannot run: {gate.API}/{gnet_id}/revisions: unreachable after {gate.RETRIES} "
            f"attempts (HTTP 503)",
            err,
        )
        self.assertEqual(self.waits, [gate.BACKOFF * n for n in range(1, gate.RETRIES)])
        self.assertNotIn("FAIL", out)

    def test_metadata_grafana_com_will_not_serve_is_dead(self):
        gnet_id, rel = self.first()
        self.grafana.boards[gnet_id]["metadata"] = False
        status, out, _ = self.run_gate()
        self.assertEqual(status, 1, out)
        self.assertIn(f"{gnet_id}  ({rel})  metadata -> HTTP 404", out)

    def test_a_dead_id_and_a_legacy_board_are_each_reported(self):
        (dead, dead_path, _), (old, old_path, _) = self.refs[:2]
        del self.grafana.boards[dead]
        self.grafana.boards[old]["panels"] = [{"title": "Errors", "alert": {"name": "x"}}]
        status, out, _ = self.run_gate()
        self.assertEqual(status, 1, out)
        self.assertIn(f"{dead}  ({dead_path.relative_to(ROOT)})  /revisions -> HTTP 404", out)
        self.assertIn(f"{old}  ({old_path.relative_to(ROOT)})", out)
        self.assertLess(out.index("FAIL — dead"), out.index("FAIL — dashboard(s) carrying legacy"))

    def tree(self, pins: Mapping[int, str | None], *, local=None):
        """A root wiring one datasource, a GrafanaDashboard pinning each of `pins`
        ({id: the title its annotation records, or None for no annotation}), and,
        when given, a locally-authored board carrying `local` as its JSON."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        base = root / "dashboards" / "base"
        (base / "datasources").mkdir(parents=True)
        (base / "kustomization.yaml").write_text("resources:\n  - datasources/managed-loki.yaml\n")
        (base / "datasources" / "managed-loki.yaml").write_text(
            "spec:\n  datasource:\n    uid: managed-loki\n"
        )
        for gnet_id, title in pins.items():
            note = (
                f'  annotations:\n    nanohype.dev/grafana-com-title: "{title}"\n' if title else ""
            )
            (base / f"board-{gnet_id}.yaml").write_text(
                f"kind: GrafanaDashboard\nmetadata:\n  name: board-{gnet_id}\n{note}"
                f"spec:\n  grafanaCom:\n    id: {gnet_id}\n"
            )
        if local is not None:
            payload = "\n".join("    " + line for line in json.dumps(local, indent=1).splitlines())
            (base / "local.yaml").write_text(
                f"kind: GrafanaDashboard\nspec:\n  json: |\n{payload}\n"
            )
        self.grafana.boards = {
            gnet_id: {"name": title or "Untitled", "revision": 7, "panels": []}
            for gnet_id, title in pins.items()
        }
        return root

    def run_tree(self, root):
        with mock.patch.object(gate.sys, "argv", ["validate-dashboards.py", "--root", str(root)]):
            return self.run_gate()

    def test_a_tree_pinning_fewer_ids_than_the_floor_cannot_run(self):
        root = self.tree({1001: "One", 1002: "Two", 1003: "Three"})
        status, out, _ = self.run_tree(root)
        self.assertEqual(status, gate.gatelib.CANNOT_RUN, out)
        self.assertIn(
            f"found 3 grafanaCom.id reference(s), below the floor of {gate.MIN_DASHBOARD_REFS}", out
        )
        self.assertEqual(self.grafana.urls, [])

    def test_a_tree_pinning_no_id_cannot_run(self):
        status, out, _ = self.run_tree(self.tree({}))
        self.assertEqual(status, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("no grafanaCom.id references found", out)

    def test_a_pin_recording_no_title_fails(self):
        pins: dict[int, str | None] = {
            1000 + n: f"Board {n}" for n in range(gate.MIN_DASHBOARD_REFS)
        }
        pins[1000] = None
        status, out, _ = self.run_tree(self.tree(pins))
        self.assertEqual(status, 1, out)
        self.assertIn(
            "1000  (dashboards/base/board-1000.yaml)  has no nanohype.dev/grafana-com-title annotation",
            out,
        )

    def test_a_local_board_naming_an_unwired_datasource_fails(self):
        pins = {1000 + n: f"Board {n}" for n in range(gate.MIN_DASHBOARD_REFS)}
        root = self.tree(pins, local={"panels": [{"datasource": "athena-cur"}]})
        status, out, _ = self.run_tree(root)
        self.assertEqual(status, 1, out)
        self.assertIn("Locally-authored dashboard problems:", out)
        self.assertIn("panel datasource 'athena-cur' is not wired", out)
        self.assertIn(
            f"Validating {gate.MIN_DASHBOARD_REFS} grafana.com dashboard reference(s)", out
        )
        self.assertNotIn("✓", out)


if __name__ == "__main__":
    unittest.main()
