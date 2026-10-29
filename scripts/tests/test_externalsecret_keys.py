"""Unit tests for the ExternalSecret key gate, scripts/check-externalsecret-keys.py.

A committed ExternalSecret names a placeholder remote secret, and the
ApplicationSet delivering it replaces that name per cluster with a kustomize
patch. External Secrets fails an ExternalSecret whole, so one name left
unpatched takes every key it carries down with it. The gate requires one remote
reference per ExternalSecret, and that reference patched by the appset rendering
its directory. These build a repository tree for each shape and hold the
verdict, including the directory-keyed patch map that keeps one app's patch from
vouching for a same-named ExternalSecret in another.
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

gate = load("check-externalsecret-keys")

KEY = "/spec/dataFrom/0/extract/key"


def external_secret(name: str = "endpoints", *, data: int = 0, extract: bool = True) -> dict:
    spec: dict = {}
    if extract:
        spec["dataFrom"] = [{"extract": {"key": "placeholder"}}]
    if data:
        spec["data"] = [{"secretKey": f"k{i}", "remoteRef": {"key": "placeholder"}}
                        for i in range(data)]
    return {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
            "metadata": {"name": name}, "spec": spec}


def replace(*paths: str) -> str:
    return yaml.safe_dump([{"op": "replace", "path": p,
                            "value": "{{ .metadata.labels.cluster_name }}-endpoints"}
                           for p in paths])


def appset(path: str, *patches: dict, elements: list[dict] | None = None) -> dict:
    gens = [{"list": {"elements": elements}}] if elements is not None else []
    return {"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet",
            "metadata": {"name": "a"},
            "spec": {"generators": gens,
                     "template": {"spec": {"source": {"path": path,
                                                      "kustomize": {"patches": list(patches)}}}}}}


def patch(body: str | None, name: str = "endpoints", kind: str = "ExternalSecret") -> dict:
    out: dict = {"target": {"kind": kind, "name": name}}
    if body is not None:
        out["patch"] = body
    return out


class KeyPaths(unittest.TestCase):
    def test_an_extract_is_one_reference(self):
        self.assertEqual(gate.key_paths(external_secret()), [KEY])

    def test_a_data_list_is_one_reference_per_key(self):
        self.assertEqual(gate.key_paths(external_secret(data=2, extract=False)),
                         ["/spec/data/0/remoteRef/key", "/spec/data/1/remoteRef/key"])

    def test_entries_naming_no_remote_secret_are_not_references(self):
        es = {"spec": {"dataFrom": [{"find": {"name": {"regexp": "x"}}}, "x"],
                       "data": [{"secretKey": "k"}, {"remoteRef": "x"}]}}
        self.assertEqual(gate.key_paths(es), [])
        self.assertEqual(gate.key_paths({}), [])


class DeliveredDirs(unittest.TestCase):
    def test_a_templated_path_is_substituted_per_element(self):
        doc = appset("{{ .path }}", elements=[{"path": "addons/a"}, {"name": "no-path"},
                                               "text"])
        doc["spec"]["generators"] = [{"matrix": {"generators": [
            {"clusters": {}}, {"merge": {"generators": doc["spec"]["generators"]}}]}}, "text"]
        self.assertEqual(gate.delivered_dirs(doc), ["addons/a"])

    def test_a_literal_path_is_its_own_directory(self):
        self.assertEqual(gate.delivered_dirs(appset("/addons/fixed/")), ["addons/fixed"])

    def test_no_source_path_delivers_nothing(self):
        self.assertEqual(gate.delivered_dirs({"spec": {"template": {"spec": {"sources": []}}}}),
                         [])


class OwningDir(unittest.TestCase):
    def test_the_longest_directory_shipping_the_manifest_owns_it(self):
        rel = pathlib.Path("addons/obs/grafana/es.yaml")
        self.assertEqual(gate.owning_dir(rel, ["addons/obs", "addons/obs/grafana", "addons/o"]),
                         "addons/obs/grafana")

    def test_a_sibling_sharing_a_prefix_does_not_own_it(self):
        self.assertIsNone(gate.owning_dir(pathlib.Path("addons/grafana-extra/es.yaml"),
                                          ["addons/grafana"]))


class ARepository(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.appsets = self.root / "applicationsets"
        self.appsets.mkdir()
        for name, value in (("ROOT", self.root), ("APPSETS", self.appsets)):
            p = mock.patch.object(gate, name, value)
            p.start()
            self.addCleanup(p.stop)

    def write(self, rel: str, *docs) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump_all(docs))

    def check(self) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = gate.main()
        return rc, out.getvalue()

    def delivered(self, es: dict, *patches: dict, where: str = "addons/obs/grafana") -> None:
        self.write(f"{where}/es.yaml", es)
        self.write(f"applicationsets/{where.replace('/', '-')}.yaml",
                   appset("{{ .path }}", *patches, elements=[{"path": where}]))

    def test_one_patched_reference_passes(self):
        self.delivered(external_secret(), patch(replace(KEY)))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("1 ExternalSecret(s) each name their remote secret once", said)

    def test_a_reference_per_key_fails_however_well_patched(self):
        paths = ["/spec/data/0/remoteRef/key", "/spec/data/1/remoteRef/key"]
        self.delivered(external_secret(data=2, extract=False), patch(replace(*paths)))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("ExternalSecret 'endpoints' names its remote secret 2 times", said)

    def test_an_unpatched_reference_fails(self):
        self.delivered(external_secret(), patch(replace("/spec/target/name")))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn(f"holds a remote secret name at {KEY}, but the ApplicationSet rendering "
                      "addons/obs/grafana/ does not replace it", said)
        self.assertIn("Patched paths for 'endpoints' in that app: ['/spec/target/name']", said)

    def test_another_apps_patch_does_not_vouch_for_a_same_named_secret(self):
        self.delivered(external_secret(), patch(replace(KEY)))
        self.delivered(external_secret(), patch(replace("/spec/target/name")),
                       where="addons/obs/monitoring")
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("addons/obs/monitoring/es.yaml", said)
        self.assertNotIn("addons/obs/grafana/es.yaml", said)

    def test_a_secret_nothing_renders_fails(self):
        self.delivered(external_secret(), patch(replace(KEY)))
        self.write("addons/orphan/es.yaml", external_secret("orphan"))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("addons/orphan/es.yaml: ExternalSecret 'orphan' sits under no directory", said)

    def test_a_secret_with_no_remote_reference_or_no_name_is_not_counted(self):
        self.delivered(external_secret(), patch(replace(KEY)))
        nameless = external_secret(data=2)
        del nameless["metadata"]["name"]
        self.write("addons/obs/grafana/generated.yaml", external_secret("gen", extract=False),
                   nameless)
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("1 ExternalSecret(s)", said)

    def test_patches_that_are_not_replace_ops_on_an_external_secret_are_not_read(self):
        self.delivered(external_secret(), patch(replace(KEY)),
                       patch(replace(KEY), kind="Deployment"), patch(replace(KEY), name=""),
                       patch(None), patch("metadata:\n  labels: {a: b}\n"),
                       patch(yaml.safe_dump([{"op": "add", "path": "/x"}, "x", {"op": "replace"}])))
        self.write("applicationsets/kustomization.yaml",
                   {"kind": "Kustomization", "spec": appset("x", patch(replace(KEY)))["spec"]})
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_an_unparseable_patch_cannot_run(self):
        self.delivered(external_secret(), patch(replace(KEY)), patch("- op: [unclosed\n"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            gate.patched_paths()
        self.assertEqual(raised.exception.code, gate.gatelib.CANNOT_RUN)
        self.assertIn("an inline kustomize patch in", out.getvalue())
        self.assertIn("target: {'kind': 'ExternalSecret', 'name': 'endpoints'}", out.getvalue())

    def test_no_external_secret_would_pass_vacuously(self):
        self.write("applicationsets/a.yaml",
                   appset("{{ .path }}", patch(replace(KEY)), elements=[{"path": "addons/x"}]))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("found no ExternalSecret manifests", said)

    def test_no_patch_would_pass_vacuously(self):
        self.write("addons/x/es.yaml", external_secret())
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("found no ExternalSecret kustomize patch ops", said)

    def test_generated_output_and_chart_templates_are_not_read(self):
        self.delivered(external_secret(), patch(replace(KEY)))
        self.write("rendered/addons/es.yaml", external_secret("rendered", data=3))
        (self.root / "charts" / "c" / "templates").mkdir(parents=True)
        (self.root / "charts" / "c" / "Chart.yaml").write_text("name: c\n")
        (self.root / "charts" / "c" / "templates" / "es.yaml").write_text(
            "{{- if .Values.x }}\nkind: ExternalSecret\n{{- end }}\n")
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_a_templates_directory_outside_a_chart_is_read(self):
        self.assertFalse(gate.is_helm_template(self.root / "addons" / "templates" / "es.yaml"))

    def test_a_manifest_that_does_not_parse_is_refused_rather_than_skipped(self):
        (self.root / "addons").mkdir()
        (self.root / "addons" / "broken.yaml").write_text("kind: [unclosed\n")
        with self.assertRaises(SystemExit) as raised:
            gate.find_external_secrets()
        self.assertIn("addons/broken.yaml is not parseable YAML", str(raised.exception.code))


if __name__ == "__main__":
    unittest.main()
