"""Unit tests for the directory-source size gate.

The gate rests on two transcriptions of argocd-repo-server, and a mistake in
either is silent: the corpus would be the wrong set of sources, or the byte
total would be the wrong number, and in both cases the run still prints a size
and a verdict. So these concentrate there.

WHICH SOURCES. Only the Directory type is measured against the combined-manifest
ceiling, and "has a path" is not that type. ArgoCD takes an explicit `helm`,
`kustomize`, `plugin` or `directory` block at its word and otherwise decides by
what the directory holds. A source misclassified as Kustomize leaves this gate
with nothing to say about it.

HOW MANY BYTES. The repo-server matches manifests by NAME before it reads them,
applies include/exclude to the path relative to the source root, descends only
when `directory.recurse` is set, and counts a jsonnet file as a manifest while
leaving its size out of the total. Each of those is a way to measure a different
number than a cluster will.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from gateloader import load

gate = load("check-directory-manifest-size")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def source(**kw):
    base = {"appset": "a", "file": "a.yaml", "repo_url": "https://example.invalid",
            "target_revision": "v1", "path": "crds", "recurse": False,
            "include": "", "exclude": "", "local": None}
    base.update(kw)
    return gate.Source(**base)


def record(**kw):
    base = {"repoURL": "https://example.invalid", "targetRevision": "v1",
            "path": "crds", "recurse": False, "include": "", "exclude": "",
            "bytes": 1000, "files": 2}
    base.update(kw)
    return base


CONTRACT = {"maxCombinedDirectoryManifestsSize": "20M", "argoCdDefault": "10M"}


def verdict(sources, records, contract=None):
    """(exit code, everything the gate printed)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = gate.check_offline(sources, records, contract or CONTRACT)
    return rc, buf.getvalue()


def write(root: pathlib.Path, rel: str, size: int) -> pathlib.Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path


class TheQuantityGrammar(unittest.TestCase):
    """A ceiling read in the wrong base is a ceiling in the wrong place."""

    def test_decimal_and_binary_suffixes_are_different_sizes(self):
        self.assertEqual(gate.quantity("10M", "t"), 10_000_000)
        self.assertEqual(gate.quantity("10Mi", "t"), 10_485_760)

    def test_every_suffix_the_api_accepts(self):
        for text, want in (("512", 512), ("4k", 4_000), ("1G", 10**9),
                           ("1Ki", 1024), ("2Gi", 2 * 2**30)):
            self.assertEqual(gate.quantity(text, "t"), want, text)

    def test_something_the_repo_server_would_not_accept_cannot_run(self):
        # Not a finding: the gate has no ceiling, so every source would measure
        # as fitting. That is exit 2, and it must not be exit 0.
        for text in ("20MB", "20 M", "1.5M", "twenty", "", "-1M"):
            with self.subTest(text=text), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                gate.quantity(text, "t")
            self.assertEqual(raised.exception.code, gate.gatelib.CANNOT_RUN, text)


class WhichSourcesAreMeasured(unittest.TestCase):
    """ArgoCD decides the type first; only Directory is measured this way."""

    def test_an_explicit_block_names_the_type(self):
        self.assertEqual(gate.explicit_type({"helm": {"valueFiles": []}}), "Helm")
        self.assertEqual(gate.explicit_type({"kustomize": {"patches": []}}), "Kustomize")
        self.assertEqual(gate.explicit_type({"plugin": {"name": "x"}}), "Plugin")
        self.assertEqual(gate.explicit_type({"directory": {"recurse": True}}), "Directory")

    def test_a_chart_is_a_helm_source_without_a_helm_block(self):
        self.assertEqual(gate.explicit_type({"chart": "argo-cd"}), "Helm")

    def test_an_empty_directory_block_still_names_the_type(self):
        # `directory: {}` is how a source asks for the defaults, and it is the
        # difference between a source this gate measures and one it never sees.
        self.assertEqual(gate.explicit_type({"directory": {}}), "Directory")

    def test_a_bare_path_names_nothing_and_is_decided_by_the_directory(self):
        self.assertIsNone(gate.explicit_type({"path": "addons/x", "repoURL": "u"}))

    def test_the_directory_decides_when_nothing_else_has(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.assertEqual(gate.discovered_type(root), "Directory")
            (root / "kustomization.yaml").write_text("resources: []\n")
            self.assertEqual(gate.discovered_type(root), "Kustomize")
            (root / "Chart.yaml").write_text("name: x\n")
            self.assertEqual(gate.discovered_type(root), "Helm")

    def test_every_name_kustomize_answers_to(self):
        for name in gate.KUSTOMIZATION_NAMES:
            with tempfile.TemporaryDirectory() as tmp, self.subTest(name=name):
                root = pathlib.Path(tmp)
                (root / name).write_text("resources: []\n")
                self.assertEqual(gate.discovered_type(root), "Kustomize")

    def test_a_kustomization_that_disappears_reclassifies_the_source(self):
        # The reason the type is decided rather than assumed: deleting the
        # kustomization does not merely break a build, it moves that source into
        # the population a size limit applies to.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "kustomization.yaml").write_text("resources: []\n")
            self.assertEqual(gate.discovered_type(root), "Kustomize")
            (root / "kustomization.yaml").unlink()
            self.assertEqual(gate.discovered_type(root), "Directory")


class TheByteAccounting(unittest.TestCase):
    """Transcribed from getPotentiallyValidManifests, one clause at a time."""

    def test_only_names_the_repo_server_treats_as_manifests_are_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ("a.yaml", "b.yml", "c.json"):
                write(root, name, 100)
            for name in ("README.md", "OWNERS", "d.txt", "e.yaml.bak"):
                write(root, name, 1000)
            self.assertEqual(gate.measure(root, False, "", ""), (300, 3))

    def test_it_does_not_descend_unless_recurse_is_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "top.yaml", 10)
            write(root, "nested/deep.yaml", 500)
            self.assertEqual(gate.measure(root, False, "", ""), (10, 1))
            self.assertEqual(gate.measure(root, True, "", ""), (510, 2))

    def test_jsonnet_counts_as_a_manifest_and_not_against_the_size(self):
        # The repo-server's own comment: jsonnet manages its own memory. A gate
        # that counted it would refuse a source the runtime accepts.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "a.yaml", 40)
            write(root, "b.jsonnet", 9_000)
            self.assertEqual(gate.measure(root, False, "", ""), (40, 2))

    def test_include_and_exclude_read_the_path_relative_to_the_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "keep.yaml", 10)
            write(root, "drop.yaml", 700)
            self.assertEqual(gate.measure(root, False, "keep.yaml", ""), (10, 1))
            self.assertEqual(gate.measure(root, False, "", "drop.yaml"), (10, 1))

    def test_a_symlink_contributes_the_size_of_what_it_points_at(self):
        # FileInfo.Size() on a symlink is the length of its target path, which is
        # why the repo-server stats the resolved file. Measuring the link instead
        # understates a large manifest as a handful of bytes.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "real/big.yaml", 5_000)
            (root / "link.yaml").symlink_to(root / "real" / "big.yaml")
            self.assertEqual(gate.measure(root, False, "", ""), (5_000, 1))

    def test_a_symlink_to_nothing_is_not_a_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "a.yaml", 10)
            (root / "dangling.yaml").symlink_to(root / "absent.yaml")
            self.assertEqual(gate.measure(root, False, "", ""), (10, 1))

    def test_an_empty_directory_measures_no_files_rather_than_a_small_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(gate.measure(pathlib.Path(tmp), True, "", ""), (0, 0))


class ExpandingATemplatedPath(unittest.TestCase):
    def doc(self, elements):
        return {"spec": {"generators": [{"matrix": {"generators": [
            {"list": {"elements": elements}}]}}]}}

    def test_the_element_path_and_the_environment_label(self):
        got = gate.expansions('{{ .path }}/overlays/{{ index .metadata.labels "environment" }}',
                              self.doc([{"path": "addons/x"}]), ["development", "hub"])
        self.assertEqual(got, ["addons/x/overlays/development", "addons/x/overlays/hub"])

    def test_a_literal_path_expands_to_itself(self):
        self.assertEqual(gate.expansions("config/crd/standard", self.doc([]), ["development"]),
                         ["config/crd/standard"])

    def test_a_shape_it_cannot_expand_keeps_its_braces(self):
        # Which is the point: an unexpanded path is reported as one this
        # repository cannot resolve, not dropped from the corpus.
        got = gate.expansions("{{ .path.path }}", self.doc([]), ["development"])
        self.assertEqual(got, ["{{ .path.path }}"])
        self.assertIn("{{", got[0])


class TheVerdict(unittest.TestCase):
    def test_a_source_under_the_ceiling_passes(self):
        rc, said = verdict([source()], {"a": record()})
        self.assertEqual(rc, 0, said)

    def test_the_boundary_is_the_one_the_repo_server_draws(self):
        # It accumulates and aborts when the total EXCEEDS the limit, so a source
        # exactly filling the ceiling still generates. A gate stricter than the
        # runtime by one byte rejects a tree that works.
        rc, said = verdict([source()], {"a": record(bytes=20_000_000)})
        self.assertEqual(rc, 0, said)
        rc, said = verdict([source()], {"a": record(bytes=20_000_001)})
        self.assertEqual(rc, 1)
        self.assertIn("contracts/repo-server.json", said)

    def test_a_directory_source_with_no_record_is_rejected(self):
        rc, said = verdict([source()], {})
        self.assertEqual(rc, 1)
        self.assertIn("scripts/directory-sources.json", said)

    def test_a_record_no_source_claims_is_rejected(self):
        rc, said = verdict([source()], {"a": record(), "gone": record()})
        self.assertEqual(rc, 1)
        self.assertIn("gone", said)

    def test_a_measurement_taken_at_another_revision_is_rejected(self):
        rc, said = verdict([source(target_revision="v2")], {"a": record()})
        self.assertEqual(rc, 1)
        self.assertIn("targetRevision", said)

    def test_every_coordinate_the_measurement_depends_on_is_compared(self):
        for field, changed in (("repo_url", {"repo_url": "https://other.invalid"}),
                               ("path", {"path": "crds/minimal"}),
                               ("recurse", {"recurse": True}),
                               ("include", {"include": "*.yaml"}),
                               ("exclude", {"exclude": "*.json"})):
            with self.subTest(field=field):
                rc, _ = verdict([source(**changed)], {"a": record()})
                self.assertEqual(rc, 1)

    def test_a_measurement_of_nothing_is_not_a_pass(self):
        rc, said = verdict([source()], {"a": record(bytes=0, files=0)})
        self.assertEqual(rc, 1)
        self.assertIn("not the evidence", said)

    def test_an_unmeasurable_source_needs_a_stated_reason(self):
        templated = source(path="{{ .path.path }}")
        rc, _ = verdict([templated],
                        {"a": record(path="{{ .path.path }}", bytes=None, files=None)})
        self.assertEqual(rc, 1)
        rc, said = verdict([templated],
                           {"a": record(path="{{ .path.path }}", bytes=None, files=None,
                                        unbounded="bounded where it is written")})
        self.assertEqual(rc, 0, said)
        self.assertIn("bounded where it is written", said)

    def test_an_in_tree_source_is_measured_rather_than_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "a.yaml", 30)
            rc, said = verdict([source(local=root, path="addons/x")], {})
            self.assertEqual(rc, 0, said)
            self.assertIn("in-tree", said)

    def test_an_in_tree_source_holding_no_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, said = verdict([source(local=pathlib.Path(tmp), path="addons/x")], {})
            self.assertEqual(rc, 1)
            self.assertIn("addons/x", said)

    def test_an_in_tree_source_meets_the_same_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "a.yaml", 20)
            tight = {"maxCombinedDirectoryManifestsSize": "20", "argoCdDefault": "10"}
            rc, said = verdict([source(local=root, path="addons/x")], {}, tight)
            self.assertEqual(rc, 0, said)
            write(root, "b.yaml", 1)
            rc, _ = verdict([source(local=root, path="addons/x")], {}, tight)
            self.assertEqual(rc, 1)

    def test_a_contract_declaring_no_ceiling_cannot_run(self):
        # Exit 2, not 0: with no ceiling every source measures as fitting, and a
        # gate that reports that has answered a question it never asked.
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as raised:
            gate.check_offline([source()], {"a": record()}, {"argoCdDefault": "10M"})
        self.assertEqual(raised.exception.code, gate.gatelib.CANNOT_RUN)


class TheLiveVerdict(unittest.TestCase):
    """The half that catches what the tree cannot: a tag moved upstream.

    Nothing in a commit records that. The measurement is a function of
    (repoURL, targetRevision, path), so the blocking gate already fails when a
    pin moves — what it cannot see is the pin staying still while the thing it
    names changes underneath it.
    """

    def live(self, measured, sources, records, contract=None):
        real = gate.remeasure
        gate.remeasure = lambda src: measured
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = gate.check_live(sources, records, contract or CONTRACT)
            return rc, buf.getvalue()
        finally:
            gate.remeasure = real

    def test_a_source_that_still_measures_what_was_recorded_passes(self):
        rc, said = self.live((1000, 2), [source()], {"a": record()})
        self.assertEqual(rc, 0, said)

    def test_a_tag_that_moved_under_a_still_pin_is_rejected(self):
        rc, said = self.live((2000, 3), [source()], {"a": record()})
        self.assertEqual(rc, 1)
        self.assertIn("The pin did not move", said)

    def test_the_boundary_is_the_repo_servers_here_too(self):
        rc, said = self.live((20_000_000, 2), [source()],
                             {"a": record(bytes=20_000_000)})
        self.assertEqual(rc, 0, said)
        rc, _ = self.live((20_000_001, 2), [source()],
                          {"a": record(bytes=20_000_001)})
        self.assertEqual(rc, 1)

    def test_a_source_resolving_to_no_manifest_file_is_rejected(self):
        # The empty comparison. A path that resolves and holds nothing generates
        # nothing, and reporting it as under the limit is the defect.
        rc, said = self.live((0, 0), [source()], {"a": record()})
        self.assertEqual(rc, 1)
        self.assertIn("generates nothing", said)

    def test_resolving_nothing_at_all_is_not_a_pass(self):
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as raised:
            self.live((1, 1), [source(path="{{ .path.path }}")], {})
        self.assertEqual(raised.exception.code, 1)


class TheRecordKeys(unittest.TestCase):
    def test_one_source_per_appset_keys_on_the_appset(self):
        self.assertEqual(sorted(gate.keyed([source(appset="crds")])), ["crds"])

    def test_two_sources_in_one_appset_are_told_apart_by_path(self):
        got = sorted(gate.keyed([source(appset="crds", path="a"),
                                 source(appset="crds", path="b")]))
        self.assertEqual(got, ["crds#a", "crds#b"])


class TheShippedCatalog(unittest.TestCase):
    """What the gate says about the tree it is shipped with."""

    def setUp(self):
        self.sources = gate.directory_sources()
        self.keyed = gate.keyed(self.sources)

    def test_the_corpus_is_not_empty(self):
        self.assertTrue(self.sources)

    def test_the_pinned_crd_directories_are_in_it(self):
        # Both are plain manifest directories in someone else's repository, which
        # is the shape the repo-server measures.
        self.assertIn("argo-workflows-crds", self.keyed)
        self.assertIn("gateway-api-crds", self.keyed)

    def test_no_kustomize_overlay_is_in_it(self):
        # Every in-tree source this catalog ships carries a kustomization, so
        # anything under addons/ or policies/ appearing here means one stopped
        # being a kustomize root.
        stray = [k for k, s in self.keyed.items()
                 if s.local is not None and s.path.startswith(("addons/", "policies/"))]
        self.assertEqual(stray, [])

    def test_every_source_has_a_record_or_is_measured_in_tree(self):
        recorded = gate.load_records()
        for key, src in self.keyed.items():
            with self.subTest(key=key):
                self.assertTrue(src.local is not None or key in recorded)

    def test_the_records_carry_a_size_or_a_reason_they_cannot(self):
        for key, rec in gate.load_records().items():
            with self.subTest(key=key):
                self.assertTrue(rec.get("bytes") is not None or rec.get("unbounded"))

    def test_the_contract_declares_a_ceiling_the_repo_server_would_accept(self):
        contract = gate.load_contract()
        self.assertGreater(
            gate.quantity(contract["maxCombinedDirectoryManifestsSize"], "t"), 0)

    def test_the_catalog_passes_its_own_gate(self):
        rc, said = verdict(self.sources, gate.load_records(), gate.load_contract())
        self.assertEqual(rc, 0, said)

    def test_the_record_file_is_what_sync_would_write(self):
        # A hand-edited record is a measurement nobody took.
        doc = json.loads((ROOT / "scripts" / "directory-sources.json").read_text())
        self.assertEqual(doc["_README"], gate.README)


if __name__ == "__main__":
    unittest.main()
