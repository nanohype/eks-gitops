"""Unit tests for the secret-store reference gate.

The defect is a name restated in eleven places with nothing holding them equal,
so the failure this gate can have is a corpus that quietly loses members: a
reference it does not read is a reference that cannot disagree with anything.
Half the consumers are Go-template chart source that does not parse as YAML,
which is exactly the half a gate written against `yaml.safe_load_all` drops
while reporting a clean run over the rest.

So these concentrate on which references are FOUND, and on the two verdicts
whose absence is silent in a cluster: an ExternalSecret naming a store that is
not there, and a kustomize patch target that stops matching.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import tempfile
import unittest

import yaml
from gateloader import load

gate = load("check-secret-store-refs")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def store(name="aws-secrets-manager", api="external-secrets.io/v1",
          kind="ClusterSecretStore"):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name},
            "spec": {"provider": {"aws": {"service": "SecretsManager",
                                          "region": "us-west-2"}}}}


def external_secret(name, store_name="aws-secrets-manager",
                    api="external-secrets.io/v1"):
    return {"apiVersion": api, "kind": "ExternalSecret",
            "metadata": {"name": name},
            "spec": {"secretStoreRef": {"name": store_name,
                                        "kind": "ClusterSecretStore"},
                     "target": {"name": name}}}


def appset(name, target_name="aws-secrets-manager",
           target_kind="ClusterSecretStore"):
    return {"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet",
            "metadata": {"name": name},
            "spec": {"template": {"spec": {"source": {
                "path": "p",
                "kustomize": {"patches": [
                    {"target": {"kind": target_kind, "name": target_name},
                     "patch": "- op: replace\n  path: /spec/x\n  value: y"}]}}}}}}


CHART_TEMPLATE = """apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: {{ include "x.name" . }}-creds
  labels:
    {{- include "common.labels" . | indent 4 }}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: %s
    kind: ClusterSecretStore
  target:
    name: {{ include "x.name" . }}-creds
"""


class ReadingChartSource(unittest.TestCase):
    """The half of the corpus that does not parse as YAML."""

    def chart(self, store_name="aws-secrets-manager"):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "Chart.yaml").write_text("apiVersion: v2\nname: x\nversion: 0.1.0\n")
        (d / "templates").mkdir()
        p = d / "templates" / "externalsecret.yaml"
        p.write_text(CHART_TEMPLATE % store_name)
        return p

    def test_the_reference_is_read_out_of_go_template_text(self):
        """`yaml.safe_load_all` raises on this file. A gate that caught the
        parse error and continued would report a clean run over the consumers
        that happen to be plain manifests."""
        p = self.chart()
        with self.assertRaises(yaml.YAMLError):
            list(yaml.safe_load_all(p.read_text()))
        self.assertEqual(gate.helm_store_refs(p),
                         [(p, "ClusterSecretStore", "aws-secrets-manager")])

    def test_a_typo_in_chart_source_is_read_as_written(self):
        p = self.chart("aws-secretsmanager")
        self.assertEqual(gate.helm_store_refs(p)[0][2], "aws-secretsmanager")

    def test_a_name_outside_the_block_is_not_taken_for_the_store(self):
        """The block is located by its key and the fields read from inside it.
        A bare grep for `name:` would take the target's, or the metadata's."""
        p = self.chart()
        p.write_text(p.read_text().replace(
            "  refreshInterval: 1h\n",
            "  refreshInterval: 1h\n  decoy:\n    name: not-a-store\n"))
        self.assertEqual([r[2] for r in gate.helm_store_refs(p)],
                         ["aws-secrets-manager"])


class TheVerdict(unittest.TestCase):
    """main() over a planted tree."""

    def verdict(self, docs, appsets=(), contract=None, write=False):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "addons").mkdir(parents=True)
        (root / "applicationsets").mkdir(parents=True)
        for i, doc in enumerate(docs):
            (root / "addons" / f"{i:02d}.yaml").write_text(yaml.safe_dump(doc))
        for i, doc in enumerate(appsets):
            (root / "applicationsets" / f"{i:02d}.yaml").write_text(
                yaml.safe_dump(doc))
        path = root / "contracts" / "secret-store.json"
        if contract is not None:
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(contract, indent=2) + "\n")
        saved = (gate.ROOT, gate.APPSET_DIR, gate.CONTRACT)
        gate.ROOT, gate.APPSET_DIR, gate.CONTRACT = (
            root, root / "applicationsets", path)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = gate.main(["--write"] if write else [])
        finally:
            gate.ROOT, gate.APPSET_DIR, gate.CONTRACT = saved
        return rc, out.getvalue(), path

    def healthy(self):
        return [store(), external_secret("a"), external_secret("b")]

    def contract_for(self, name="aws-secrets-manager",
                     api="external-secrets.io/v1"):
        return {
            "_generated": "scripts/check-secret-store-refs.py --write; the source "
                          "of truth is the manifest under "
                          "addons/bootstrap/secret-stores/. Edit that, then "
                          "regenerate.",
            "_purpose": "Consumers outside this repository assert their chart "
                        "defaults against these values instead of restating them.",
            "clusterSecretStore": {"apiVersion": api,
                                   "kind": "ClusterSecretStore", "name": name},
            "externalSecret": {"apiVersion": api},
        }

    def test_a_consistent_catalog_passes(self):
        """The control. Without it every case below could be failing for a
        reason the case did not plant."""
        rc, out, _ = self.verdict(self.healthy(), contract=self.contract_for())
        self.assertEqual(rc, 0, out)

    def test_an_external_secret_naming_an_undeclared_store_is_reported(self):
        docs = self.healthy()
        docs[1]["spec"]["secretStoreRef"]["name"] = "aws-secretsmanager"
        rc, out, _ = self.verdict(docs, contract=self.contract_for())
        self.assertEqual(rc, 1, out)
        self.assertIn("SecretSyncedError", out)

    def test_a_patch_target_that_stops_matching_is_reported(self):
        """kustomize exits 0 on an unmatched target and emits the unpatched
        base, so nothing downstream can fail on this."""
        rc, out, _ = self.verdict(
            self.healthy(), appsets=[appset("s", "aws-secretsmanager")],
            contract=self.contract_for())
        self.assertEqual(rc, 1, out)
        self.assertIn("does not treat an unmatched target as an error", out)

    def test_a_patch_target_that_matches_is_not_reported(self):
        rc, out, _ = self.verdict(self.healthy(), appsets=[appset("s")],
                                  contract=self.contract_for())
        self.assertEqual(rc, 0, out)

    def test_a_reference_naming_no_store_at_all_is_reported(self):
        docs = self.healthy()
        docs[1]["spec"]["secretStoreRef"]["name"] = ""
        rc, out, _ = self.verdict(docs, contract=self.contract_for())
        self.assertEqual(rc, 1, out)
        self.assertIn("names no store at all", out)

    def test_two_external_secret_versions_leave_nothing_to_publish(self):
        docs = self.healthy()
        docs[2]["apiVersion"] = "external-secrets.io/v1beta1"
        rc, out, _ = self.verdict(docs, contract=self.contract_for())
        self.assertEqual(rc, 1, out)
        self.assertIn("pinning to a coin flip", out)

    def test_two_cluster_stores_leave_the_contract_undecided(self):
        docs = self.healthy() + [store(name="aws-secrets-manager-2")]
        rc, out, _ = self.verdict(docs, contract=self.contract_for())
        self.assertEqual(rc, 1, out)
        self.assertIn("has not decided", out)

    def test_a_contract_that_drifted_from_the_manifest_is_reported(self):
        """The failure mode of publishing: consumers assert against it and
        pass, which is worse than having nothing to assert against."""
        rc, out, _ = self.verdict(
            self.healthy(), contract=self.contract_for("aws-secretsmanager"))
        self.assertEqual(rc, 1, out)
        self.assertIn("does not state what this tree states", out)

    def test_a_missing_contract_is_reported(self):
        rc, out, _ = self.verdict(self.healthy())
        self.assertEqual(rc, 1, out)
        self.assertIn("does not exist", out)

    def test_a_contract_that_does_not_parse_is_reported(self):
        """A contract a consumer cannot parse is one it skips, which lands it
        back where it started: restating the name and hoping."""
        _rc, _out, path = self.verdict(self.healthy(),
                                       contract=self.contract_for())
        path.write_text("{not json")
        root = path.parent.parent
        saved = (gate.ROOT, gate.APPSET_DIR, gate.CONTRACT)
        gate.ROOT, gate.APPSET_DIR, gate.CONTRACT = (
            root, root / "applicationsets", path)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = gate.main([])
        finally:
            gate.ROOT, gate.APPSET_DIR, gate.CONTRACT = saved
        self.assertEqual(rc, 1)
        self.assertIn("not valid JSON", out.getvalue())

    def test_write_regenerates_the_contract_from_the_tree(self):
        rc, out, path = self.verdict(self.healthy(), write=True)
        self.assertEqual(rc, 0, out)
        written = json.loads(path.read_text())
        self.assertEqual(written["clusterSecretStore"]["name"],
                         "aws-secrets-manager")
        self.assertEqual(written["externalSecret"]["apiVersion"],
                         "external-secrets.io/v1")

    def test_no_store_declared_cannot_run(self):
        """Exit 2. A tree with no store is a gate with nothing to compare
        against, which reports the same as a tree whose references all resolve."""
        rc, out, _ = self.verdict([external_secret("a")],
                                  contract=self.contract_for())
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("examined nothing", out)

    def test_no_consumer_at_all_cannot_run(self):
        rc, out, _ = self.verdict([store()], contract=self.contract_for())
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("read no consumer", out)


class TheShippedCatalog(unittest.TestCase):
    """Over the tree, so a reference added later is checked here."""

    @classmethod
    def setUpClass(cls):
        cls.declared, cls.consumers, cls.versions = gate.survey()

    def test_the_catalog_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(gate.main([]), 0, out.getvalue())

    def test_every_reference_the_tree_holds_is_in_the_corpus(self):
        """Derived per file rather than counted. A second, cruder reading finds
        the files; this asserts the gate's own two readers found the same ones,
        so a reader that stops matching fails here rather than shrinking the
        corpus quietly.

        The key, not the word: prose naming `secretStoreRef` is not a reference,
        and matching the bare substring picks up this repository's own CI
        comments about the gate.
        """
        key = re.compile(r"^\s*secretStoreRef:\s*$", re.M)
        grepped = {path for path in gate.tracked_yaml()
                   if key.search(path.read_text(encoding="utf-8"))}
        self.assertEqual({p for p, _k, _n in self.consumers}, grepped)

    def test_the_corpus_spans_both_readers(self):
        """One of them is chart source. A catalog whose consumers were all plain
        manifests would pass a gate with no Go-template reader at all."""
        helm = [p for p, _k, _n in self.consumers
                if gate.gatelib.is_helm_template(p)]
        plain = [p for p, _k, _n in self.consumers
                 if not gate.gatelib.is_helm_template(p)]
        self.assertTrue(helm, "no chart-source consumer — the text reader is "
                              "exercised by nothing on this tree")
        self.assertTrue(plain)

    def test_the_published_contract_is_the_declared_store(self):
        published = json.loads(gate.CONTRACT.read_text(encoding="utf-8"))
        (kind, name), (path, api) = next(
            iter({k: v for k, v in self.declared.items()
                  if k[0] == gate.CLUSTER_STORE}.items()))
        self.assertEqual(published["clusterSecretStore"],
                         {"apiVersion": api, "kind": kind, "name": name},
                         f"{gate.rel(gate.CONTRACT)} and {gate.rel(path)} "
                         f"disagree about the store this catalog owns")

    def test_the_contract_is_not_ignored_by_git(self):
        """A published contract that git refuses to track is one no consumer can
        fetch. `.gitignore` carries `*secret*.json` under its secrets rules, and
        the file's own name matches it."""
        import subprocess
        proc = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--error-unmatch",
             str(gate.CONTRACT.relative_to(ROOT))],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0,
                         f"{gate.rel(gate.CONTRACT)} is not tracked: "
                         f"{proc.stderr.strip()}")


if __name__ == "__main__":
    unittest.main()
