"""Unit tests for the fork-safety gate, scripts/check-hardcoded-org.py.

The gate decides two things: which lines are a repoURL naming this catalog, and
what a scan over the applied ApplicationSets concludes. The first is the
pattern; each case here is a line the pattern must take as the catalog or must
leave alone, because the catalog's published artifacts are correctly hardcoded
and a pattern that took them would have a fork point at products that do not
exist. The second is main, run over a scratch root holding the ApplicationSets
each case needs.

The positive control in scripts/tests/controls.py proves the gate rejects one
planted repoURL in the real tree. These cover what that one plant does not:
every spelling the pattern takes or leaves, the floor, the report-only mode, and
what is outside the scan.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import shutil
import tempfile
import unittest

from gateloader import load

gate = load("check-hardcoded-org")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

TEMPLATED = "repoURL: '{{ index .metadata.annotations \"gitops/repo-url\" }}'"
HARDCODED = "repoURL: https://github.com/nanohype/eks-gitops.git"


def appset(repo_url: str = TEMPLATED) -> str:
    """An ApplicationSet whose one source names `repo_url`."""
    return (
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: ApplicationSet\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      source:\n"
        f"        {repo_url}\n"
    )


class TheCatalogRepoURL(unittest.TestCase):
    """Which lines name this catalog as a source: those, and nothing else."""

    def test_each_spelling_of_the_catalog_is_taken(self):
        for line in (
            "repoURL: https://github.com/nanohype/eks-gitops",
            "repoURL: https://github.com/nanohype/eks-gitops.git",
            "repoURL: git@github.com:nanohype/eks-gitops.git",
            "repoURL: 'https://github.com/nanohype/eks-gitops.git'",
            'repoURL: "https://github.com/nanohype/eks-gitops"',
            "  - repoURL: https://github.com/nanohype/eks-gitops.git",
            "repoURL: https://github.com/nanohype/eks-gitops.git  # upstream",
            "repoURL: https://GitHub.com/NanoHype/EKS-GitOps.git",
        ):
            with self.subTest(line=line):
                self.assertIsNotNone(gate.CATALOG_REPO_URL.match(line))

    def test_what_is_not_the_catalog_as_a_source_is_left(self):
        for name, line in {
            "the templated source": TEMPLATED,
            "a published product repo": "repoURL: https://github.com/nanohype/eks-agent-platform",
            "another org's catalog": "repoURL: https://github.com/acme/eks-gitops.git",
            "a longer repo name": "repoURL: https://github.com/nanohype/eks-gitops-extra.git",
            "an OCI chart repo": "repoURL: oci://ghcr.io/nanohype/charts",
            "an image": "image: ghcr.io/nanohype/eks-gitops:1.0.0",
            "another key": "source: https://github.com/nanohype/eks-gitops.git",
            "a path after the repo": "repoURL: https://github.com/nanohype/eks-gitops/tree/main",
        }.items():
            with self.subTest(name=name):
                self.assertIsNone(gate.CATALOG_REPO_URL.match(line))


class AScan(unittest.TestCase):
    """main over a scratch root: what it reads, and what it concludes."""

    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.root = pathlib.Path(tmp)
        self.appsets = self.root / "applicationsets"
        self.appsets.mkdir()
        for i in range(gate.MIN_APPSETS):
            (self.appsets / f"addons-{i:02}.yaml").write_text(appset())

    def scan(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = gate.main(["--root", str(self.root), *argv])
        return status, out.getvalue()

    def test_a_catalog_templated_throughout_is_clean(self):
        status, said = self.scan("--blocking")
        self.assertEqual(status, 0, said)
        self.assertIn(f"Scanned {gate.MIN_APPSETS} applied ApplicationSet(s)", said)
        self.assertIn("✓ no applied ApplicationSet hardcodes nanohype/eks-gitops", said)

    def test_a_hardcoded_repo_url_fails_a_blocking_scan(self):
        (self.appsets / "addons-03.yaml").write_text(appset(HARDCODED))
        status, said = self.scan("--blocking")
        self.assertEqual(status, 1, said)
        self.assertIn(
            "Found 1 hardcoded catalog repoURL(s) across 1 applied ApplicationSet(s)", said
        )
        self.assertIn("  applicationsets/addons-03.yaml\n    7: " + HARDCODED, said)
        self.assertNotIn("WARNING (non-blocking)", said)

    def test_without_blocking_it_reports_and_passes(self):
        (self.appsets / "addons-03.yaml").write_text(appset(HARDCODED))
        status, said = self.scan()
        self.assertEqual(status, 0, said)
        self.assertIn("Found 1 hardcoded catalog repoURL(s)", said)
        self.assertIn("WARNING (non-blocking)", said)

    def test_each_file_is_named_once_above_its_lines(self):
        (self.appsets / "addons-03.yaml").write_text(appset(HARDCODED) + f"        {HARDCODED}\n")
        (self.appsets / "addons-07.yaml").write_text(appset(HARDCODED))
        status, said = self.scan("--blocking")
        self.assertEqual(status, 1, said)
        self.assertIn(
            "Found 3 hardcoded catalog repoURL(s) across 2 applied ApplicationSet(s)", said
        )
        self.assertEqual(said.count("  applicationsets/addons-03.yaml\n"), 1, said)
        self.assertIn(f"    7: {HARDCODED}\n    8: {HARDCODED}\n", said)

    def test_a_commented_out_repo_url_is_prose(self):
        (self.appsets / "addons-03.yaml").write_text(appset(f"# {HARDCODED}"))
        status, said = self.scan("--blocking")
        self.assertEqual(status, 0, said)

    def test_a_yml_file_is_read_too(self):
        (self.appsets / "addons-99.yml").write_text(appset(HARDCODED))
        status, said = self.scan("--blocking")
        self.assertEqual(status, 1, said)
        self.assertIn("applicationsets/addons-99.yml", said)

    def test_opt_in_appsets_are_not_applied_so_not_read(self):
        (self.appsets / "opt-in").mkdir()
        (self.appsets / "opt-in" / "hub.yaml").write_text(appset(HARDCODED))
        status, said = self.scan("--blocking")
        self.assertEqual(status, 0, said)
        self.assertIn(f"Scanned {gate.MIN_APPSETS} applied ApplicationSet(s)", said)

    def test_no_applicationsets_directory_could_not_run(self):
        shutil.rmtree(self.appsets)
        status, said = self.scan("--blocking")
        self.assertEqual(status, 2, said)
        self.assertIn("examined nothing, which is not the same as finding nothing", said)

    def test_fewer_appsets_than_the_floor_could_not_run(self):
        (self.appsets / "addons-00.yaml").unlink()
        status, said = self.scan("--blocking")
        self.assertEqual(status, 2, said)
        self.assertIn(
            f"found {gate.MIN_APPSETS - 1} applied ApplicationSet(s) under applicationsets, "
            f"below the floor of {gate.MIN_APPSETS}",
            said,
        )


class TheTree(unittest.TestCase):
    def test_the_catalog_hardcodes_no_repo_url(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = gate.main(["--root", str(ROOT), "--blocking"])
        self.assertEqual(status, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()
