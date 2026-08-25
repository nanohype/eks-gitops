"""Unit tests for the prose gate's extractors.

The positive control proves the gate rejects a bad reference on the real tree.
It cannot prove the gate draws the right boundary around what counts as a
reference, because the real tree contains no colliding pair — and that boundary
is where this gate is most likely to be wrong in a way nothing surfaces. A
population too wide buries a real finding in noise until readers stop looking;
too narrow and the gate passes over the claims it exists to check.

So these exercise the classification directly, with the shapes this repo's prose
actually contains.
"""

from __future__ import annotations

import pathlib
import unittest

from gateloader import load

gate = load("check-named-things")

# The prefixes are derived from the tree under test, not from module state, so
# a caller must supply them. Pinning the real repo's here keeps these unit
# tests asserting the classification rule rather than the tree's shape.
ROOTED = gate.rooted_prefixes(pathlib.Path(__file__).resolve().parent.parent.parent)


class ClassifyReference(unittest.TestCase):
    def test_rooted_backtick_is_a_claim(self):
        self.assertTrue(gate.is_repo_path("scripts/check-sync-waves.py", False, ROOTED))
        self.assertTrue(gate.is_repo_path("docs/runbooks/rollback.md", False, ROOTED))

    def test_bare_convention_name_is_not_a_claim(self):
        # `values.yaml` in this repo's prose means "the addon's values.yaml": a
        # convention true of forty-odd directories and of no repo-root path.
        for ref in ("values.yaml", "values-development.yaml", "kustomization.yaml"):
            with self.subTest(ref=ref):
                self.assertFalse(gate.is_repo_path(ref, False, ROOTED))

    def test_link_target_is_always_a_claim(self):
        # A link is a promise that following it arrives somewhere, whatever the
        # target looks like.
        self.assertTrue(gate.is_repo_path("README.md", True, ROOTED))
        self.assertTrue(gate.is_repo_path("../architecture/overview.md", True, ROOTED))

    def test_external_and_placeholder_references_are_skipped(self):
        for ref in ("https://taskfile.dev/", "mailto:x@example.com", "#anchor",
                    "oci://docker.io/envoyproxy/ai-gateway-helm",
                    "git@github.com:nanohype/clusters.git",
                    "addons/<category>/<name>/", "{{ .path }}", "a b c"):
            with self.subTest(ref=ref):
                self.assertFalse(gate.is_repo_path(ref, False, ROOTED))
                if ref.startswith(("http", "mailto", "#", "oci", "git@")) or "<" in ref:
                    self.assertFalse(gate.is_repo_path(ref, True, ROOTED))


class TaskReferences(unittest.TestCase):
    def test_task_as_a_noun_is_not_a_command(self):
        # Druid calls its unit of work a task. "the overlord launches task pods"
        # is prose, and reading it as a CLI invocation reports on a population
        # the Taskfile was never part of.
        prose = "the overlord launches task pods as Jobs from the task template\n"
        self.assertEqual(list(gate.command_spans(prose)), [])

    def test_backticked_command_is_a_claim(self):
        spans = dict(gate.command_spans("Run `task validate` before opening a PR.\n"))
        self.assertIn("task validate", spans.values())

    def test_fenced_command_is_a_claim(self):
        doc = "```bash\ntask render\n```\n"
        self.assertIn("task render", dict(gate.command_spans(doc)).values())

    def test_shell_prompt_is_stripped(self):
        doc = "```bash\n$ task scan\n```\n"
        self.assertIn("task scan", dict(gate.command_spans(doc)).values())


class FenceHandling(unittest.TestCase):
    def test_line_count_survives_blanking(self):
        # Line numbers in a finding must resolve in the file the reader opens.
        doc = "a\n```\nb\nc\n```\nd\n"
        self.assertEqual(len(gate.strip_fences(doc).splitlines()),
                         len(doc.splitlines()))

    def test_fenced_content_is_removed_from_the_path_view(self):
        doc = "```\n`addons/nope/missing.yaml`\n```\n"
        self.assertEqual(list(gate.candidates(doc)), [])

    def test_unfenced_content_survives(self):
        doc = "see `scripts/check-sync-waves.py` for the table\n"
        refs = [r for _, r, _ in gate.candidates(doc)]
        self.assertIn("scripts/check-sync-waves.py", refs)


class Citations(unittest.TestCase):
    def test_citation_shape_is_recognised(self):
        m = gate.CITATION.search("wired as the fork-safety job (ci.yml:122-130).")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "ci.yml")
        self.assertEqual((m.group(2), m.group(3)), ("122", "130"))

    def test_single_line_citation(self):
        m = gate.CITATION.search("the base keeps it at verify-images.yaml:21")
        self.assertIsNotNone(m)
        self.assertEqual((m.group(1), m.group(2), m.group(3)),
                         ("verify-images.yaml", "21", None))

    def test_a_version_is_not_a_citation(self):
        # `chart 1.4.2` and `KSV-0012` must not read as file:line.
        self.assertIsNone(gate.CITATION.search("cert-manager v1.21.1"))
        self.assertIsNone(gate.CITATION.search("KSV-0012/0023"))


if __name__ == "__main__":
    unittest.main()
