"""The Kyverno test corpus is intact, asserted here rather than inferred.

`kyverno test` fails when policies/kyverno/tests/resources.yaml is missing, but
it fails because the CLI errors on an unreadable path — not because anything
checks the corpus. That property belongs to the CLI's error handling, so a
version that downgrades a missing input to a warning, or a flag that defaults to
ignoring it, turns a suite over zero resources into a passing run.

These assertions move the property here: every resource a result names must
exist in the corpus, and every policy the suite loads must exist on disk. A
fixture removed while its expectation remains is caught by name.
"""

import pathlib
import unittest

import yaml

TESTS = pathlib.Path(__file__).resolve().parent.parent.parent / "policies" / "kyverno" / "tests"
MANIFEST = TESTS / "kyverno-test.yaml"


def _load():
    return yaml.safe_load(MANIFEST.read_text())


class Corpus(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MANIFEST.exists(), f"{MANIFEST} is absent — the Kyverno "
                                           f"suite has no manifest to run")
        self.spec = _load()

    def test_results_are_declared(self):
        self.assertTrue(self.spec.get("results"),
                        "the suite declares no results — `kyverno test` over an "
                        "empty expectation set reports success")

    def test_every_policy_path_exists(self):
        for rel in self.spec.get("policies") or []:
            self.assertTrue((TESTS / rel).resolve().exists(),
                            f"policy {rel} named by the suite does not exist")

    def test_every_named_resource_exists_in_the_corpus(self):
        docs = []
        for rel in self.spec.get("resources") or []:
            path = (TESTS / rel).resolve()
            self.assertTrue(path.exists(), f"resource file {rel} is absent")
            docs += [d for d in yaml.safe_load_all(path.read_text()) if d]
        present = {d["metadata"]["name"] for d in docs if d.get("metadata")}
        self.assertTrue(present, "the resource corpus is empty")

        named = {n for r in self.spec["results"] for n in (r.get("resources") or [])}
        missing = sorted(named - present)
        self.assertFalse(missing, f"results name resources absent from the corpus: "
                                  f"{missing} — the expectation survives, the fixture "
                                  f"does not, and the assertion silently stops running")

    def test_both_directions_are_exercised(self):
        # A suite asserting only passes proves a policy admits; it cannot prove
        # the policy rejects anything.
        outcomes = {r.get("result") for r in self.spec["results"]}
        self.assertIn("pass", outcomes)
        self.assertIn("fail", outcomes,
                      "no result expects a failure — the suite would pass against "
                      "policies that reject nothing")


if __name__ == "__main__":
    unittest.main()
