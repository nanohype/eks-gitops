"""Unit tests for the Renovate coverage gate.

The gate answers "is this chart pin watched by a manager that resolves?". Its
own failure mode is a FALSE POSITIVE — reporting a pin covered when nothing
watches it — because that failure is silent in exactly the way the gate exists
to prevent. These tests therefore concentrate on the negative direction.
"""

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

import yaml
from gateloader import load

cov = load("check-renovate-coverage")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


class SubstringFalsePositive(unittest.TestCase):
    """A chart name must not be matched by a longer chart's pin.

    `loki` is a substring of `loki-distributed`. Both are real charts in this
    ecosystem, and Grafana's OSS charts have already moved repositories once. A
    substring test reports `loki` as covered by a `loki-distributed` pin, so a
    genuinely unwatched pin passes the gate.
    """

    PINNED_LONGER = """
                - appName: x
                  chartRepo: https://example.com
                  chart: loki-distributed
                  chartVersion: "1.2.3"
"""

    def setUp(self):
        self.patterns = cov.load_patterns()
        self.assertTrue(self.patterns, "no customManager regexes loaded — this "
                                       "suite would pass vacuously")

    def test_exact_chart_is_covered(self):
        self.assertTrue(
            cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "1.2.3", self.patterns)
        )

    def test_substring_chart_is_not_covered(self):
        self.assertFalse(
            cov.covered_by_custom(self.PINNED_LONGER, "loki", "1.2.3", self.patterns),
            "'loki' reported as covered by a 'loki-distributed' pin — a chart "
            "nothing watches would pass the gate",
        )

    def test_version_mismatch_is_not_covered(self):
        self.assertFalse(
            cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "9.9.9", self.patterns)
        )


class RE2Rejection(unittest.TestCase):
    """Patterns Renovate cannot run must be rejected, not compiled and trusted.

    Python's `re` accepts lookaround and backreferences; Renovate's RE2 does not.
    A pattern using them compiles here and matches nothing in production, which
    would make the gate itself the vacuous thing.
    """

    def test_unsupported_constructs_are_listed(self):
        probes = [p for p, _ in cov.RE2_UNSUPPORTED]
        for needed in (r"\(\?=", r"\(\?<=", r"\\[1-9]"):
            self.assertIn(needed, probes)


class OciRepoUrlShape(unittest.TestCase):
    """The repoURL/chart redundancy ArgoCD requires, asserted rather than described.

    Exercised through the gate's own comparison. A test that re-implements the
    last-segment split inside itself passes against any gate, including one that
    never runs the check — which is what these looked like before they were
    pointed at check_oci_repourl_shape.
    """

    def _pin(self, repo, chart, matrix):
        return cov.Pin("probe.yaml", "applicationsets/probe.yaml", "", repo, chart,
                       "1.0.0", matrix)

    def _verdict(self, pins):
        """Run the shape check in isolation; return (examined, failures)."""
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        seen = cov.check_oci_repourl_shape(pins)
        return seen, list(cov.failures)

    def test_pin_as_written_is_accepted(self):
        pin = self._pin("oci://ghcr.io/n/eks-agent-platform/charts/operator",
                        "operator", False)
        seen, failures = self._verdict([pin])
        self.assertEqual((seen, failures), (1, []))

    def test_tidied_pin_is_rejected(self):
        # Dropping the "redundant" trailing segment makes ArgoCD request
        # .../charts/manifests/<version>, which is not a package.
        pin = self._pin("oci://ghcr.io/n/eks-agent-platform/charts", "operator", False)
        seen, failures = self._verdict([pin])
        self.assertEqual(seen, 1)
        self.assertTrue(failures, "a repoURL that resolves to no package was accepted")

    def test_a_matrix_pin_is_rejected_the_same_way(self):
        """The blind spot itself: written as a matrix element, checked identically.

        Read from source syntax the assertion matched `repoURL:` beside a literal
        `oci://`, a pair a matrix appset never writes — it templates repoURL from
        the element's chartRepo. This asserts the shape check reaches such a pin,
        so narrowing it back to direct-source pins fails here rather than going
        quiet.
        """
        pin = self._pin("oci://docker.io/envoyproxy", "gateway-helm", True)
        seen, failures = self._verdict([pin])
        self.assertEqual(seen, 1, "a matrix-written OCI pin was not examined at all")
        self.assertTrue(failures, "a matrix-written OCI pin was examined and excused")

    def test_https_pins_are_not_subject_to_the_shape_rule(self):
        # Paired with a sound OCI pin so the anti-vacuity guard is satisfied and
        # the only thing under test is whether the https pin was examined.
        ok = self._pin("oci://example.com/charts/thing", "thing", False)
        https = self._pin("https://charts.example.com", "anything", True)
        self.assertEqual(self._verdict([ok, https]), (1, []))

    def test_an_all_https_catalog_is_reported_as_vacuous(self):
        """Examining nothing is not the same as finding nothing."""
        https = self._pin("https://charts.example.com", "anything", True)
        seen, failures = self._verdict([https])
        self.assertEqual(seen, 0)
        self.assertTrue(any("found no OCI pins" in f for f in failures),
                        f"a run that examined no OCI pin reported success: {failures}")

    def test_every_oci_pin_in_the_catalog_is_examined(self):
        """The count the check reports must be the whole OCI population.

        `if not seen` only catches the population reaching zero, so the number is
        asserted against an independent count of the pins themselves — otherwise
        the corpus can fall from five to two without a word.
        """
        pins = cov.rendered_pins()
        expected = sum(1 for p in pins if p.is_oci)
        self.assertGreater(expected, 0, "no OCI pin derived — this asserts nothing")
        self.assertTrue([p for p in pins if p.is_oci and p.matrix],
                        "no OCI pin is written as a matrix element, so the shape "
                        "this test exists for is absent from the catalog")
        seen, failures = self._verdict(pins)
        self.assertEqual(seen, expected,
                         "the shape check examined fewer OCI pins than the catalog has")
        self.assertEqual(failures, [], f"the shipped catalog should pass: {failures}")


class RenderedPinDerivation(unittest.TestCase):
    """Coordinates are read as ArgoCD renders them, whatever the pin's spelling.

    A matrix appset and a literal source produce Applications that are
    indistinguishable at the cluster, so an assertion about a pin that can only
    read one of the two spellings is narrower than the sentence it prints.
    """

    def setUp(self):
        self.pins = cov.rendered_pins()

    def _isolated(self, fn):
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        fn()
        return list(cov.failures)

    def test_both_spellings_are_present(self):
        self.assertTrue([p for p in self.pins if p.matrix])
        self.assertTrue([p for p in self.pins if not p.matrix])

    def test_no_pin_carries_an_unrendered_template(self):
        for pin in self.pins:
            for field in (pin.repo, pin.chart, pin.version):
                self.assertNotIn("{{", field, f"{pin.rel}: {field!r} is unrendered")

    def test_walk_covers_every_literal_pin_shape(self):
        self.assertEqual(self._isolated(lambda: cov.assert_corpus_floor(self.pins)), [])

    def test_floor_rejects_a_walk_that_lost_pins(self):
        kept = [p for p in self.pins if not p.matrix]
        failures = self._isolated(lambda: cov.assert_corpus_floor(kept))
        self.assertTrue(any("dropped out of the walk" in f for f in failures),
                        f"a walk missing every matrix pin was accepted: {failures}")

    def test_floor_names_the_file_that_lost_a_pin(self):
        """A per-file floor, so slack in one file cannot pay for a drop in another.

        Summed repo-wide, a shape the regex misses anywhere raises the number of
        genuine omissions tolerated everywhere.
        """
        victim = next(p for p in self.pins if p.matrix)
        kept = [p for p in self.pins if p is not victim]
        failures = self._isolated(lambda: cov.assert_corpus_floor(kept))
        self.assertTrue(any(victim.appset in f for f in failures),
                        f"the file that lost a pin was not named: {failures}")


class UnrenderableCoordinates(unittest.TestCase):
    """A coordinate this cannot render is reported, never admitted as a literal.

    Admitted, it reaches the walk disguised as a registry path: not `oci://`, not
    matrix, so it lands in the one branch that asserts nothing — while still
    counting toward the total the summary certifies.
    """

    def _keys(self, src):
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        keys = cov._templated_keys(src, "applicationsets/probe.yaml")
        return keys, list(cov.failures)

    def test_the_supported_form_resolves(self):
        keys, failures = self._keys({"repoURL": "{{ .chartRepo }}"})
        self.assertEqual((keys, failures), ({"repoURL": "chartRepo"}, []))

    def test_an_index_call_is_reported(self):
        keys, failures = self._keys({"repoURL": '{{ index . "chartRepo" }}'})
        self.assertEqual(keys, {})
        self.assertTrue(failures, "an unrenderable template form was accepted")

    def test_a_concatenation_is_reported(self):
        keys, failures = self._keys({"repoURL": "oci://{{ .registry }}/charts"})
        self.assertEqual(keys, {})
        self.assertTrue(failures, "a concatenated repoURL was accepted")

    def test_a_literal_is_not_treated_as_templated(self):
        self.assertEqual(self._keys({"repoURL": "oci://example.com/x"}), ({}, []))


class EveryChartSourceIsRead(unittest.TestCase):
    """A template may carry several chart sources, and all of them reach a cluster.

    No ApplicationSet in this catalog does yet, which is exactly why the case is
    constructed here: read from the real tree, a derivation that stops at the
    first chart source is indistinguishable from one that reads them all, and the
    summary line would certify a corpus quietly missing every source after the
    first.
    """

    TWO = {
        "sources": [
            {"repoURL": "https://charts.example.com", "chart": "alpha",
             "targetRevision": "1.0.0"},
            {"chart": "beta", "repoURL": "oci://registry.example.com/wrongnamespace",
             "targetRevision": "2.0.0"},
            {"repoURL": "https://github.com/x/y", "targetRevision": "main"},
        ]
    }

    def test_both_chart_sources_are_returned(self):
        got = cov._chart_sources(self.TWO, "applicationsets/probe.yaml")
        self.assertEqual([s["chart"] for s in got], ["alpha", "beta"],
                         "a chart source after the first was dropped")

    def test_a_source_without_a_chart_is_not_one(self):
        got = cov._chart_sources(self.TWO, "applicationsets/probe.yaml")
        self.assertTrue(all("chart" in s for s in got))

    def test_the_singular_source_key_is_read(self):
        one = {"source": {"repoURL": "oci://r/x", "chart": "x", "targetRevision": "1"}}
        got = cov._chart_sources(one, "applicationsets/probe.yaml")
        self.assertEqual([s["chart"] for s in got], ["x"])


class VersionsAreNotCoerced(unittest.TestCase):
    """A version YAML parsed as a number is rejected, not stringified.

    `str(1.10)` is `'1.1'`. Coerced, the gate compares a pin against a version
    that appears nowhere in the repo and reports a watched pin as unwatched.
    """

    def _literal(self, value):
        saved = list(cov.failures)
        self.addCleanup(lambda: cov.failures.__setitem__(slice(None), saved))
        cov.failures.clear()
        got = cov._literal("targetRevision", value, "applicationsets/probe.yaml", "x")
        return got, list(cov.failures)

    def test_a_quoted_version_passes_through(self):
        self.assertEqual(self._literal("1.10"), ("1.10", []))

    def test_a_yaml_float_is_rejected(self):
        got, failures = self._literal(1.10)
        self.assertIsNone(got)
        self.assertTrue(failures, "a float version was coerced instead of rejected")

    def test_an_absent_field_is_reported_as_absent(self):
        got, failures = self._literal(None)
        self.assertIsNone(got)
        self.assertTrue(any("has no targetRevision" in f for f in failures),
                        f"an absent field was not named as absent: {failures}")

    def test_present_but_numeric_is_not_reported_as_absent(self):
        _, failures = self._literal(4.2)
        self.assertFalse(any("has no targetRevision" in f for f in failures),
                         "a present field was reported as missing, sending the "
                         "reader to the wrong line")


class DerivingTheToolchainPins(unittest.TestCase):
    """What a workflow resolves is read off the workflow, not off a file list.

    A list of files to look in is a list of the pins somebody remembered. These
    plant each shape a step can pin something through, and one shape that looks
    like a pin and is not.
    """

    def workspace(self, workflow: dict, files=None):
        """A repo root holding one workflow and whatever files it names."""
        root = pathlib.Path(tempfile.mkdtemp())
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(yaml.safe_dump(workflow))
        for rel, body in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        return root

    def pins(self, workflow, files=None):
        original = cov.ROOT
        cov.ROOT = self.workspace(workflow, files)
        try:
            return cov.workflow_pins()
        finally:
            cov.ROOT = original

    def steps(self, *steps):
        return {"jobs": {"a": {"runs-on": "ubuntu-latest", "steps": list(steps)}}}

    def test_an_action_reference_is_a_pin(self):
        pins = self.pins(self.steps({"uses": "actions/checkout@" + "a" * 40}))
        self.assertEqual([(p.family, p.manager, p.dep, p.version) for p in pins],
                         [("GitHub Action", "github-actions", "actions/checkout",
                           "a" * 40)])

    def test_an_action_in_a_subdirectory_keeps_its_path(self):
        """`owner/repo/path@ref` is how a composite action inside a repo is named."""
        pins = self.pins(self.steps({"uses": "nanohype/.github/actions/merge-gate@v1"}))
        self.assertEqual(pins[0].dep, "nanohype/.github/actions/merge-gate")

    def test_a_local_action_is_not_a_pin(self):
        """`./` resolves inside this repo — there is no upstream to watch."""
        self.assertEqual(self.pins(self.steps({"uses": "./.github/actions/x"})), [])

    def test_a_container_step_is_not_a_pin(self):
        """`docker://image@digest` carries an `@` and is not an action reference.

        Admitted, it would put a pin in the population that no manager can claim
        — and the claim check would then report the repo unwatched for a step
        Renovate's github-actions manager never looks up as an action.
        """
        self.assertEqual(
            self.pins(self.steps({"uses": "docker://alpine@sha256:" + "0" * 64})), [])

    def test_a_step_with_no_uses_contributes_nothing(self):
        self.assertEqual(self.pins(self.steps({"run": "echo hi"})), [])

    def test_a_python_version_file_is_the_interpreter_pin(self):
        """setup-python installs what the file says, so the file is the pin."""
        pins = self.pins(
            self.steps({"uses": "actions/setup-python@" + "b" * 40,
                        "with": {"python-version-file": ".python-version"}}),
            {".python-version": "3.13\n"})
        interpreter = [p for p in pins if p.family == "Python interpreter"]
        self.assertEqual(len(interpreter), 1)
        self.assertEqual((interpreter[0].manager, interpreter[0].dep,
                          interpreter[0].version), ("pyenv", "python", "3.13"))

    def test_a_go_version_file_is_the_toolchain_pin(self):
        pins = self.pins(
            self.steps({"uses": "actions/setup-go@" + "c" * 40,
                        "with": {"go-version-file": "go.mod"}}),
            {"go.mod": "module x\n\ngo 1.26.3\n"})
        toolchain = [p for p in pins if p.family == "Go toolchain"]
        self.assertEqual([(p.manager, p.dep, p.version) for p in toolchain],
                         [("gomod", "go", "1.26.3")])

    def test_an_installed_lockfile_contributes_every_distribution(self):
        pins = self.pins(
            self.steps({"run": "pip install --require-hashes -r requirements.txt"}),
            {"requirements.txt": "pyyaml==6.0.2 \\\n    --hash=sha256:aa\nruff==0.9.1\n"})
        packages = sorted((p.dep, p.version) for p in pins
                          if p.family == "Python package")
        self.assertEqual(packages, [("pyyaml", "6.0.2"), ("ruff", "0.9.1")])

    def test_one_pin_resolved_by_many_steps_is_one_pin(self):
        """Twelve jobs asking for the same interpreter is one thing to watch."""
        step = {"uses": "actions/setup-python@" + "b" * 40,
                "with": {"python-version-file": ".python-version"}}
        pins = self.pins(self.steps(step, step, step), {".python-version": "3.13\n"})
        self.assertEqual(len([p for p in pins if p.family == "Python interpreter"]), 1)

    def test_a_version_file_that_does_not_exist_refuses_to_run(self):
        """What that step installs is unknown, which is not the same as unpinned."""
        with self.assertRaises(SystemExit) as caught, \
                contextlib.redirect_stdout(io.StringIO()):
            self.pins(self.steps({"with": {"python-version-file": ".gone"}}))
        self.assertEqual(caught.exception.code, cov.gatelib.CANNOT_RUN)

    def test_a_lockfile_with_no_pins_refuses_to_run(self):
        with self.assertRaises(SystemExit) as caught, \
                contextlib.redirect_stdout(io.StringIO()):
            self.pins(self.steps({"run": "pip install -r requirements.txt"}),
                      {"requirements.txt": "# nothing pinned here\n"})
        self.assertEqual(caught.exception.code, cov.gatelib.CANNOT_RUN)


class ClaimingEveryDerivedPin(unittest.TestCase):
    """Both directions, planted. Each fails for the opposite reason.

    An unclaimed pin ages with nothing watching it. A manager claiming nothing is
    config that reads as coverage: renovate-config-validator accepts it, the
    Dependency Dashboard shows no lookup for it, and the only symptom is a
    version that never moves.
    """

    def pin(self, manager="github-actions", family="GitHub Action",
            dep="actions/checkout", version="a" * 40):
        return cov.DerivedPin(family, manager, ".github/workflows/ci.yml",
                              f"uses: {dep}", dep, version)

    def verdict(self, pins, enabled, config=None):
        root = pathlib.Path(tempfile.mkdtemp())
        body = {"enabledManagers": list(enabled)}
        body.update(config or {})
        (root / "renovate.json").write_text(json.dumps(body))
        original, cov.ROOT = cov.ROOT, root
        cov.failures.clear()
        try:
            count = cov.check_derived_pins(pins)
        finally:
            cov.ROOT = original
        return count, list(cov.failures)

    def tearDown(self):
        cov.failures.clear()

    def test_a_claimed_pin_passes(self):
        count, failures = self.verdict([self.pin()], ["github-actions"])
        self.assertEqual(count, 1)
        self.assertEqual(failures, [])

    def test_a_pin_whose_manager_is_not_enabled_is_reported(self):
        """The `.python-version` shape: a real pin, and no manager reads the file."""
        _, failures = self.verdict(
            [self.pin(manager="pyenv", family="Python interpreter",
                      dep="python", version="3.13")],
            ["github-actions"])
        self.assertEqual(len(failures), 2)
        joined = " ".join(failures)
        self.assertIn("needs the pyenv manager, which renovate.json does not enable",
                      joined)
        self.assertIn("watched by nothing", joined)

    def test_a_manager_no_pin_claims_is_reported(self):
        _, failures = self.verdict([self.pin()], ["github-actions", "npm"])
        self.assertEqual(len(failures), 1)
        self.assertIn("enables the npm manager and no pin in this repo is attributed",
                      failures[0])

    def test_an_empty_manager_list_is_reported(self):
        _, failures = self.verdict([self.pin()], [])
        self.assertIn("declares no enabledManagers", failures[0])

    def test_deriving_no_pins_at_all_is_reported(self):
        """A verdict over an empty population reports what a healthy one reports."""
        _, failures = self.verdict([], ["github-actions"])
        self.assertEqual(len(failures), 1)
        self.assertIn("no toolchain pin was derived", failures[0])
        self.assertIn("vacuous", failures[0])

    def test_a_manager_with_no_default_patterns_and_no_config_is_reported(self):
        """pip-compile ships an empty defaultConfig.managerFilePatterns, so
        enabling it without configuring one adds a manager that reads nothing."""
        _, failures = self.verdict(
            [self.pin(manager="pip-compile", family="Python package",
                      dep="pyyaml", version="6.0.2")],
            ["pip-compile"])
        self.assertEqual(len(failures), 1)
        self.assertIn("configures no managerFilePatterns", failures[0])
        self.assertIn("watches nothing", failures[0])

    def test_configuring_the_patterns_clears_it(self):
        count, failures = self.verdict(
            [self.pin(manager="pip-compile", family="Python package",
                      dep="pyyaml", version="6.0.2")],
            ["pip-compile"],
            {"pip-compile": {"managerFilePatterns": ["/^requirements\\.txt$/"]}})
        self.assertEqual(failures, [])
        self.assertEqual(count, 1)

    def test_the_generic_managers_are_not_required_to_claim_a_derived_pin(self):
        """argocd reads chart pins and custom.regex the annotated env block; both
        are asserted over their own populations rather than this one."""
        _, failures = self.verdict([self.pin()],
                                   ["github-actions", "argocd", "custom.regex"])
        self.assertEqual(failures, [])


class TheShippedToolchainIsWatched(unittest.TestCase):
    """Over the tree, so a workflow edit that strands a pin fails here."""

    def test_every_derived_pin_is_claimed(self):
        cov.failures.clear()
        try:
            count = cov.check_derived_pins(cov.workflow_pins())
            self.assertEqual(cov.failures, [])
            self.assertGreater(count, 0)
        finally:
            cov.failures.clear()

    def test_the_interpreter_every_python_job_runs_on_is_a_derived_pin(self):
        pins = cov.workflow_pins()
        interpreter = [p for p in pins if p.family == "Python interpreter"]
        self.assertTrue(interpreter,
                        "no workflow step names a python-version-file, so the "
                        "interpreter every Python job runs on is outside this "
                        "gate's population")

    def test_every_action_the_workflows_use_is_a_derived_pin(self):
        """Counted against the files rather than a number, so a workflow added
        without its actions being claimed fails here."""
        seen = {p.dep for p in cov.workflow_pins() if p.family == "GitHub Action"}
        for wf in cov.workflow_files():
            doc = yaml.safe_load(wf.read_text())
            for step in cov._steps(doc):
                uses = step.get("uses")
                if not isinstance(uses, str) or uses.startswith("./"):
                    continue
                with self.subTest(uses=uses):
                    self.assertIn(uses.split("@", 1)[0], seen)


if __name__ == "__main__":
    unittest.main()
