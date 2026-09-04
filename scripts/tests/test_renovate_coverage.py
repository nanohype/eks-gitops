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
        self.managers = cov.load_custom_managers()
        self.assertTrue(self.managers, "no customManagers loaded — this suite "
                                       "would pass vacuously")

    def test_exact_chart_is_covered(self):
        self.assertIsNotNone(
            cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "1.2.3",
                                  self.managers)
        )

    def test_the_matching_manager_is_returned_not_a_yes(self):
        """Which manager matched decides whose file patterns have to reach the file.

        A boolean answers "some manager recognises this pin", and every reach
        assertion downstream would then have to pick a manager to ask about —
        which is the attribution this gate exists to stop accepting.
        """
        cm = cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "1.2.3",
                                   self.managers)
        self.assertIsInstance(cm, cov.CustomManager)
        self.assertIn(cm, self.managers)
        self.assertTrue(cm.file_patterns,
                        f"{cm.where} matched a pin and states no managerFilePatterns")

    def test_substring_chart_is_not_covered(self):
        self.assertIsNone(
            cov.covered_by_custom(self.PINNED_LONGER, "loki", "1.2.3", self.managers),
            "'loki' reported as covered by a 'loki-distributed' pin — a chart "
            "nothing watches would pass the gate",
        )

    def test_version_mismatch_is_not_covered(self):
        self.assertIsNone(
            cov.covered_by_custom(self.PINNED_LONGER, "loki-distributed", "9.9.9",
                                  self.managers)
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
            dep="actions/checkout", version="a" * 40,
            source=".github/workflows/ci.yml"):
        return cov.DerivedPin(family, manager, source, f"uses: {dep}", dep, version)

    def package(self, dep, version="1.0.0", source="requirements.txt"):
        """A distribution pin, which lives in the lockfile rather than the workflow."""
        return cov.DerivedPin("Python package", "pip-compile", source,
                              "pip install -r", dep, version)

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
        _, failures = self.verdict([self.package("pyyaml", "6.0.2")], ["pip-compile"])
        self.assertEqual(len(failures), 1)
        self.assertIn("has no file patterns at all", failures[0])
        self.assertIn("nothing looks the pin up", failures[0])

    def test_configuring_the_patterns_clears_it(self):
        count, failures = self.verdict(
            [self.package("pyyaml", "6.0.2")], ["pip-compile"],
            {"pip-compile": {"managerFilePatterns": ["/^requirements\\.txt$/"]}})
        self.assertEqual(failures, [])
        self.assertEqual(count, 1)

    def test_a_pattern_that_does_not_reach_the_pin_is_reported(self):
        """The manager is enabled, configured, and opens no file the pin is in.

        Every earlier assertion here is satisfied: pip-compile is on
        enabledManagers, it configures a managerFilePatterns, and the pattern is
        a valid regex. It names a path this repository does not have, so Renovate
        runs the manager, the manager opens nothing, and the pin is watched by
        no one — while a rule reading the manager's NAME reports it covered.
        """
        _, failures = self.verdict(
            [self.package("pyyaml", "6.0.2")], ["pip-compile"],
            {"pip-compile": {"managerFilePatterns": ["/^locks/requirements\\.txt$/"]}})
        self.assertEqual(len(failures), 1)
        self.assertIn("none of the managerFilePatterns it runs with reaches that file",
                      failures[0])

    def test_the_unreached_report_names_the_patterns_and_where_they_came_from(self):
        """Two different repairs, so the message has to say which one applies.

        A pattern this repository configures is fixed by editing renovate.json. A
        recorded default that stopped reaching is fixed upstream or by
        configuring one here, and the reader cannot tell those apart from the
        file name alone.
        """
        _, failures = self.verdict(
            [self.package("pyyaml", "6.0.2")], ["pip-compile"],
            {"pip-compile": {"managerFilePatterns": ["/^locks/requirements\\.txt$/"]}})
        self.assertIn("/^locks/requirements\\.txt$/", failures[0])
        self.assertIn("from renovate.json", failures[0])

        _, defaulted = self.verdict(
            [self.pin(source="tools/ci.yml")], ["github-actions"])
        self.assertEqual(len(defaulted), 1)
        self.assertIn("from the recorded default", defaulted[0])

    def test_repointing_one_manager_unwatches_every_pin_it_read(self):
        """The population is the file's, not one pin's.

        A lockfile carries every distribution a job installs, so one pattern
        deciding nothing reaches it takes all of them at once — which is why a
        spot check on a single pin cannot see this.
        """
        packages = [self.package(f"dist{i}", "1.0.0") for i in range(12)]
        _, failures = self.verdict(
            packages, ["pip-compile"],
            {"pip-compile": {"managerFilePatterns": ["/^locks/requirements\\.txt$/"]}})
        self.assertEqual(len(failures), 12)

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


class TheFilePatternForm(unittest.TestCase):
    """managerFilePatterns entries, read the way Renovate reads them.

    Renovate accepts two spellings in one list: `/regex/` and, for anything else,
    a minimatch glob. Both decide which files a manager opens, and a gate
    implementing one and guessing at the other would certify pins against a
    pattern it made up. So the unimplemented spelling stops the run by name.
    """

    def test_the_regex_form_compiles_and_anchors(self):
        rx = cov.compile_file_pattern(r"/^requirements\.txt$/")
        self.assertTrue(rx.search("requirements.txt"))
        self.assertFalse(rx.search("locks/requirements.txt"))

    def test_a_recorded_default_from_the_package_compiles(self):
        """The shipped github-actions pattern, which is the shape this gate has
        to read correctly for every action pin in the repository."""
        rx = cov.compile_file_pattern(
            r"/(^|/)(workflow-templates|\.(?:github|gitea|forgejo)/(?:workflows|actions))/.+\.ya?ml$/")
        self.assertTrue(rx.search(".github/workflows/ci.yml"))
        self.assertTrue(rx.search(".github/workflows/ci.yaml"))
        self.assertFalse(rx.search("tools/ci.yml"))

    def test_the_case_insensitive_flag_is_applied(self):
        self.assertTrue(cov.compile_file_pattern(r"/^GO\.MOD$/i").search("go.mod"))
        self.assertFalse(cov.compile_file_pattern(r"/^GO\.MOD$/").search("go.mod"))

    def _cannot_run(self, raw):
        with self.assertRaises(SystemExit) as caught, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            cov.compile_file_pattern(raw)
        self.assertEqual(caught.exception.code, cov.gatelib.CANNOT_RUN)
        return out.getvalue()

    def test_a_minimatch_glob_refuses_to_run(self):
        """Not a failure of the tree: which files that pattern reaches is unknown
        here, and answering it by treating the glob as a regex would certify pins
        against a matcher Renovate does not run."""
        self.assertIn("minimatch glob", self._cannot_run("**/*.yaml"))

    def test_an_unknown_flag_refuses_to_run(self):
        self.assertIn("does not implement", self._cannot_run(r"/^go\.mod$/m"))

    def test_an_re2_unsupported_construct_refuses_to_run(self):
        """RE2 has no lookahead, so Renovate opens no file with this pattern —
        and Python's re would happily match one, reporting reach that is not there."""
        self.assertIn("lookahead", self._cannot_run(r"/^(?=x)go\.mod$/"))

    def test_an_invalid_regex_refuses_to_run(self):
        self.assertIn("not a valid", self._cannot_run("/^go(\\.mod$/"))


class WhichPatternsAManagerRunsWith(unittest.TestCase):
    """Configured REPLACES default, and an unrecorded manager stops the run.

    Renovate does not merge a manager-level managerFilePatterns into the shipped
    default, it replaces it. A gate that unioned them would report reach through
    a default the deployment no longer uses.
    """

    def test_a_configured_pattern_replaces_the_default(self):
        found = cov.manager_file_patterns(
            {"gomod": {"managerFilePatterns": ["/^tools/go\\.mod$/"]}}, "gomod")
        self.assertEqual(found, cov.FilePatterns(["/^tools/go\\.mod$/"], "renovate.json"))
        self.assertNotIn(r"/(^|/)go\.mod$/", found.patterns)

    def test_configuring_nothing_falls_back_to_the_record(self):
        found = cov.manager_file_patterns({}, "gomod")
        self.assertEqual(found.origin, "the recorded default")
        self.assertEqual(found.patterns, [r"/(^|/)go\.mod$/"])

    def test_an_empty_configured_list_is_not_a_narrowing(self):
        """`managerFilePatterns: []` is not "this manager reads no file" — Renovate
        drops an empty list and runs the default, so reading it as a narrowing
        would report an unreachable pin the deployment actually watches."""
        self.assertEqual(cov.manager_file_patterns({"gomod": {"managerFilePatterns": []}},
                                                   "gomod").origin,
                         "the recorded default")

    def test_a_manager_absent_from_the_record_refuses_to_run(self):
        """"No pattern recorded" and "reads every file" are opposite answers and
        only one of them is safe to guess."""
        with self.assertRaises(SystemExit) as caught, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            cov.manager_file_patterns({}, "npm")
        self.assertEqual(caught.exception.code, cov.gatelib.CANNOT_RUN)
        self.assertIn("records no default for the npm manager", out.getvalue())

    def test_every_enabled_manager_is_resolvable(self):
        """Over the shipped config, so enabling a manager without recording its
        default fails here rather than at the next run of the gate."""
        cfg = json.loads((ROOT / "renovate.json").read_text())
        for manager in cfg["enabledManagers"]:
            if manager == "custom.regex":     # each customManager states its own
                continue
            with self.subTest(manager=manager):
                self.assertTrue(cov.manager_file_patterns(cfg, manager).patterns,
                                f"{manager} runs with no file pattern at all")


class ReachIsAsserted(unittest.TestCase):
    """A manager's name on enabledManagers is attribution; reach is the property.

    managerFilePatterns decides which files a manager opens. A pattern naming a
    path this repository does not have is valid config that opens nothing: the
    schema is fine so renovate-config-validator passes, no lookup is attempted so
    the Dependency Dashboard reports no failure, and the only symptom is a
    version that stops moving.
    """

    def setUp(self):
        cov.failures.clear()
        self.addCleanup(cov.failures.clear)
        for tally in (cov.reach_configured, cov.reach_recorded):
            tally.clear()
            self.addCleanup(tally.clear)

    def test_a_pattern_that_reaches_the_file_certifies(self):
        cov.assert_reach("gomod", cov.FilePatterns([r"/(^|/)go\.mod$/"], "renovate.json"),
                         "applicationsets/rendertest/go.mod", "Go module pin x v1")
        self.assertEqual(cov.failures, [])

    def test_a_pattern_that_does_not_reach_the_file_fails(self):
        cov.assert_reach("gomod", cov.FilePatterns([r"/^go\.mod$/"], "renovate.json"),
                         "applicationsets/rendertest/go.mod", "Go module pin x v1")
        self.assertEqual(len(cov.failures), 1)
        self.assertIn("none of the managerFilePatterns it runs with reaches that file",
                      cov.failures[0])

    def test_an_empty_pattern_set_fails_with_no_pattern_to_point_at(self):
        """argocd and pip-compile both ship one, so this is a live shape."""
        cov.assert_reach("pip-compile", cov.FilePatterns([], "the recorded default"),
                         "requirements.txt", "Python package pyyaml 6.0.2")
        self.assertEqual(len(cov.failures), 1)
        self.assertIn("has no file patterns at all", cov.failures[0])

    def test_the_tally_records_where_the_matching_pattern_came_from(self):
        """Printed on every run, split two ways. A pattern this repository
        configures is a decision made here; a recorded default moves when
        Renovate does, without this repository changing."""
        cov.assert_reach("a", cov.FilePatterns(["/^x$/"], "renovate.json"), "x", "pin")
        cov.assert_reach("b", cov.FilePatterns(["/^y$/"], "the recorded default"),
                         "y", "pin")
        self.assertEqual(cov.reach_configured, [("a", "x")])
        self.assertEqual(cov.reach_recorded, [("b", "y")])

    def test_a_failing_reach_is_not_tallied_as_coverage(self):
        cov.assert_reach("a", cov.FilePatterns(["/^x$/"], "renovate.json"), "z", "pin")
        self.assertEqual(cov.reach_configured, [])
        self.assertEqual(cov.reach_recorded, [])


class RepointingAnyManagerInTheShippedConfig(unittest.TestCase):
    """Over the real tree, one manager at a time, from the config rather than a list.

    The property is that no single manager can be pointed at a file this
    repository does not have and still leave the gate green. Enumerated from
    renovate.json so a manager added later is covered without an edit here — a
    hand-written list of managers to try is the same defect one layer up.
    """

    def setUp(self):
        self.cfg = json.loads((ROOT / "renovate.json").read_text())
        cov.failures.clear()
        self.addCleanup(cov.failures.clear)
        for tally in (cov.reach_configured, cov.reach_recorded):
            tally.clear()
            self.addCleanup(tally.clear)

    def run_with(self, cfg):
        """main() over the real tree, reading `cfg` in place of renovate.json."""
        real = cov.gatelib.read_json

        def reading(path):
            if str(path).endswith("renovate.json"):
                return json.loads(json.dumps(cfg))
            return real(path)

        cov.gatelib.read_json = reading
        cov.failures.clear()
        cov.reach_configured.clear()
        cov.reach_recorded.clear()
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = cov.main()
        finally:
            cov.gatelib.read_json = real
        return rc, out.getvalue()

    # A path no file in this repository has, so a manager pointed here opens
    # nothing while every other manager still matches what it always did.
    NOWHERE = "/^no/such/directory/[^/]+$/"

    def test_the_shipped_config_passes(self):
        """The control. Without it every mutation below could be failing for a
        reason the mutation did not introduce, and the sweep would read as proof."""
        rc, _ = self.run_with(self.cfg)
        self.assertEqual(rc, 0, f"unmutated run failed: {cov.failures}")

    def test_repointing_any_configured_manager_is_caught(self):
        blocks = [k for k, v in self.cfg.items()
                  if isinstance(v, dict) and "managerFilePatterns" in v]
        self.assertTrue(blocks, "no manager block configures managerFilePatterns — "
                                "this test would sweep nothing")
        for manager in blocks:
            with self.subTest(manager=manager):
                cfg = json.loads(json.dumps(self.cfg))
                cfg[manager]["managerFilePatterns"] = [self.NOWHERE]
                rc, _ = self.run_with(cfg)
                self.assertEqual(rc, 1)
                self.assertTrue(
                    any("reaches that file" in f for f in cov.failures),
                    f"{manager} repointed at nothing and the gate did not say so: "
                    f"{cov.failures}")

    def test_repointing_any_custom_manager_is_caught(self):
        """Each one separately: repointing all five at once is a failure any
        pooled check would also catch, while repointing one leaves every other
        manager matching and is the shape a pooled check reports as covered."""
        self.assertTrue(self.cfg["customManagers"])
        for i in range(len(self.cfg["customManagers"])):
            with self.subTest(customManager=i):
                cfg = json.loads(json.dumps(self.cfg))
                cfg["customManagers"][i]["managerFilePatterns"] = [self.NOWHERE]
                rc, _ = self.run_with(cfg)
                self.assertEqual(rc, 1)
                self.assertTrue(
                    any("reaches that file" in f for f in cov.failures),
                    f"customManagers[{i}] repointed at nothing and the gate did not "
                    f"say so: {cov.failures}")

    def test_repointing_a_manager_that_rests_on_its_recorded_default_is_caught(self):
        """The managers with no block in renovate.json are covered by the record,
        and configuring one is how a repository narrows what it reads — so the
        same mistake is available to them and is caught the same way."""
        resting = [m for m in self.cfg["enabledManagers"]
                   if m != "custom.regex" and m not in self.cfg]
        self.assertTrue(resting, "every enabled manager configures its own patterns — "
                                 "this test would sweep nothing")
        for manager in resting:
            with self.subTest(manager=manager):
                cfg = json.loads(json.dumps(self.cfg))
                cfg[manager] = {"managerFilePatterns": [self.NOWHERE]}
                rc, _ = self.run_with(cfg)
                self.assertEqual(rc, 1)
                self.assertTrue(
                    any("reaches that file" in f for f in cov.failures),
                    f"{manager} repointed at nothing and the gate did not say so: "
                    f"{cov.failures}")


class TheAppsetCorpusReadsBothSpellings(unittest.TestCase):
    """`.yml` and `.yaml` are one corpus, to Renovate and to ArgoCD.

    A walk reading one spelling leaves the other applied to every cluster and in
    no population this gate builds — including the literal floor under the walk,
    which read the same directory the same way and so could not see the gap.
    """

    def test_every_yaml_file_in_the_directory_is_in_the_corpus(self):
        found = set(cov.appset_files())
        for path in (ROOT / "applicationsets").iterdir():
            if path.is_file() and path.suffix in {".yaml", ".yml"}:
                with self.subTest(path=path.name):
                    self.assertIn(path, found)

    def test_a_short_extension_file_is_read(self):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "applicationsets").mkdir()
        for name in ("a.yaml", "b.yml", "c.txt"):
            (root / "applicationsets" / name).write_text("")
        original = cov.APPSETS
        cov.APPSETS = root / "applicationsets"
        try:
            self.assertEqual([p.name for p in cov.appset_files()], ["a.yaml", "b.yml"])
        finally:
            cov.APPSETS = original

    def test_a_missing_directory_refuses_to_run(self):
        original = cov.APPSETS
        cov.APPSETS = pathlib.Path(tempfile.mkdtemp()) / "gone"
        try:
            with self.assertRaises(SystemExit) as caught, \
                    contextlib.redirect_stdout(io.StringIO()):
                cov.appset_files()
            self.assertEqual(caught.exception.code, cov.gatelib.CANNOT_RUN)
        finally:
            cov.APPSETS = original


class AJobThatCallsAWorkflowIsAPin(unittest.TestCase):
    """A reusable-workflow reference sits on the job, not on a step.

    A step walker reaches none of them, and a guard sharing that walker inherits
    the same blind spot and reports the population as complete — which is why
    this walks the jobs itself rather than reusing _steps.
    """

    def test_a_called_workflow_is_yielded(self):
        doc = {"jobs": {"gate": {"uses": "nanohype/.github/.github/workflows/x.yml@v1"}}}
        self.assertEqual(list(cov._called_workflows(doc)),
                         [("gate", "nanohype/.github/.github/workflows/x.yml@v1")])

    def test_the_step_walker_does_not_see_it(self):
        """Stated as a test because it is the reason the second walk exists."""
        doc = {"jobs": {"gate": {"uses": "owner/repo/.github/workflows/x.yml@v1"}}}
        self.assertEqual(list(cov._steps(doc)), [])

    def test_a_job_running_steps_is_not_a_called_workflow(self):
        doc = {"jobs": {"a": {"runs-on": "ubuntu-latest", "steps": [{"run": "x"}]}}}
        self.assertEqual(list(cov._called_workflows(doc)), [])

    def test_a_called_workflow_becomes_a_derived_pin(self):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(yaml.safe_dump(
            {"jobs": {"gate": {"uses": "owner/repo/.github/workflows/x.yml@v1.2.3"}}}))
        original, cov.ROOT = cov.ROOT, root
        try:
            pins = cov.workflow_pins()
        finally:
            cov.ROOT = original
        self.assertEqual([(p.family, p.manager, p.dep, p.version) for p in pins],
                         [("Reusable workflow", "github-actions",
                           "owner/repo/.github/workflows/x.yml", "v1.2.3")])

    def test_every_called_workflow_in_this_repo_is_a_derived_pin(self):
        seen = {p.dep for p in cov.workflow_pins()}
        for wf in cov.workflow_files():
            doc = yaml.safe_load(wf.read_text())
            for job_id, uses in cov._called_workflows(doc):
                if uses.startswith("./"):
                    continue
                with self.subTest(job=job_id):
                    self.assertIn(uses.split("@", 1)[0], seen)


class AVersionFileRuntimeNobodyWroteAReaderFor(unittest.TestCase):
    """`<runtime>-version-file` is recognised by shape, so an unknown one is seen.

    A list of keys would make a step pinning a runtime nobody wrote a key for
    invisible, which reports the same as a repository that pins nothing. Seen
    and unattributable is a different answer from absent, and it stops the run.
    """

    def workspace(self, with_):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(yaml.safe_dump(
            {"jobs": {"a": {"runs-on": "ubuntu-latest",
                            "steps": [{"uses": "actions/setup-x@" + "a" * 40,
                                       "with": with_}]}}}))
        (root / ".ruby-version").write_text("3.4.1\n")
        return root

    def test_an_unrecognised_runtime_refuses_to_run(self):
        """A runtime this repository does not pin, so no reader names it.

        Which runtime is incidental — the point is that the KEY is recognised by
        shape and the runtime is not, so the step is seen and unattributable
        rather than invisible. Every runtime in VERSION_FILE_RUNTIMES is a
        runtime some workflow here installs; one that stops being installed is
        removed with its reader, and this case keeps holding.
        """
        original, cov.ROOT = cov.ROOT, self.workspace(
            {"ruby-version-file": ".ruby-version"})
        try:
            with self.assertRaises(SystemExit) as caught, \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                cov.workflow_pins()
        finally:
            cov.ROOT = original
        self.assertEqual(caught.exception.code, cov.gatelib.CANNOT_RUN)
        self.assertIn("which Renovate manager reads a ruby version file is not known",
                      out.getvalue())

    SOURCES = {
        "python": (".python-version", "3.13\n"),
        "go": ("go.mod", "module x\n\ngo 1.26.3\n"),
        "node": (".node-version", "24.20.0\n"),
    }

    def test_every_runtime_with_a_reader_attributes_to_an_enabled_manager(self):
        """Enumerated from the mapping, so a runtime added later is covered here.

        A reader naming a manager renovate.json does not enable derives a pin
        nothing claims. That fails, but one layer down and with a message about
        the pin — the reader is where the wrong name was written.
        """
        enabled = set(json.loads((ROOT / "renovate.json").read_text())["enabledManagers"])
        self.assertEqual(set(cov.VERSION_FILE_RUNTIMES), set(self.SOURCES),
                         "a runtime gained or lost a reader and this case did not "
                         "gain or lose the file it reads")
        root = pathlib.Path(tempfile.mkdtemp())
        original, cov.ROOT = cov.ROOT, root
        try:
            for runtime, reader in sorted(cov.VERSION_FILE_RUNTIMES.items()):
                rel, body = self.SOURCES[runtime]
                (root / rel).write_text(body)
                with self.subTest(runtime=runtime):
                    pins = reader(".github/workflows/ci.yml", rel)
                    self.assertEqual(len(pins), 1)
                    self.assertIn(pins[0].manager, enabled,
                                  f"the {runtime} reader attributes its pin to the "
                                  f"{pins[0].manager} manager, which renovate.json "
                                  f"does not enable")
                    self.assertEqual(pins[0].source, rel)
        finally:
            cov.ROOT = original

    def test_a_recognised_runtime_is_read(self):
        """The same shape, one runtime along, so the refusal above is about the
        runtime rather than about the key being read at all."""
        root = self.workspace({"python-version-file": ".python-version"})
        (root / ".python-version").write_text("3.13\n")
        original, cov.ROOT = cov.ROOT, root
        try:
            pins = cov.workflow_pins()
        finally:
            cov.ROOT = original
        self.assertIn(("Python interpreter", "3.13"),
                      [(p.family, p.version) for p in pins])


class TheNonChartPinFamilies(unittest.TestCase):
    """The git-pinned CRDs, the CI tool binaries and the Go module.

    Each was watched by a manager nothing asserted, so deleting one left the gate
    printing the same success over a smaller repository.
    """

    ANNOTATED_CI = (
        "env:\n"
        "  # renovate: datasource=github-releases depName=kyverno/kyverno\n"
        "  KYVERNO_VERSION: \"1.18.2\"\n"
    )

    CRDS = ("        repoURL: https://github.com/kubernetes-sigs/gateway-api\n"
            "        targetRevision: v1.2.1\n")

    GOMOD = "module x\n\ngo 1.26.3\n\nrequire (\n\tgithub.com/x/y v1.2.3\n)\n"

    def workspace(self, cfg, ci=None, crds=None, gomod=None, no_pins=True):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "renovate.json").write_text(json.dumps(cfg))
        for rel, body in ((".github/workflows/ci.yml", ci if ci is not None else self.ANNOTATED_CI),
                          ("applicationsets/gateway-api-crds.yaml",
                           crds if crds is not None else self.CRDS),
                          ("applicationsets/rendertest/go.mod",
                           gomod if gomod is not None else self.GOMOD)):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        if no_pins:
            for rel in cov.NO_PINS:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("spec: {}\n")
        return root

    def verdict(self, root, custom_managers=None):
        original, cov.ROOT = cov.ROOT, root
        cov.failures.clear()
        for tally in (cov.reach_configured, cov.reach_recorded):
            tally.clear()
        try:
            managers = (cov.load_custom_managers() if custom_managers is None
                        else custom_managers)
            seen = cov.check_other_families(managers)
        finally:
            cov.ROOT = original
        failures = list(cov.failures)
        cov.failures.clear()
        return seen, failures

    def config(self, **over):
        cfg = json.loads((ROOT / "renovate.json").read_text())
        cfg.update(over)
        return cfg

    def test_the_three_families_are_each_counted(self):
        seen, failures = self.verdict(self.workspace(self.config()))
        self.assertEqual(failures, [])
        self.assertEqual(seen, 3)

    def test_a_family_whose_file_is_gone_is_reported(self):
        root = self.workspace(self.config())
        (root / "applicationsets" / "gateway-api-crds.yaml").unlink()
        _, failures = self.verdict(root)
        self.assertEqual(len(failures), 1)
        self.assertIn("the reference outlived the file", failures[0])

    def test_a_family_whose_shape_is_gone_is_vacuous_not_clean(self):
        """The file is there and carries no pin the regex knows. Passing over it
        would report the family covered while nothing in it was examined."""
        _, failures = self.verdict(self.workspace(self.config(), crds="spec: {}\n"))
        self.assertEqual(len(failures), 1)
        self.assertIn("coverage claim over that family is vacuous", failures[0])

    def test_the_go_module_needs_the_gomod_manager_enabled(self):
        cfg = self.config()
        cfg["enabledManagers"] = [m for m in cfg["enabledManagers"] if m != "gomod"]
        _, failures = self.verdict(self.workspace(cfg))
        self.assertEqual(len(failures), 1)
        self.assertIn("gomod manager is not in renovate.json's enabledManagers",
                      failures[0])

    def test_the_go_module_needs_gomods_patterns_to_reach_go_mod(self):
        """Enabled and unreached: the manager runs, opens no such file, and the
        config reads as coverage."""
        _, failures = self.verdict(self.workspace(
            self.config(gomod={"managerFilePatterns": ["/^go\\.mod$/"]})))
        self.assertEqual(len(failures), 1)
        self.assertIn("reaches that file", failures[0])

    def test_a_crd_pin_no_custom_manager_matches_is_reported(self):
        cfg = self.config()
        cfg["customManagers"] = [m for m in cfg["customManagers"]
                                 if "gateway-api" not in json.dumps(m)]
        _, failures = self.verdict(self.workspace(cfg))
        self.assertEqual(len(failures), 1)
        self.assertIn("matched by no customManager", failures[0])

    def test_a_crd_pin_whose_manager_cannot_reach_the_file_is_reported(self):
        cfg = self.config()
        for m in cfg["customManagers"]:
            if "gateway-api" in json.dumps(m):
                m["managerFilePatterns"] = ["/^no/such/file$/"]
        _, failures = self.verdict(self.workspace(cfg))
        self.assertEqual(len(failures), 1)
        self.assertIn("reaches that file", failures[0])

    def test_a_file_asserted_to_pin_nothing_that_carries_one_is_reported(self):
        root = self.workspace(self.config())
        (root / cov.NO_PINS[0]).write_text("        targetRevision: v1.2.3\n")
        _, failures = self.verdict(root)
        self.assertEqual(len(failures), 1)
        self.assertIn("asserted to pin nothing", failures[0])

    def test_a_file_asserted_to_pin_nothing_that_is_gone_is_reported(self):
        root = self.workspace(self.config(), no_pins=False)
        _, failures = self.verdict(root)
        self.assertEqual(len(failures), len(cov.NO_PINS))
        self.assertTrue(all("does not exist" in f for f in failures))


class EveryCiToolPinCarriesItsOwnAnnotation(unittest.TestCase):
    """Renovate reads a `# renovate:` comment as a property of the line below it.

    A file-level comment would silently adopt every version added afterwards, and
    a pin with no comment at all is watched by nothing — which is exactly the pin
    a rule keyed on the annotation cannot see.
    """

    def setUp(self):
        self.managers = cov.load_custom_managers()
        cov.failures.clear()
        self.addCleanup(cov.failures.clear)
        for tally in (cov.reach_configured, cov.reach_recorded):
            tally.clear()
            self.addCleanup(tally.clear)

    def verdict(self, text, managers=None):
        hits = list(next(rx for label, _, rx in cov.OTHER_FAMILIES
                         if label == "CI tool binary").finditer(text))
        count = cov.check_ci_tool_pins(text, ".github/workflows/ci.yml", hits,
                                       self.managers if managers is None else managers)
        return count, list(cov.failures)

    ANNOTATED = ("  # renovate: datasource=github-releases depName=kyverno/kyverno\n"
                 "  KYVERNO_VERSION: \"1.18.2\"\n")

    def test_an_annotated_and_reached_pin_passes(self):
        count, failures = self.verdict(self.ANNOTATED)
        self.assertEqual((count, failures), (1, []))

    def test_an_unannotated_pin_is_reported(self):
        _, failures = self.verdict("  KYVERNO_VERSION: \"1.18.2\"\n")
        self.assertEqual(len(failures), 1)
        self.assertIn("no `# renovate:` annotation", failures[0])

    def test_one_annotation_covers_one_pin(self):
        """A second pin under the same comment is watched by nothing.

        Renovate's matchString consumes the annotation together with the pin that
        follows it, so a comment at the top of the block does not adopt the rest
        of it. A gate keyed on the annotation alone would report the whole block
        covered, which is the reading that leaves the un-annotated pin invisible.
        """
        count, failures = self.verdict(
            self.ANNOTATED + "  GITLEAKS_VERSION: \"8.28.0\"\n")
        self.assertEqual(count, 2)
        self.assertEqual(len(failures), 1)
        self.assertIn("GITLEAKS_VERSION", failures[0])
        self.assertIn("no `# renovate:` annotation", failures[0])

    def test_an_annotated_pin_no_custom_manager_matches_is_reported(self):
        _, failures = self.verdict(self.ANNOTATED, managers=[])
        self.assertEqual(len(failures), 1)
        self.assertIn("matched by no customManager", failures[0])

    def test_an_annotated_pin_whose_manager_cannot_reach_ci_yml_is_reported(self):
        repointed = [cm._replace(file_patterns=["/^no/such/file$/"])
                     for cm in self.managers]
        _, failures = self.verdict(self.ANNOTATED, managers=repointed)
        self.assertEqual(len(failures), 1)
        self.assertIn("reaches that file", failures[0])


if __name__ == "__main__":
    unittest.main()
