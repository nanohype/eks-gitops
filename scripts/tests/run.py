#!/usr/bin/env python3
"""Run the gate-script tests and refuse to pass over an empty corpus.

`python -m unittest discover` returns success when it discovers nothing on
interpreters before 3.12, and the suite's own fail-closed behaviour would then
be a property of whichever interpreter the runner happens to ship rather than of
the suite. A test directory that stops matching — renamed files, a moved
directory, a changed pattern — reports the same success as a passing run.

Two assertions close that:

  * every module named in EXPECTED is importable, so deleting or renaming one
    fails rather than silently shrinking coverage
  * at least MIN_TESTS tests actually execute

Both are floors, not exact counts: adding tests must never require editing
either, or the floor becomes something people lower to make a run go green.
The coverage bounds below hold to the same rule: adding a test never requires
an edit here, and adding a gate no test executes fails the run that adds it.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import math
import os
import pathlib
import sys
import unittest
from typing import NamedTuple

HERE = pathlib.Path(__file__).resolve().parent

# The directory `coverage run` started in, read before any test can change it.
# Coverage names each file in its report relative to that directory.
STARTED_IN = pathlib.Path.cwd()

# Named rather than counted. A module that disappears takes its assertions with
# it, and nothing else in the suite would notice.
EXPECTED = (
    "test_renovate_coverage",
    "test_renovate_defaults",
    "test_label_values",
    "test_sync_waves",
    "test_kyverno_corpus",
    "test_named_things",
    "test_falco_rule_floor",
    "test_alert_severity_routes",
    "test_gatelib",
    # The registry client every chart and OCI artifact is read through: which
    # statuses it retries, answers or reports, and the digest each archive is
    # checked against when it is fetched and again when the cache hands it out.
    "test_registry",
    # The harness layer. controls.py excuses the harnesses from carrying a
    # positive control because each asserts its own outcome when it runs, and
    # the reader deciding whether anything runs them is covered nowhere else.
    "test_controls",
    # The gates the positive-control sweep exempts, because they reach a chart
    # registry or an API. A control cannot be written for them, so a unit test on
    # the half that decides the verdict is the only thing that proves they say
    # anything.
    "test_policy_admission",
    # The signing-identity contract. Its positive control proves it rejects one
    # rewrite; these prove it rejects each weakening that both kyverno fixtures
    # still satisfy, and hold the trusted subject expression to a corpus.
    "test_image_verification",
    # What the policy-validity gate reads out of `kyverno apply`, which exits 0
    # over a policy it discarded, and the digest pin it holds every rendered
    # ImageValidatingPolicy to.
    "test_policy_validity",
    "test_platform_crs",
    "test_dashboards",
    "test_render_addons",
    "test_image_pins",
    "test_log_volume_budget",
    # Every verdict on the signature-verification path that the digest-rewrite
    # gate and the Kyverno suite's runner reach, in the one module both scripts
    # ask: a transport failure, a run its time bound ended or killed, a
    # refusal's cause, an identity outcome and a digest pin, each read to the
    # exit status the script acts on.
    "test_verdicts",
    # How the Kyverno suite's runner acts on what verdicts.py reads out of a
    # run: a run repeated and then one that could not verify, never a verdict,
    # and a reading that could not be reached is never a pass.
    "test_kyverno_test",
    # The digest-rewrite gate's steps against a stubbed kubectl: each refusal
    # handed to verdicts.py with the window the verifier's log is read from, the
    # log read only when the refusal alone decides nothing, and a bound on every
    # step, all without the cluster it runs on in CI.
    "test_digest_rewrite",
    # The image population both image gates read, and the acknowledgement file
    # the vulnerability verdict is decided against. One walk answers every
    # question either gate asks, so an extractor that stops seeing a shape
    # removes those images from all of them at once.
    "test_image_extraction",
    "test_image_vulnerabilities",
    # The floors that keep an emptied corpus from reading as a clean one,
    # asserted apart from the gates that carry them.
    "test_corpus_floors",
    # The arithmetic behind a figure an on-call reads at the worst moment, and
    # the anchoring that keeps it from being a constant compared to nothing.
    "test_burn_rate_budgets",
    # A name restated in eleven places, and the two readers it takes to find
    # them all — half the corpus is chart source that does not parse as YAML.
    "test_secret_store_refs",
    # The source-type decision that says which sources a size limit even applies
    # to, and the byte accounting the repo-server does once it has decided.
    "test_directory_manifest_size",
    # The walk that derives which inputs decide a load balancer's scheme, and the
    # two verdicts that make an input nobody thought about visible.
    "test_lb_scheme_inputs",
    # The scheduled provenance check: the sentence a failed chart read becomes in
    # the live verdict, the offline verdict, and what --sync records from
    # upstream. The read itself is registry.py's, held in test_registry.
    "test_chart_deprecation",
    # What a failed schema scan leaves in the log: kubeconform's own output, the
    # status it exited with, and the catalog commits the run read.
    "test_kubeconform_scan",
    # The workflows as YAML: a timeout on every job, a bound on every download,
    # and the conditions deciding which key the chart cache is kept under.
    "test_workflows",
    # The AI control plane held to llm-policy and to itself: model ids Bedrock
    # accepts, routes IAM allows, and a budget the kill switch can act on.
    "test_ai_config",
    # An alert guarding `!= 0` and the rule in its group reporting the zero it
    # excludes, which only `== bool 0` does.
    "test_alert_coverage",
    # Which identifiers in an Athena panel's SQL are columns, held to the ones
    # the CUR export delivers.
    "test_athena_panel_columns",
    # A source reading the catalog's URL from the cluster Secret reads its
    # revision from there too.
    "test_catalog_revision",
    # The environments a cluster selector reaches, and a values file for each.
    "test_env_coverage",
    # One remote reference per ExternalSecret, patched by the appset rendering
    # its directory and by no other.
    "test_externalsecret_keys",
    # The ServiceAccounts a chart's pods run as and the ones it creates, held to
    # one set in both directions.
    "test_serviceaccount_bindings",
)

# A floor well under the real count. It catches "discovery found almost nothing",
# not "somebody removed one test".
MIN_TESTS = 31

# THE ASSERTION THAT IS NOT A NUMBER
#
# Every gate carries at least one kind of proof that it says something:
#
#   * a positive control in controls.py, which supplies the violation the gate
#     names and requires a rejection; or
#   * unit tests over the decision that produces the verdict.
#
# A gate with neither has been read by nobody and asserts nothing that anything
# has checked. controls.py exempts every gate that reaches a chart registry or an
# API, since a control cannot be written for a gate whose input arrives over the
# network, and for exactly those a unit test is the only proof available.
#
# check_coverage fails on any Python file in scripts/ that the suite never
# executes, so a gate arrives with tests or fails the run that adds it. It reads
# the exemption list out of controls.py rather than repeating it
# (`control_exempt_gates` below), names an exempt gate the suite never executes
# apart from the rest, and fails on an exempt gate with no floor of its own in
# PER_GATE_FLOORS. "Executed" is coverage's reading, and coverage cannot tell a
# test from an import: a gate a test module only loads, to read a constant,
# executes its module body with no assertion of its own. The per-file floors are
# what hold the half of a gate that decides its verdict covered.
#
# testing-rubric's `security-critical-100` (severity: reject) asks for a per-file
# 100% override on every file on a security-critical path. These sit on one:
# check-policy-admission.py is an approval gate, deciding whether the fleet is
# admissible at Enforce; check-image-verification.py holds the signature-
# verification contract; check-policy-validity.py holds every rendered
# ImageValidatingPolicy to the digest pin that verification depends on; and
# verdicts.py decides what each refusal, run and time bound on the verification
# path in check-digest-rewrite.sh and kyverno-test.sh established. Each carries
# 100 lines and 100 branches in PER_GATE_FLOORS, so a branch added to any of
# them without a test fails this run rather than lowering a ratchet.

# testing-rubric's content.coverage_floor over the gate scripts, enforced when
# `coverage` is collecting. Statements and branches are measured apart, each
# against its own floor: a combined figure averages one over the other, so a
# branch shortfall hides behind line coverage and the reverse. coverage.py counts
# statements and branches, so the rubric's lines and statements floors both read
# its statement count, and its functions floor has no counterpart here. Both
# figures come from coverage's JSON report. Read the standing with
#
#     COVERAGE_REQUIRED=1 coverage run --rcfile=.coveragerc scripts/tests/run.py
#     coverage report --rcfile=.coveragerc --include="scripts/*.py"
#
# What neither figure captures: scripts/tests/controls.py runs every gate it does
# not exempt end to end as a subprocess against a mutated tree, so those gates
# have behavioural coverage this count cannot see. The controls prove a gate
# rejects; the unit tests prove it computes the right verdict on a case the real
# tree does not contain; neither substitutes for the other. The gates controls.py
# exempts have no behavioural coverage, so for them the unit figure is the whole
# of the evidence, which is why each must carry a floor in PER_GATE_FLOORS.
LINE_FLOOR = 75
BRANCH_FLOOR = 60

# Per-file (lines, branches) floors, in percent. Below 100 each is a ratchet set
# just under what the suite reaches, so a covered file cannot regress silently,
# and raising one is what lands with the tests that earn it. A file with no
# branches reads as covering all of them.
PER_GATE_FLOORS: dict[str, tuple[int, int]] = {
    "scripts/check-named-things.py": (42, 34),
    "scripts/check-renovate-coverage.py": (90, 84),
    "scripts/check-label-values.py": (56, 54),
    "scripts/check-sync-waves.py": (14, 1),
    "scripts/gatelib.py": (73, 80),
    # The registry client checks every chart archive against a digest and
    # handles a pull token. That is signature verification's path in the sense
    # testing-rubric's `security-critical-100` uses, so its floor is that rule's
    # 100 rather than a ratchet: a branch no test reaches here is a check that
    # nothing proves still checks.
    "scripts/registry.py": (100, 100),
    # The security-critical files, at the rubric's per-file override; see
    # THE ASSERTION THAT IS NOT A NUMBER above.
    "scripts/check-policy-admission.py": (100, 100),
    "scripts/check-image-verification.py": (100, 100),
    "scripts/check-policy-validity.py": (100, 100),
    "scripts/verdicts.py": (100, 100),
    # The control-exempt gates. Their floors are what keeps the verdict half
    # covered after the module that covers it is edited.
    "scripts/check-platform-crs.py": (51, 51),
    "scripts/validate-dashboards.py": (52, 49),
    "scripts/render-addons.py": (67, 56),
    "scripts/check-log-volume-budget.py": (65, 59),
    "scripts/check-falco-rule-floor.py": (58, 33),
    "scripts/check-alert-severity-routes.py": (96, 90),
    "scripts/check-image-vulnerabilities.py": (76, 70),
    "scripts/check-image-pins.py": (91, 85),
    # The half of the directory-size gate that decides the verdict. The rest is
    # `--sync`, `--live` and `--self-test`, which run against a clone.
    "scripts/check-directory-manifest-size.py": (68, 71),
    # The Go reading and the offline verdict. `--sync`, `--live` and the chart
    # render reach the network and are covered by stubbing what they return.
    "scripts/check-lb-scheme-inputs.py": (69, 73),
    # Both verdicts over stubbed reads, --sync and --self-test.
    "scripts/check-chart-deprecation.py": (86, 80),
}


def main() -> int:
    missing = [m for m in EXPECTED if not (HERE / f"{m}.py").exists()]
    if missing:
        print(f"FAIL  expected test modules are absent: {', '.join(missing)} — "
              f"coverage was removed without the suite failing.")
        return 1

    suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    if result.testsRun < MIN_TESTS:
        print(f"FAIL  only {result.testsRun} tests ran, expected at least "
              f"{MIN_TESTS} — discovery is matching almost nothing, which passes "
              f"on some interpreters and proves nothing on any.")
        return 1
    if not result.wasSuccessful():
        return 1

    print(f"gate-script tests OK: {result.testsRun} tests across "
          f"{len(EXPECTED)} modules")
    return check_coverage()


def control_exempt_gates() -> tuple[list[str], str]:
    """Python gates controls.py exempts from a positive control, and why it might not.

    Read out of controls.py rather than repeated here. A second copy of an
    exemption list is a copy that drifts, and the direction it drifts is
    permissive: the gate added to one list and not the other is excused by both.

    A list that cannot be read is reported rather than treated as empty — an
    empty exemption set makes the assertion above vacuously true, which is the
    shape this whole suite exists to reject.
    """
    path = HERE / "controls.py"
    try:
        spec = importlib.util.spec_from_file_location("controls", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules["controls"] = module
        spec.loader.exec_module(module)
        exempt = sorted(module.NEEDS_NETWORK_PY)
    except Exception as exc:                    # noqa: BLE001 — reported, not raised
        return [], (f"{path.name} could not be read for its control exemptions "
                    f"({type(exc).__name__}: {exc}), so no gate could be checked for "
                    f"having neither kind of proof")
    if not exempt:
        return [], (f"{path.name} exempts no gate from a positive control, so the "
                    f"assertion that every exempt gate carries unit tests holds over "
                    f"an empty set and states nothing")
    return exempt, ""


def percent(covered: int, total: int) -> float:
    return 100.0 if total == 0 else 100.0 * covered / total


def shown(pct: float) -> str:
    """`pct` cut, not rounded, to one decimal, so a figure short of its floor
    never prints as reaching it."""
    return f"{math.floor(pct * 10) / 10:.1f}%"


class Figures(NamedTuple):
    """Covered and total statements and branches, named as coverage's JSON report names them."""

    covered_lines: int
    num_statements: int
    covered_branches: int
    num_branches: int

    @classmethod
    def of(cls, summary: dict) -> Figures:
        return cls(*(int(summary.get(field, 0)) for field in cls._fields))

    @property
    def lines(self) -> float:
        return percent(self.covered_lines, self.num_statements)

    @property
    def branches(self) -> float:
        return percent(self.covered_branches, self.num_branches)


def coverage_figures(cov) -> tuple[dict[pathlib.Path, Figures], Figures]:
    """Per-file and total figures, read from coverage's JSON report.

    The report lists every file under the configured source, executed or not,
    and names each relative to STARTED_IN, so each name is resolved against it.
    """
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cov.json_report(outfile="-")
    report = json.loads(out.getvalue())
    files = {(STARTED_IN / name).resolve(): Figures.of(entry["summary"])
             for name, entry in report["files"].items()}
    return files, Figures.of(report["totals"])


def check_coverage() -> int:
    """Enforce the coverage floors, when this run was measured.

    Silent when coverage is not collecting: the floors exist to stop a
    regression, and a developer running the suite bare should not be told the
    measurement failed. CI always measures, so the floors always apply there —
    `task validate:gate-tests` and the CI step both invoke through coverage.
    """
    # COVERAGE_REQUIRED is set by the callers that always measure — the Taskfile
    # target and the CI step. Without it a bare `./run.py` skips the floors,
    # which is right for a developer; with it, a run that could not measure is a
    # failure rather than a silent pass. Otherwise "the measurement did not run"
    # and "the measurement passed" print the same thing, which is the shape this
    # suite exists to reject everywhere else.
    required = os.environ.get("COVERAGE_REQUIRED") == "1"

    try:
        import coverage
    except ImportError:
        if required:
            print("FAIL  COVERAGE_REQUIRED=1 but the coverage package is not "
                  "importable — the floors were not checked, which is not a pass.")
            return 1
        return 0

    cov = coverage.Coverage.current()
    if cov is None:
        if required:
            print("FAIL  COVERAGE_REQUIRED=1 but this process is not running under "
                  "coverage — invoke it as `coverage run --rcfile=.coveragerc "
                  "scripts/tests/run.py`. The floors were not checked.")
            return 1
        return 0

    cov.stop()
    cov.save()
    if not cov.get_data().measured_files():
        print("FAIL  coverage collected no data — the run was measured and saw "
              "nothing, which reports the same as full coverage of an empty set.")
        return 1

    files, total = coverage_figures(cov)

    failures = []
    for what, pct, floor in (("line", total.lines, LINE_FLOOR),
                             ("branch", total.branches, BRANCH_FLOOR)):
        if pct < floor:
            failures.append(f"{what} coverage over the gate scripts is {shown(pct)}, below "
                            f"testing-rubric's {floor}% floor")

    root = HERE.parent.parent
    for rel, (line_floor, branch_floor) in sorted(PER_GATE_FLOORS.items()):
        figures = files.get(root / rel)
        if figures is None or figures.covered_lines == 0:
            failures.append(f"{rel} carries a coverage floor but was not measured — "
                            f"the gate was renamed, or its tests stopped importing it")
            continue
        for what, pct, floor in (("lines", figures.lines, line_floor),
                                 ("branches", figures.branches, branch_floor)):
            if pct < floor:
                failures.append(f"{rel}: {what} at {shown(pct)} are below its {floor}% floor")

    # Read from every Python file in scripts/, so a gate added tomorrow is in
    # the population without anyone remembering to add it.
    gates = sorted((root / "scripts").glob("*.py"))
    unexecuted = [g.name for g in gates
                  if (figures := files.get(g)) is None or figures.covered_lines == 0]
    if unexecuted:
        failures.append(
            f"{len(unexecuted)} Python file(s) in scripts/ are never executed by the suite: "
            f"{', '.join(unexecuted)}. A gate arrives with tests"
        )

    exempt, exempt_problem = control_exempt_gates()
    if exempt_problem:
        failures.append(exempt_problem)
    unproven = sorted(set(exempt) & set(unexecuted))
    if unproven:
        failures.append(
            f"{len(unproven)} gate(s) have neither a positive control nor unit "
            f"coverage: {', '.join(unproven)}. controls.py exempts them because "
            f"their input arrives over the network, so a unit test on the half "
            f"that decides the verdict is the only proof available that they say "
            f"anything at all"
        )
    floorless = sorted(g for g in exempt if f"scripts/{g}" not in PER_GATE_FLOORS)
    if floorless:
        failures.append(
            f"{len(floorless)} control-exempt gate(s) carry no floor in PER_GATE_FLOORS: "
            f"{', '.join(floorless)}. Unit tests are the only proof these say anything, "
            f"so the half that decides the verdict needs a floor holding it covered"
        )

    if failures:
        print()
        for f in failures:
            print(f"FAIL  {f}")
        print("\n  Add the tests that restore a figure, or move a per-file ratchet"
              "\n  deliberately in scripts/tests/run.py with the reason. LINE_FLOOR and"
              "\n  BRANCH_FLOOR are testing-rubric's, and move only with it.")
        return 1

    print(f"coverage OK: lines {shown(total.lines)} (floor {LINE_FLOOR}%), branches "
          f"{shown(total.branches)} (floor {BRANCH_FLOOR}%), {len(PER_GATE_FLOORS)} "
          f"per-file floor(s) held, all {len(gates)} Python file(s) in scripts/ executed.")
    print(f"control-exempt gates: all {len(exempt)} carry unit coverage and a floor of "
          f"their own. scripts/tests/controls.py holds the other half of the claim — "
          f"that every gate it does NOT exempt rejects the violation it names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
