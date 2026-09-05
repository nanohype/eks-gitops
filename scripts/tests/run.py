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

Both are floors, not exact counts: adding tests must never require editing this
file, or the floor becomes something people lower to make a run go green.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent

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
    # The harness layer. controls.py excuses the harnesses from carrying a
    # positive control because each asserts its own outcome when it runs, and
    # the reader deciding whether anything runs them is covered nowhere else.
    "test_controls",
    # The gates the positive-control sweep exempts, because they reach a chart
    # registry or an API. A control cannot be written for them, so a unit test on
    # the half that decides the verdict is the only thing that proves they say
    # anything.
    "test_policy_admission",
    "test_platform_crs",
    "test_dashboards",
    "test_render_addons",
    "test_image_pins",
    "test_log_volume_budget",
    # The image population both image gates read, and the acknowledgement file
    # the vulnerability verdict is decided against. One walk answers every
    # question either gate asks, so an extractor that stops seeing a shape
    # removes those images from all of them at once.
    "test_image_extraction",
    "test_image_vulnerabilities",
    # The floors that keep an emptied corpus from reading as a clean one,
    # asserted apart from the gates that carry them.
    "test_corpus_floors",
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
# API — the exemption is honest, because a control cannot be written for a gate
# whose input arrives over the network — and for exactly those a unit test is the
# only proof available.
#
# One of them, check-policy-admission.py, is an approval gate in the sense
# testing-rubric's `security-critical-100` uses the term, and that rule
# (severity: reject) asks for a per-file 100% override. PER_GATE_FLOORS below
# sets it far under that, and the gap is the finding: a floor set where the
# tests reach is a ratchet, not the rule. Read the number from the table rather
# than from this sentence — a figure written twice drifts, and the reader who
# trusts the prose edits the table down to match it and unratchets the gate.
# The rule is UNMET and saying so is the point of naming it: a floor set where
# the tests reach is a ratchet, and a rule cited without its requirement reads as
# satisfied.
#
# `control_exempt_gates` below reads that exemption list out of controls.py
# rather than repeating it, and check_coverage fails on any gate in both it and
# the uncovered set. A gate added to the exemption must arrive with tests, and
# cannot be excused by a percentage that moves a point.
#
# The floors that follow are the weaker half. They stop a covered file
# regressing; they cannot state what is covered, and a count loose enough to
# survive an honest refactor is loose enough to miss a decision going untested.

# Combined statement+branch coverage floor over the gate scripts, enforced when
# `coverage` is available. A ratchet, not a target: set just under what the suite
# reaches, so coverage cannot fall silently, and raising it is what lands with
# the tests that earn it.
#
# The org testing-rubric asks for 75% lines and 60% branches, and this sits under
# that. What the gap is made of is readable rather than asserted here: the gates
# still carrying no unit tests are the ones controls.py DOES cover, so each of
# them has been observed to reject the violation it names. Read the standing with
#
#     COVERAGE_REQUIRED=1 coverage run --rcfile=.coveragerc scripts/tests/run.py
#     coverage report --rcfile=.coveragerc --include="scripts/*.py"
#
# rather than from a number written here, which would be accurate on the day and
# a confident falsehood after the next test lands.
#
# COMBINED_FLOOR is compared against what coverage.report() returns, which with
# branch=True is a COMBINED statement-and-branch figure, not line coverage. The
# two differ enough to matter, so the name here says combined and the printed
# line says so too. Calling a combined figure "line coverage" would be a
# measurement mislabelled as the one the rubric asks about.
#
# What the number does NOT capture: scripts/tests/controls.py runs most gates end
# to end as a subprocess against a mutated tree, so those gates have behavioural
# coverage this line count cannot see. Neither figure substitutes for the other —
# the controls prove a gate rejects, the unit tests prove it computes the right
# answer on a case the real tree does not contain.
#
# MOST, and the exceptions are the ones that matter to this floor. controls.py
# exempts every gate that reaches a chart registry or an API, and its own run
# prints the split. Those gates have neither kind of coverage, they are the
# largest in the tree, and among them are the gates on the paths testing-rubric
# calls security-critical. So this figure being low is not offset by behavioural
# coverage for precisely the files where that offset was being claimed.
COMBINED_FLOOR = 42

# A ceiling on gate scripts carrying NO unit coverage at all, complementing the
# floors below. The floors stop a covered file regressing; nothing stopped a NEW
# gate arriving with no tests.
#
# Ratchets downward only. Adding a gate without tests fails here rather than
# diluting the combined figure by a percentage point nobody notices.
#
# Two of the files this counts as covered are covered by IMPORT, not by tests.
# check-image-vulnerabilities.py loads check-image-pins.py by path so the two
# cannot disagree about what the fleet is, and that loads render-addons.py in
# turn; a test module importing the first executes the module bodies of all
# three. Coverage cannot tell that from a test, so both read as non-zero while
# carrying no assertions of their own. The ceiling is lowered anyway, because a
# ratchet that declines to move is one nobody can regress against — but it is
# the weaker half of this file's claim, and the per-gate floors and the controls
# in scripts/tests/controls.py are where the real one lives.
MAX_UNCOVERED_GATES = 11

PER_GATE_FLOORS = {
    "scripts/check-named-things.py": 35,
    "scripts/check-renovate-coverage.py": 88,
    "scripts/check-label-values.py": 33,
    "scripts/check-sync-waves.py": 10,
    "scripts/gatelib.py": 55,
    # The control-exempt gates. Their floors are what keeps the verdict half
    # covered after the module that covers it is edited.
    "scripts/check-policy-admission.py": 63,
    "scripts/check-platform-crs.py": 51,
    "scripts/validate-dashboards.py": 49,
    "scripts/render-addons.py": 40,
    "scripts/check-log-volume-budget.py": 58,
    "scripts/check-falco-rule-floor.py": 28,
    "scripts/check-alert-severity-routes.py": 95,
    "scripts/check-image-vulnerabilities.py": 41,
    "scripts/check-image-pins.py": 88,
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


def check_coverage() -> int:
    """Enforce the coverage ratchet, when this run was measured.

    Silent when coverage is not collecting: the floors exist to stop a
    regression, and a developer running the suite bare should not be told the
    measurement failed. CI always measures, so the ratchet always applies there
    — `task validate:gate-tests` and the CI step both invoke through coverage.
    """
    # COVERAGE_REQUIRED is set by the callers that always measure — the Taskfile
    # target and the CI step. Without it a bare `./run.py` skips the ratchet,
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
                  "importable — the ratchet did not run, which is not a pass.")
            return 1
        return 0

    cov = coverage.Coverage.current()
    if cov is None:
        if required:
            print("FAIL  COVERAGE_REQUIRED=1 but this process is not running under "
                  "coverage — invoke it as `coverage run --rcfile=.coveragerc "
                  "scripts/tests/run.py`. The ratchet did not run.")
            return 1
        return 0

    cov.stop()
    cov.save()
    data = cov.get_data()
    if not data.measured_files():
        print("FAIL  coverage collected no data — the run was measured and saw "
              "nothing, which reports the same as full coverage of an empty set.")
        return 1

    import io
    buf = io.StringIO()
    total = cov.report(file=buf, show_missing=False)

    failures = []
    if total < COMBINED_FLOOR:
        failures.append(f"combined statement+branch coverage {total:.1f}% is below "
                        f"the {COMBINED_FLOOR}% ratchet")

    root = HERE.parent.parent
    for rel, floor in sorted(PER_GATE_FLOORS.items()):
        path = str(root / rel)
        if path not in data.measured_files():
            failures.append(f"{rel} carries a coverage floor but was not measured — "
                            f"the gate was renamed, or its tests stopped importing it")
            continue
        analysis = cov._analyze(path)
        pct = analysis.numbers.pc_covered
        if pct < floor:
            failures.append(f"{rel} at {pct:.0f}% is below its {floor}% floor")

    # Gate scripts with no unit coverage whatsoever. Counted from what coverage
    # measured rather than from a list here, so a gate added tomorrow is in the
    # population without anyone remembering to add it.
    gates = sorted((root / "scripts").glob("*.py"))
    uncovered = []
    for gate in gates:
        path = str(gate)
        if path not in data.measured_files():
            uncovered.append(gate.name)
            continue
        if cov._analyze(path).numbers.pc_covered == 0:
            uncovered.append(gate.name)
    if len(uncovered) > MAX_UNCOVERED_GATES:
        failures.append(
            f"{len(uncovered)} of {len(gates)} gate scripts carry no unit coverage, "
            f"above the ceiling of {MAX_UNCOVERED_GATES}: "
            f"{', '.join(uncovered[:4])}{' …' if len(uncovered) > 4 else ''}"
        )

    exempt, exempt_problem = control_exempt_gates()
    if exempt_problem:
        failures.append(exempt_problem)
    unproven = sorted(set(exempt) & set(uncovered))
    if unproven:
        failures.append(
            f"{len(unproven)} gate(s) have neither a positive control nor unit "
            f"coverage: {', '.join(unproven)}. controls.py exempts them because "
            f"their input arrives over the network, so a unit test on the half "
            f"that decides the verdict is the only proof available that they say "
            f"anything at all"
        )

    if failures:
        print()
        for f in failures:
            print(f"FAIL  {f}")
        print("\n  Coverage floors ratchet. Add the tests that restore the number, or "
              "\n  lower the floor deliberately in scripts/tests/run.py with the reason.")
        return 1

    print(f"coverage ratchet OK: {total:.1f}% combined statement+branch "
          f"(floor {COMBINED_FLOOR}%), {len(PER_GATE_FLOORS)} per-gate floor(s) held, "
          f"{len(uncovered)} of {len(gates)} gate script(s) with no unit coverage "
          f"(ceiling {MAX_UNCOVERED_GATES}). Under the rubric's 75% lines / 60% "
          f"branches — see the note in this file.")
    print(f"control-exempt gates: all {len(exempt)} carry unit coverage. "
          f"scripts/tests/controls.py holds the other half of the claim — that "
          f"every gate it does NOT exempt rejects the violation it names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
