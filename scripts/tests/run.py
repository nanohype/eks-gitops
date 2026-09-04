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

import os
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent

# Named rather than counted. A module that disappears takes its assertions with
# it, and nothing else in the suite would notice.
EXPECTED = (
    "test_renovate_coverage",
    "test_label_values",
    "test_sync_waves",
    "test_kyverno_corpus",
    "test_named_things",
    "test_falco_rule_floor",
    "test_gatelib",
    "test_corpus_floors",
)

# A floor well under the real count. It catches "discovery found almost nothing",
# not "somebody removed one test".
MIN_TESTS = 31

# Line coverage floors over the gate scripts, enforced when `coverage` is
# available. A ratchet, not a target: each is set just under what the suite
# reaches, so coverage cannot fall silently, and raising one is what lands with
# the tests that earn it.
#
# The org testing-rubric asks for 75% lines and 60% branches. COMBINED_FLOOR
# sitting far below that is the record of the gap, kept rather than papered over:
# most gate files carry no unit tests at all, and the floor cannot rise without
# writing them. Read the current standing with
#
#     COVERAGE_REQUIRED=1 coverage run --rcfile=.coveragerc scripts/tests/run.py
#     coverage report --rcfile=.coveragerc --include="scripts/*.py"
#
# rather than from a number written here, which would be accurate on the day and
# a confident falsehood after the next test lands.
#
# COMBINED_FLOOR is compared against what coverage.report() returns, which with
# branch=True is a COMBINED statement-and-branch figure, not line coverage. The
# two differ enough to matter, so the name below says combined and the printed
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
COMBINED_FLOOR = 12

# A ceiling on gate scripts carrying NO unit coverage at all, complementing the
# floors below. The floors stop a covered file regressing; nothing stopped a NEW
# gate arriving with no tests, and most of this tree arrived that way.
#
# Ratchets downward only. Adding a gate without tests fails here rather than
# diluting the combined figure by a percentage point nobody notices, which is how
# a suite reaches this state one honest commit at a time.
MAX_UNCOVERED_GATES = 17

PER_GATE_FLOORS = {
    "scripts/check-named-things.py": 35,
    "scripts/check-renovate-coverage.py": 55,
    "scripts/check-label-values.py": 33,
    "scripts/check-sync-waves.py": 10,
    "scripts/gatelib.py": 55,
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
          f"(ceiling {MAX_UNCOVERED_GATES}). Well under the rubric's 75% lines / "
          f"60% branches — see the note in this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
