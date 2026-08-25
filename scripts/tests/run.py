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
)

# A floor well under the real count. It catches "discovery found almost nothing",
# not "somebody removed one test".
MIN_TESTS = 25

# Line coverage floors over the gate scripts, enforced when `coverage` is
# available. A ratchet, not a target: each is set just under what the suite
# reaches, so coverage cannot fall silently, and raising one is what lands with
# the tests that earn it.
#
# The org testing-rubric asks for 75% lines and 60% branches, and this suite is
# nowhere near that — the honest figure is in TOTAL_FLOOR below. The gap is
# real and stated rather than papered over: eleven of the eighteen gates have no
# unit test, so the number cannot move without writing them.
#
# What the number does NOT capture: scripts/tests/controls.py runs every gate
# end to end as a subprocess against a mutated tree, so every gate has
# behavioural coverage that this line count cannot see. Neither figure
# substitutes for the other — the controls prove a gate rejects, the unit tests
# prove it computes the right answer on a case the real tree does not contain.
TOTAL_FLOOR = 6
PER_GATE_FLOORS = {
    "scripts/check-named-things.py": 35,
    "scripts/check-renovate-coverage.py": 30,
    "scripts/check-label-values.py": 33,
    "scripts/check-sync-waves.py": 10,
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
    try:
        import coverage
    except ImportError:
        return 0

    cov = coverage.Coverage.current()
    if cov is None:
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
    if total < TOTAL_FLOOR:
        failures.append(f"total line coverage {total:.0f}% is below the "
                        f"{TOTAL_FLOOR}% ratchet")

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

    if failures:
        print()
        for f in failures:
            print(f"FAIL  {f}")
        print("\n  Coverage floors ratchet. Add the tests that restore the number, or "
              "\n  lower the floor deliberately in scripts/tests/run.py with the reason.")
        return 1

    print(f"coverage ratchet OK: {total:.0f}% total (floor {TOTAL_FLOOR}%), "
          f"{len(PER_GATE_FLOORS)} per-gate floor(s) held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
