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
)

# A floor well under the real count. It catches "discovery found almost nothing",
# not "somebody removed one test".
MIN_TESTS = 15


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
    return 0


if __name__ == "__main__":
    sys.exit(main())
