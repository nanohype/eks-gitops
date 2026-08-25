"""Shared helpers for the gate scripts.

Small on purpose. The gates are standalone executables and mostly should stay
that way; what belongs here is the handful of things that are wrong in the same
way when each gate does them itself.

Loading it: the gates are hyphenated filenames and are run from varying working
directories, so they load this by path rather than by import name — the pattern
check-policy-admission.py already uses for render-addons.py:

    import importlib.util, pathlib, sys
    _p = pathlib.Path(__file__).resolve().parent / "gatelib.py"
    _s = importlib.util.spec_from_file_location("gatelib", _p)
    gatelib = importlib.util.module_from_spec(_s)
    sys.modules["gatelib"] = gatelib
    _s.loader.exec_module(gatelib)
"""

from __future__ import annotations

import shutil
import sys

# Exit code for "this gate could not run", distinct from 1 for "this gate
# rejected the tree". A caller that cannot tell those apart reads a missing
# binary as a finding — which is how a CI job with no kyverno installed reported
# a policy failure, and how a positive-control floor reading only exit status
# scores a crash as a catch.
CANNOT_RUN = 2


def require(*tools: str) -> None:
    """Exit 2 unless every named binary is on PATH.

    Without this a gate shelling out to a missing tool raises FileNotFoundError,
    exits non-zero, and prints an interpreter traceback naming the Python
    subprocess machinery rather than the tool nobody installed. The status is
    then indistinguishable from a rejection, and the message points the reader
    at the wrong thing entirely.

    Asserting the precondition converts that into a sentence a reader can act
    on, and into a status a caller can classify.
    """
    missing = [t for t in tools if shutil.which(t) is None]
    if not missing:
        return
    plural = "s" if len(missing) > 1 else ""
    print(f"Cannot run: required tool{plural} not on PATH: {', '.join(missing)}.")
    print("This gate has NOT checked anything — that is different from finding")
    print("nothing. Install the tool(s) and re-run; the versions CI pins are in")
    print("the env block at the top of .github/workflows/ci.yml.")
    sys.exit(CANNOT_RUN)
