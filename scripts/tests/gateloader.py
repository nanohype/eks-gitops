"""Import a gate script by filename.

The gates are executables named with hyphens (`check-sync-waves.py`), which are
not importable module names. Each one guards its entry point with
`if __name__ == "__main__"`, so loading the file executes only its definitions —
verified by these tests existing at all: a script that ran main() on import would
fail the suite immediately rather than subtly.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent


def load(script: str):
    """Load scripts/<script>.py and return the module."""
    path = SCRIPTS / f"{script}.py"
    if not path.exists():                       # a renamed gate must fail loudly
        raise FileNotFoundError(
            f"{path} does not exist — the gate was renamed or removed and this "
            f"test is now asserting nothing."
        )
    name = "gate_" + script.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
