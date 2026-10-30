"""Import a gate script by filename.

The gates are executables named with hyphens (`check-sync-waves.py`), which are
not importable module names. Each one guards its entry point with
`if __name__ == "__main__"`, so loading the file executes only its definitions —
verified by these tests existing at all: a script that ran main() on import would
fail the suite immediately rather than subtly.

The gates import gatelib and registry by name, which resolves because a script's
own directory leads sys.path when it runs. A test process starts from
scripts/tests, so scripts/ is put on sys.path here, and a module with an
importable name is imported rather than loaded: the test then holds the same
instance the gates it loads hold, and patches what they call.

Every suite that loads a gate imports this module first, so it is also where
the test process is kept from reading the logins of whoever runs it.
registry.py reads a stored `docker login` from $DOCKER_CONFIG, and the process
is pointed at an empty directory before any gate is loaded. A token request in
such a suite then carries no credentials the test did not write, and a
subprocess one of its tests starts inherits the same empty directory. A test
reading a docker config of its own names that directory instead, for as long
as it needs it.
"""

from __future__ import annotations

import atexit
import importlib
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

DOCKER_CONFIG = tempfile.mkdtemp(prefix="docker-config-")
atexit.register(shutil.rmtree, DOCKER_CONFIG, True)
os.environ["DOCKER_CONFIG"] = DOCKER_CONFIG


def load(script: str):
    """Load scripts/<script>.py and return the module."""
    path = SCRIPTS / f"{script}.py"
    if not path.exists():                       # a renamed gate must fail loudly
        raise FileNotFoundError(
            f"{path} does not exist — the gate was renamed or removed and this "
            f"test is now asserting nothing."
        )
    if script.isidentifier():
        return importlib.import_module(script)
    name = "gate_" + script.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"{path} is not loadable as a module"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
