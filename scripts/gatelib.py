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

import pathlib
import shutil
import sys

# Exit code for "this gate could not run", distinct from 1 for "this gate
# rejected the tree". A caller that cannot tell those apart reads a missing
# binary as a finding — which is how a CI job with no kyverno installed reported
# a policy failure, and how a positive-control floor reading only exit status
# scores a crash as a catch.
CANNOT_RUN = 2


def read_yaml_all(path) -> list:
    """Every document in `path`, or exit 2 NAMING the file that will not parse.

    An unguarded `yaml.safe_load_all` raises, which exits non-zero — so by exit
    status alone a malformed manifest is indistinguishable from a gate that
    examined the tree and rejected it. The traceback then names a parser
    internal rather than the file the reader has to fix, and the reader goes
    looking in the wrong place.

    A missing input and a malformed one are also different facts, and they get
    different sentences here: an absent file is not this gate's business to
    invent, a malformed one is a defect somebody introduced.
    """
    import yaml

    path = pathlib.Path(path)
    if not path.is_file():
        print(f"Cannot run: {path} does not exist. This gate examined nothing, which "
              f"is not the same as finding nothing.")
        sys.exit(CANNOT_RUN)
    try:
        return [d for d in yaml.safe_load_all(path.read_text()) if d is not None]
    except yaml.YAMLError as exc:
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
        print(f"Cannot run: {path} is not parseable YAML — {first}")
        print("This gate examined nothing past that file. Fix the manifest and re-run.")
        sys.exit(CANNOT_RUN)


def read_yaml(path):
    """The first document in `path`, or exit 2 naming the file. See read_yaml_all.

    For the gates that read one manifest to derive what they check against — a
    chart pin, an appset's coordinates. An unguarded `read_text()` there raises
    FileNotFoundError, which exits 1: the status this repo uses for "the gate
    rejected the tree". By exit code a reader cannot tell that from a finding,
    and the traceback names a pathlib internal rather than the manifest that is
    missing.
    """
    docs = read_yaml_all(path)
    if not docs:
        print(f"Cannot run: {pathlib.Path(path)} holds no YAML document, so the "
              f"coordinates this gate reads from it are unknown.")
        sys.exit(CANNOT_RUN)
    return docs[0]


def read_json(path):
    """`path` parsed as JSON, or exit 2 naming the file. See read_yaml_all."""
    import json

    path = pathlib.Path(path)
    if not path.is_file():
        print(f"Cannot run: {path} does not exist. This gate examined nothing, which "
              f"is not the same as finding nothing.")
        sys.exit(CANNOT_RUN)
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        print(f"Cannot run: {path} is not parseable JSON — {exc}")
        print("This gate examined nothing past that file. Fix it and re-run.")
        sys.exit(CANNOT_RUN)


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


def matrix_generators(doc: dict):
    """Every generator an ApplicationSet declares, matrix members flattened.

    A `matrix` combines axes and contributes its inner generators; a bare
    generator contributes itself.
    """
    for gen in (doc.get("spec") or {}).get("generators") or []:
        if not isinstance(gen, dict):
            continue
        if "matrix" in gen:
            for inner in (gen.get("matrix") or {}).get("generators") or []:
                if isinstance(inner, dict):
                    yield inner
        else:
            yield gen


def list_elements(doc: dict) -> list[dict]:
    """Elements of EVERY list generator in `doc`, not the first one found.

    An ApplicationSet may declare more than one — this catalog already ships one
    that does — and each contributes its own Applications. A walker that returns
    on the first match drops the rest, and the failure is invisible from the
    outside: the gate's own count is derived from the same truncated list, so a
    run that examined half the Applications prints the same sentence, and the
    same total, as a run that examined all of them.

    That is the shape a copy of this walk had in two gates at once. It lives here
    so the next gate to need it inherits the fixed one rather than the paragraph
    explaining why the broken one looked fine.
    """
    out: list[dict] = []
    for gen in matrix_generators(doc):
        for el in (gen.get("list") or {}).get("elements") or []:
            if isinstance(el, dict):
                out.append(el)
    return out


def is_helm_template(path) -> bool:
    """True for a file that is Go-template text rather than a YAML manifest.

    Detected STRUCTURALLY, not by a path list and not by catching the parse
    error: a file under a directory named `templates` whose parent holds a
    `Chart.yaml` is chart source, and Helm renders it before anything applies
    it. Every other tracked YAML file in this repo is a manifest or a values
    file and must parse.

    The distinction matters because the alternative — `except YAMLError:
    continue` — silently removes a file from a gate's corpus, and a corpus that
    quietly shrinks reports exactly what a clean one reports. A gate may skip
    what it can justify structurally; it may not skip whatever happens to
    break its parser.
    """
    path = pathlib.Path(path)
    for parent in path.parents:
        if parent.name == "templates" and (parent.parent / "Chart.yaml").is_file():
            return True
    return False
