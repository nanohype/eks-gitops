#!/usr/bin/env python3
"""No gate reports success over a corpus that is not there.

A gate reports on the population it read. Nothing in an exit code separates "this
catalog holds no violation" from "this run held no catalog", and the second is
what a renamed directory, a wrong working directory, a narrowed glob or a filter
that stopped matching all look like. The fork-safety gate printed
`Scanned 0 applied ApplicationSet(s)` followed by its success line and exited 0
under `--blocking`.

Naming the gates that do it is a list of the ones somebody found. This empties
the corpus and asks every gate, so the class is closed rather than three
instances of it:

    * the gate population is every executable under scripts/, derived from the
      tree — a gate added tomorrow is probed without anyone remembering to add it
    * the corpus is every tracked file the gates read, emptied wholesale, so no
      per-gate knowledge of what each one walks has to be maintained here
    * a gate must exit NON-ZERO, and must not do it by crashing

The last is its own defect and is why this reads the output rather than the
status alone. An unguarded `read_text()` on an absent manifest raises
FileNotFoundError, which exits 1 — the status this repo uses for "the gate
rejected the tree". By exit code a crash and a finding are the same answer, and
the traceback names a pathlib internal rather than the file that is missing.

WHAT THIS DOES NOT ESTABLISH

That a gate examined the RIGHT population — only that it noticed an absent one.
A gate reading one file of thirty passes here. That is the corpus-completeness
question, and it belongs with each gate's own tests.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPTS = ROOT / "scripts"

# Seconds one gate may run against the emptied tree.
GATE_TIMEOUT = 300

# Directories whose contents are the gates' subject matter. Emptied wholesale
# rather than per gate: a per-gate map of what each one walks is the same
# hand-maintained list this harness exists to replace, and it would go stale in
# the direction that matters — a gate whose corpus moved would be probed against
# the directory it no longer reads and would pass.
CORPUS_DIRS = ("applicationsets", "addons", "policies", "dashboards", "catalog", "docs")

# Gates that answer about something other than the catalog's manifests, so
# emptying the corpus above leaves their real subject in place and the probe
# would assert nothing about them. Each names what it reads instead, and is
# asserted: an entry naming a gate that no longer exists fails, and so does one
# whose stated subject is no longer part of the tree.
OTHER_SUBJECT = {
    "check-workflows.sh": ".github/workflows",
    "kubeconform-scan.sh": ".github/workflows",
}

# A floor on gates PROBED. With the glob answering nothing this would report that
# every gate refuses an empty corpus, over no gates.
MIN_PROBED = 20

CRASH_MARKERS = ("Traceback (most recent call last)", "\npanic: ")


def gate_files() -> list[pathlib.Path]:
    """Every executable gate, from the tree rather than a list here."""
    return sorted(
        p for p in SCRIPTS.rglob("*")
        if p.is_file() and os.access(p, os.X_OK) and p.suffix in {".py", ".sh"}
        and p.parent != SCRIPTS / "tests"
    )


def tracked_files() -> list[str]:
    """What git tracks, which is the tree the gates are shipped to read.

    Not a filesystem walk: a local build cache, a rendered/ directory or an
    uncommitted scratch file would be copied into the probe and then fail the
    staging below, and none of them is part of what a gate examines.
    """
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                          text=True, timeout=GATE_TIMEOUT)
    if proc.returncode != 0:
        print(f"Cannot run: `git ls-files` failed in {ROOT} — {proc.stderr.strip()}")
        sys.exit(2)
    return [p for p in proc.stdout.split("\0") if p]


def emptied_tree(dest: pathlib.Path) -> int:
    """A copy of the tracked tree with every corpus file removed."""
    for rel in tracked_files():
        src = ROOT / rel
        if not src.is_file():
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)

    removed = 0
    for name in CORPUS_DIRS:
        for path in sorted((dest / name).rglob("*")):
            if path.is_file() and path.suffix != ".py":
                path.unlink()
                removed += 1

    # The gates that ask git what the tree tracks need an answer, and an
    # uninitialised directory makes them exit 2 for that reason instead of for
    # the corpus being empty — which would score a pass this harness did not earn.
    subprocess.run(["git", "init", "-q"], cwd=dest, check=True, timeout=GATE_TIMEOUT)
    survivors = sorted(str(p.relative_to(dest)) for p in dest.rglob("*")
                       if p.is_file() and not str(p.relative_to(dest)).startswith(".git/"))
    subprocess.run(["git", "add", "--", *survivors], cwd=dest, check=True,
                   timeout=GATE_TIMEOUT, capture_output=True)
    return removed


def probe(gate: pathlib.Path, tree: pathlib.Path) -> tuple[bool, str]:
    """Whether `gate` refused the emptied tree, and why not if it did not."""
    rel = gate.relative_to(SCRIPTS)
    try:
        proc = subprocess.run([str(tree / "scripts" / rel)], cwd=tree,
                              capture_output=True, text=True, timeout=GATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"did not finish in {GATE_TIMEOUT}s against an empty corpus"
    out = proc.stdout + proc.stderr
    if any(marker in out for marker in CRASH_MARKERS):
        first = next((ln for ln in out.splitlines() if "Error" in ln or "panic:" in ln),
                     "").strip()
        return False, (f"CRASHED rather than refusing (exit {proc.returncode}) — "
                       f"{first[:120]}. A crash exits non-zero, so by status alone it "
                       f"is a finding; the traceback then names a library internal "
                       f"rather than the input that is absent")
    if proc.returncode == 0:
        return False, (f"exited 0 over an empty corpus — {out.strip().splitlines()[-1][:120] if out.strip() else 'silently'}")
    return True, ""


def main() -> int:
    gates = gate_files()
    if not gates:
        print("FAIL  found no gate executables under scripts/ — this harness probed")
        print("      nothing, which is not the same as every gate refusing.")
        return 2

    problems: list[str] = []
    for name, subject in sorted(OTHER_SUBJECT.items()):
        if not any(g.name == name for g in gates):
            problems.append(f"{name} is exempted as answering about {subject} rather "
                            f"than the catalog, but no such gate exists under scripts/ "
                            f"— the exemption outlived its file.")
        elif not (ROOT / subject).is_dir():
            problems.append(f"{name} is exempted as answering about {subject}, which "
                            f"is not a directory in this tree — the exemption names a "
                            f"subject the repo does not have.")

    with tempfile.TemporaryDirectory() as tmp:
        tree = pathlib.Path(tmp) / "tree"
        removed = emptied_tree(tree)
        if not removed:
            print("FAIL  emptying the corpus removed no file, so every gate below was")
            print("      run against the real tree and refusing it would prove nothing.")
            return 2
        print(f"── {len(gates)} gate(s) against a tree with {removed} corpus file(s) "
              f"removed ──\n")

        probed = 0
        for gate in gates:
            if gate.name in OTHER_SUBJECT:
                print(f"  skip  {gate.name}: answers about {OTHER_SUBJECT[gate.name]}, "
                      f"which this probe does not empty")
                continue
            probed += 1
            ok, why = probe(gate, tree)
            if ok:
                print(f"  ok    {gate.name}")
            else:
                print(f"  FAIL  {gate.name}: {why}")
                problems.append(f"{gate.name} {why}")

    if probed < MIN_PROBED:
        problems.append(f"only {probed} gate(s) were probed, under the floor of "
                        f"{MIN_PROBED} — the population this harness reads shrank, and "
                        f"a clean run over it says nothing about the rest.")

    print()
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        print("\n  A gate that reports success over an absent corpus reports the same")
        print("  thing as one over a clean tree. Give it a floor on what it EXAMINED,")
        print("  or make the absent input exit 2 with the file named.")
        return 1

    print(f"✓ all {probed} probed gate(s) refuse an empty corpus, and none does it by "
          f"crashing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
