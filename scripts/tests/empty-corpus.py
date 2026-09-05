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

Two things, both stated rather than implied by a green run.

That a gate examined the RIGHT population — only that it noticed an absent one.
A gate reading one file of thirty passes here. That is the corpus-completeness
question, and it belongs with each gate's own tests.

And WHY a gate refused. Several derive their coordinates from an ApplicationSet
— which chart to render, which environments exist — and emptying every corpus at
once takes that input away too, so they exit 2 naming the appset rather than
saying anything about the corpus they check. Those runs are marked below. A
two-pass probe keeping applicationsets/ was tried and does not separate the
cases: for a gate whose corpus IS applicationsets/, the same file is both. What
would separate them is per-gate knowledge of which input is which, which is the
hand-maintained map this harness exists to avoid, so the limit is recorded
instead of papered over.
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

# Gates this repository runs that are not executables under scripts/. The
# workflow blocks the same merges on them, so a probe named for flooring every
# corpus that skipped them would have a population quietly narrower than its
# name. Each names the command as its caller runs it and the corpus it reads.
#
# All three passed over an absent corpus when this list was written: `kyverno
# test` printed that no tests are available and exited 0; `trivy config` over an
# empty render exited 0; and the render loop matched no overlays and printed
# "All manifests built successfully", which is the sentence a reader takes as
# proof the fleet renders.
COMMAND_GATES = {
    "kyverno test": (["./scripts/kyverno-test.sh"], "policies"),
    "trivy config": (["trivy", "config", "--exit-code", "1", "--severity",
                      "MEDIUM,HIGH,CRITICAL", "--ignorefile", ".trivyignore.yaml",
                      "rendered"], "rendered"),
    "kustomize build loop": (["task", "kustomize:build"], "addons"),
}

# Gates that answer about something other than the catalog's manifests, so
# emptying the corpus above leaves their real subject in place and the probe
# would assert nothing about them. Each names what it reads instead, and is
# asserted: an entry naming a gate that no longer exists fails, and so does one
# whose stated subject is no longer part of the tree.
OTHER_SUBJECT = {
    "check-workflows.sh": ".github/workflows",
}

# Gates whose corpus is an argument, not a default. Run with no argv a gate like
# this reads stdin or its own default and says nothing about the tree, so the
# probe hands it the argv its callers do — the same reason
# scripts/tests/controls.py carries GATE_ARGS.
#
# kubeconform-scan.sh was exempted here as answering about .github/workflows. It
# does not read that directory: Taskfile.yaml and ci.yml pass it
# `applicationsets/` and `rendered`. Both halves of that exemption's assertion
# held — the file exists, the directory exists — while the claim was false, which
# is what an exemption asserted on the wrong operand looks like.
GATE_ARGS = {
    "kubeconform-scan.sh": ["applicationsets/"],
    "check-hardcoded-org.py": ["--blocking"],
}

# A floor on gates PROBED. With the glob answering nothing this would report that
# every gate refuses an empty corpus, over no gates.
#
# And a floor on THAT, because a floor of zero is the shape this whole harness
# exists to reject, one level up: set MIN_PROBED to 0 and the tree stays green
# over a probe that examined nothing. The lower bound is not a second constant —
# it is the size of the population the probe is named for, so it cannot be
# lowered without deleting gates.
MIN_PROBED = 23

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


def emptied_tree(dest: pathlib.Path, keep: tuple[str, ...] = ()) -> int:
    """A copy of the tracked tree with the corpus removed, `keep` left intact."""
    for rel in tracked_files():
        src = ROOT / rel
        if not src.is_file():
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)

    removed = 0
    for name in [d for d in CORPUS_DIRS if d not in keep]:
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


def probe(gate: pathlib.Path, tree: pathlib.Path) -> tuple[bool, str, bool]:
    """(refused, why not, refused-on-a-derivation-input).

    The third value is what keeps CANNOT_RUN meaningful. A gate that exits 2
    because an ApplicationSet it reads to learn its coordinates is gone has said
    nothing about its corpus, and scoring that as a corpus refusal is the
    collapse this repo avoids everywhere else.
    """
    rel = gate.relative_to(SCRIPTS)
    try:
        proc = subprocess.run([str(tree / "scripts" / rel), *GATE_ARGS.get(gate.name, [])],
                              cwd=tree, capture_output=True, text=True,
                              timeout=GATE_TIMEOUT, env={**os.environ,
                                                         "KUBECONFORM_SKIP": ""})
    except subprocess.TimeoutExpired:
        return False, f"did not finish in {GATE_TIMEOUT}s against an empty corpus", False
    out = proc.stdout + proc.stderr
    if any(marker in out for marker in CRASH_MARKERS):
        first = next((ln for ln in out.splitlines() if "Error" in ln or "panic:" in ln),
                     "").strip()
        return False, (f"CRASHED rather than refusing (exit {proc.returncode}) — "
                       f"{first[:120]}. A crash exits non-zero, so by status alone it "
                       f"is a finding; the traceback then names a library internal "
                       f"rather than the input that is absent"), False
    if proc.returncode == 0:
        last = out.strip().splitlines()[-1][:120] if out.strip() else "silently"
        return False, f"exited 0 over an empty corpus — {last}", False
    on_derivation = (proc.returncode == gatelib_cannot_run()
                     and any(f"{d}/" in out for d in CORPUS_DIRS))
    return True, "", on_derivation


def probe_command(label: str, argv: list[str], corpus: str,
                  tree: pathlib.Path) -> tuple[bool, str]:
    """Whether a command this repo runs as a gate refuses its corpus emptied.

    Not an executable under scripts/, so it carries none of the conventions the
    gates share — no CANNOT_RUN, no diagnostic naming the input. The question is
    the same one: does it report success having read nothing.
    """
    if shutil.which(argv[0]) is None:
        return True, ""            # the tool is absent; that is not a verdict
    try:
        proc = subprocess.run(argv, cwd=tree, capture_output=True, text=True,
                              timeout=GATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"did not finish in {GATE_TIMEOUT}s"
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        return True, ""
    last = out.strip().splitlines()[-1][:110] if out.strip() else "silently"
    return False, (f"exited 0 with {corpus}/ emptied — {last}")


def gatelib_cannot_run() -> int:
    """The shared "this did not run" status, read from gatelib rather than 2."""
    text = (ROOT / "scripts" / "gatelib.py").read_text()
    for line in text.splitlines():
        if line.startswith("CANNOT_RUN"):
            return int(line.split("=", 1)[1].strip())
    return 2


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

    probed = 0
    with tempfile.TemporaryDirectory() as tmp:
        tree = pathlib.Path(tmp) / "tree"
        removed = emptied_tree(tree)
        if not removed:
            print("FAIL  emptying the corpus removed no file, so every gate below was")
            print("      run against the real tree and refusing it would prove nothing.")
            return 2
        print(f"── {len(gates)} gate(s) against a tree with {removed} corpus file(s) "
              f"removed ──\n")

        for gate in gates:
            if gate.name in OTHER_SUBJECT:
                print(f"  skip  {gate.name}: answers about {OTHER_SUBJECT[gate.name]}, "
                      f"which this probe does not empty")
                continue
            probed += 1
            ok, why, on_derivation = probe(gate, tree)
            if ok:
                print(f"  ok    {gate.name}"
                      + ("  (refused on a derivation input, not on its corpus)"
                         if on_derivation else ""))
            else:
                print(f"  FAIL  {gate.name}: {why}")
                problems.append(f"{gate.name} {why}")

        for label, (argv, corpus) in sorted(COMMAND_GATES.items()):
            probed += 1
            ok, why = probe_command(label, argv, corpus, tree)
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}"
                  + ("" if ok else f": {why}"))
            if not ok:
                problems.append(f"{label} {why}")
    print()

    # The floor's own floor. A probe population of 25 with MIN_PROBED at 0 reports
    # success over nothing, and nothing else in the tree reads this constant.
    if MIN_PROBED < 1:
        problems.append(
            f"MIN_PROBED is {MIN_PROBED}, so this harness would report every gate "
            f"refusing an empty corpus over a population of none. A floor of zero is "
            f"the shape this harness exists to reject.")
    elif len(gates) < MIN_PROBED:
        problems.append(
            f"MIN_PROBED is {MIN_PROBED} and scripts/ holds {len(gates)} gate(s), so "
            f"this harness cannot pass on any tree. A floor above its corpus fails "
            f"every run, which is the other way a floor is wrong.")
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
