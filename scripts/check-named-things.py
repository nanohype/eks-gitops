#!/usr/bin/env python3
"""Every repo path, task target and script named in prose resolves.

Prose that names a thing is a claim about the world. The claim is true when
written and nothing keeps it true, so it decays into a confident false statement
at the first unrelated edit — a reader following a runbook under pressure lands
on a path that no longer exists, and the document that was supposed to help is
the thing that misled them.

Three claims are mechanically checkable, so they are checked here rather than
described:

  * a repo-relative path in a markdown link or in backticks names a file or
    directory that exists
  * `task <target>` names a target the Taskfile defines
  * a `scripts/<name>` reference names a script that exists

DECLARED ESCAPE SURFACE. Inputs that name a thing and are deliberately not
checked, established by running them rather than by reading the patterns:

  * a path written as bare prose, without backticks or a link. This is the
    narrowing that makes the gate usable — `values.yaml` in this repo's prose is
    a convention, not a path — and it means `see scripts/typo.py` passes.
  * a path inside an HTML comment, which renders to nothing.

Two halves of the same rule are NOT checked here, and a pass says nothing about
either:

  * A measurement stated as documentation. "returns an empty list", "four hits",
    "all 34" are claims with no mechanism keeping them true and no syntax
    marking them out. They need a reader.
  * A citation whose line number is in range but names the wrong content. The
    range check catches a citation that outlived its file; it cannot catch one
    that outlived the lines while the file kept growing. That is the more common
    direction, and it is unaddressed.

The count of references examined is printed on every run. A gate that passes
over a corpus it silently stopped matching reads exactly like a clean tree, so
the denominator is stated rather than implied.

Views: markdown link targets and backticked spans are read from the raw text,
because in prose the reference IS the text. Fenced code blocks are excluded —
they carry illustrative paths that deliberately do not exist ("addons/<category>/
<name>/"), which is a different kind of writing.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A floor on the corpus. A glob that stops matching reports the same clean
# result as a tree with nothing wrong, so the count is asserted rather than
# inferred from silence.
MIN_DOCS = 15
MIN_REFS = 60

# Placeholder syntax: prose that names a SHAPE rather than a path. Angle
# brackets and template braces are the two spellings this repo uses.
PLACEHOLDER = re.compile(r"[<>{}*]|\.\.\.")

# What counts as a claim about THIS tree, as opposed to prose about a shape.
#
# A bare `values.yaml` in this repo's prose means "the addon's values.yaml" —
# a description of the per-addon contract, true of forty-odd directories and of
# no repo-root path. Treating it as a claim makes the gate disagree with the
# population it guards, and a gate that reports on a different set than the one
# under test is noise that trains readers to ignore it.
#
# So a backticked span is a claim only when it is rooted: it starts at one of
# the repo's own top-level entries. `scripts/check-sync-waves.py` names a file
# and either resolves or does not; `values.yaml` names a convention. Markdown
# link targets are checked whatever they look like, because a link is a claim
# that following it arrives somewhere.
def rooted_prefixes(root: pathlib.Path) -> tuple[str, ...]:
    """Top-level entries of the tree UNDER TEST, not of the tree this file ships in.

    Derived from the passed root. Computed once at import from the module's own
    ROOT, `--root` checked another tree's documents against THIS repo's shape and
    Taskfile — the corpus and the subject were different trees, so a verdict was
    about a mixture of the two. Demonstrated: a target present in a fixture's
    Taskfile was reported missing because the real repo's Taskfile was consulted.
    That direction fails closed; the mirror image, a fixture MISSING something
    this repo has, would have passed falsely.
    """
    return tuple(sorted(
        p.name + ("/" if p.is_dir() else "")
        for p in root.iterdir()
        if not p.name.startswith(".git") and p.name not in {"rendered"}
    ))

# A `path:line` or `path:lo-hi` citation. The file must exist and the line must
# be inside it: a citation past the end of a file is a reference that grew stale
# while reading as precise, which is the failure mode a line number has that a
# path does not.
CITATION = re.compile(r"([A-Za-z0-9._/-]+\.(?:yaml|yml|py|sh|go|json|md)):(\d+)(?:-(\d+))?\b")

# Inline link. The target stops at whitespace so a titled link — [x](path "T") —
# yields the path rather than `path "T"`, which resolved to nothing and so was
# skipped as a non-path rather than reported as a broken one.
LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+[\"'(][^)]*)?\)")

# Reference-style link definition: `[label]: target`. A different syntax for the
# same claim, and invisible to the inline pattern.
LINK_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?")
CODE_SPAN = re.compile(r"`([^`\n]+)`")
FENCE = re.compile(r"^\s*```", re.M)
# `task` is also an ordinary English noun, and a Druid one — "task pods", "the
# task template", "the k8s task runner". A reference is a claim about the CLI
# only when it is formatted as a command: inside backticks, or at the start of a
# line in a fenced block. Matching the bare word instead reports on a population
# the Taskfile was never part of.
# The first segment allows hyphens too. Without them the pattern truncated at
# the first `-`, so `task validate-nonexistent` matched `validate`, a real
# target, and the fabricated name passed while being COUNTED as checked — the
# most natural way to write a wrong target was the one shape invisible to the
# gate. Anchored at both ends so a partial match cannot stand in for the whole.
# The first segment allows hyphens. Without them the pattern truncated at the
# first `-`, so `task validate-nonexistent` matched `validate`, a real target,
# and the fabricated name passed while being COUNTED as checked — the most
# natural way to write a wrong target was the one shape invisible to the gate.
#
# The target is bounded by whitespace or end-of-string rather than by `$` alone,
# because this repo documents `task render ENVIRONMENT=staging` and anchoring
# hard at the line end silently dropped every invocation carrying an argument:
# 34 of 181 references, a fifth of the corpus, stopping being checked to fix a
# false negative in the other direction.
TASK_REF = re.compile(r"^task\s+([a-z][a-z0-9-]*(?::[a-z0-9-]+)*)(?:\s|$)")


def strip_fences(text: str) -> str:
    """Blank fenced code blocks, preserving line count.

    Blanked rather than removed so a reported line number still resolves in the
    file the reader opens.
    """
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if FENCE.match(line):
            inside = not inside
            out.append("\n")
            continue
        out.append("\n" if inside else line)
    return "".join(out)


def task_targets(root: pathlib.Path) -> set[str]:
    """Target names the Taskfile of the tree UNDER TEST defines."""
    text = (root / "Taskfile.yaml").read_text()
    return set(re.findall(r"^  ([a-z][a-z0-9]*(?::[a-z0-9-]+)*):$", text, re.M))


def candidates(text: str):
    """(line, reference, came-from-a-link) for each claim outside fenced code."""
    body = strip_fences(text)
    for lineno, line in enumerate(body.splitlines(), 1):
        for m in LINK.finditer(line):
            yield lineno, m.group(1), True
        m = LINK_DEF.match(line)
        if m:
            yield lineno, m.group(1), True
        for m in CODE_SPAN.finditer(line):
            yield lineno, m.group(1), False


def command_spans(text: str):
    """(line, command) for every span written as a shell command.

    Two spellings count: a backticked span, and a line inside a fenced block.
    Both are the author saying "this is a command", which is what makes the
    target a claim rather than a word.
    """
    inside = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            inside = not inside
            continue
        if inside:
            yield lineno, line.strip().lstrip("$ ").strip()
            continue
        for m in CODE_SPAN.finditer(line):
            yield lineno, m.group(1).strip().lstrip("$ ").strip()


def is_repo_path(ref: str, from_link: bool, rooted: tuple[str, ...]) -> bool:
    if ref.startswith(("http://", "https://", "mailto:", "#", "oci://", "git@")):
        return False
    if PLACEHOLDER.search(ref):
        return False
    ref = ref.split("#", 1)[0].strip()
    if not ref or ref.startswith("/") or " " in ref:
        return False
    if from_link:
        return True
    return ref.startswith(rooted)


def index_by_name(root: pathlib.Path) -> dict[str, list[pathlib.Path]]:
    """basename -> files carrying it, so a bare-filename citation can resolve."""
    idx: dict[str, list[pathlib.Path]] = {}
    for p in root.rglob("*"):
        if p.is_file() and ".git" not in p.parts and "rendered" not in p.parts:
            idx.setdefault(p.name, []).append(p)
    return idx


def resolve(root, doc, target, by_name) -> pathlib.Path | None:
    """The file a citation names, or None when it is absent or ambiguous.

    A bare filename resolves only when exactly one file in the tree carries it.
    Two candidates means the citation does not identify a file and this gate
    cannot say which line count to check against — reported as nothing rather
    than as a guess.
    """
    for base in (doc.parent, root):
        if (base / target).is_file():
            return base / target
    if "/" not in target:
        hits = by_name.get(target, [])
        if len(hits) == 1:
            return hits[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(ROOT), help="tree to check (default: the repo)")
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()

    docs = sorted(p for p in root.rglob("*.md")
                  if ".git" not in p.parts and "rendered" not in p.parts)
    if len(docs) < MIN_DOCS:
        print(f"FAIL  found {len(docs)} markdown file(s), fewer than the {MIN_DOCS} this "
              f"repo carries — the glob no longer matches the tree, so a pass here "
              f"would prove nothing.")
        return 2

    targets = task_targets(root)
    if not targets:
        print("FAIL  read no task targets out of Taskfile.yaml — the parser and the "
              "Taskfile disagree, so every `task ...` reference would pass unchecked.")
        return 2

    rooted = rooted_prefixes(root)
    by_name = index_by_name(root)
    failures: list[str] = []
    checked = 0

    for doc in docs:
        rel_doc = doc.relative_to(root)
        text = doc.read_text()

        for lineno, ref, from_link in candidates(text):
            if not is_repo_path(ref, from_link, rooted):
                continue
            checked += 1
            bare = ref.split("#", 1)[0].strip().rstrip("/")
            # Relative to the document, then to the repo root: both spellings
            # appear in this tree and both are legitimate.
            if (doc.parent / bare).exists() or (root / bare).exists():
                continue
            failures.append(f"{rel_doc}:{lineno}: `{ref}` names no file or directory")

        for lineno, cmd in command_spans(text):
            m = TASK_REF.match(cmd)
            if not m:
                continue
            name = m.group(1)
            checked += 1
            if name not in targets:
                failures.append(
                    f"{rel_doc}:{lineno}: `task {name}` names no target the "
                    f"Taskfile defines")

        # Citations are read from the RAW line, not from backticked spans:
        # this repo writes them as bare prose ("wired as the CI fork-safety job
        # (ci.yml:122-130)"), so the view that finds paths would find none of
        # them.
        for lineno, line in enumerate(strip_fences(text).splitlines(), 1):
            for m in CITATION.finditer(line):
                target, lo = m.group(1), int(m.group(2))
                hi = int(m.group(3) or lo)
                cited = resolve(root, doc, target, by_name)
                if cited is None:
                    continue  # ambiguous or absent; the path half covers absence
                checked += 1
                total = len(cited.read_text().splitlines())
                if hi > total:
                    failures.append(
                        f"{rel_doc}:{lineno}: cites {target}:{m.group(2)}"
                        f"{'-' + m.group(3) if m.group(3) else ''} but "
                        f"{cited.relative_to(root)} has {total} line(s) — the citation "
                        f"outlived the lines it named")

    if checked < MIN_REFS:
        print(f"FAIL  extracted only {checked} reference(s) from {len(docs)} document(s), "
              f"fewer than the {MIN_REFS} this repo's prose carries — the extractor is "
              f"matching almost nothing.")
        return 2

    if failures:
        print(f"Prose names {len(failures)} thing(s) that do not resolve:\n")
        for f in failures:
            print(f"  {f}")
        print("\n  Prose that names a path, a target or a script is a claim about the")
        print("  world. State the requirement, or give the command that answers it,")
        print("  or fix the reference.")
        return 1

    print(f"✓ all {checked} path/target reference(s) across {len(docs)} document(s) resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
