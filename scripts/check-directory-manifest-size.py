#!/usr/bin/env python3
"""Every directory-source Application fits the repo-server's combined-manifest ceiling.

    python3 scripts/check-directory-manifest-size.py             # blocking gate, offline
    python3 scripts/check-directory-manifest-size.py --live      # scheduled, clones each pinned source
    python3 scripts/check-directory-manifest-size.py --sync      # re-measure and rewrite the records
    python3 scripts/check-directory-manifest-size.py --self-test

WHAT THE RUNTIME DOES

argocd-repo-server walks a directory-type source, accumulates the size of every
file whose name matches `^.*\\.(yaml|yml|json|jsonnet)$` (jsonnet excluded from
the sum), and aborts generation the moment the running total exceeds
`--max-combined-directory-manifests-size`. The Application then renders nothing.
It does not go `OutOfSync`; it goes `ComparisonError`, and the sync column reads
`Unknown` — which is the state a human scanning a list of Applications is least
likely to stop at. The symptom surfaces waves later as whatever workload needed
the kind that never installed.

WHICH SOURCES THIS IS ABOUT

Not every source with a `path`. ArgoCD decides the source type first, and only
the Directory type is measured this way: an explicit `helm`, `kustomize` or
`plugin` block names the type outright, an explicit `directory` block names
Directory, and a source with none of them is classified by what the directory
holds — a `Chart.yaml` makes it Helm, a kustomization file makes it Kustomize,
anything else is Directory. So the population is derived by running that same
decision over the tree rather than by listing the sources somebody noticed. A
kustomization file deleted out of an overlay does not merely break a build; it
reclassifies that source into this gate's corpus.

Scope is `applicationsets/*.yaml`, non-recursive, matching check-hardcoded-org.py
and check-catalog-revision.py: app-of-apps sources `applicationsets` without
`directory.recurse`, so the `opt-in/` subdirectory is not applied by an install
and is not what a cluster runs.

WHERE THE CEILING COMES FROM, AND WHY IT IS NOT DERIVED HERE

It is a repo-server flag, set by whatever installs ArgoCD. This catalog installs
none and pins no ArgoCD version, so there is nothing in this tree to read it from
and nothing to derive it against. It is therefore GATED, not derived:
contracts/repo-server.json records the size the host must be configured for, and
the repository that configures the repo-server is where the two are held equal.
contracts/secret-store.json publishes a value this catalog declares for others to
assert against; this one runs the other way, publishing what this catalog needs
of its host, and the contract directory is what makes either assertable from
outside.

The comparison itself is the runtime's, not a margin on it: the repo-server
accumulates and aborts when the total EXCEEDS the limit, so a source exactly
filling the ceiling still generates, and this rejects at the same byte. Headroom
comes from somewhere better than a threshold fraction. The measurements are a
function of (repoURL, targetRevision, path), so a pin cannot move without its
record going stale, and a stale record fails the offline gate on the pull request
that moves the pin — every byte of growth arrives as a diff in
scripts/directory-sources.json, rather than one warning at whatever percentage
somebody picked.

THE TWO QUESTIONS, AND WHY ONLY ONE BLOCKS

    default (offline, BLOCKING) — the corpus and the records agree, every
        recorded size is under the contracted ceiling, and every in-repo
        directory source measures under it right now. A function of the tree.

    --live (network, SCHEDULED) — resolve each pinned source at its revision and
        confirm it still measures what the record says. Splitting it this way is
        the same reason check-chart-deprecation.py splits: the merge path does
        not get to depend on a clone of somebody else's repository.
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"
CONTRACT = ROOT / "contracts" / "repo-server.json"
# Beside the checker rather than beside the appsets, for the reason
# scripts/chart-provenance.json is: applicationsets/ is read by kubeconform as
# manifests, and a record living there would have to be exempted from a schema
# gate to exist.
RECORDS = ROOT / "scripts" / "directory-sources.json"

# argocd-repo-server's own predicates, transcribed. A file counts as a manifest
# by NAME, before anything reads it.
MANIFEST_FILE = re.compile(r"^.*\.(yaml|yml|json|jsonnet)$")
# util/kustomize KustomizationNames. Any one of these makes a directory Kustomize.
KUSTOMIZATION_NAMES = ("kustomization.yaml", "kustomization.yml", "Kustomization")

# The catalog's own repoURL is templated off the cluster Secret, never literal.
URL_ANNOTATION = "gitops/repo-url"

# Seconds one `git clone` of a pinned source may take under --live/--sync.
NETWORK_TIMEOUT = 300

# resource.Quantity suffixes. Decimal and binary are different sizes and reading
# one as the other understates the ceiling, which is the direction that lets a
# source through.
SUFFIXES = {
    "": 1, "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18,
    "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60,
}
QUANTITY = re.compile(r"^(?P<num>\d+)(?P<suffix>[kMGTPE]|[KMGTPE]i|)$")


def die(msg: str) -> None:
    print(f"directory-manifest-size: {msg}", file=sys.stderr)
    sys.exit(1)


def quantity(text: str, where: str) -> int:
    """A k8s resource.Quantity as a byte count, or exit 2 naming where it came from."""
    m = QUANTITY.fullmatch(str(text).strip())
    if not m:
        print(f"Cannot run: {where} holds {text!r}, which is not a quantity "
              f"argocd-repo-server would accept for its combined-manifest ceiling.")
        sys.exit(gatelib.CANNOT_RUN)
    return int(m.group("num")) * SUFFIXES[m.group("suffix")]


def human(n: int) -> str:
    return f"{n / 10**6:.2f}M"


# ------------------------------------------------------------------ the corpus


@dataclass(frozen=True)
class Source:
    """One ApplicationSet source ArgoCD would generate manifests for."""

    appset: str
    file: str
    repo_url: str
    target_revision: str
    path: str
    recurse: bool
    include: str
    exclude: str
    # The in-tree directory this resolves to, when the source is this catalog and
    # the path template expands. None means nothing here can measure it.
    local: pathlib.Path | None

    @property
    def templated(self) -> bool:
        return any("{{" in v for v in (self.repo_url, self.target_revision, self.path))


def sources_of(doc: dict) -> list[dict]:
    """Every source block an ApplicationSet template declares."""
    spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    out = [s for s in (spec.get("sources") or []) if isinstance(s, dict)]
    if isinstance(spec.get("source"), dict):
        out.append(spec["source"])
    return out


def explicit_type(src: dict) -> str | None:
    """ArgoCD's ApplicationSource.ExplicitType, for the fields this catalog uses.

    A `chart` names a Helm source as surely as a `helm` block does; ArgoCD
    reaches the same verdict by a different route, and either way such a source
    is never measured as a directory.
    """
    if src.get("helm") or src.get("chart"):
        return "Helm"
    if src.get("kustomize"):
        return "Kustomize"
    if src.get("plugin"):
        return "Plugin"
    if src.get("directory") is not None:
        return "Directory"
    return None


def discovered_type(local: pathlib.Path) -> str:
    """ArgoCD's util/app/discovery, run against a directory that is in this tree."""
    if (local / "Chart.yaml").is_file():
        return "Helm"
    if any((local / n).is_file() for n in KUSTOMIZATION_NAMES):
        return "Kustomize"
    return "Directory"


def expansions(template: str, doc: dict, environments: list[str]) -> list[str]:
    """The paths a source template resolves to, expanded where that is possible.

    Only the two substitutions this catalog's paths use: the `path` an element of
    a list generator carries, and the environment label off the cluster Secret.
    Anything else comes back with its `{{` intact and the caller treats that
    source as one this repository cannot resolve — a source to record as
    unmeasurable, not one to drop.
    """
    bases = [e["path"] for e in gatelib.list_elements(doc) if isinstance(e.get("path"), str)]
    out = set()
    for base in bases or [None]:
        one = template.replace("{{ .path }}", base) if base else template
        if '{{ index .metadata.labels "environment" }}' in one:
            for env in environments:
                out.add(one.replace('{{ index .metadata.labels "environment" }}', env))
        else:
            out.add(one)
    return sorted(out)


def environments() -> list[str]:
    """The environment labels the overlays in this tree are written for."""
    found = {p.name for p in ROOT.glob("addons/*/*/overlays/*") if p.is_dir()}
    found |= {p.name for p in ROOT.glob("policies/*/*/overlays/*") if p.is_dir()}
    if not found:
        print("Cannot run: no overlay directories under addons/ or policies/, so the "
              "environments a templated source path expands over are unknown.")
        sys.exit(gatelib.CANNOT_RUN)
    return sorted(found)


def directory_sources() -> list[Source]:
    """Every applied source ArgoCD would classify as a Directory, derived from the tree."""
    if not APPSETS.is_dir():
        print(f"Cannot run: {APPSETS} is not a directory. This gate examined nothing, "
              f"which is not the same as finding nothing.")
        sys.exit(gatelib.CANNOT_RUN)

    envs = environments()
    appsets = 0
    considered = 0
    found: list[Source] = []

    for path in sorted(p for p in APPSETS.glob("*.y*ml") if p.is_file()):
        for doc in gatelib.read_yaml_all(path):
            if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
                continue
            appsets += 1
            name = ((doc.get("metadata") or {}).get("name")) or path.stem
            for src in sources_of(doc):
                if "path" not in src:
                    continue
                considered += 1
                kind = explicit_type(src)
                directory = src.get("directory") or {}
                template = str(src["path"])
                repo_url = str(src.get("repoURL", ""))
                revision = str(src.get("targetRevision", ""))

                # A source pointing at this catalog resolves in the tree; anything
                # else is somebody else's repository at a pinned revision. An
                # expansion naming no directory contributes nothing — an addon
                # with no hub overlay is one the cluster selector does not send
                # there, and whether that selector and those overlays agree is
                # what check-env-coverage.py asks.
                locals_: list[pathlib.Path | None] = [None]
                if URL_ANNOTATION in repo_url:
                    expanded = expansions(template, doc, envs)
                    existing = [ROOT / e for e in expanded if "{{" not in e and (ROOT / e).is_dir()]
                    if expanded and not existing:
                        die(f"{name} ({path.name}) sources {template!r} from this catalog "
                            f"and it resolves to no directory in the tree — this gate "
                            f"cannot classify a source it cannot find.")
                    locals_ = list(existing) or [None]

                for local in locals_:
                    verdict = kind or (discovered_type(local) if local else None)
                    # An unclassifiable REMOTE source is a directory source until
                    # something proves otherwise: ArgoCD falls through to Directory
                    # when it finds no Chart.yaml and no kustomization, and this
                    # repository can see neither.
                    undecidable = verdict is None and local is None
                    if verdict != "Directory" and not undecidable:
                        continue
                    found.append(Source(
                        appset=name,
                        file=path.name,
                        repo_url=repo_url,
                        target_revision=revision,
                        path=str(local.relative_to(ROOT)) if local else template,
                        recurse=bool(directory.get("recurse", False)),
                        include=str(directory.get("include", "")),
                        exclude=str(directory.get("exclude", "")),
                        local=local,
                    ))

    if not appsets:
        die(f"read no ApplicationSet out of {APPSETS.relative_to(ROOT)} — the parser "
            f"and the catalog disagree, and a run that examined nothing must not "
            f"report that nothing is wrong.")
    if not considered:
        die(f"read {appsets} ApplicationSet(s) out of {APPSETS.relative_to(ROOT)} and "
            f"not one source with a path. Every source in this catalog carries one, "
            f"so the walk stopped seeing them rather than the catalog changing.")
    return found


def keyed(sources: list[Source]) -> dict[str, Source]:
    """Record keys: the ApplicationSet name, disambiguated by path only when it must be."""
    counts: dict[str, int] = {}
    for s in sources:
        counts[s.appset] = counts.get(s.appset, 0) + 1
    return {(s.appset if counts[s.appset] == 1 else f"{s.appset}#{s.path}"): s
            for s in sources}


# ----------------------------------------------------------------- measurement


def measure(root: pathlib.Path, recurse: bool, include: str, exclude: str) -> tuple[int, int]:
    """(bytes, files) exactly as argocd-repo-server accumulates them.

    Transcribed from getPotentiallyValidManifests: name-matched before it is read,
    include/exclude applied to the path relative to the source root, jsonnet
    counted as a manifest but not against the size, and the size taken from the
    resolved file so a symlink contributes its target's bytes rather than the
    length of its own name.
    """
    total = 0
    files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        here = pathlib.Path(dirpath)
        if not recurse and here != root:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            if not MANIFEST_FILE.match(name):
                continue
            path = here / name
            rel = str(path.relative_to(root))
            if exclude and fnmatch.fnmatch(rel, exclude):
                continue
            if include and not fnmatch.fnmatch(rel, include):
                continue
            if not path.is_file():
                continue        # a symlink to something that is not a regular file
            files += 1
            if name.endswith(".jsonnet"):
                continue
            total += path.stat().st_size
    return total, files


def clone(src: Source, into: pathlib.Path) -> pathlib.Path:
    """The pinned source directory, checked out. Exits 1 naming what would not resolve."""
    gatelib.require("git")
    proc = subprocess.run(
        ["git", "clone", "--quiet", "--depth", "1", "--branch", src.target_revision,
         src.repo_url, str(into)],
        capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
    if proc.returncode != 0:
        last = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
        die(f"{src.appset}: {src.repo_url} at {src.target_revision} would not clone — "
            f"{last[-1][:200] if last else 'no output'}")
    resolved = into / src.path
    if not resolved.is_dir():
        die(f"{src.appset}: {src.repo_url} at {src.target_revision} has no {src.path}/. "
            f"A source path that is not there generates nothing.")
    return resolved


def remeasure(src: Source) -> tuple[int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        return measure(clone(src, pathlib.Path(tmp) / "src"),
                       src.recurse, src.include, src.exclude)


# ------------------------------------------------------------------- the parts


def load_contract() -> dict:
    doc = gatelib.read_json(CONTRACT)
    if "maxCombinedDirectoryManifestsSize" not in doc:
        print(f"Cannot run: {CONTRACT.relative_to(ROOT)} declares no "
              f"maxCombinedDirectoryManifestsSize, so this gate has no ceiling to "
              f"measure against and would report every source as fitting.")
        sys.exit(gatelib.CANNOT_RUN)
    return doc


def load_records() -> dict:
    if not RECORDS.exists():
        die(f"{RECORDS.relative_to(ROOT)} does not exist. Run --sync to create it.")
    return gatelib.read_json(RECORDS).get("sources", {})


COORDINATES = ("repoURL", "targetRevision", "path", "recurse", "include", "exclude")


def coordinates(src: Source) -> dict:
    return {"repoURL": src.repo_url, "targetRevision": src.target_revision,
            "path": src.path, "recurse": src.recurse,
            "include": src.include, "exclude": src.exclude}


# ---------------------------------------------------------------- offline gate


def check_offline(sources: list[Source], recorded: dict, contract: dict) -> int:
    if "maxCombinedDirectoryManifestsSize" not in contract:
        print(f"Cannot run: {CONTRACT.relative_to(ROOT)} declares no "
              f"maxCombinedDirectoryManifestsSize, so this gate has no ceiling to "
              f"measure against and would report every source as fitting.")
        sys.exit(gatelib.CANNOT_RUN)
    ceiling = quantity(contract["maxCombinedDirectoryManifestsSize"],
                       f"{CONTRACT.relative_to(ROOT)} maxCombinedDirectoryManifestsSize")
    stock = quantity(contract.get("argoCdDefault", "10M"),
                     f"{CONTRACT.relative_to(ROOT)} argoCdDefault")

    problems: list[str] = []
    lines: list[str] = []
    corpus = keyed(sources)

    for key, src in sorted(corpus.items()):
        if src.local is not None:
            size, files = measure(src.local, src.recurse, src.include, src.exclude)
            if files == 0:
                problems.append(
                    f"{key} sources {src.path}/ from this catalog and it holds no "
                    f"manifest file. A directory source that generates nothing is not "
                    f"a directory source under the limit.")
                continue
            lines.append(f"{key:24} {human(size):>9}  {100 * size / ceiling:5.1f}% of ceiling  "
                         f"{files:3} file(s)  in-tree")
            if size > ceiling:
                problems.append(
                    f"{key} is {human(size)}, over the "
                    f"{contract['maxCombinedDirectoryManifestsSize']} ceiling "
                    f"{CONTRACT.relative_to(ROOT)} records. The repo-server refuses to "
                    f"generate it and the Application reports ComparisonError, not "
                    f"OutOfSync — the sync column reads Unknown.")
            continue

        rec = recorded.get(key)
        if rec is None:
            problems.append(
                f"{key} ({src.file}) is a directory source with no entry in "
                f"{RECORDS.relative_to(ROOT)}. Nothing bounds what it asks the "
                f"repo-server to combine. Run --sync.")
            continue
        drift = [f for f in COORDINATES if rec.get(f) != coordinates(src)[f]]
        if drift:
            problems.append(
                f"{key} is pinned at coordinates {RECORDS.relative_to(ROOT)} was not "
                f"measured against ({', '.join(drift)}), so the recorded size is a "
                f"measurement of something else. Re-measure with --sync.")
            continue
        if rec.get("bytes") is None:
            if not rec.get("unbounded"):
                problems.append(
                    f"{key} has an entry in {RECORDS.relative_to(ROOT)} with no size "
                    f"and no stated reason it cannot have one. A source nothing "
                    f"measured and nothing excused is the gap this gate exists to "
                    f"close.")
                continue
            lines.append(f"{key:24} {'unbounded':>9}  {rec['unbounded']}")
            continue
        size, files = int(rec["bytes"]), int(rec.get("files", 0))
        if files == 0 or size == 0:
            problems.append(
                f"{key} is recorded in {RECORDS.relative_to(ROOT)} as {size} byte(s) "
                f"across {files} file(s). A measurement of nothing recorded as a pass "
                f"is the defect, not the evidence.")
            continue
        note = "  EXCEEDS A STOCK REPO-SERVER" if size > stock else ""
        lines.append(f"{key:24} {human(size):>9}  {100 * size / ceiling:5.1f}% of ceiling  "
                     f"{files:3} file(s)  {src.target_revision}{note}")
        if size > ceiling:
            problems.append(
                f"{key} measures {human(size)} at {src.target_revision}, over the "
                f"{contract['maxCombinedDirectoryManifestsSize']} ceiling "
                f"{CONTRACT.relative_to(ROOT)} records. The repo-server refuses to "
                f"generate it and the Application reports ComparisonError, not "
                f"OutOfSync — the sync column reads Unknown.")

    for key in sorted(set(recorded) - set(corpus)):
        problems.append(
            f"{key} has an entry in {RECORDS.relative_to(ROOT)} and is no longer a "
            f"directory source in the catalog — drop it, or find out what "
            f"reclassified the source.")

    for line in lines:
        print(f"        {line}")
    if problems:
        print(f"FAIL  {len(problems)} problem(s) across {len(corpus)} directory source(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    {len(corpus)} directory source(s), each under the "
          f"{contract['maxCombinedDirectoryManifestsSize']} ceiling "
          f"{CONTRACT.relative_to(ROOT)} records.")
    return 0


# ------------------------------------------------------------------ live check


def check_live(sources: list[Source], recorded: dict, contract: dict) -> int:
    ceiling = quantity(contract["maxCombinedDirectoryManifestsSize"],
                       f"{CONTRACT.relative_to(ROOT)} maxCombinedDirectoryManifestsSize")
    problems: list[str] = []
    checked = 0

    for key, src in sorted(keyed(sources).items()):
        if src.local is not None or src.templated:
            continue
        size, files = remeasure(src)
        checked += 1
        if files == 0:
            problems.append(
                f"{key}: {src.repo_url} at {src.target_revision} has {src.path}/ but no "
                f"manifest file in it. That source generates nothing.")
            continue
        print(f"        {key:24} {human(size):>9}  {files:3} file(s)  {src.target_revision}")
        rec = recorded.get(key) or {}
        if rec.get("bytes") is not None and int(rec["bytes"]) != size:
            problems.append(
                f"{key} measures {size} byte(s) at {src.target_revision} and "
                f"{RECORDS.relative_to(ROOT)} says {rec['bytes']}. The pin did not "
                f"move, so the tag did — read what changed upstream before running "
                f"--sync.")
        if size > ceiling:
            problems.append(
                f"{key} measures {human(size)}, over the "
                f"{contract['maxCombinedDirectoryManifestsSize']} ceiling "
                f"{CONTRACT.relative_to(ROOT)} records.")

    if not checked:
        die("resolved no pinned directory source, so this run measured nothing. "
            "The offline gate reads the same corpus — if it finds sources and this "
            "does not, the coordinates stopped resolving.")
    if problems:
        print(f"FAIL  {len(problems)} problem(s) across {checked} pinned source(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    all {checked} pinned directory source(s) measure what their record says.")
    return 0


# ------------------------------------------------------------------------ sync


def sync(sources: list[Source], recorded: dict) -> int:
    out: dict[str, dict] = {}
    for key, src in sorted(keyed(sources).items()):
        if src.local is not None:
            continue        # measured on every offline run; a record would go stale
        rec = dict(coordinates(src))
        if src.templated:
            was = recorded.get(key) or {}
            rec["bytes"] = None
            rec["files"] = None
            rec["unbounded"] = was.get("unbounded", "")
            if not rec["unbounded"]:
                die(f"{key} resolves its coordinates from a cluster annotation, so "
                    f"nothing here can measure it. Add an `unbounded` note to "
                    f"{RECORDS.relative_to(ROOT)} saying what bounds it instead, then "
                    f"re-run --sync.")
            print(f"  recorded {key:24} unbounded")
        else:
            size, files = remeasure(src)
            if files == 0:
                die(f"{key}: {src.path}/ at {src.target_revision} holds no manifest "
                    f"file. Recording a zero would make an unmeasured source look "
                    f"like a small one.")
            rec["bytes"], rec["files"] = size, files
            print(f"  recorded {key:24} {human(size):>9}  {files:3} file(s)  "
                  f"{src.target_revision}")
        out[key] = rec

    RECORDS.write_text(json.dumps({"_README": README, "sources": out}, indent=2) + "\n")
    print(f"\nwrote {RECORDS.relative_to(ROOT)} ({len(out)} source(s))")
    return 0


README = (
    "What each directory-source Application asks argocd-repo-server to combine, "
    "measured the way the repo-server measures it. A source over the ceiling in "
    "contracts/repo-server.json generates nothing and reports ComparisonError, "
    "which is quieter than OutOfSync. The sizes are a function of (repoURL, "
    "targetRevision, path): moving a pin makes this record stale, and a stale "
    "record fails the blocking gate, so a bump cannot land without the new size "
    "landing in the same diff. Re-measure with "
    "scripts/check-directory-manifest-size.py --sync."
)


# ------------------------------------------------------------------- self-test


def self_test() -> int:
    """Break each input the offline verdict rests on and confirm it is rejected."""
    import contextlib
    import copy
    import io

    real_sources = directory_sources()
    real_records = load_records()
    real_contract = load_contract()

    def run(s, r, c):
        with contextlib.redirect_stdout(io.StringIO()):
            return check_offline(s, r, c)

    remote = [s for s in real_sources if s.local is None and not s.templated]
    if not remote:
        print("FAIL  no pinned directory source to break — the corpus this self-test "
              "reasons about is not there.")
        return 1
    pinned = sorted(k for k, s in keyed(real_sources).items()
                    if s.local is None and not s.templated)[0]

    breaks = []

    # The ceiling ArgoCD ships with, against the tree as it stands. This is the
    # comparison that was never made: crds/full does not fit a stock repo-server.
    stock = dict(real_contract)
    stock["maxCombinedDirectoryManifestsSize"] = real_contract.get("argoCdDefault", "10M")
    breaks.append(("a source measured against the stock ArgoCD ceiling",
                   real_sources, real_records, stock))

    # A directory source nobody measured.
    r = copy.deepcopy(real_records)
    r.pop(pinned)
    breaks.append(("a directory source with no size record", real_sources, r, real_contract))

    # A record for a source the catalog no longer has.
    r = copy.deepcopy(real_records)
    r["retired-source"] = {"repoURL": "https://example.invalid", "targetRevision": "v0",
                           "path": "crds", "recurse": False, "include": "", "exclude": "",
                           "bytes": 1, "files": 1}
    breaks.append(("a record no directory source claims", real_sources, r, real_contract))

    # The pin moved and the measurement did not.
    r = copy.deepcopy(real_records)
    r[pinned]["targetRevision"] = "some-other-tag"
    breaks.append(("a record measured at a revision nothing pins",
                   real_sources, r, real_contract))

    # A measurement of nothing, recorded as a pass.
    r = copy.deepcopy(real_records)
    r[pinned]["bytes"], r[pinned]["files"] = 0, 0
    breaks.append(("a source recorded as zero bytes over zero files",
                   real_sources, r, real_contract))

    # An unmeasurable source with no stated reason.
    r = copy.deepcopy(real_records)
    r[pinned]["bytes"] = None
    breaks.append(("a source with no size and no reason it has none",
                   real_sources, r, real_contract))

    failures = []
    for label, s, r, c in breaks:
        if run(s, r, c) == 0:
            failures.append(label)
            print(f"  ACCEPTED  {label}   <-- not caught")
        else:
            print(f"  rejected  {label}")

    if run(real_sources, real_records, real_contract) != 0:
        failures.append("the shipped catalog does not pass")
        print("  ACCEPTED  (control) the shipped catalog is rejected")
    else:
        print(f"  passed    (control) the shipped catalog, {len(real_sources)} source(s)")

    if failures:
        print(f"\nFAIL  {len(failures)} break(s) not caught.")
        return 1
    print(f"\nOK    all {len(breaks)} breaks rejected, and the shipped catalog passes.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--live", action="store_true",
                    help="clone each pinned source and re-measure it (network)")
    ap.add_argument("--sync", action="store_true",
                    help="rewrite the size records from upstream (network)")
    ap.add_argument("--self-test", action="store_true",
                    help="break the offline gate's inputs and confirm each is caught")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.sync:
        return sync(directory_sources(), load_records() if RECORDS.exists() else {})
    if args.live:
        return check_live(directory_sources(), load_records(), load_contract())
    return check_offline(directory_sources(), load_records(), load_contract())


if __name__ == "__main__":
    sys.exit(main())
