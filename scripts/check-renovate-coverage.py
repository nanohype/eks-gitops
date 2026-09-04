#!/usr/bin/env python3
"""Every version this repo pins is watched by a manager that resolves it.

Two populations, derived rather than listed. The chart pins come from the
Application ArgoCD renders; the toolchain pins come from what a workflow step
actually consumes — a `uses:` reference, a file a setup action reads as the
version to install, a lockfile a job installs from. A list of files to look in is
a list of the pins somebody remembered, and the pin nobody remembered is the one
that ages.

A Renovate manager that detects a pin is not the same as a manager that can look
it up. Both failures are silent in opposite ways:

  - A customManager whose regex matches nothing is valid config.
    `renovate-config-validator` passes it happily — the schema is fine and the
    pattern is never run against a file. Nothing watches the pin, and nothing
    says so.

  - The built-in argocd manager reads `repoURL` + `chart` and concatenates them
    into a package name. Two appsets here deliberately repeat the chart name in
    repoURL, because ArgoCD resolves the OCI digest from repoURL alone. The
    manager therefore *detects* those pins and derives `.../operator/operator`
    and `.../karpenter/karpenter`, which are not packages. Renovate reports the
    lookup failure on the Dependency Dashboard and nowhere else, so the pins age
    in silence while the config looks complete.

COVERAGE IS REACH, NOT ATTRIBUTION

A manager on enabledManagers is a manager Renovate runs. Which files it opens is
managerFilePatterns, and a pattern naming a path this repo does not have is
valid config that opens nothing: the schema is fine so the validator passes, no
lookup is attempted so the Dependency Dashboard reports no failure, and the only
symptom is a version that stops moving. So every pin is matched against the
patterns of the manager it is attributed to — per customManager rather than
against a pool, because repointing one manager leaves the pins it read watched
by nothing while every other manager still matches something.

A manager configuring no managerFilePatterns runs on the defaultConfig shipped
inside the Renovate package, which no offline gate reads. That default is
transcribed into scripts/renovate-manager-defaults.json and used here, so every
pin is matched against a real pattern rather than certified by attribution. What
keeps the transcript honest is scripts/check-renovate-defaults.mjs, which
re-resolves every entry against the package and fails on any difference: a stale
record would certify pins against a pattern Renovate does not use and print the
same success as a correct one. The renovate-coverage CI job runs it beside
renovate-config-validator, which is where the package already is.

Two managers this repo enables ship an EMPTY default — argocd and pip-compile —
so a manager with no effective pattern at all is a live shape and fails here.

So this reads the customManager regexes out of renovate.json — the shipped ones,
not a copy — applies them to applicationsets/, and decides coverage per pin:

  matrix-list pins        must be matched by a customManager
  direct-source, https    the argocd manager resolves these correctly
  direct-source, oci      the argocd manager resolves these correctly ONLY when
                          repoURL's last segment differs from the chart name;
                          otherwise a customManager must cover it

Which manager can read a pin does depend on how it is written, because Renovate
reads files. What a pin MEANS does not, so every assertion about the pin itself
runs over the coordinates ArgoCD renders: a matrix appset templates repoURL from
its list element's chartRepo, and the Application that reaches the cluster is
indistinguishable from one written with the coordinates inline. Deciding those
assertions from source syntax made pinning style the thing that chose what got
checked, which is how three OCI charts pinned through a matrix went unasserted.

Edit a regex and break coverage, and this fails. Add an appset in a shape no
manager reads, and this fails. That is the point: the next new shape does not get
to introduce the same blind spot quietly.

It also rejects regex constructs Renovate cannot run. Renovate uses RE2, which
has no backreferences and no lookaround; Python's `re` has both. A pattern using
them would pass here and match nothing in production.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
from typing import NamedTuple, NoReturn

import yaml

# Shared helpers, loaded by path: these are hyphenated executables run from
# varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"


def appset_files() -> list[pathlib.Path]:
    """The top-level ApplicationSets, in both spellings YAML has.

    Renovate's file pattern for this directory admits `.yml` and `.yaml`, and so
    does ArgoCD. A glob reading one spelling leaves the other applied to every
    cluster and in no population this gate builds — including the literal floor
    below, which globbed the same way and so could not see the gap.

    One definition because three call sites read this directory and a fourth
    counts it in the summary. Spelled separately they drift, and the direction
    they drift is quiet: a file drops out of the walk and out of the floor at
    once, and the run prints the success it printed the day before.
    """
    if not APPSETS.is_dir():
        _cannot_run("applicationsets/", "does not exist, so the chart-pin corpus "
                                        "this gate reports on is not there at all")
    return sorted(p for p in APPSETS.iterdir()
                  if p.is_file() and p.suffix in {".yaml", ".yml"})

# Valid in Python's re, absent from RE2. A pattern using one of these would pass
# locally and match nothing when Renovate runs it.
RE2_UNSUPPORTED = [
    (r"\(\?=", "lookahead (?=...)"),
    (r"\(\?!", "negative lookahead (?!...)"),
    (r"\(\?<=", "lookbehind (?<=...)"),
    (r"\(\?<!", "negative lookbehind (?<!...)"),
    (r"\\[1-9]", "backreference"),
    (r"\\k<", "named backreference"),
]

# The two pin shapes this catalog uses, as literal text. Kept here rather than
# read from renovate.json on purpose: this is the ground truth the config is
# checked against, so deriving it from the config would make the check circular.
#
# These no longer drive the walk — rendered_pins() does — and are retained as an
# independent floor under it. A parser and a regex fail on different inputs, so a
# structural derivation that stops seeing a shape is caught by the one that reads
# the bytes, rather than shrinking the corpus in silence.
MATRIX = re.compile(
    r"chartRepo:\s*(?P<repo>\S+)\s*\n\s*chart:\s*(?P<chart>\S+)\s*\n\s*chartVersion:\s*\"?(?P<ver>[^\"\s]+)\"?"
)
DIRECT = re.compile(
    r"repoURL:\s*(?P<repo>(?:oci|https)://\S+)\s*\n\s*chart:\s*(?P<chart>\S+)\s*\n\s*targetRevision:\s*\"?(?P<ver>[^\"\s]+)\"?"
)

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


class CustomManager(NamedTuple):
    """One customManager: what it recognises, and which files it opens.

    The two halves are kept together because either alone certifies nothing. The
    matchStrings decide whether the manager recognises a pin; the
    managerFilePatterns decide whether it ever reads the file the pin is in. A
    pooled list of matchStrings answers the first question for the repository
    and the second for no one, so repointing any single manager's file patterns
    leaves every pin it read still reported as covered.
    """

    where: str                          # how renovate.json identifies it
    file_patterns: list[str]
    matchers: list[re.Pattern[str]]


def load_custom_managers() -> list[CustomManager]:
    cfg = gatelib.read_json(ROOT / "renovate.json")
    managers = cfg.get("customManagers") or []
    if not managers:
        fail("renovate.json declares no customManagers, so no chart pin in "
             "applicationsets/ is watched by anything.")
        return []

    out: list[CustomManager] = []
    for i, m in enumerate(managers):
        where = f"customManagers[{i}]"
        matchers: list[re.Pattern[str]] = []
        for s in m.get("matchStrings") or []:
            for probe, label in RE2_UNSUPPORTED:
                if re.search(probe, s):
                    fail(f"{where}: matchString uses {label}, which RE2 does not "
                         f"support. Renovate would match nothing:\n      {s}")
                    break
            else:
                # RE2 and Python spell named groups differently: `(?<name>)` vs
                # `(?P<name>)`. renovate.json carries the RE2 form, translated
                # here to run under Python. Safe only because the lookbehind
                # forms were rejected above — after that, a remaining `(?<` can
                # only be a named group.
                try:
                    matchers.append(re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", s)))
                except re.error as exc:
                    fail(f"{where}: matchString is not a valid regex ({exc}):\n      {s}")
        patterns = m.get("managerFilePatterns")
        out.append(CustomManager(
            where, list(patterns) if isinstance(patterns, list) else [], matchers))
    return out


# A field an ApplicationSet templates from a generator, in the only form this
# catalog uses: the whole value is one dotted key. Any other form — a sprig call,
# a concatenation, `index . "chartRepo"` — is REPORTED rather than resolved by
# guessing, because a value this cannot render is a pin whose coordinates are
# unknown, and an unknown pin admitted to the walk as a literal lands in the one
# branch that asserts nothing about it while still counting toward the total.
TEMPLATED_KEY = re.compile(r"^\s*\{\{\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}\s*$")

# The three fields that locate a chart, in the order ArgoCD reads them.
COORDS = ("repoURL", "chart", "targetRevision")


class Pin:
    """One chart pin as ArgoCD renders it, plus how it was written.

    `repo`/`chart`/`version` are the coordinates that reach the cluster, so every
    assertion about the pin itself reads them. `matrix` records the source shape,
    which stays relevant for exactly one question — whether Renovate's built-in
    argocd manager can see the pin — because Renovate reads the file, not the
    render.
    """

    def __init__(self, appset, rel, text, repo, chart, version, matrix):
        self.appset, self.rel, self.text = appset, rel, text
        self.repo, self.chart, self.version, self.matrix = repo, chart, version, matrix

    @property
    def is_oci(self) -> bool:
        return self.repo.startswith("oci://")


def _cannot_run(rel, detail: str) -> NoReturn:
    """Exit 2, not 1: a shape this cannot read is not a tree it examined.

    An uncaught AttributeError on a manifest that parses but nests something
    unexpected exits 1, which is the status this gate uses for "the tree is
    wrong". A reader cannot tell those apart, and the traceback names a line of
    this file rather than the manifest to fix.
    """
    print(f"Cannot run: {rel} — {detail}")
    print("This gate examined nothing past that file, which is not the same as "
          "finding nothing.")
    sys.exit(gatelib.CANNOT_RUN)


def _chart_sources(tspec: dict, rel) -> list[dict]:
    """EVERY template source that names a Helm chart.

    Reading only the first was a blind spot of exactly the kind this gate is
    for: a template may carry several chart sources, and the ones after the
    first would be rendered onto a cluster while the summary line counted the
    pins it did see.
    """
    sources = tspec.get("sources")
    if sources is None:
        one = tspec.get("source")
        sources = [one] if isinstance(one, dict) else []
    if not isinstance(sources, list):
        _cannot_run(rel, f"spec.template.spec.sources is {type(sources).__name__}, "
                         f"not a list")
    return [s for s in sources if isinstance(s, dict) and "chart" in s]


def _list_elements(spec: dict, rel) -> list[dict]:
    """Elements of EVERY list generator, not the first one found.

    A matrix combines axes, and only one of them carries chart coordinates; the
    others (cluster selectors, tiers) contribute elements that name none of the
    templated keys and are skipped below. An appset in this catalog already
    declares two matrix generators each with its own list, so stopping at the
    first drops a whole generator's pins out of the walk.
    """
    if not isinstance(spec.get("generators") or [], list):
        _cannot_run(rel, "spec.generators is not a list")
    found: list[dict] = []
    for gen in spec.get("generators") or []:
        if not isinstance(gen, dict):
            _cannot_run(rel, f"a spec.generators entry is {type(gen).__name__}, "
                             f"not a mapping")
        for inner in (gen.get("matrix") or {}).get("generators") or []:
            if not isinstance(inner, dict):
                _cannot_run(rel, "a matrix generator entry is not a mapping")
            found.extend((inner.get("list") or {}).get("elements") or [])
        found.extend((gen.get("list") or {}).get("elements") or [])
    return [e for e in found if isinstance(e, dict)]


def _templated_keys(src: dict, rel) -> dict[str, str]:
    """Which coordinate fields are templated, and from which generator key.

    A field holding `{{` in any other spelling fails here rather than being
    passed through as a literal: the render is what every downstream assertion
    reads, so a coordinate this cannot render must not reach them disguised as
    one it could.
    """
    keys: dict[str, str] = {}
    for field in COORDS:
        value = src.get(field)
        if not isinstance(value, str) or "{{" not in value:
            continue
        m = TEMPLATED_KEY.match(value)
        if not m:
            fail(f"{rel}: {field} is templated as {value!r}, a form this cannot "
                 f"render. Its coordinates are unknown, so the pin would be walked "
                 f"as though {value!r} were a registry path and asserted about "
                 f"nothing.")
            continue
        keys[field] = m.group(1)
    return keys


def _literal(field: str, value, rel, what: str) -> str | None:
    """A coordinate written inline, rejected rather than coerced when it is not text."""
    if value is None:
        fail(f"{rel}: {what} has no {field}, so its chart coordinates cannot be "
             f"reconstructed and the pin would drop out of this walk unexamined.")
        return None
    if not isinstance(value, str):
        fail(f"{rel}: {what} sets {field} to {value!r}, which YAML parsed as "
             f"{type(value).__name__} rather than text. Quote it: a version read as "
             f"a number does not round-trip ('1.10' becomes '1.1'), so the pin would "
             f"be compared against a string that appears nowhere in the repo.")
        return None
    return value


def rendered_pins() -> list[Pin]:
    r"""Every chart pin in the top level of applicationsets/, as ArgoCD renders it.

    Top level because that is the scope Renovate's own managerFilePatterns reach
    (`^applicationsets/[^/]+\.ya?ml$`); a pin below it is watched by nothing, and
    the two files that live there are asserted to carry none by NO_PINS.

    A matrix appset is one Application per chart-bearing list element, so it is
    one pin per element here; a literal source is one pin. Both arrive with the
    same three fields, which is the point — nothing downstream has to know which
    it was.
    """
    pins: list[Pin] = []
    for path in appset_files():
        rel = path.relative_to(ROOT)
        text = path.read_text()
        for doc in gatelib.read_yaml_all(path):
            if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
                continue
            spec = doc.get("spec")
            if not isinstance(spec, dict):
                _cannot_run(rel, "an ApplicationSet has no mapping at spec")
            tspec = (spec.get("template") or {}).get("spec")
            if not isinstance(tspec, dict):
                continue
            for src in _chart_sources(tspec, rel):
                keys = _templated_keys(src, rel)
                if not keys:
                    what = "its chart source"
                    repo, chart, ver = (_literal(f, src.get(f), rel, what)
                                        for f in COORDS)
                    if None not in (repo, chart, ver):
                        pins.append(Pin(path.name, rel, text, repo, chart, ver, False))
                    continue

                elements = _list_elements(spec, rel)
                if not elements:
                    fail(f"{rel}: its source templates {', '.join(sorted(keys))} but no "
                         f"list generator supplies elements, so its pins are invisible "
                         f"here.")
                    continue
                for el in elements:
                    have = [k for k in keys.values() if k in el]
                    if not have:
                        continue  # a different axis of the matrix — clusters, tiers
                    what = f"list element {el.get('appName', el)!r}"
                    if len(have) != len(keys):
                        missing = sorted(set(keys.values()) - set(have))
                        fail(f"{rel}: {what} sets {', '.join(sorted(have))} but not "
                             f"{', '.join(missing)}, so it is a chart-bearing element "
                             f"whose coordinates cannot be completed.")
                        continue
                    vals = []
                    for field in COORDS:
                        if field in keys:
                            vals.append(_literal(field, el.get(keys[field]), rel, what))
                        else:
                            vals.append(_literal(field, src.get(field), rel, what))
                    if None in vals:
                        continue
                    repo, chart, ver = vals
                    pins.append(Pin(path.name, rel, text, repo, chart, ver, True))
    return pins


def assert_corpus_floor(pins: list[Pin]) -> None:
    """The rendered walk sees at least every pin the literal shapes do, PER FILE.

    The two are derived differently on purpose. If a parser change, a schema the
    appsets start using, or a template form this cannot render drops a pin, the
    walk gets quieter and reports exactly what a clean run reports — so the count
    the regexes find is asserted as a floor under it.

    Per file rather than in total, because a repo-wide sum lets slack in one file
    pay for a real drop in another: a shape the regex misses anywhere raises the
    number of genuine omissions the floor tolerates everywhere.
    """
    for path in appset_files():
        text = path.read_text()
        for label, rx, matrix in (("matrix-list", MATRIX, True),
                                  ("direct-source", DIRECT, False)):
            literal = len(rx.findall(text))
            walked = sum(1 for p in pins if p.appset == path.name and p.matrix is matrix)
            if walked < literal:
                fail(f"{path.relative_to(ROOT)}: the rendered walk found {walked} "
                     f"{label} pin(s) where the literal {label} shape appears "
                     f"{literal} time(s). Pins dropped out of the walk, which reports "
                     f"the same success as a file with none missing.")


# ── Reach: whether the manager attributed to a pin opens the pin's file ──────

# A managerFilePatterns entry wrapped in slashes is a regular expression. A bare
# value is a minimatch glob, which is a different language and is refused rather
# than guessed at.
FILE_PATTERN = re.compile(r"^/(?P<body>.*)/(?P<flags>[a-z]*)$", re.S)
FILE_PATTERN_FLAGS = {"i": re.IGNORECASE}

_file_patterns: dict[str, re.Pattern[str]] = {}


def compile_file_pattern(raw: str) -> re.Pattern[str]:
    """One managerFilePatterns entry, as a matcher over repo-relative paths."""
    if raw in _file_patterns:
        return _file_patterns[raw]
    m = FILE_PATTERN.match(raw)
    if not m:
        _cannot_run("renovate.json",
                    f"sets the managerFilePattern {raw!r}, which is not the /regex/ "
                    f"form. Renovate reads a bare value as a minimatch glob, this "
                    f"gate implements only the regex form, and which files that "
                    f"pattern reaches is therefore unknown here")
    body, flags = m.group("body"), m.group("flags")
    for probe, label in RE2_UNSUPPORTED:
        if re.search(probe, body):
            _cannot_run("renovate.json",
                        f"sets the managerFilePattern {raw!r}, which uses {label}. "
                        f"RE2 does not support it, so Renovate opens no file with it")
    unknown = [f for f in flags if f not in FILE_PATTERN_FLAGS]
    if unknown:
        _cannot_run("renovate.json",
                    f"sets the managerFilePattern {raw!r} with flag {''.join(unknown)!r}, "
                    f"which this gate does not implement")
    try:
        compiled = re.compile(body, sum(FILE_PATTERN_FLAGS[f] for f in flags) if flags else 0)
    except re.error as exc:
        _cannot_run("renovate.json",
                    f"sets the managerFilePattern {raw!r}, which is not a valid "
                    f"regex ({exc})")
    _file_patterns[raw] = compiled
    return compiled


# defaultConfig.managerFilePatterns per manager, transcribed from the Renovate
# package because a Python gate with no network cannot import it. What keeps the
# transcript honest is scripts/check-renovate-defaults.mjs, which re-resolves
# every entry against the shipped package and fails on any difference — a stale
# record is worse than none, because it certifies pins against a pattern
# Renovate does not use and prints the same success.
RECORDED_DEFAULTS = ROOT / "scripts" / "renovate-manager-defaults.json"

# Where each pin's pattern came from, accumulated as pins are certified and
# printed on every run. Two sources rather than one total: a pattern this
# repository configures is a decision someone here made, and an upstream default
# is a decision that moves without this repository changing.
reach_configured: list[tuple[str, str]] = []
reach_recorded: list[tuple[str, str]] = []


class FilePatterns(NamedTuple):
    """The patterns a manager runs with, and which decision put them there."""

    patterns: list[str]
    origin: str


def manager_file_patterns(cfg, manager: str) -> FilePatterns:
    """The file patterns `manager` actually runs with, and where they came from.

    What renovate.json configures, which REPLACES the default; otherwise the
    recorded default. A manager absent from the record stops the gate rather
    than defaulting to unconstrained: "no pattern recorded" and "reads every
    file" are opposite answers and only one of them is safe to guess.
    """
    block = cfg.get(manager)
    if isinstance(block, dict):
        configured = block.get("managerFilePatterns")
        if isinstance(configured, list) and configured:
            return FilePatterns(list(configured), "renovate.json")

    record = gatelib.read_json(RECORDED_DEFAULTS).get("managers") or {}
    if manager not in record:
        _cannot_run(RECORDED_DEFAULTS.relative_to(ROOT),
                    f"records no default for the {manager} manager, which renovate.json "
                    f"enables and configures no managerFilePatterns for. Re-record with "
                    f"`node scripts/check-renovate-defaults.mjs --write`")
    default = record[manager]
    return FilePatterns(list(default) if isinstance(default, list) else [],
                        "the recorded default")


def assert_reach(manager: str, found: FilePatterns, source: str, what: str) -> None:
    """Whether the manager a pin is attributed to reads the file the pin is in.

    enabledManagers says Renovate RUNS a manager. managerFilePatterns says which
    files it opens, and a pattern naming a path this repo does not have is valid
    config that opens nothing: the schema is fine so the validator passes, no
    lookup is attempted so the Dependency Dashboard shows no failure, and the
    only symptom is a version that stops moving. A manager's name on the
    allowlist is attribution; attribution is not coverage.

    An empty pattern set is the same defect with no pattern to point at. Two
    managers this repository enables ship one — argocd and pip-compile — so it
    is a live shape rather than a hypothetical, and renovate.json configures
    both for that reason.
    """
    patterns, origin = found
    if not patterns:
        fail(f"{source}: {what} is attributed to the {manager} manager, which has no "
             f"file patterns at all — renovate.json configures none and the manager's "
             f"own default is empty. It opens no file, so nothing looks the pin up.")
        return
    if any(compile_file_pattern(raw).search(source) for raw in patterns):
        tally = reach_configured if origin == "renovate.json" else reach_recorded
        tally.append((manager, source))
        return
    fail(f"{source}: {what} is attributed to the {manager} manager and none of the "
         f"managerFilePatterns it runs with reaches that file — {', '.join(patterns)}, "
         f"from {origin}. Renovate runs the manager, the manager opens no such file, "
         f"and the config reads as coverage.")


def covered_by_custom(text: str, chart: str, ver: str,
                      managers: list[CustomManager]) -> CustomManager | None:
    """The customManager matching this exact pin (identified by chart + version).

    The manager rather than a yes: which one matched is what decides whose
    managerFilePatterns have to reach the file, and a pooled answer cannot say.

    Every comparison here is exact. A substring test — which this used to do —
    reports `loki` as covered by a `loki-distributed` pin at the same version,
    so a chart nothing watches passes the gate. That is the one failure this
    gate must not have: a false positive is silent in precisely the way an
    unwatched pin is.
    """
    for cm in managers:
        for pat in cm.matchers:
            for m in pat.finditer(text):
                gd = m.groupdict()
                if gd.get("currentValue") != ver:
                    continue

                # https matrix + CLI-tool managers capture the chart as depName.
                if gd.get("depName") == chart:
                    return cm

                # OCI managers capture the registry path, whose last segment is
                # the chart name (.../charts/operator,
                # public.ecr.aws/karpenter/karpenter).
                pkg = gd.get("packageName")
                if pkg and pkg.rstrip("/").rsplit("/", 1)[-1] == chart:
                    return cm

                # The matrix OCI manager does not capture the chart name at all,
                # so fall back to the `chart:` line inside the matched span —
                # anchored, not a containment test.
                if re.search(rf"chart:\s*{re.escape(chart)}\s*$", m.group(0), re.M):
                    return cm
    return None


# ── The toolchain a job runs on ──────────────────────────────────────────────
#
# Derived from the workflows rather than listed here, because a list of files to
# look in is a list of the pins somebody remembered. What a workflow RESOLVES is
# a fact about the workflow: `uses:` is an action reference GitHub resolves,
# `python-version-file:` and `go-version-file:` name files the setup actions read
# as the version to install, and `pip install -r` names a lockfile the job
# installs from. Adding a step that pins something new therefore adds a pin here
# without an edit to this gate.
#
# Each derived pin carries the MANAGER that would have to see it. That mapping is
# the part a reader has to check, so it is stated per family below and asserted
# in both directions: a pin no enabled manager claims fails, and an enabled
# manager no pin is attributed to fails.

# What a `uses:` reference looks like once GitHub has resolved it: owner/repo,
# optionally with a subdirectory, at a ref.
#
# Two other `uses:` forms resolve to no upstream action and are excluded by
# shape rather than by hoping they never appear. A local step (`./path`) is this
# repository, so there is nothing upstream to watch. A container step
# (`docker://image@digest`) is an image reference — the digest after the `@` is
# not a ref, `docker://image` is not a package Renovate's github-actions manager
# looks up, and admitting one would put a pin in the population that no manager
# can ever claim.
USES_PIN = re.compile(r"^(?!\.|docker://)(?P<dep>[^@\s]+)@(?P<ver>\S+)$")

# `pip install --require-hashes -r requirements.txt` — the lockfile a job installs.
PIP_REQUIREMENTS = re.compile(r"pip install[^\n]*?-r\s+(?P<path>[\w./-]+)")

# A pinned distribution in a pip-compile lockfile.
PIP_PIN = re.compile(r"^(?P<dep>[A-Za-z0-9][\w.-]*)==(?P<ver>[^\s\\]+)", re.M)

# The `go` directive, which is the toolchain the appset-render job builds with —
# separate from the tab-indented requires the Go module family already reads.
GO_DIRECTIVE = re.compile(r"^go\s+(?P<ver>[0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$", re.M)


class DerivedPin(NamedTuple):
    family: str
    manager: str
    source: str   # the file the pin is written in
    via: str      # the workflow step or key that resolves it
    dep: str
    version: str


def workflow_files() -> list[pathlib.Path]:
    return sorted(p for p in (ROOT / ".github" / "workflows").glob("*.y*ml")
                  if p.is_file())


# A `with:` key naming a file whose contents ARE the version a setup step
# installs. Recognised by shape rather than by a list of keys: with a list, a
# step pinning a runtime nobody wrote a key for is not passed over — it is
# invisible, which reports the same as a repository that pins nothing.
VERSION_FILE_KEY = re.compile(r"^(?P<runtime>[a-z][a-z0-9]*)-version-file$")


def _steps(doc: dict):
    """Every step of every job, which is what GitHub actually runs."""
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict):
                yield step


def _called_workflows(doc: dict):
    """(job id, `uses:`) for every job that CALLS a workflow instead of running steps.

    A separate walk from _steps on purpose. A reusable-workflow reference sits on
    the job, not on a step, so a step walker reaches none of them — and a guard
    sharing that walker inherits the same blind spot and reports the population
    as complete.
    """
    for job_id, job in (doc.get("jobs") or {}).items():
        if isinstance(job, dict) and isinstance(job.get("uses"), str):
            yield str(job_id), job["uses"]


def workflow_pins() -> list[DerivedPin]:
    """Every version a workflow resolves, derived from what its steps consume."""
    pins: list[DerivedPin] = []
    for wf in workflow_files():
        rel = str(wf.relative_to(ROOT))
        try:
            doc = yaml.safe_load(wf.read_text())
        except yaml.YAMLError as exc:
            _toolchain_cannot_run(rel, f"is not parseable YAML — {str(exc).splitlines()[0]}")
        if not isinstance(doc, dict):
            _toolchain_cannot_run(rel, "does not parse to a workflow mapping")

        for job_id, uses in _called_workflows(doc):
            m = USES_PIN.match(uses.strip())
            if m:
                pins.append(DerivedPin(
                    "Reusable workflow", "github-actions", rel,
                    f"job {job_id} uses:", m.group("dep"), m.group("ver")))

        for step in _steps(doc):
            uses = step.get("uses")
            if isinstance(uses, str):
                m = USES_PIN.match(uses.strip())
                if m:
                    pins.append(DerivedPin(
                        "GitHub Action", "github-actions", rel,
                        f"uses: {m.group('dep')}", m.group("dep"), m.group("ver")))

            with_ = step.get("with") or {}
            if isinstance(with_, dict):
                for key, value in with_.items():
                    km = VERSION_FILE_KEY.match(str(key))
                    if not km or not isinstance(value, str):
                        continue
                    runtime = km.group("runtime")
                    reader = VERSION_FILE_RUNTIMES.get(runtime)
                    if reader is None:
                        _toolchain_cannot_run(
                            rel, f"has a step with `{key}: {value}`, and which Renovate "
                                 f"manager reads a {runtime} version file is not known "
                                 f"here. A version file attributed to nothing is a pin "
                                 f"whose watcher is unknown, so this refuses rather "
                                 f"than passing over it")
                    pins.extend(reader(rel, value))

            # `run:` is arbitrary shell, so this reads the one install shape the
            # repository uses rather than pretending to read them all. The CI
            # tool binaries a job downloads are watched through their
            # `# renovate:` annotations and asserted by check_ci_tool_pins; any
            # other install shape in a run step is outside this population and
            # is named as such in the summary.
            run = step.get("run")
            if isinstance(run, str):
                for m in PIP_REQUIREMENTS.finditer(run):
                    pins.extend(_python_package_pins(rel, m.group("path")))
    # One pin resolved by twelve steps is one pin. Deduplicated on what is
    # pinned rather than on which step reached it, so the count below is the
    # population a manager has to watch and not the number of times a job asked
    # for it. `via` is dropped from the key for the same reason and the first
    # resolver is kept, so a failure still names a step a reader can open.
    seen: dict[tuple[str, str, str, str], DerivedPin] = {}
    for pin in pins:
        seen.setdefault((pin.family, pin.manager, pin.dep, pin.version), pin)
    return list(seen.values())


def _read_pin_source(workflow_rel: str, rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        _toolchain_cannot_run(workflow_rel, f"names {rel} as a version source and no such file "
                                  f"exists, so what that step installs is unknown")
    return path.read_text()


def _interpreter_pins(workflow_rel: str, rel: str) -> list[DerivedPin]:
    """The interpreter setup-python installs, read from the file the step names."""
    version = _read_pin_source(workflow_rel, rel).strip()
    if not version:
        _toolchain_cannot_run(workflow_rel, f"names {rel} as its python-version-file and that "
                                  f"file is empty")
    return [DerivedPin("Python interpreter", "pyenv", rel,
                       f"{workflow_rel} python-version-file", "python", version)]


def _python_package_pins(workflow_rel: str, rel: str) -> list[DerivedPin]:
    """Every distribution the job installs, read from the lockfile it names."""
    text = _read_pin_source(workflow_rel, rel)
    pins = [DerivedPin("Python package", "pip-compile", rel,
                       f"{workflow_rel} pip install -r", m.group("dep"), m.group("ver"))
            for m in PIP_PIN.finditer(text)]
    if not pins:
        _toolchain_cannot_run(workflow_rel, f"installs from {rel} and no pinned distribution was "
                                  f"found in it, so the job's dependencies are unknown")
    return pins


def _go_toolchain_pins(workflow_rel: str, rel: str) -> list[DerivedPin]:
    """The Go toolchain setup-go installs, read from the go.mod the step names."""
    m = GO_DIRECTIVE.search(_read_pin_source(workflow_rel, rel))
    if not m:
        _toolchain_cannot_run(workflow_rel, f"names {rel} as its go-version-file and that file "
                                  f"carries no `go` directive")
    return [DerivedPin("Go toolchain", "gomod", rel,
                       f"{workflow_rel} go-version-file", "go", m.group("ver"))]


# Which reader turns a `<runtime>-version-file` into pins. A runtime absent from
# here stops the gate by name rather than passing unseen: an entry added for a
# runtime this repository does not pin would be a rule matching nothing, and an
# unrecognised one that passed quietly is the defect the shape-driven key exists
# to close.
VERSION_FILE_RUNTIMES = {
    "python": _interpreter_pins,
    "go": _go_toolchain_pins,
}


def _toolchain_cannot_run(rel: str, detail: str) -> NoReturn:
    print(f"Cannot run: {rel} {detail}.")
    print("The toolchain a job runs on could not be derived, so this gate examined")
    print("less than it reports on — which is not the same as finding nothing.")
    sys.exit(gatelib.CANNOT_RUN)


def check_derived_pins(pins: list[DerivedPin]) -> int:
    """Every derived pin is claimed by an enabled manager, and every manager claims one.

    Both directions, because they fail for opposite reasons. An unclaimed pin
    ages with nothing watching it. A manager claiming nothing is config that
    reads as coverage — `renovate-config-validator` accepts it, the Dependency
    Dashboard shows no lookup for it, and the only symptom is a version that
    never moves.
    """
    enabled = enabled_managers()
    if not enabled:
        fail("renovate.json declares no enabledManagers, so no manager reads "
             "anything and every pin below is unwatched.")
        return 0
    if not pins:
        fail("no toolchain pin was derived from any workflow — no step carries a "
             "`uses:`, a version-file or a pip install, so this gate's claim over "
             "the toolchain is vacuous.")
        return 0

    cfg = gatelib.read_json(ROOT / "renovate.json")
    claimed: set[str] = set()
    for pin in pins:
        if pin.manager not in enabled:
            fail(f"{pin.source}: {pin.family} {pin.dep} {pin.version} needs the "
                 f"{pin.manager} manager, which renovate.json does not enable. "
                 f"Resolved by {pin.via}, and watched by nothing.")
            continue
        claimed.add(pin.manager)
        assert_reach(pin.manager, manager_file_patterns(cfg, pin.manager), pin.source,
                     f"{pin.family} {pin.dep} {pin.version}")

    # A manager reading nothing is the same defect one layer up, and it is the
    # one an enabledManagers allowlist makes easy: the name stays after the thing
    # it read is gone.
    unclaimed = sorted(enabled - claimed - {"argocd", "custom.regex"})
    for manager in unclaimed:
        fail(f"renovate.json enables the {manager} manager and no pin in this repo is "
             f"attributed to it. A manager that reads nothing is config that reads as "
             f"coverage.")
    return len(pins)


# Version pins outside applicationsets/ chart elements. Each family names the
# file that carries it and a regex for the pin; every match must be covered by
# some manager, and a family whose regex matches nothing fails.
#
# Chart pins were the only family this gate read, and the sentence it printed —
# "every one watched by a manager that resolves" — was true of the population it
# scanned and read as true of the repo. The git-pinned CRDs, the CI tool
# binaries and the Go module were all watched, by managers nothing asserted:
# deleting one left the gate printing the same success.
OTHER_FAMILIES = [
    (
        "git-pinned manifest directory",
        "applicationsets/gateway-api-crds.yaml",
        # depName as the shipped manager spells it: the org/repo pair, not the
        # URL it is embedded in. Matching the URL would compare a string the
        # manager never produces and report a watched pin as unwatched.
        re.compile(r"repoURL:\s*https://github\.com/(?P<repo>[^\s/]+/[^\s/]+)\s*\n\s*"
                   r"targetRevision:\s*(?P<ver>v[0-9]\S*)"),
    ),
    (
        "CI tool binary",
        ".github/workflows/ci.yml",
        # Anchored on the pin, NOT on the annotation above it. Matching the
        # annotation would make an unannotated pin invisible to this gate: the
        # pin nothing watches is exactly the one that carries no `# renovate:`
        # line, so keying on the annotation finds every pin except the ones
        # that matter. The annotation is then checked as a property of each pin
        # found, in check_ci_tool_pins.
        re.compile(r"^  (?P<var>[A-Z][A-Z0-9_]*_VERSION):\s*\"?(?P<ver>[^\"\s]+)\"?\s*$",
                   re.M),
    ),
    (
        "Go module",
        "applicationsets/rendertest/go.mod",
        re.compile(r"^\t(?P<repo>[a-z0-9./-]+\S*)\s+(?P<ver>v[0-9]\S*)", re.M),
    ),
]

# Files that must carry NO version pin. Asserted rather than described: a
# comment saying a file has no versions cannot fail when one appears, and this
# can. Both opt-in appsets read their revision from a cluster-Secret annotation,
# which is the fork-safety contract — a literal here would be a pin nothing
# watches AND a hardcoded org reference.
NO_PINS = [
    "applicationsets/opt-in/apps-tenants.yaml",
    "applicationsets/opt-in/clusters-appset.yaml",
]

PIN_SHAPED = re.compile(r"(?:targetRevision|chartVersion):\s*[\"\']?(?P<ver>v?[0-9]+\.[0-9]+\S*)")


def check_other_families(managers: list[CustomManager]) -> int:
    """Assert every non-chart pin family is watched, and the pin-free files are."""
    cfg = gatelib.read_json(ROOT / "renovate.json")
    seen = 0
    for label, rel, rx in OTHER_FAMILIES:
        path = ROOT / rel
        if not path.exists():
            fail(f"{rel} does not exist, but this gate asserts a {label} pin lives "
                 f"there — the reference outlived the file.")
            continue
        text = path.read_text()
        hits = list(rx.finditer(text))
        if not hits:
            fail(f"{rel}: found no {label} pin. The shape this gate looks for is gone, "
                 f"so its coverage claim over that family is vacuous.")
            continue
        if label == "CI tool binary":
            seen += check_ci_tool_pins(text, rel, hits, managers)
            continue

        for m in hits:
            seen += 1
            gd = m.groupdict()
            if rel.endswith("go.mod"):
                # The built-in gomod manager reads go.mod wholesale; there is no
                # per-pin annotation to check, so the assertion is that the
                # manager is enabled at all.
                if "gomod" not in enabled_managers():
                    fail(f"{rel}: the gomod manager is not in renovate.json's "
                         f"enabledManagers, so {gd['repo']} {gd['ver']} is watched by "
                         f"nothing.")
                else:
                    assert_reach("gomod", manager_file_patterns(cfg, "gomod"), rel,
                                 f"{label} pin {gd['repo']} {gd['ver']}")
                continue
            cm = covered_by_custom(text, gd["repo"], gd["ver"], managers)
            if cm is None:
                fail(f"{rel}: {label} pin {gd['repo']} {gd['ver']} is matched by no "
                     f"customManager. Nothing opens a currency PR for it.")
            else:
                assert_reach(f"custom.regex {cm.where}",
                         FilePatterns(cm.file_patterns, "renovate.json"), rel,
                         f"{label} pin {gd['repo']} {gd['ver']}")

    # NOT counted into `seen`: these files are asserted to hold zero pins, so
    # adding one per file reports pins the repo does not have — and the same
    # sentence already names them separately as files asserted to pin nothing.
    for rel in NO_PINS:
        path = ROOT / rel
        if not path.exists():
            fail(f"{rel} is asserted to carry no version pin but does not exist.")
            continue
        for m in PIN_SHAPED.finditer(path.read_text()):
            fail(f"{rel}: carries a literal version {m.group('ver')!r}. This file is "
                 f"asserted to pin nothing — its revision comes from a cluster-Secret "
                 f"annotation — so a literal here is both an unwatched pin and a "
                 f"hardcoded reference a fork would inherit.")
    return seen


# The annotation that makes one CI tool pin watchable, spelled as Renovate's own
# matchString spells it: the comment and the pin that follows are consumed in one
# match, so an annotation covers ONE pin. A comment at the top of the block does
# not adopt the versions added under it, and each of those needs its own.
ANNOTATED = re.compile(
    r"#\s*renovate:\s*datasource=(?P<ds>[a-z-]+)\s+depName=(?P<dep>\S+)\s*\n"
    r"\s*(?P<var>[A-Z][A-Z0-9_]*_VERSION):")


def check_ci_tool_pins(text: str, rel: str, hits,
                       managers: list[CustomManager]) -> int:
    """Every *_VERSION pin carries its own annotation and a manager that reads it."""
    annotated = {m.group("var"): (m.group("dep"), m.group("ds"))
                 for m in ANNOTATED.finditer(text)}
    for m in hits:
        var, ver = m.group("var"), m.group("ver")
        if var not in annotated:
            fail(f"{rel}: {var} pins {ver} with no `# renovate:` annotation on the line "
                 f"above it. The customManager keys on that annotation, so this pin is "
                 f"watched by nothing and ages silently.")
            continue
        dep, _ds = annotated[var]
        cm = covered_by_custom(text, dep, ver, managers)
        if cm is None:
            fail(f"{rel}: {var} ({dep} {ver}) is annotated but matched by no "
                 f"customManager — the annotation names a datasource nothing reads.")
        else:
            assert_reach(f"custom.regex {cm.where}",
                         FilePatterns(cm.file_patterns, "renovate.json"), rel,
                         f"CI tool pin {var} ({dep} {ver})")
    return len(hits)


def check_oci_repourl_shape(pins: list[Pin]) -> int:
    """Every OCI pin's rendered repoURL last segment equals its `chart`.

    ArgoCD resolves the OCI digest from repoURL alone, so repoURL must name the
    package and `chart` repeats it. Point repoURL at the enclosing namespace and
    ArgoCD requests `.../<namespace>/manifests/<version>`, which is not a
    package, and manifest generation fails at sync.

    A recurring constraint named in prose and enforced nowhere is an open class
    with a memorial: the redundancy is load-bearing, and a tidy-up that removes
    it breaks a sync rather than a lint. So it is asserted over what ArgoCD
    renders. Written from source syntax the assertion read `repoURL:` only, and
    a matrix appset never writes that key next to a literal registry path — it
    templates it from the element's `chartRepo`. Every OCI chart pinned that way
    was therefore outside an assertion whose message claims to cover the repo,
    and breaking one left this gate reporting the same pin count and the same
    success.

    This is also the shape that makes the built-in argocd manager derive a
    package name resolving to nothing, which is why this gate already reasons
    about it for coverage.
    """
    seen = 0
    for pin in pins:
        if not pin.is_oci:
            continue
        seen += 1
        last = pin.repo[len("oci://"):].rstrip("/").rsplit("/", 1)[-1]
        if last != pin.chart:
            fail(f"{pin.rel}: repoURL renders to one ending in {last!r} but chart is "
                 f"{pin.chart!r}. ArgoCD resolves the OCI digest from repoURL "
                 f"alone, so it would request .../{last}/manifests/<version>, which "
                 f"is not a package, and manifest generation fails at sync.")
    if not seen:
        fail("found no OCI pins in applicationsets/ — this repo carries several, so "
             "the derivation stopped seeing them and the repoURL shape is unasserted.")
    return seen


def enabled_managers() -> set[str]:
    cfg = gatelib.read_json(ROOT / "renovate.json")
    return set(cfg.get("enabledManagers") or [])


def main() -> int:
    managers = load_custom_managers()
    if failures:
        report()
        return 1

    pins = rendered_pins()
    if failures:
        report()
        return 1
    assert_corpus_floor(pins)

    total = len(pins)
    cfg = gatelib.read_json(ROOT / "renovate.json")
    argocd_patterns = manager_file_patterns(cfg, "argocd")
    for pin in pins:
        source, what = str(pin.rel), f"{pin.chart} {pin.version}"
        if pin.matrix:
            cm = covered_by_custom(pin.text, pin.chart, pin.version, managers)
            if cm is None:
                fail(f"{pin.rel}: matrix pin {pin.chart} {pin.version} is matched by no "
                     f"customManager. The argocd manager cannot read matrix list "
                     f"elements, so nothing watches it.")
            else:
                assert_reach(f"custom.regex {cm.where}",
                             FilePatterns(cm.file_patterns, "renovate.json"),
                             source, f"matrix pin {what}")
            continue
        if pin.is_oci:
            last = pin.repo.rstrip("/").rsplit("/", 1)[-1]
            if last == pin.chart:
                cm = covered_by_custom(pin.text, pin.chart, pin.version, managers)
                if cm is None:
                    fail(f"{pin.rel}: OCI pin {pin.chart} {pin.version} has repoURL "
                         f"ending in '{last}', so the argocd manager derives "
                         f"'{pin.repo[len('oci://'):]}/{pin.chart}' — not a package. It "
                         f"needs a customManager and has none.")
                else:
                    assert_reach(f"custom.regex {cm.where}",
                                 FilePatterns(cm.file_patterns, "renovate.json"),
                                 source, f"OCI pin {what}")
                continue
        # Everything else is resolved by the built-in argocd manager: it reads
        # repoURL as the registry and chart as the package, which is correct for
        # an https source and for an OCI one whose repoURL does not end in the
        # chart name. Correct is not the same as reached, so the manager's own
        # file patterns are asserted against the file the pin is in.
        assert_reach("argocd", argocd_patterns, source, f"chart pin {what}")

    if not total:
        fail("no chart pins found in applicationsets/ — no ApplicationSet template "
             "names a chart, so this gate proved nothing.")

    others = check_other_families(managers)
    oci = check_oci_repourl_shape(pins)
    derived = check_derived_pins(workflow_pins())

    if failures:
        report()
        return 1

    # Every number here names the population it was measured over. The OCI pins
    # are a SUBSET of the chart pins, re-examined for a second property, so
    # folding them into one total would report a repo with more pins than it has
    # — and widening what the shape check reads would then read as pins
    # appearing. The file count is the files pins were FOUND in, not the files
    # walked: most ApplicationSets here are kustomize or git-sourced and pin no
    # chart at all, so certifying them alongside the pins would claim coverage
    # over a population this never examined.
    bearing = len({p.appset for p in pins})
    print(f"renovate coverage OK: {total} chart pin(s) across {bearing} of "
          f"{len(appset_files())} ApplicationSets, plus {others} pin(s) "
          f"in the git-pinned CRDs, the CI tool binaries and the Go module — "
          f"every one watched by a manager that resolves. {oci} of the chart pins "
          f"are OCI and also assert repoURL repeats their chart name; "
          f"{len(NO_PINS)} file(s) are asserted to pin nothing")
    print(f"toolchain OK: {derived} pin(s) derived from what the workflows resolve — "
          f"every action reference, every version-file a setup step reads and every "
          f"distribution a job installs is claimed by an enabled manager, and every "
          f"enabled manager claims one")

    # Split by where the pattern came from. One is a decision made in this
    # repository; the other moves when Renovate does, without this repository
    # changing, which is why the record has a drift check and this line names it.
    recorded = sorted({m for m, _ in reach_recorded})
    print(f"file patterns OK: every pin above sits in a file the manager it is "
          f"attributed to actually opens — {len(reach_configured)} matched by a "
          f"pattern renovate.json configures, {len(reach_recorded)} by the recorded "
          f"default of {', '.join(recorded) if recorded else 'no manager'}, which "
          f"scripts/check-renovate-defaults.mjs holds to the shipped package")
    return 0


def report() -> None:
    for f in failures:
        print(f"FAIL  {f}")


if __name__ == "__main__":
    sys.exit(main())
