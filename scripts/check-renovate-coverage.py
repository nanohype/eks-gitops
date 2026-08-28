#!/usr/bin/env python3
"""Every chart pin in applicationsets/ is watched by something that resolves.

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
import json
import pathlib
import re
import sys

# Shared helpers, loaded by path: these are hyphenated executables run from
# varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"

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


def load_patterns() -> list[re.Pattern[str]]:
    cfg = gatelib.read_json(ROOT / "renovate.json")
    managers = cfg.get("customManagers") or []
    if not managers:
        fail("renovate.json declares no customManagers, so no chart pin in "
             "applicationsets/ is watched by anything.")
        return []

    patterns = []
    for m in managers:
        for s in m.get("matchStrings") or []:
            for probe, label in RE2_UNSUPPORTED:
                if re.search(probe, s):
                    fail(f"matchString uses {label}, which RE2 does not support. "
                         f"Renovate would match nothing:\n      {s}")
                    break
            else:
                # RE2 and Python spell named groups differently: `(?<name>)` vs
                # `(?P<name>)`. renovate.json carries the RE2 form, translated
                # here to run under Python. Safe only because the lookbehind
                # forms were rejected above — after that, a remaining `(?<` can
                # only be a named group.
                try:
                    patterns.append(re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", s)))
                except re.error as exc:
                    fail(f"matchString is not a valid regex ({exc}):\n      {s}")
    return patterns


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


def _cannot_run(rel, detail: str) -> None:
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
    """Every chart pin in the top level of applicationsets/, as ArgoCD renders it.

    Top level because that is the scope Renovate's own managerFilePatterns reach
    (`^applicationsets/[^/]+\.ya?ml$`); a pin below it is watched by nothing, and
    the two files that live there are asserted to carry none by NO_PINS.

    A matrix appset is one Application per chart-bearing list element, so it is
    one pin per element here; a literal source is one pin. Both arrive with the
    same three fields, which is the point — nothing downstream has to know which
    it was.
    """
    pins: list[Pin] = []
    for path in sorted(APPSETS.glob("*.yaml")):
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
                    vals = [_literal(f, src.get(f), rel, what) for f in COORDS]
                    if None not in vals:
                        pins.append(Pin(path.name, rel, text, *vals, False))
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
                    pins.append(Pin(path.name, rel, text, *vals, True))
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
    for path in sorted(APPSETS.glob("*.yaml")):
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


def covered_by_custom(text: str, chart: str, ver: str, patterns) -> bool:
    """A customManager matches this exact pin (identified by chart + version).

    Every comparison here is exact. A substring test — which this used to do —
    reports `loki` as covered by a `loki-distributed` pin at the same version,
    so a chart nothing watches passes the gate. That is the one failure this
    gate must not have: a false positive is silent in precisely the way an
    unwatched pin is.
    """
    for pat in patterns:
        for m in pat.finditer(text):
            gd = m.groupdict()
            if gd.get("currentValue") != ver:
                continue

            # https matrix + CLI-tool managers capture the chart as depName.
            if gd.get("depName") == chart:
                return True

            # OCI managers capture the registry path, whose last segment is the
            # chart name (.../charts/operator, public.ecr.aws/karpenter/karpenter).
            pkg = gd.get("packageName")
            if pkg and pkg.rstrip("/").rsplit("/", 1)[-1] == chart:
                return True

            # The matrix OCI manager does not capture the chart name at all, so
            # fall back to the `chart:` line inside the matched span — anchored,
            # not a containment test.
            if re.search(rf"chart:\s*{re.escape(chart)}\s*$", m.group(0), re.M):
                return True
    return False


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


def check_other_families(patterns) -> int:
    """Assert every non-chart pin family is watched, and the pin-free files are."""
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
            seen += check_ci_tool_pins(text, rel, hits, patterns)
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
                continue
            if not covered_by_custom(text, gd["repo"], gd["ver"], patterns):
                fail(f"{rel}: {label} pin {gd['repo']} {gd['ver']} is matched by no "
                     f"customManager. Nothing opens a currency PR for it.")

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


# The annotation that makes one CI tool pin watchable. Renovate reads it as a
# property of the line immediately below, so it covers ONE pin — a file-level
# comment would silently adopt every version added afterwards.
ANNOTATED = re.compile(
    r"#\s*renovate:\s*datasource=(?P<ds>[a-z-]+)\s+depName=(?P<dep>\S+)\s*\n"
    r"\s*(?P<var>[A-Z][A-Z0-9_]*_VERSION):")


def check_ci_tool_pins(text: str, rel: str, hits, patterns) -> int:
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
        if not covered_by_custom(text, dep, ver, patterns):
            fail(f"{rel}: {var} ({dep} {ver}) is annotated but matched by no "
                 f"customManager — the annotation names a datasource nothing reads.")
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
    patterns = load_patterns()
    if failures:
        report()
        return 1

    pins = rendered_pins()
    if failures:
        report()
        return 1
    assert_corpus_floor(pins)

    total = len(pins)
    for pin in pins:
        if pin.matrix:
            if not covered_by_custom(pin.text, pin.chart, pin.version, patterns):
                fail(f"{pin.rel}: matrix pin {pin.chart} {pin.version} is matched by no "
                     f"customManager. The argocd manager cannot read matrix list "
                     f"elements, so nothing watches it.")
        elif pin.is_oci:
            last = pin.repo.rstrip("/").rsplit("/", 1)[-1]
            if last == pin.chart and not covered_by_custom(
                pin.text, pin.chart, pin.version, patterns
            ):
                fail(f"{pin.rel}: OCI pin {pin.chart} {pin.version} has repoURL ending "
                     f"in '{last}', so the argocd manager derives "
                     f"'{pin.repo[len('oci://'):]}/{pin.chart}' — not a package. It "
                     f"needs a customManager and has none.")
        # https direct-source pins: the argocd manager resolves repoURL as the
        # registry and chart as the package, which is correct.

    if not total:
        fail("no chart pins found in applicationsets/ — no ApplicationSet template "
             "names a chart, so this gate proved nothing.")

    others = check_other_families(patterns)
    oci = check_oci_repourl_shape(pins)

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
          f"{len(list(APPSETS.glob('*.yaml')))} ApplicationSets, plus {others} pin(s) "
          f"in the git-pinned CRDs, the CI tool binaries and the Go module — "
          f"every one watched by a manager that resolves. {oci} of the chart pins "
          f"are OCI and also assert repoURL repeats their chart name; "
          f"{len(NO_PINS)} file(s) are asserted to pin nothing")
    return 0


def report() -> None:
    for f in failures:
        print(f"FAIL  {f}")


if __name__ == "__main__":
    sys.exit(main())
