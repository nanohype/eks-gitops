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

# The two pin shapes this catalog uses. Kept here rather than read from
# renovate.json on purpose: this is the ground truth the config is checked
# against, so deriving it from the config would make the check circular.
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

    for rel in NO_PINS:
        path = ROOT / rel
        if not path.exists():
            fail(f"{rel} is asserted to carry no version pin but does not exist.")
            continue
        seen += 1
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


def check_oci_repourl_shape() -> int:
    """An OCI direct-source pin's repoURL last segment equals its `chart`.

    ArgoCD resolves the OCI digest from repoURL alone, so repoURL must name the
    package and `chart` repeats it. Point repoURL at the enclosing namespace and
    ArgoCD requests `.../<namespace>/manifests/<version>`, which is not a
    package, and manifest generation fails at sync.

    Two ApplicationSets carry that shape and two comments describe it — one of
    them saying "Same shape the Envoy charts in addons-ai-platform use". A
    recurring constraint named in prose in two places and enforced nowhere is an
    open class with a memorial, so it is asserted here: the redundancy is
    load-bearing, and a tidy-up that removes it breaks a sync rather than a
    lint.

    This is also the shape that makes the built-in argocd manager derive a
    package name resolving to nothing, which is why this gate already reasons
    about it for coverage.
    """
    seen = 0
    for path in sorted(APPSETS.glob("*.yaml")):
        text = path.read_text()
        for m in re.finditer(
            r"repoURL:\s*oci://(?P<repo>\S+)\s*\n\s*chart:\s*(?P<chart>\S+)", text
        ):
            seen += 1
            last = m.group("repo").rstrip("/").rsplit("/", 1)[-1]
            if last != m.group("chart"):
                fail(f"{path.relative_to(ROOT)}: repoURL ends in {last!r} but chart is "
                     f"{m.group('chart')!r}. ArgoCD resolves the OCI digest from repoURL "
                     f"alone, so it would request .../{last}/manifests/<version>, which "
                     f"is not a package, and manifest generation fails at sync.")
    if not seen:
        fail("found no OCI direct-source pins — this repo carries two, so the "
             "pattern stopped matching and the repoURL shape is unasserted.")
    return seen


def enabled_managers() -> set[str]:
    cfg = gatelib.read_json(ROOT / "renovate.json")
    return set(cfg.get("enabledManagers") or [])


def main() -> int:
    patterns = load_patterns()
    if failures:
        report()
        return 1

    total = 0
    for path in sorted(APPSETS.glob("*.yaml")):
        text = path.read_text()
        rel = path.relative_to(ROOT)

        for m in MATRIX.finditer(text):
            total += 1
            if not covered_by_custom(text, m["chart"], m["ver"], patterns):
                fail(f"{rel}: matrix pin {m['chart']} {m['ver']} is matched by no "
                     f"customManager. The argocd manager cannot read matrix list "
                     f"elements, so nothing watches it.")

        for m in DIRECT.finditer(text):
            total += 1
            repo, chart, ver = m["repo"], m["chart"], m["ver"]
            if repo.startswith("oci://"):
                last = repo.rstrip("/").rsplit("/", 1)[-1]
                if last == chart and not covered_by_custom(text, chart, ver, patterns):
                    fail(f"{rel}: OCI pin {chart} {ver} has repoURL ending in "
                         f"'{last}', so the argocd manager derives "
                         f"'{repo[len('oci://'):]}/{chart}' — not a package. It "
                         f"needs a customManager and has none.")
            # https direct-source pins: the argocd manager resolves repoURL as
            # the registry and chart as the package, which is correct.

    if not total:
        fail("no chart pins found in applicationsets/ — the pin regexes no "
             "longer match this repo's shape, so this gate proved nothing.")

    total += check_other_families(patterns)
    total += check_oci_repourl_shape()

    if failures:
        report()
        return 1

    print(f"renovate coverage OK: {total} pin(s) across chart elements in "
          f"{len(list(APPSETS.glob('*.yaml')))} ApplicationSets, the git-pinned CRDs, "
          f"the CI tool binaries and the Go module — every one watched by a manager "
          f"that resolves, and {len(NO_PINS)} file(s) asserted to pin nothing")
    return 0


def report() -> None:
    for f in failures:
        print(f"FAIL  {f}")


if __name__ == "__main__":
    sys.exit(main())
