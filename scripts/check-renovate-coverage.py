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

import json
import pathlib
import re
import sys

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
    cfg = json.loads((ROOT / "renovate.json").read_text())
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

    if failures:
        report()
        return 1

    print(f"renovate coverage OK: {total} chart pins in "
          f"{len(list(APPSETS.glob('*.yaml')))} ApplicationSets, every one watched "
          f"by a manager that resolves")
    return 0


def report() -> None:
    for f in failures:
        print(f"FAIL  {f}")


if __name__ == "__main__":
    sys.exit(main())
