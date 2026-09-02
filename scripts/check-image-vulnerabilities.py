#!/usr/bin/env python3
"""Every image the production render carries is scanned, and a CRITICAL is a decision.

    scripts/check-image-vulnerabilities.py             # blocking gate
    scripts/check-image-vulnerabilities.py --list      # print every finding
    scripts/check-image-vulnerabilities.py --self-test # the canary alone

WHOSE QUESTION THIS IS

An adopter of this catalog inherits every chart pin in it without reading. The
version a pin resolves to decides which image lands on their nodes, so whoever
moves the pin owns what the image carries. Nothing else in the pipeline can:
trivy-operator reports at runtime, on a cluster that already pulled the image,
to an operator who cannot change the pin without a PR here.

WHAT IS BLOCKING AND WHAT IS NOT

Blocking: a CRITICAL vulnerability WITH A FIX AVAILABLE, in an image the fleet
renders, that `image-advisories.yaml` does not acknowledge. Those three
qualifiers are the whole bar. A CRITICAL with no fix published is not a decision
anyone here can act on; a HIGH is counted and printed, and the count is not
gated, because holding a merge on it would gate this repo on the rate at which
upstream chart images accumulate advisories rather than on anything the commit
changed.

That leaves a real objection, and the answer to it is the advisory file rather
than a softer bar. What this gate reads is not a function of the commit alone: it
is the commit against a vulnerability database and against whatever the pinned
tags resolve to today. Both move, and they move in both directions.

A database that GAINS an advisory turns a tree red that passed yesterday. The
failure names the image, the CVE and the fixed version, and clears by bumping the
chart or by recording why the finding stands.

A database that LOSES one — a reclassification, a withdrawn advisory — turns a
tree red that passed for the opposite reason: rules 3 and 4 fire, the entry
acknowledging it no longer matches any scanned image, and the clearing action is
deleting an entry. The same happens with no database change at all, because this
fleet is pinned by version tag and a tag is not immutable (see
check-image-pins.py on what counts as pinned): a publisher re-pushing the same
tag on a patched base removes the finding underneath a standing entry.

Neither direction is silent and neither is permanent, and both are decisions with
an author. That is the whole of what the advisory file buys.

THE ADVISORY FILE IS ASSERTED IN FOUR DIRECTIONS

An acknowledgement list nobody re-checks only ever widens, so every entry is
checked against the scan rather than trusted:

  * a finding whose (id, package) no entry names        -> the gate's own question
  * a finding on an image its entry does not list       -> the entry does not cover it
  * an entry whose (id, package) no image carries       -> the entry outlived its reason
  * an entry listing an image with no such finding      -> the same, per image

Entries name images WITHOUT a tag, because the acknowledgement is about the
image and a chart bump moves the tag. A bump that FIXES the finding therefore
fails the third or fourth rule rather than leaving a stale excuse behind.

THE CANARY, WHICH IS WHAT MAKES A CLEAN RESULT MEAN ANYTHING

A vulnerability scanner that has lost its database, or been handed a flag it
reads as "report nothing", returns a clean result for every image. That is
indistinguishable from a healthy fleet by exit code and by output alone.

So every run first scans a digest-pinned image with historical, fixed CRITICALs
and requires them to come back. A canary that comes back clean exits 2: it is a
statement about the scanner, not about the catalogue, and the two must not print
the same thing.

CHART-SOURCED APPLICATIONS ONLY, SAID PLAINLY

The population comes from check-image-pins.inventory, which walks the
ApplicationSets that pin a Helm chart. A kustomize-sourced Application renders
workloads through no chart and contributes nothing — check-policy-admission.py
names one by path in KUSTOMIZE_WORKLOADS (dashboards/base, the grafana-operator
namespace), and its images run on every full-tier cluster and are not scanned
here. Taking them in means a second render path; until that lands the boundary is
written down, the same way the environment one below is.

ONE ENVIRONMENT, SAID PLAINLY

The population is the production render. render-addons produces four —
development, staging, production and hub — and nothing here asserts they agree,
so a component enabled only in development or on the hub is deployed by this
fleet and is not scanned. That is a narrower claim than "every image the fleet
renders", and it is the claim this gate holds: every image the PRODUCTION render
carries. Widening it means four scans of seventy images per run, which is a cost
decision rather than a technical one, and until it is taken the boundary belongs
in writing rather than in the reader's assumption.

UNSCANNABLE IS NOT CLEAN

An image that could not be pulled contributed no findings. Counting the rest as
the whole fleet is how a partial scan reads as a complete one, so any image that
fails to scan exits 2 with the image named.
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import pathlib
import subprocess
import sys
from typing import NoReturn

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

# The image inventory, from the gate that already derives it. Re-deriving the
# population here would let the two disagree about what the fleet is, and the
# one that scanned fewer images would be the one printing a clean result.
_ip_path = pathlib.Path(__file__).resolve().parent / "check-image-pins.py"
_ip_spec = importlib.util.spec_from_file_location("check_image_pins", _ip_path)
assert _ip_spec and _ip_spec.loader, f"{_ip_path} is not loadable as a module"
image_pins = importlib.util.module_from_spec(_ip_spec)
sys.modules["check_image_pins"] = image_pins
_ip_spec.loader.exec_module(image_pins)

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADVISORIES = ROOT / "image-advisories.yaml"

# Seconds one trivy invocation may run. A scan with no deadline turns a stalled
# registry into a job that hangs until the CI runner's own ceiling, with no
# diagnostic naming the image that stalled.
SCAN_TIMEOUT = 600

# The severity that blocks. HIGH is counted and printed; see the header.
BLOCKING_SEVERITY = "CRITICAL"
REPORTED_SEVERITIES = ["CRITICAL", "HIGH"]

# The floor on images scanned is DERIVED, not picked: one image per chart the
# render covers, asserted per chart by check-image-pins.chart_coverage. A total
# cannot see the shape that actually happened — an extractor missed the ordinary
# `- image:` list-item spelling, two charts' whole workloads left the inventory,
# and the count stayed large enough to look healthy. The per-chart form catches
# exactly that, and it moves with the catalog rather than with a constant.

# A digest-pinned image with historical CRITICALs that have published fixes.
# Alpine 3.10 is end-of-life, so these cannot be patched away underneath the
# canary, and the digest means the tag cannot be repointed at a clean build.
#
# mirror.gcr.io rather than docker.io: this pulls on every CI run, and Docker
# Hub's anonymous limits are the problem that mirror exists to solve. The
# catalog already pulls trivy-operator through it.
CANARY = ("mirror.gcr.io/library/alpine@sha256:"
          "ca1c944a4f8486a153024d9965aafbe24f5723c1d5c02f4964c045a16d19dc54")

Finding = collections.namedtuple("Finding", "image bare id package installed fixed severity")

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


def cannot_run(*lines: str) -> NoReturn:
    for line in lines:
        print(line)
    print("This gate examined nothing, which is not the same as finding nothing.")
    sys.exit(gatelib.CANNOT_RUN)


def bare(ref: str) -> str:
    """An image reference with tag and digest removed.

    What an advisory names. The tag moves with every chart bump and the digest
    moves with every rebuild; the image is what a reader recognises and what the
    acknowledgement is actually about.

    The tag separator is the last colon in the FINAL path segment. A registry
    with a port carries a colon that is not one, and cutting there produces a key
    no advisory can match and no reader can recognise.
    """
    ref = ref.split("@", 1)[0]
    name = ref.rsplit("/", 1)[-1]
    return ref.rsplit(":", 1)[0] if ":" in name else ref


def scan(ref: str) -> list[Finding] | None:
    """Fixed findings at the reported severities, or None if the image did not scan."""
    cmd = ["trivy", "image", "--quiet", "--scanners", "vuln",
           "--severity", ",".join(REPORTED_SEVERITIES),
           "--ignore-unfixed", "--format", "json", ref]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    out = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            out.append(Finding(ref, bare(ref), v["VulnerabilityID"], v.get("PkgName", ""),
                               v.get("InstalledVersion", ""), v.get("FixedVersion", ""),
                               v.get("Severity", "")))
    return out


def read_advisories() -> list[dict]:
    """The acknowledged findings, or exit 2 naming what is wrong with the file."""
    if not ADVISORIES.is_file():
        cannot_run(f"Cannot run: {ADVISORIES.name} does not exist, so every finding "
                   f"below would be reported as unacknowledged whether or not a "
                   f"decision had been recorded about it.")
    doc = gatelib.read_yaml_all(ADVISORIES)
    entries = (doc[0] or {}).get("advisories") if doc else None
    if entries is None:
        cannot_run(f"Cannot run: {ADVISORIES.name} declares no `advisories` key.")
    return list(entries)


def verdict(findings: list[Finding], advisories: list[dict]) -> list[str]:
    """Everything wrong, over a scan and an acknowledgement list.

    Four directions, and only the first is the question the gate is named for.
    The other three are what stop the acknowledgement list from becoming a
    permanent waiver nobody re-reads.

    Deduplicated in order. One image can carry the same advisory in several
    scanned artifacts — a Go binary and the layer it sits in — and printing the
    identical sentence twice reads as two findings needing two decisions.
    """
    problems: list[str] = []
    blocking = [f for f in findings if f.severity == BLOCKING_SEVERITY]

    by_key: dict[tuple[str, str], dict] = {}
    for entry in advisories:
        if not isinstance(entry, dict):
            problems.append(
                f"image-advisories.yaml: an entry under `advisories:` is a "
                f"{type(entry).__name__}, not a mapping — nothing can be read from it, "
                f"and the findings it was meant to acknowledge are unacknowledged.")
            continue
        key = (str(entry.get("id", "")), str(entry.get("package", "")))
        # str() around the read, not just the strip: a `reason:` key written and
        # left empty parses as None, and `None.strip()` raises — reaching a
        # traceback instead of the sentence two lines below, which is written for
        # exactly this case. id and package were already read defensively.
        if not str(entry.get("reason") or "").strip():
            problems.append(
                f"image-advisories.yaml: {key[0]} in {key[1]} is acknowledged with no "
                f"reason recorded, so nothing states what would let it be removed.")
        by_key[key] = entry

    # 1. A blocking finding nothing acknowledges — the gate's own question.
    # 2. A blocking finding on an image its entry does not name.
    for f in blocking:
        key = (f.id, f.package)
        acknowledged = by_key.get(key)
        if acknowledged is None:
            problems.append(
                f"{f.image}: {f.id} in {f.package} {f.installed} is CRITICAL and fixed "
                f"in {f.fixed}, and no entry in image-advisories.yaml names it. Move the "
                f"chart pin to a version carrying the fix, or record why the finding "
                f"stands.")
            continue
        listed = [str(i) for i in (acknowledged.get("images") or [])]
        if f.bare not in listed:
            problems.append(
                f"{f.image}: {f.id} in {f.package} is acknowledged, but the entry does "
                f"not list {f.bare}. An acknowledgement covers the images it names — a "
                f"new image acquiring a known CRITICAL is a decision, not an inheritance.")
            continue

    # 3. An entry no image carries. 4. An entry listing an image with no such finding.
    carried = {(f.id, f.package, f.bare) for f in blocking}
    # The mappings only: a non-mapping entry is already reported above, and
    # reaching `.get` on it here is the traceback that sentence exists to
    # replace.
    for entry in [e for e in advisories if isinstance(e, dict)]:
        key = (str(entry.get("id", "")), str(entry.get("package", "")))
        listed = [str(i) for i in (entry.get("images") or [])]
        if not listed:
            problems.append(
                f"image-advisories.yaml: {key[0]} in {key[1]} lists no images, so it "
                f"acknowledges nothing while reading as a considered decision.")
            continue
        if not any((key[0], key[1], img) in carried for img in listed):
            problems.append(
                f"image-advisories.yaml: {key[0]} in {key[1]} is acknowledged but no "
                f"scanned image carries it — the entry outlived its reason. Delete it.")
            continue
        for img in listed:
            if (key[0], key[1], img) not in carried:
                problems.append(
                    f"image-advisories.yaml: {key[0]} in {key[1]} lists {img}, which no "
                    f"longer carries it. Drop that image from the entry.")
    return list(dict.fromkeys(problems))


def run_canary() -> int:
    """Prove the scanner reports something before believing it reported nothing."""
    found = scan(CANARY)
    if found is None:
        cannot_run("Cannot run: the canary image could not be scanned.",
                   f"  {CANARY}",
                   "An unreachable registry is a fact about the network, not about "
                   "the images this catalog pins.")
    critical = [f for f in found if f.severity == BLOCKING_SEVERITY]
    if not critical:
        cannot_run("Cannot run: the canary returned no fixed CRITICAL findings.",
                   f"  {CANARY}",
                   "The canary is pinned by digest to an image whose CRITICALs have "
                   "published fixes and cannot be patched away underneath it, so an "
                   "empty result here is a fact about the scanner. One with no "
                   "database, or one reading a flag as 'report nothing', returns a "
                   "clean result for every image — including every image below.")
    print(f"canary OK: {len(critical)} fixed CRITICAL finding(s) from the pinned "
          f"end-of-life image, so a clean result below is a result rather than a "
          f"silence — "
          + ", ".join(sorted({f"{f.id} ({f.package})" for f in critical})))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true",
                    help="print every finding at the reported severities, then exit 0")
    ap.add_argument("--self-test", action="store_true",
                    help="run the canary alone")
    ap.add_argument("--env", default="production")
    args = ap.parse_args()

    gatelib.require("trivy", "helm")
    run_canary()
    if args.self_test:
        return 0

    seen: set[str] = set()
    images, unrendered = image_pins.inventory(args.env, seen)
    if unrendered:
        cannot_run("Cannot run: charts that did not render contributed no images, so "
                   "the scan below would cover part of the fleet and report on all of "
                   "it.",
                   *(f"  {path}: {err}" for path, err in unrendered))
    units = image_pins.render_addons.discover()
    coverage = image_pins.chart_coverage(images, units, seen)
    if coverage:
        cannot_run("Cannot run: the image population is smaller than the charts that "
                   "rendered it, so a scan over it says less than it appears to:",
                   *(f"  {problem}" for problem in coverage))
    if len(images) < len(units):
        cannot_run(f"Cannot run: the render produced {len(images)} image(s) from "
                   f"{len(units)} chart(s). Every chart shipping a workload "
                   f"contributes at least one, so the walk got smaller rather than "
                   f"the catalog.")

    findings: list[Finding] = []
    unscannable: list[str] = []
    for ref in sorted(images):
        got = scan(ref)
        if got is None:
            unscannable.append(ref)
            continue
        findings.extend(got)
    if unscannable:
        cannot_run("Cannot run: these images could not be scanned, and the ones that "
                   "were say nothing about them:",
                   *(f"  {ref}  (via {', '.join(sorted(images[ref]))})"
                     for ref in unscannable))

    if args.list:
        for f in sorted(findings, key=lambda f: (f.severity, f.image, f.id)):
            print(f"{f.severity:8} {f.image}  {f.id}  {f.package} {f.installed} "
                  f"-> {f.fixed}")
        print(f"\n{len(findings)} fixed finding(s) at {'/'.join(REPORTED_SEVERITIES)} "
              f"across {len(images)} image(s)")
        return 0

    for problem in verdict(findings, read_advisories()):
        fail(problem)

    critical = [f for f in findings if f.severity == BLOCKING_SEVERITY]
    high = [f for f in findings if f.severity == "HIGH"]

    if failures:
        print(f"{len(failures)} problem(s) across {len(images)} scanned image(s):\n")
        for problem in failures:
            print(f"  {problem}")
        return 1

    print(f"image vulnerabilities OK: {len(images)} image(s) scanned across "
          f"{len(set().union(*images.values()))} chart(s). "
          f"{len(critical)} fixed CRITICAL finding(s), every one acknowledged in "
          f"image-advisories.yaml against the image carrying it, and every "
          f"acknowledgement still matched by the scan. {len(high)} fixed HIGH "
          f"finding(s) counted and not gated — run --list to read them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
