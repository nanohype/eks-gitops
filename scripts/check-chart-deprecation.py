#!/usr/bin/env python3
"""Every chart this catalog pins is still the chart it was pinned for.

    python3 scripts/check-chart-deprecation.py            # blocking gate, offline
    python3 scripts/check-chart-deprecation.py --live     # scheduled, hits the registries
    python3 scripts/check-chart-deprecation.py --sync     # rewrite the records from upstream
    python3 scripts/check-chart-deprecation.py --self-test

Two different questions, and only one of them is a function of this commit.

A chart can be deprecated, handed to a different maintainer, or re-scoped to a
different product at any moment, with no change here. Asking that at merge time
would turn an unrelated pull request red because someone upstream pushed
overnight — the same reason mirror-check asks "has upstream moved?" on a
schedule rather than in the gate. So the work splits:

  default (offline, BLOCKING) — every pinned chart has a provenance record and
      every record names a chart still pinned. A function of the tree, so the
      verdict cannot change without a commit.

  --live (network, SCHEDULED) — fetch each pinned chart and compare it against
      its record: a `deprecated: true`, or a description that no longer matches.

The description comparison is the part that earns its keep. `deprecated: true`
is easy and loud. The failure that prompted this was quiet: the OSS Loki chart
moved to grafana-community, and the chart still published at the original
repository was re-scoped to Grafana Enterprise Logs. No deprecation flag was
ever set on it. The pin resolved, the chart installed, CI stayed green, and
Renovate kept offering patches — a currency signal reporting "current" for a
chart that had changed product underneath it. The description was the only
field that moved.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

import yaml

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
# Beside the checker, not beside the pins. `applicationsets/` is scanned by
# kubeconform, which reads every file in it as a manifest and rejects one with
# no `kind` — the record would have had to be exempted from a schema gate to
# live next to what it describes, and weakening a gate to make room for a new
# file is the wrong trade.
RECORDS = ROOT / "scripts" / "chart-provenance.json"


def die(msg: str) -> None:
    print(f"chart-provenance: {msg}", file=sys.stderr)
    sys.exit(1)


def walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk(v)


def pins() -> dict[str, dict]:
    """{chart: {repo, version, source}} for every literal helm pin in the catalog.

    Two shapes carry one: an ApplicationSet source (`repoURL` + `chart` +
    `targetRevision`) and a list-generator element (`chartRepo` + `chart` +
    `chartVersion`). Templated pins are skipped — their value is not in the tree.
    """
    found: dict[str, dict] = {}
    for path in sorted(APPSETS.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            for node in walk(doc or {}):
                chart = node.get("chart")
                version = node.get("chartVersion") or node.get("targetRevision")
                repo = node.get("repoURL") or node.get("chartRepo")
                if not (isinstance(chart, str) and isinstance(version, str) and isinstance(repo, str)):
                    continue
                if "{{" in chart or "{{" in version or "{{" in repo:
                    continue
                if not repo.startswith(("http://", "https://", "oci://")):
                    continue
                prior = found.get(chart)
                if prior and (prior["repo"], prior["version"]) != (repo, version):
                    die(
                        f"{chart} is pinned twice and they disagree: "
                        f"{prior['version']} from {prior['repo']} ({prior['source']}) "
                        f"vs {version} from {repo} ({path.name})"
                    )
                found[chart] = {"repo": repo, "version": version, "source": path.name}
    if not found:
        die("read no chart pins out of applicationsets/ — the parser and the catalog disagree")
    return found


def load_records() -> dict:
    if not RECORDS.exists():
        die(f"{RECORDS.relative_to(ROOT)} does not exist. Run --sync to create it.")
    return json.loads(RECORDS.read_text()).get("charts", {})


def fetch(chart: str, repo: str, version: str) -> dict:
    """Chart.yaml as upstream currently publishes it."""
    if repo.startswith("oci://"):
        cmd = ["helm", "show", "chart", repo, "--version", version]
    else:
        cmd = ["helm", "show", "chart", "--repo", repo, chart, "--version", version]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        return {"_error": (out.stderr or out.stdout).strip().splitlines()[-1][:200]}
    return yaml.safe_load(out.stdout) or {}


# ---------------------------------------------------------------- offline gate

def check_offline(live: dict, recorded: dict) -> int:
    problems = []

    for chart, pin in sorted(live.items()):
        rec = recorded.get(chart)
        if rec is None:
            problems.append(
                f"{chart} is pinned ({pin['version']}, {pin['source']}) with no provenance record. "
                f"Nothing would notice if that chart were deprecated or re-scoped. Run --sync."
            )
            continue
        if rec.get("repo") != pin["repo"]:
            problems.append(
                f"{chart} is pinned from {pin['repo']} but recorded against {rec.get('repo')}. "
                f"A repository change is a change of maintainer — re-record it deliberately."
            )
        if not rec.get("description"):
            problems.append(f"{chart} has a provenance record with no description to compare against.")
        if rec.get("deprecated") is True:
            problems.append(
                f"{chart} is recorded as deprecated upstream and is still pinned. "
                f"Either migrate it or record why it stays."
            )

    for chart in sorted(set(recorded) - set(live)):
        problems.append(f"{chart} has a provenance record but is no longer pinned — drop the record.")

    if problems:
        print(f"FAIL  {len(problems)} problem(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    {len(live)} chart pin(s), each with a provenance record, none recorded deprecated.")
    return 0


# ------------------------------------------------------------------ live check

def check_live() -> int:
    live = pins()
    recorded = load_records()
    problems, ok = [], 0

    for chart, pin in sorted(live.items()):
        meta = fetch(chart, pin["repo"], pin["version"])
        if "_error" in meta:
            problems.append(f"{chart}: could not read upstream metadata — {meta['_error']}")
            continue
        rec = recorded.get(chart, {})
        if meta.get("deprecated") is True:
            problems.append(
                f"{chart} {pin['version']} is marked deprecated by upstream ({pin['repo']})."
            )
        desc = (meta.get("description") or "").strip()
        was = (rec.get("description") or "").strip()
        if was and desc != was:
            problems.append(
                f"{chart} changed what it says it is.\n"
                f"            recorded: {was}\n"
                f"            upstream: {desc}\n"
                f"          A chart that redescribes itself may have changed product or maintainer. "
                f"Read the upstream notes, then --sync if it is still the chart you want."
            )
        if not problems or problems[-1].split()[0] != chart:
            ok += 1

    if problems:
        print(f"FAIL  {len(problems)} problem(s) across {len(live)} pinned chart(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    all {len(live)} pinned chart(s) match their record and none is deprecated.")
    return 0


# ------------------------------------------------------------------------ sync

def sync() -> int:
    live = pins()
    charts = {}
    for chart, pin in sorted(live.items()):
        meta = fetch(chart, pin["repo"], pin["version"])
        if "_error" in meta:
            die(f"{chart}: {meta['_error']}")
        charts[chart] = {
            "repo": pin["repo"],
            "description": (meta.get("description") or "").strip(),
            "deprecated": bool(meta.get("deprecated", False)),
        }
        print(f"  recorded {chart:32} {pin['version']:12} deprecated={charts[chart]['deprecated']}")
    RECORDS.write_text(
        json.dumps(
            {
                "_README": (
                    "What each pinned chart says it is, recorded so that a change is visible. "
                    "check-chart-deprecation.py compares upstream against this on a schedule; the "
                    "blocking gate only checks that every pin has a record and every record a pin. "
                    "A description change means the chart redescribed itself — read the upstream "
                    "notes before running --sync, because that is the signal a chart has changed "
                    "product or maintainer without ever setting a deprecated flag."
                ),
                "charts": charts,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nwrote {RECORDS.relative_to(ROOT)} ({len(charts)} charts)")
    return 0


# ------------------------------------------------------------------- self-test

def self_test() -> int:
    """Break the offline gate's inputs and confirm each break is rejected."""
    import contextlib
    import io

    real_pins = pins()
    real_records = load_records()

    def run(p, r):
        with contextlib.redirect_stdout(io.StringIO()):
            return check_offline(p, r)

    breaks = []
    # a pinned chart with no record
    p = dict(real_pins)
    p["ghost-chart"] = {"repo": "https://example.invalid", "version": "1.0.0", "source": "x.yaml"}
    breaks.append(("a pinned chart with no provenance record", p, real_records))
    # a record for a chart nobody pins
    r = dict(real_records)
    r["retired-chart"] = {"repo": "https://example.invalid", "description": "x", "deprecated": False}
    breaks.append(("a record for a chart no longer pinned", real_pins, r))
    # the recorded repo disagrees with the pin
    name = sorted(real_pins)[0]
    r2 = json.loads(json.dumps(real_records))
    r2[name]["repo"] = "https://somewhere.else.invalid"
    breaks.append(("the recorded repository differs from the pin", real_pins, r2))
    # a record marked deprecated but still pinned
    r3 = json.loads(json.dumps(real_records))
    r3[name]["deprecated"] = True
    breaks.append(("a chart recorded deprecated but still pinned", real_pins, r3))
    # a record with no description to compare
    r4 = json.loads(json.dumps(real_records))
    r4[name]["description"] = ""
    breaks.append(("a record with no description", real_pins, r4))

    failures = []
    for label, p, r in breaks:
        if run(p, r) == 0:
            failures.append(label)
            print(f"  ACCEPTED  {label}   <-- not caught")
        else:
            print(f"  rejected  {label}")

    if run(real_pins, real_records) != 0:
        failures.append("the real catalog does not pass")
        print("  ACCEPTED  (control) the shipped catalog is rejected")
    else:
        print("  passed    (control) the shipped catalog")

    if failures:
        print(f"\nFAIL  {len(failures)} break(s) not caught.")
        return 1
    print(f"\nOK    all {len(breaks)} breaks rejected, and the shipped catalog passes.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    if "--sync" in sys.argv:
        gatelib.require("helm")     # --sync resolves every chart upstream
        return sync()
    if "--live" in sys.argv:
        gatelib.require("helm")     # --live fetches each pinned chart
        return check_live()
    return check_offline(pins(), load_records())


if __name__ == "__main__":
    sys.exit(main())
