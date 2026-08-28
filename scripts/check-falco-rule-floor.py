#!/usr/bin/env python3
"""Every Falco rule set installed on a node is one Falco actually loads.

WHY THIS EXISTS

Downloading a rule set and loading it are different things, and the config makes
them look like one. falcoctl fetches each ref in `falcoctl.config.artifact` as an
OCI artifact and writes it to the root of `rulesfilesDir`, an emptyDir the Falco
container reads as /etc/falco. Falco then reads only the files and directories
`falco.rules_files` enumerates. A ref added without a matching entry there is
pulled onto every node, occupies disk, and is never evaluated.

Two shapes produce that outcome and neither fails any other gate:

  * `refs` written under `falcoctl.artifact` rather than `falcoctl.config.artifact`.
    The first path carries the init and sidecar containers' own settings and
    accepts no refs key. The chart ships no values.schema.json, so the list
    renders clean and the rendered config still names the stable tier alone.

  * `refs` on the correct path with `rules_files` left at the chart default,
    which names three specific filenames and no directory the artifacts land in.

Both are invisible to a reader of the values file, because the values file is
where they look correct. Only the rendered ConfigMaps, resolved against the
registry the refs point at, tell them apart — so that is what this reads.

WHAT IT CHECKS

Per environment the ApplicationSet reaches:

  * Every rulesfile ref the rendered falcoctl config installs writes a file that
    `rules_files` names. This is structural: it cannot go stale, and it fails on
    exactly the two shapes above.
  * The number of rules that clear the configured `priority` floor, in files that
    are actually read, meets RULE_FLOOR. A ratchet, not a target — set below the
    count the pinned majors deliver, so dropping a tier or raising the priority
    fails while upstream's own churn does not.

A rule set's rules are counted only when its file is read, so the two assertions
cannot mask each other: installing three tiers and reading one fails the first
check and never reaches a count that looks healthy.

UNREACHABLE IS NOT A VERDICT

A registry that cannot be reached says nothing about this repo, and exits 2. A
registry that answers and does not have the pinned major is a finding about a
ref somebody wrote, and exits 1. Collapsing those into one status reports a
network outage as a defect in the catalogue.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from typing import NoReturn

import yaml

_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSET = ROOT / "applicationsets" / "addons-security.yaml"
ADDON = ROOT / "addons" / "security" / "falco"

# The directory the Falco container reads. falcoctl writes into rulesfilesDir,
# which the chart mounts here; both halves are asserted below rather than assumed.
FALCO_DIR = "/etc/falco"

# A floor on rules LOADED, set below what the pinned majors deliver. Upstream
# adds and retires rules on its own cadence, so an exact count would fail on
# their release rather than on an edit here. What this catches is a tier
# dropped from the refs, a tier installed but not read, and a priority floor
# raised past rules that exist — each of which removes rules in blocks.
#
# Raising it is what lands with a change that earns it, the same way the
# coverage ratchet in scripts/tests/run.py works.
RULE_FLOOR = 85

# Falco loads a rule when its priority is at least this severe. Order is
# upstream's, most severe first; `informational` is the long spelling of `info`.
SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice",
            "info", "debug"]

# The least permissive floor this catalog accepts. Asserted directly rather than
# left to RULE_FLOOR, because a count cannot separate the two ways rules vanish:
# dropping a tier removes them in tens, while raising the floor one step removes
# a handful, and a count loose enough to survive upstream's churn is loose enough
# to miss the second. The rules that motivate it are the smallest group — the
# privileged-container ones are INFO, so a floor of `notice` installs them on
# every node and loads none of them.
MIN_PRIORITY = "info"

# The media type a rulesfile artifact's config carries. A plugin ref resolves to
# something else and installs no rules, so it is skipped rather than counted.
RULESFILE_CONFIG = "application/vnd.cncf.falco.rulesfile.config.v1+json"

REGISTRY = "ghcr.io"
# falcoctl resolves a bare `name:tag` through the falcosecurity index, which maps
# every rulesfile to this repository prefix.
INDEX_PREFIX = "falcosecurity/rules"

NETWORK_TIMEOUT = 120

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


def cannot_run(*lines: str) -> NoReturn:
    for line in lines:
        print(line)
    print("This gate examined nothing, which is not the same as finding nothing.")
    sys.exit(gatelib.CANNOT_RUN)


def rank(priority: str) -> int:
    """Position in Falco's severity order, or -1 for a spelling it does not use."""
    p = priority.strip().lower()
    p = "info" if p == "informational" else p
    return SEVERITY.index(p) if p in SEVERITY else -1


def chart_pin() -> tuple[str, str, str]:
    """Falco's chart coordinates, DERIVED from the ApplicationSet."""
    doc = yaml.safe_load(APPSET.read_text())
    spec = doc.get("spec") or {}
    for gen in spec.get("generators") or []:
        for inner in (gen.get("matrix") or {}).get("generators") or []:
            for el in (inner.get("list") or {}).get("elements") or []:
                if el.get("appName") == "falco":
                    return (str(el["chartRepo"]), str(el["chart"]),
                            str(el["chartVersion"]))
    cannot_run(f"Cannot run: {APPSET.relative_to(ROOT)} carries no falco element, so "
               f"this gate has no chart to render.")


def environments() -> list[str]:
    return sorted(p.name[len("values-"):-len(".yaml")]
                  for p in ADDON.glob("values-*.yaml"))


def render(repo: str, chart: str, version: str, env: str) -> tuple[dict, dict]:
    """The falco and falcoctl configs as the chart produces them for one env."""
    cmd = ["helm", "template", "falco", chart, "--repo", repo, "--version", version,
           "-n", "falco",
           "-f", str(ADDON / "values.yaml"),
           "-f", str(ADDON / f"values-{env}.yaml")]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
    if proc.returncode != 0:
        cannot_run(f"Cannot run: helm could not render falco for {env}.",
                   ((proc.stderr or "") + (proc.stdout or "")).strip())
    found: dict[str, dict] = {}
    for doc in yaml.safe_load_all(proc.stdout):
        if not doc or doc.get("kind") != "ConfigMap":
            continue
        data = doc.get("data") or {}
        if "falco.yaml" in data:
            found["falco"] = yaml.safe_load(data["falco.yaml"])
        if "falcoctl.yaml" in data:
            found["falcoctl"] = yaml.safe_load(data["falcoctl.yaml"])
    for key in ("falco", "falcoctl"):
        if key not in found:
            cannot_run(f"Cannot run: the {env} render produced no ConfigMap carrying "
                       f"{key}.yaml, so neither the rules it reads nor the refs it "
                       f"installs could be determined.")
    return found["falco"], found["falcoctl"]


def ghcr(repo: str, path: str, accept: str | None = None) -> bytes:
    """One anonymous ghcr.io read, classifying its own failure."""
    try:
        token_url = (f"https://{REGISTRY}/token?scope=repository:{repo}:pull"
                     f"&service={REGISTRY}")
        with urllib.request.urlopen(token_url, timeout=NETWORK_TIMEOUT) as resp:
            token = json.load(resp)["token"]
        req = urllib.request.Request(f"https://{REGISTRY}/v2/{repo}/{path}",
                                     headers={"Authorization": f"Bearer {token}"})
        if accept:
            req.add_header("Accept", accept)
        with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        # The registry answered. 404 on a pinned major is a finding about a ref
        # in this repo; anything else is not this gate's to interpret.
        raise _RegistrySaidNo(exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        cannot_run(f"Cannot run: {REGISTRY} could not be reached — {exc}.",
                   "An unreachable registry is a fact about the network, not about "
                   "the rule sets this repo pins.")


class _RegistrySaidNo(Exception):
    def __init__(self, code: int):
        super().__init__(str(code))
        self.code = code


def rulesfile(ref: str) -> dict[str, str] | None:
    """Filenames and contents a rulesfile ref installs, or None for a plugin."""
    name, tag = ref.rsplit(":", 1)
    repo = name if "/" in name else f"{INDEX_PREFIX}/{name}"
    repo = repo[len(f"{REGISTRY}/"):] if repo.startswith(f"{REGISTRY}/") else repo
    try:
        manifest = json.loads(ghcr(
            repo, f"manifests/{tag}",
            "application/vnd.oci.image.manifest.v1+json,"
            "application/vnd.oci.image.index.v1+json"))
    except _RegistrySaidNo as exc:
        if exc.code == 404:
            fail(f"ref {ref!r} does not resolve: {REGISTRY}/{repo} answered 404 for "
                 f"tag {tag!r}. falcoctl installs nothing for it, so every rule that "
                 f"set carries is absent from every node.")
            return None
        cannot_run(f"Cannot run: {REGISTRY} answered {exc.code} for {repo}:{tag}.")
    if manifest.get("config", {}).get("mediaType") != RULESFILE_CONFIG:
        return None  # a plugin, or a multi-arch index — installs no rules
    try:
        blob = ghcr(repo, f"blobs/{manifest['layers'][0]['digest']}")
    except _RegistrySaidNo as exc:
        cannot_run(f"Cannot run: {REGISTRY} answered {exc.code} for a layer of "
                   f"{repo}:{tag}.")
    out: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            handle = tf.extractfile(member)
            if handle is None:
                continue
            out[pathlib.PurePosixPath(member.name).name] = handle.read().decode()
    return out


def reachable(path: str, files: set[str], dirs: set[str]) -> bool:
    """Falco reads `path` because rules_files names it, or a directory above it.

    Anchored on a separator rather than a prefix: `/etc/falco/rules.d` must not
    make `/etc/falco/rules.disabled` reachable, and a containment test would.
    """
    return path in files or any(path.startswith(d + "/") for d in dirs)


def read_paths(falco: dict, env: str) -> tuple[set[str], set[str]]:
    """The files and directories `rules_files` names, as absolute paths."""
    listed = falco.get("rules_files")
    if not listed:
        fail(f"values-{env}.yaml: the render names no falco.rules_files, so Falco "
             f"reads nothing that falcoctl installs.")
        return set(), set()
    files = {p for p in listed if str(p).endswith((".yaml", ".yml"))}
    dirs = {str(p).rstrip("/") for p in listed if p not in files}
    return files, dirs


def main() -> int:
    gatelib.require("helm")
    repo, chart, version = chart_pin()
    envs = environments()
    if not envs:
        fail(f"{ADDON.relative_to(ROOT)} carries no values-<env>.yaml, so this gate "
             f"examined no environment.")

    summary: list[tuple[str, int, int]] = []
    for env in envs:
        falco, falcoctl = render(repo, chart, version, env)
        rel = f"addons/security/falco/values-{env}.yaml"

        floor = falco.get("priority")
        if floor is None or rank(str(floor)) < 0:
            fail(f"{rel}: the render sets falco.priority to {floor!r}, which is not "
                 f"one of {', '.join(SEVERITY)}. Falco's own floor is then unknown "
                 f"and the count below cannot be interpreted.")
            continue
        if rank(str(floor)) < rank(MIN_PRIORITY):
            fail(f"{rel}: falco.priority is {floor!r}, stricter than {MIN_PRIORITY!r}. "
                 f"Every rule less severe than {floor!r} is still downloaded to every "
                 f"node and never loaded — including the privileged-container rules, "
                 f"which upstream classifies INFO.")

        refs = (((falcoctl.get("artifact") or {}).get("install") or {})
                .get("refs") or [])
        if not refs:
            fail(f"{rel}: the rendered falcoctl config installs no refs. Note that "
                 f"`refs` belongs under falcoctl.config.artifact — falcoctl.artifact "
                 f"carries the containers' own settings and accepts no refs key, and "
                 f"the chart ships no values.schema.json to reject the wrong path.")
            continue

        files, dirs = read_paths(falco, env)
        loaded = installed = sets = 0
        for ref in refs:
            contents = rulesfile(ref)
            if contents is None:
                continue  # a plugin ref, or a ref this run already reported
            sets += 1
            for fname, text in contents.items():
                path = f"{FALCO_DIR}/{fname}"
                is_read = reachable(path, files, dirs)
                rules = [i for i in yaml.safe_load(text)
                         if isinstance(i, dict) and "rule" in i]
                passing = [r for r in rules if 0 <= rank(str(r.get("priority", "")))
                           <= rank(str(floor))]
                installed += len(rules)
                if is_read:
                    loaded += len(passing)
                else:
                    fail(f"{rel}: ref {ref!r} installs {path}, which falco.rules_files "
                         f"does not name. Its {len(rules)} rule(s) are pulled onto "
                         f"every node and never evaluated — the download succeeds, so "
                         f"nothing else reports this.")

        if sets == 0:
            fail(f"{rel}: none of the {len(refs)} installed ref(s) is a rule set, so "
                 f"Falco runs its probe against no rules this repo pins.")
        if loaded < RULE_FLOOR:
            fail(f"{rel}: {loaded} rule(s) load at priority {floor!r}, below the floor "
                 f"of {RULE_FLOOR}. {installed} are installed on disk. A tier dropped "
                 f"from the refs, a tier installed but not read, or a priority floor "
                 f"raised past rules that exist each remove rules in blocks.")
        summary.append((env, loaded, installed))

    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1

    detail = ", ".join(f"{e} {ld}/{inst}" for e, ld, inst in summary)
    print(f"falco rule floor OK: every installed rule set is named in rules_files, "
          f"every environment loads at {MIN_PRIORITY!r} or more permissive, and the "
          f"rules that load clear the floor of {RULE_FLOOR} — loaded/installed "
          f"{detail}. Counted from the rendered ConfigMaps against the registry the "
          f"refs resolve to, not from the values files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
