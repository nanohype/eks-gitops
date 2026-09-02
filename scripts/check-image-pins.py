#!/usr/bin/env python3
"""Every image the fleet renders carries an immutable reference.

    scripts/check-image-pins.py            # blocking gate
    scripts/check-image-pins.py --list     # print the rendered image inventory

WHY THE RENDERED STACK IS THE INPUT

A values file names an image only when this catalog overrides one. Almost every
image reaching a cluster comes from a chart's own defaults, so scanning
`addons/**/values.yaml` scans the handful this repo happens to have opinions
about and misses the rest. The population is what `helm template` produces.

That is also how this gate found its first defect: the kyverno chart leaves its
readiness-checker tag unset, which resolves to `:latest`, and no values file in
this repo mentions the image at all.

WHY IT BLOCKS RATHER THAN RUNNING SCHEDULED

Whether a reference is mutable is a fact about the commit under test — a pin is
in the tree or it is not, and the answer cannot change without an edit. So it
blocks a merge.

Its sibling question, whether a CVE landed in an image overnight, is not a fact
about the commit and belongs on a schedule: blocking a merge on the world
changing is how a gate teaches people to route around it. That half lives with
the scheduled chart-provenance workflow and with trivy-operator at runtime.

WHAT COUNTS AS PINNED

A digest is immutable. A version tag is not, strictly — a publisher can move it
— but repinning every upstream chart's images by digest here would fork every
chart's values and go stale the moment a chart bumps. The line this gate draws
is the one that catches real drift: a reference with no tag, or an explicitly
mutable one (`latest`, `main`, `master`, `edge`, `stable`, `dev`), resolves to
something different tomorrow with nothing in this repo changing.

UNSCANNABLE IS REPORTED, NEVER COUNTED CLEAN

A chart that fails to render is named in the output and its images are absent
from the inventory. A gate that silently skipped it would report the remaining
charts as the whole fleet.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import re
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


# Reuse render-addons' discovery, repo setup and render path rather than
# re-deriving which chart a path belongs to. Three earlier attempts at a local
# resolver each got a different subset of the fleet: the matrix shape only, then
# the matrix plus single-source shapes, then a parameter scan loose enough to
# apply one appset's `--set` values to another chart — which is the failure the
# karpenter appset's own comment warns about, a stray settings.clusterName
# failing a chart whose schema rejects unknown keys.
#
# The module file is hyphenated, so it loads by path. Registering it in
# sys.modules BEFORE exec_module is what lets its dataclass resolve its
# annotations.
_ra_path = pathlib.Path(__file__).resolve().parent / "render-addons.py"
_spec = importlib.util.spec_from_file_location("render_addons", _ra_path)
assert _spec and _spec.loader, f"{_ra_path} is not loadable as a module"
render_addons = importlib.util.module_from_spec(_spec)
sys.modules["render_addons"] = render_addons
_spec.loader.exec_module(render_addons)

# Helm charts occasionally emit the YAML `=` default-value sentinel (e.g. `- =`
# inside a ConfigMap payload). PyYAML's SafeLoader has no constructor for it and
# raises, which would drop a whole chart's render out of the walk below — so map
# the sentinel to its literal scalar rather than lose the chart.
yaml.SafeLoader.add_constructor(
    "tag:yaml.org,2002:value",
    lambda loader, node: loader.construct_scalar(node),  # type: ignore[arg-type]
)

ROOT = render_addons.REPO_ROOT
NETWORK_TIMEOUT = 300

# Tags whose meaning changes under you. `latest` is the one a chart lands on by
# leaving a tag unset, which is why an untagged reference is treated the same.
MUTABLE_TAGS = {"latest", "main", "master", "edge", "stable", "dev", "nightly"}

IMAGE = re.compile(r'^\s*image:\s*"?([^"\s]+)"?\s*$', re.M)

# Exemptions, asserted against the real render. An entry naming an image the
# fleet no longer renders mutably FAILS: an exemption that matches nothing is a
# description that rots, and it rots toward permissive.
ALLOWED_MUTABLE: dict[str, str] = {}


def inventory(env: str) -> tuple[dict[str, set[str]], list[tuple[str, str]]]:
    """(image -> charts that render it, [(path, why-not-scanned)])."""
    gatelib.require('helm')
    units = render_addons.discover()
    aliases = render_addons.add_repos(units)
    images: dict[str, set[str]] = {}
    unscannable: list[tuple[str, str]] = []

    for u in units:
        if u.chart in getattr(render_addons, "SKIP_CHARTS", {}):
            unscannable.append((u.path, "chart is on render-addons' SKIP_CHARTS list"))
            continue
        d = ROOT / u.path
        if not d.is_dir():
            unscannable.append((u.path, "path does not exist"))
            continue
        vf = []
        if (d / "values.yaml").exists():
            vf += ["-f", str(d / "values.yaml")]
        if (d / f"values-{env}.yaml").exists():
            vf += ["-f", str(d / f"values-{env}.yaml")]
        ref = [u.oci_ref()] if u.is_oci else [f"{aliases[u.repo]}/{u.chart}"]
        cmd = ["helm", "template", u.chart, *ref, "--version", u.version]
        if u.namespace:
            cmd += ["--namespace", u.namespace]
        for name, value in u.params:
            cmd += ["--set", f"{name}={value}"]
        cmd += vf
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
        if proc.returncode != 0:
            unscannable.append((u.path, (proc.stderr.strip() or proc.stdout.strip())[:200]))
            continue
        for ref_str in extract_images(proc.stdout, u.chart, unscannable):
            images.setdefault(ref_str, set()).add(u.chart)
    return images, unscannable


# Kinds that own a pod template, and the path from the document to its podSpec.
# The deployable surface: every container the cluster starts comes from one of
# these, so this is the population any question about "what runs" reads.
POD_OWNERS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

CONTAINER_LISTS = ("initContainers", "containers", "ephemeralContainers")

# Images that reach a cluster without ever appearing as a YAML `image:` key,
# because a controller reads them out of a string payload it is handed. Neither
# structural walk can see one, so the text scan is what finds them — and an entry
# here is asserted in both directions below: one a structural walk DOES find is
# stale, and an image only the text scan finds that is not listed means a walk
# stopped seeing a shape.
TEXT_ONLY_IMAGES = {
    "docker.io/envoyproxy/ratelimit": "the Envoy Gateway controller reads the rate-limit "
                                      "image out of its own EnvoyGateway ConfigMap, so it "
                                      "is a string inside a config blob rather than a "
                                      "container in a pod template",
}


# Charts that render no container image because they ship only CustomResource
# definitions. Asserted in both directions by chart_coverage below: one that
# starts shipping a workload fails here, and one that is named and no longer
# rendered fails too.
IMAGELESS_CHARTS = {
    "ai-gateway-crds-helm": "the Envoy AI Gateway CRDs, applied ahead of the "
                            "controller that renders one of their kinds",
    "prometheus-operator-crds": "the Prometheus operator CRDs, applied ahead of "
                                "the charts that render ServiceMonitors",
}


def chart_coverage(images: dict[str, set[str]], units) -> list[str]:
    """Every chart the render covered contributed an image, or is declared not to.

    A per-chart floor rather than a total, because a total cannot see the shape
    that actually happened: an extractor missed the ordinary `- image:` list-item
    spelling, two charts' entire workloads fell out of the inventory, and the
    count stayed large enough to look healthy. One image per chart is derived
    from the corpus — no constant to pick, and it moves with the catalog.
    """
    problems: list[str] = []
    rendered = {u.chart for u in units if u.chart not in getattr(
        render_addons, "SKIP_CHARTS", {})}
    contributing = set().union(*images.values()) if images else set()

    for chart in sorted(rendered - contributing):
        if chart in IMAGELESS_CHARTS:
            continue
        problems.append(
            f"{chart} rendered and contributed no image. Every chart shipping a "
            f"workload contributes at least one, so either the extraction stopped "
            f"seeing a shape this chart uses, or the chart ships only CRDs and "
            f"belongs in IMAGELESS_CHARTS with the reason.")

    for chart, reason in sorted(IMAGELESS_CHARTS.items()):
        if chart not in rendered:
            problems.append(
                f"{chart} is declared imageless but the fleet no longer renders it — "
                f"the entry outlived its chart. (recorded: {reason})")
        elif chart in contributing:
            problems.append(
                f"{chart} is declared imageless and now contributes an image. It "
                f"ships a workload; delete the entry so its images are scanned like "
                f"every other chart's. (recorded: {reason})")
    return problems


def bare_name(ref: str) -> str:
    """A reference with tag and digest removed, which is what an entry names.

    The tag separator is the last colon in the FINAL path segment: a registry
    with a port carries a colon that is not one, and cutting there produces a key
    no entry can match and no reader can recognise.
    """
    ref = ref.split("@", 1)[0]
    name = ref.rsplit("/", 1)[-1]
    return ref.rsplit(":", 1)[0] if ":" in name else ref


def _podspec(doc: dict, path: tuple[str, ...]) -> dict | None:
    cur: object = doc
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur if isinstance(cur, dict) else None


def podspec_images(docs: list) -> set[str]:
    """Every container image the rendered documents start, walked structurally."""
    found: set[str] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if not isinstance(kind, str):
            continue
        path = POD_OWNERS.get(kind)
        if path is None:
            continue
        spec = _podspec(doc, path)
        if spec is None:
            continue
        for key in CONTAINER_LISTS:
            for container in spec.get(key) or []:
                if isinstance(container, dict) and isinstance(container.get("image"), str):
                    found.add(container["image"])
    return found


def keyed_images(node) -> set[str]:
    """Every `image:` key anywhere in the documents, whatever declares it.

    A custom resource can name an image its operator then runs — the agent
    platform's eval-runner is one — and no pod template in this render carries
    it. Restricting the walk to pod owners would drop it.
    """
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "image" and isinstance(value, str):
                found.add(value)
            else:
                found |= keyed_images(value)
    elif isinstance(node, list):
        for value in node:
            found |= keyed_images(value)
    return found


def extract_images(rendered: str, chart: str,
                   unscannable: list[tuple[str, str]]) -> set[str]:
    """Every image one chart's render deploys, and an assertion that it is every one.

    Structural first, because a pattern is a claim about spelling. IMAGE is
    anchored on `image:` preceded only by whitespace, so the ordinary list-item
    form `- image: <ref>` never matched it: against this catalog's render the
    pattern yielded 55 images where the pod specs hold 57, and the four it missed
    were the whole workload of two charts. A scanner that omits images silently
    is worse than none, because its green result becomes evidence.

    The text scan is kept as an independent floor under the walks rather than
    replaced. A parser and a pattern fail on different inputs, so a structural
    walk that stops seeing a shape is caught by the one that reads the bytes —
    and an image ONLY the pattern finds is either a string payload a controller
    reads (declared in TEXT_ONLY_IMAGES) or a walk that has drifted.
    """
    try:
        docs = list(yaml.safe_load_all(rendered))
    except yaml.YAMLError as exc:
        first = str(exc).strip().splitlines()[0]
        unscannable.append((chart, f"rendered YAML this gate could not parse — {first}"))
        return set()

    structural = podspec_images(docs) | keyed_images(docs)
    textual = {m.group(1) for m in IMAGE.finditer(rendered)}

    for ref_str in sorted(textual - structural):
        if bare_name(ref_str) not in TEXT_ONLY_IMAGES:
            unscannable.append((
                chart,
                f"{ref_str} appears in the rendered text and in no pod template or "
                f"`image:` key — either a structural walk stopped seeing a shape, or "
                f"a controller reads it out of a payload and it belongs in "
                f"TEXT_ONLY_IMAGES with the reason"))
    return structural | textual


def classify(ref: str) -> str:
    """'digest', 'tag', or 'mutable'."""
    if "@sha256:" in ref:
        return "digest"
    name = ref.rsplit("/", 1)[-1]
    if ":" not in name:
        return "mutable"          # no tag resolves to :latest
    tag = name.rsplit(":", 1)[1]
    return "mutable" if tag.lower() in MUTABLE_TAGS else "tag"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print the image inventory")
    ap.add_argument("--env", default="production")
    args = ap.parse_args()

    images, unscannable = inventory(args.env)

    if args.list:
        for ref in sorted(images):
            print(f"{classify(ref):8} {ref}  ({', '.join(sorted(images[ref]))})")
        print(f"\n{len(images)} image(s); {len(unscannable)} chart(s) unscannable")
        for path, err in unscannable:
            print(f"  unscannable  {path}: {err}")
        return 0

    if not images:
        print("FAIL  rendered no images at all. Every chart failed, or the extractor "
              "stopped matching — either way this reports the same as a clean fleet.")
        for path, err in unscannable:
            print(f"        {path}: {err}")
        return 2

    failures = chart_coverage(images, render_addons.discover())
    mutable_seen: set[str] = set()

    for ref in sorted(images):
        if classify(ref) != "mutable":
            continue
        name = ref.rsplit("/", 1)[-1]
        bare = ref.rsplit(":", 1)[0] if ":" in name else ref
        mutable_seen.add(bare)
        if bare in ALLOWED_MUTABLE:
            continue
        failures.append(
            f"{ref} (via {', '.join(sorted(images[ref]))}) resolves to a moving target. "
            f"Pin it in the addon's values.yaml to the chart's appVersion or a digest.")

    for bare, reason in sorted(ALLOWED_MUTABLE.items()):
        if bare not in mutable_seen:
            failures.append(
                f"{bare} is on the mutable-tag exemption list but the fleet no longer "
                f"renders it mutably — the exemption outlived its reason. Delete it. "
                f"(recorded: {reason[:100]})")

    # Reported whatever the verdict: a chart that did not render contributed no
    # images, and counting the rest as the whole fleet is how a partial scan
    # reads as a complete one.
    if unscannable:
        print(f"{len(unscannable)} chart(s) could not be rendered and were NOT scanned:")
        for path, err in unscannable:
            print(f"  {path}: {err}")
        print()

    if failures:
        print(f"{len(failures)} image-pin problem(s) across {len(images)} rendered image(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1

    print(f"✓ all {len(images)} rendered image(s) across {len(images and set().union(*images.values()) or [])} "
          f"chart(s) carry an immutable reference "
          f"({len(ALLOWED_MUTABLE)} exemption(s), each still matching the render)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
