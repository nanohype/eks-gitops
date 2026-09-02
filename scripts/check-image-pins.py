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
        for m in IMAGE.finditer(proc.stdout):
            images.setdefault(m.group(1), set()).add(u.chart)
    return images, unscannable


def classify(ref: str) -> str:
    """'digest', 'tag', or 'mutable'."""
    if "@sha256:" in ref:
        return "digest"
    name = ref.rsplit("/", 1)[-1]
    if ":" not in name:
        return "mutable"          # no tag resolves to :latest
    tag = name.rsplit(":", 1)[1]
    return "mutable" if tag.lower() in MUTABLE_TAGS else "tag"


def bare_name(ref: str) -> str:
    """A reference with its tag removed, which is what an exemption names.

    Split on the last colon only when it sits in the final path segment: a
    registry with a port (`registry:5000/x/y`) carries a colon that is not a tag
    separator, and cutting there would produce a key no exemption can match and
    no reader can recognise.
    """
    name = ref.rsplit("/", 1)[-1]
    return ref.rsplit(":", 1)[0] if ":" in name else ref


def verdict(images: dict[str, set[str]], allowed: dict[str, str]) -> list[str]:
    """Every image-pin problem, over an inventory and an exemption list.

    Two directions, and the second is the one that rots. A mutable reference with
    no exemption is the defect the gate exists for. An exemption the fleet no
    longer renders mutably is a description that outlived its reason, and an
    exemption list nobody re-checks only ever widens.
    """
    failures = []
    mutable_seen: set[str] = set()

    for ref in sorted(images):
        if classify(ref) != "mutable":
            continue
        bare = bare_name(ref)
        mutable_seen.add(bare)
        if bare in allowed:
            continue
        failures.append(
            f"{ref} (via {', '.join(sorted(images[ref]))}) resolves to a moving target. "
            f"Pin it in the addon's values.yaml to the chart's appVersion or a digest.")

    for bare, reason in sorted(allowed.items()):
        if bare not in mutable_seen:
            failures.append(
                f"{bare} is on the mutable-tag exemption list but the fleet no longer "
                f"renders it mutably — the exemption outlived its reason. Delete it. "
                f"(recorded: {reason[:100]})")
    return failures


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

    failures = verdict(images, ALLOWED_MUTABLE)

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
