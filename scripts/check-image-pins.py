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
ALLOWED_MUTABLE: dict[str, str] = {
    "ghcr.io/kyverno/kyverno":
        "the kyverno chart carries this in a ConfigMap as the CLI image for "
        "`kyverno` invocations, with no values key to pin it. Invisible until "
        "controller-supplied references entered the population. Clears when the "
        "chart exposes the tag, or when this catalog stops shipping that "
        "ConfigMap.",
    "nats-streaming":
        "the argo-events version table's oldest streaming row carries `latest`, "
        "alongside rows that pin. An eventbus asking for that version gets a "
        "moving image; nothing in this catalog selects it, and nothing here can "
        "pin it. Clears on a chart that pins the row.",
    "natsio/prometheus-nats-exporter":
        "an argo-events eventbus default the controller passes to the NATS "
        "StatefulSet it creates. The chart pins two other tags of this image and "
        "leaves the exporter's unset. Clears on a chart version that pins it.",
}


def inventory(env: str, seen: set[str] | None = None
              ) -> tuple[dict[str, set[str]], list[tuple[str, str]]]:
    """(image -> charts that render it, [(path, why-not-scanned)]).

    `seen`, if given, collects every image-shaped reference the render carried —
    including the ones excluded from the population — so a declaration can be
    checked against what the render contains rather than against what survived.
    """
    gatelib.require('helm')
    units = render_addons.discover()
    aliases = render_addons.add_repos(units)
    images: dict[str, set[str]] = {}
    unscannable: list[tuple[str, str]] = []
    seen = set() if seen is None else seen

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
        for ref_str in extract_images(proc.stdout, u.chart, unscannable, seen):
            images.setdefault(ref_str, set()).add(u.chart)
    return images, unscannable


# An image reference as a controller is handed one: in a flag, a ConfigMap value,
# a CR field. Requires a path separator, which is what separates an image from
# the host:port strings that fill a rendered config — `loki.monitoring.svc:3100`
# and `127.0.0.1:8080` are addresses, not images, and no grammar that admits them
# can be read by a human.
# Two alternatives, because an official image carries neither a registry nor an
# organisation: `nats:2.10.10` is the whole reference. Requiring a path separator
# made that shape invisible, and the argo-events event-bus controller declares
# exactly it — `natsImage` beside the two `natsio/*` sidecars in the same rows,
# so one StatefulSet had its helpers scanned and its main container silent.
#
# The single-segment alternative needs two discriminators the prefixed one does
# not, because a rendered config is full of strings with that shape:
#
#   * the match may not begin part-way through a longer token. Without that the
#     alternative starts after a dot and `vault.example.com:8200` yields
#     `com:8200`, which is a hostname's last label and a port.
#   * the NAME must start with a letter and carry no dot. That excludes a
#     timestamp (`00:00Z`), an address (`10.0.0.5:8080`,
#     `telemetry.monitoring.svc.cluster.local:4318`), an IPv6 fragment and a
#     ratio (`1:1`).
#   * the TAG must be `latest` or begin with a digit, optionally after a `v`.
#     That excludes the RBAC names — `kyverno:admission-controller`,
#     `system:auth-delegator` — which are the shape's other common occupant.
#
# Together they admit every official-image reference this fleet pins and no
# string in the render that is not one.
IMAGE_REF = re.compile(
    r"(?<![a-z0-9._:/-])(?:"
    r"((?:[a-z0-9][a-z0-9._-]*(?:\.[a-z0-9._-]+)+(?::\d+)?/)?"
    r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+:[a-zA-Z0-9][\w.-]*)"
    r"|([a-z][a-z0-9]*(?:[_-][a-z0-9]+)*:(?:latest|v?[0-9][\w.-]*))"
    r")\b")

# Images a CONTROLLER starts, which no pod template in this render declares. The
# controller is handed the reference and creates the pod later, so the deployable
# surface is strictly larger than what `helm template` shows as a container.
#
# Whether a given string is one of these is a fact about a controller's behaviour,
# and this gate reads manifests. So it is declared rather than inferred, and the
# declaration is what the assertion is against: every image-shaped string the
# render carries must be in the structural population, on this list, or on
# NOT_A_CONTAINER. An unclassified one is reported, so the answer to "is this
# deployed?" is never silence.
CONTROLLER_IMAGES = {
    "nats":
        "the NATS server the argo-events eventbus controller starts, declared as "
        "`natsImage` in its own version table beside the two natsio/* sidecars it "
        "creates in the same StatefulSet",
    "nats-streaming":
        "the same table's streaming variant, for eventbus resources that ask for "
        "it",
    "docker.io/envoyproxy/ratelimit":
        "the Envoy Gateway controller reads it from its own EnvoyGateway "
        "ConfigMap and creates the rate-limit Deployment",
    "docker.io/envoyproxy/ai-gateway-extproc":
        "the AI Gateway controller injects it as the ext-proc sidecar on every "
        "gateway pod it manages",
    "ghcr.io/aquasecurity/node-collector":
        "trivy-operator creates one node-collector pod per node scan",
    "quay.io/argoproj/argoexec":
        "the workflow controller injects it as the init and wait container of "
        "every workflow step pod",
    "quay.io/jetstack/cert-manager-acmesolver":
        "cert-manager creates one solver pod per HTTP-01 challenge",
    "natsio/nats-server-config-reloader":
        "the argo-events eventbus controller creates the NATS StatefulSet with "
        "this sidecar",
    "natsio/prometheus-nats-exporter":
        "the same controller, same StatefulSet",
    "ghcr.io/kyverno/kyverno":
        "the chart's own CLI image reference, carried in a ConfigMap for "
        "`kyverno` invocations rather than as a container",
}

# Image-shaped strings that are not container images. An OCI artifact reference
# resolves through a registry and looks identical, and pulling one starts no
# container — so scanning it for a running-container CVE would report on
# something nothing runs.
NOT_A_CONTAINER = {
    "falco-rules":
        "a falcoctl rulesfile OCI artifact; check-falco-rule-floor.py resolves "
        "these against the registry and asserts Falco loads what they install",
    "falco-incubating-rules":
        "the same, the incubating tier",
    "falco-sandbox-rules":
        "the same, the sandbox tier",
    "sha256":
        "the digest half of a reference the walk already holds whole — `image@"
        "sha256:<hex>` splits at the `@` and the tail has the single-segment "
        "shape",
    "localhost":
        "a memcached address in a Loki config value; `localhost:11211` is a host "
        "and a port",
    "hubble-relay":
        "a Kubernetes Service address in a Cilium config value — `hubble-relay:80` "
        "has the shape of a single-segment image and is a host and a port",
    "ghcr.io/falcosecurity/plugins/plugin/container":
        "a falcoctl rules/plugin OCI artifact, unpacked into an emptyDir",
    "ghcr.io/falcosecurity/plugins/plugin/k8smeta":
        "the same, the k8smeta plugin",
    "mirror.gcr.io/aquasec/trivy-checks":
        "the trivy checks bundle, an OCI artifact trivy-operator downloads",
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


def chart_coverage(images: dict[str, set[str]], units,
                   seen: set[str] | None = None) -> list[str]:
    """Every chart the render covered contributed an image, or is declared not to.

    A per-chart floor rather than a total, because a total cannot see the shape
    that actually happened: an extractor missed the ordinary `- image:` list-item
    spelling, two charts' entire workloads fell out of the inventory, and the
    count stayed large enough to look healthy. One image per chart is derived
    from the corpus — no constant to pick, and it moves with the catalog.
    """
    problems: list[str] = []
    # Keyed by chart NAME, which is what `images` records, and this catalog pins
    # opentelemetry-collector three times — otel-agent, otel-gateway and
    # otel-gateway-floor. Any one of those can render nothing while the other two
    # keep the name contributing, so the floor is per chart name and says so
    # rather than reading as per render unit.
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

    problems += declaration_rot(seen if seen is not None
                                else {bare_name(ref) for ref in images})

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


def string_scalars(node) -> list[str]:
    """Every string a rendered document carries, at any depth.

    A controller is handed an image the same way it is handed anything else — a
    flag in `args`, a value in a ConfigMap, a field on a custom resource — so the
    surface an image can arrive through is every string, not a key name.
    """
    out: list[str] = []
    if isinstance(node, dict):
        for value in node.values():
            out.extend(string_scalars(value))
    elif isinstance(node, list):
        for value in node:
            out.extend(string_scalars(value))
    elif isinstance(node, str):
        out.append(node)
    return out


def keyed_images(node) -> set[str]:
    """Every `image:` key anywhere in the documents, whatever declares it.

    Structure, not text. The pattern this replaced was anchored on `image:`
    preceded only by whitespace, so the ordinary list-item form `- image: <ref>`
    under `containers:` never matched it and two charts' entire workloads were
    absent from a scan reporting fifty-five images.

    Deliberately not restricted to pod templates. A walk over pod owners is a
    strict SUBSET of this one — every container's image is an `image:` key — so
    it would be mechanism with no effect, and it would drop the custom resources
    that name an image an operator then runs.
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
                   unscannable: list[tuple[str, str]],
                   seen: set[str] | None = None) -> set[str]:
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

    structural = keyed_images(docs)
    textual = {m.group(1) for m in IMAGE.finditer(rendered)}
    candidates = {c for s in string_scalars(docs)
                  for groups in IMAGE_REF.findall(s) for c in groups if c}
    if seen is not None:
        # Every image-shaped reference the render carried, including the ones
        # excluded below. A declaration is about what the render CONTAINS, so
        # checking it against the surviving population would report every
        # NOT_A_CONTAINER entry as stale by construction.
        seen |= {bare_name(r) for r in structural | textual | candidates}

    # Compared on the bare name, because the same image reaches a render twice:
    # once as a container reference carrying a digest, and once as a bare
    # `repo:tag` in an annotation or a config value. Those are one image, and
    # reporting the second as unreachable would be reporting the first.
    structural_bare = {bare_name(r) for r in structural}
    controller: set[str] = set()
    for ref_str in sorted((textual | candidates) - structural):
        bare = bare_name(ref_str)
        if bare in structural_bare or bare in NOT_A_CONTAINER:
            continue
        if bare in CONTROLLER_IMAGES:
            controller.add(ref_str)
            continue
        unscannable.append((
            chart,
            f"{ref_str} is image-shaped and reaches no pod template or `image:` key. "
            f"Either a structural walk stopped seeing a shape, or a controller is "
            f"handed it and starts a pod later — in which case it belongs in "
            f"CONTROLLER_IMAGES with the controller that starts it, or in "
            f"NOT_A_CONTAINER if pulling it runs nothing"))
    return structural | textual | controller


def declaration_rot(seen: set[str]) -> list[str]:
    """Declarations the render no longer supports.

    Both lists say something about images this catalog renders. An entry for one
    it does not is an excuse for nothing, and an exemption list nobody re-reads
    only ever widens.
    """
    problems = []
    for table, label in ((CONTROLLER_IMAGES, "started by a controller"),
                         (NOT_A_CONTAINER, "not a container image")):
        for bare, reason in sorted(table.items()):
            if bare not in seen:
                problems.append(
                    f"{bare} is declared {label} and the fleet renders no reference to "
                    f"it — the declaration outlived its image. (recorded: {reason})")
    return problems


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

    seen: set[str] = set()
    images, unscannable = inventory(args.env, seen)

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

    failures = chart_coverage(images, render_addons.discover(), seen)
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
