#!/usr/bin/env python3
"""Validate the catalog's own platform CRs against the CRDs the catalog installs.

WHY THIS EXISTS

`kubeconform-scan.sh` skips Platform, Tenant, ModelGateway, BudgetPolicy,
AgentFleet and EvalSuite. Its comment is honest about why — their schemas live
in eks-agent-platform and are published to no public catalog — and says they are
validated "out-of-band" with `kubectl apply --dry-run=server`.

For `addons/ai-platform/agent-platform/base/platform.yaml` that never happened.
It shipped an AgentFleet whose single agent carried name, systemPrompt and
modelRoute, and the AgentFleet CRD requires `spec.agents[].image`. Every cluster
syncing the addon got

    AgentFleet.agents.nanohype.dev "ops-fleet" is invalid:
      spec.agents[0].image: Required value

and that Application never reached Healthy. A skip that records a gap is better
than a green tick that pretends there is none, but a gap nobody closes is still
a gap, and this one was in a manifest applied to every cluster in the fleet.

WHAT THIS DOES

Resolves the CRDs from the operator chart at the version the catalog PINS —
`applicationsets/addons-agent-operator.yaml`'s targetRevision — and walks every
CR of those kinds in the tree:

  - every `required` property must be present, at every level
  - no property may be absent from the schema (the API server prunes it, so a
    field set here has never reached a cluster)

The version comes from the appset rather than from `latest` deliberately. The
question is not "is this manifest valid against the newest CRDs" but "is it
valid against the CRDs this catalog installs", and those are different whenever
a chart bump is in flight.

It needs the network (one `helm pull` from ghcr.io, anonymous). With
--offline it skips instead of failing, so a local run without a registry is
honest about having checked nothing.

    scripts/check-platform-crs.py
    scripts/check-platform-crs.py --list      # print what it resolved and walked
    scripts/check-platform-crs.py --self-test # check the walker, not the repo
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
OPERATOR_APPSET = ROOT / "applicationsets" / "addons-agent-operator.yaml"
CHART = "oci://ghcr.io/nanohype/eks-agent-platform/charts/operator"
CRD_VERSION = "v1alpha1"

# Directories with no bearing on what a cluster applies.
SKIP_DIRS = {".git", "node_modules", "rendertest", "__pycache__", ".task"}


def pinned_chart_version() -> str:
    """The operator chart version this catalog installs.

    Read out of the ApplicationSet rather than passed in, so the gate cannot be
    run against a version the fleet is not on. The chart source block is the one
    whose repoURL is the operator chart; its sibling `targetRevision: main` is
    the catalog's own git revision and must not be mistaken for it.
    """
    text = OPERATOR_APPSET.read_text()
    m = re.search(
        r"repoURL:\s*\S*ghcr\.io/nanohype/eks-agent-platform/charts.*?targetRevision:\s*(\S+)",
        text,
        re.S,
    )
    if not m:
        sys.exit(
            f"{OPERATOR_APPSET}: could not find the operator chart's targetRevision. "
            "This gate resolves CRDs from the version the catalog pins; without it "
            "there is nothing to validate against."
        )
    return m.group(1).strip().strip("\"'")


def crd_schemas(version: str, workdir: Path) -> dict[str, dict]:
    """kind -> spec schema, from the operator chart's shipped CRDs."""
    subprocess.run(
        ["helm", "pull", CHART, "--version", version, "--untar", "--untardir", str(workdir)],
        check=True,
        capture_output=True,
        text=True,
    )
    crd_dir = workdir / "operator" / "crds"
    if not crd_dir.is_dir():
        sys.exit(f"operator chart {version} ships no crds/ directory")

    out: dict[str, dict] = {}
    for f in sorted(crd_dir.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
        if not doc or doc.get("kind") != "CustomResourceDefinition":
            continue
        kind = doc["spec"]["names"]["kind"]
        for v in doc["spec"]["versions"]:
            if v["name"] != CRD_VERSION:
                continue
            schema = v["schema"]["openAPIV3Schema"]["properties"].get("spec")
            if schema:
                out[kind] = schema
    if not out:
        sys.exit(f"operator chart {version} ships no {CRD_VERSION} CRD schemas")
    return out


def list_identities(value, schema):
    """What the API server compares two entries of this list by, or None.

    `map` identifies an entry by its listMapKeys tuple; `set` identifies a scalar
    entry by itself. Any other list-type (`atomic`, or none) imposes no
    uniqueness, so there is nothing to compare.

    Absent keys participate in a map identity: under listMapKeys ["name"],
    `[{"name": "a"}, {"name": "a", "kind": "cache"}]` is a duplicate, and reading
    only the fields that happen to be set would miss it. Entries of the wrong
    shape are skipped rather than guessed at — a non-dict in a map list is a type
    error the type checker below reports on its own terms.
    """
    kind_of_list = schema.get("x-kubernetes-list-type")
    if kind_of_list == "map":
        keys = schema.get("x-kubernetes-list-map-keys") or []
        if not keys:
            return None
        pairs = [
            (i, tuple(v.get(k) for k in keys))
            for i, v in enumerate(value)
            if isinstance(v, dict)
        ]
        return "+".join(keys), pairs
    if kind_of_list == "set":
        pairs = [
            (i, v) for i, v in enumerate(value)
            if isinstance(v, (str, int, float, bool))
        ]
        return "value", pairs
    return None


def check_list_uniqueness(value, schema, path, kind, source, problems):
    """x-kubernetes-list-type is a validation rule, not documentation.

    A violation is a hard rejection of the whole object at admission — not a
    warning, not a merge of the two entries.

    Nothing in the org checked this, which is how a Platform declaring two
    datastores both named `main` passed every gate green and was refused by the
    API server on a live cluster. `required`-and-pruning is the obvious half of
    admissibility; this is the half a schema walker written from first
    principles does not think to add, and the CRDs carry 16 of these arrays.
    """
    resolved = list_identities(value, schema)
    if resolved is None:
        return
    label, pairs = resolved

    seen: dict = {}
    for i, identity in pairs:
        if identity in seen:
            shown = (
                "/".join("<unset>" if p is None else str(p) for p in identity)
                if isinstance(identity, tuple) else str(identity)
            )
            problems.append(
                f"{source}: {kind} {path}[{i}] repeats {label}={shown}, already at "
                f"{path}[{seen[identity]}] — the CRD declares this array "
                f"`x-kubernetes-list-type: {schema['x-kubernetes-list-type']}`, so the API "
                f"server rejects the whole object with `{path.lstrip('.')}: Duplicate value`. "
                f"Nothing partial is applied and the Application never reaches Healthy"
            )
            continue
        seen[identity] = i


def walk(value, schema, path, kind, source, problems):
    """Required present, nothing excess, list identities unique — arrays transparent.

    Stops descending wherever the schema declines to describe the shape
    (x-kubernetes-preserve-unknown-fields, or an object with no properties),
    because the API server does not prune there either.
    """
    if not isinstance(schema, dict):
        return

    if isinstance(value, list):
        check_list_uniqueness(value, schema, path, kind, source, problems)
        items = schema.get("items")
        if isinstance(items, dict):
            for i, item in enumerate(value):
                walk(item, items, f"{path}[{i}]", kind, source, problems)
        return

    if not isinstance(value, dict):
        return
    if schema.get("x-kubernetes-preserve-unknown-fields"):
        return
    props = schema.get("properties")
    if props is None:
        return

    for name in schema.get("required") or []:
        if name in value:
            continue
        # A required property that declares a `default` is NOT a rejection.
        # Structural-schema defaulting runs BEFORE validation, so the API server
        # fills the value in and the object is admitted. Reading `required`
        # alone reports the catalog's Tenant as refused over
        # spec.primaryPersona, which carries `default: generic` and has been
        # admitted on every cluster this catalog has ever reached.
        if "default" in (props.get(name) or {}):
            continue
        problems.append(
            f"{source}: {kind} {path}.{name} is REQUIRED by the CRD, carries no default, "
            f"and this manifest does not set it — the API server rejects it with "
            f"`{path.lstrip('.')}.{name}: Required value`, and the Application never "
            f"reaches Healthy"
        )

    for name, child in value.items():
        child_schema = props.get(name)
        if child_schema is None:
            problems.append(
                f"{source}: {kind} {path}.{name} is set by this manifest but is not in the "
                "CRD — it is pruned at admission, so it has never reached a cluster"
            )
            continue
        walk(child, child_schema, f"{path}.{name}", kind, source, problems)


def manifests():
    for f in sorted(ROOT.rglob("*.yaml")):
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        yield f


def check(listing: bool, offline: bool) -> int:
    version = pinned_chart_version()
    if offline:
        print(f"--offline: skipped (would validate against operator chart {version})")
        return 0

    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        schemas = crd_schemas(version, Path(tmp))
        if listing:
            print(f"operator chart {version} → {', '.join(sorted(schemas))}")

        walked = 0
        for f in manifests():
            try:
                docs = list(yaml.safe_load_all(f.read_text()))
            except yaml.YAMLError:
                # Helm templates and kustomize patches are not always loadable YAML.
                # Anything a cluster applies is, and this gate is about those.
                continue
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind")
                if kind not in schemas:
                    continue
                if not str(doc.get("apiVersion", "")).endswith("/" + CRD_VERSION):
                    continue
                rel = f.relative_to(ROOT)
                name = (doc.get("metadata") or {}).get("name", "<unnamed>")
                if listing:
                    print(f"  {rel}: {kind}/{name}")
                walk(doc.get("spec") or {}, schemas[kind], "spec", kind, f"{rel} ({name})", problems)
                walked += 1

    if problems:
        print("\nthe catalog declares custom resources the API server will refuse:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nThese kinds are on kubeconform-scan.sh's skip list because their schemas are "
            "not in any public catalog. This gate is what closes that gap — it resolves them "
            "from the operator chart the catalog pins.",
            file=sys.stderr,
        )
        return 1

    print(f"\nok: {walked} platform CR(s) admissible against operator chart {version}")
    return 0


def self_test() -> int:
    """The walker has to be wrong loudly, not quietly.

    A walker that descends into nothing passes every catalog. These pin the
    properties the check depends on: required is enforced, excess is caught,
    arrays are transparent, list identities are unique, and an unrestricted
    schema is left alone.
    """
    schema = {
        "properties": {
            "agents": {
                "items": {
                    "required": ["image", "name"],
                    "properties": {"image": {}, "name": {}, "replicas": {}},
                },
            },
            "free": {"x-kubernetes-preserve-unknown-fields": True, "properties": {}},
            "defaulted": {
                "required": ["persona"],
                "properties": {"persona": {"default": "generic"}},
            },
            "datastores": {
                "x-kubernetes-list-type": "map",
                "x-kubernetes-list-map-keys": ["name"],
                "items": {"properties": {"name": {}, "kind": {}}},
            },
            "routes": {
                "x-kubernetes-list-type": "map",
                "x-kubernetes-list-map-keys": ["group", "name"],
                "items": {"properties": {"group": {}, "name": {}}},
            },
            "finalizers": {"x-kubernetes-list-type": "set", "items": {}},
            "ordered": {"x-kubernetes-list-type": "atomic", "items": {"properties": {"name": {}}}},
        },
    }
    cases = [
        ("required present", {"agents": [{"name": "a", "image": "i"}]}, 0),
        # Defaulting runs before validation, so a required property with a default
        # is admitted. Without this the catalog's own Tenant reads as rejected.
        ("required but defaulted is not a rejection", {"defaulted": {}}, 0),
        ("required missing in an array element", {"agents": [{"name": "a"}]}, 1),
        ("second element also checked", {"agents": [{"name": "a", "image": "i"}, {"name": "b"}]}, 1),
        ("excess property", {"agents": [{"name": "a", "image": "i", "tools": []}]}, 1),
        ("preserve-unknown-fields is left alone", {"free": {"anything": {"nested": 1}}}, 0),
        ("unknown top-level key", {"nope": 1}, 1),
        # The live failure: a Platform with two datastores both named `main`. Every
        # property is present and none is excess, so every other rule here passes it.
        ("duplicate list-map key", {"datastores": [{"name": "main"}, {"name": "main"}]}, 1),
        ("distinct list-map keys", {"datastores": [{"name": "main"}, {"name": "logstream"}]}, 0),
        # Same name, different kind — a duplicate, because `kind` is not a map key.
        # Uniqueness is per listMapKeys, not per whole entry.
        (
            "duplicate on the key alone, not the whole entry",
            {"datastores": [{"name": "main", "kind": "relational"}, {"name": "main", "kind": "cache"}]},
            1,
        ),
        # Composite keys collide only when every key matches.
        ("composite key differing in one field", {"routes": [{"group": "g", "name": "a"}, {"group": "g", "name": "b"}]}, 0),
        ("composite key matching in both", {"routes": [{"group": "g", "name": "a"}, {"group": "g", "name": "a"}]}, 1),
        # An unset key is a value: two entries omitting it collide on <unset>.
        ("unset key participates in the identity", {"routes": [{"group": "g"}, {"group": "g"}]}, 1),
        ("duplicate set member", {"finalizers": ["a", "a"]}, 1),
        ("distinct set members", {"finalizers": ["a", "b"]}, 0),
        # atomic imposes no uniqueness — flagging it would be a false positive that
        # teaches operators to work around the gate.
        ("atomic list permits repeats", {"ordered": [{"name": "a"}, {"name": "a"}]}, 0),
    ]
    bad = 0
    for name, value, want in cases:
        problems: list[str] = []
        walk(value, schema, "spec", "Test", "self-test", problems)
        ok = len(problems) == want
        if not ok:
            bad += 1
        print(f"{'ok ' if ok else 'FAIL'} {name}: {len(problems)} problem(s), wanted {want}")
        if not ok:
            for p in problems:
                print(f"      {p}", file=sys.stderr)
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print what was resolved and walked")
    ap.add_argument("--offline", action="store_true", help="skip rather than fail with no registry")
    ap.add_argument("--self-test", action="store_true", help="check the walker, not the repo")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return check(args.list, args.offline)


if __name__ == "__main__":
    sys.exit(main())
