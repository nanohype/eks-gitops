#!/usr/bin/env python3
"""Validate the catalog's own platform CRs against the CRDs the catalog installs.

WHY THIS EXISTS

`kubeconform-scan.sh` skips Platform, Tenant, ModelGateway, BudgetPolicy,
AgentFleet and EvalSuite. Its comment is honest about why — their schemas live
in eks-agent-platform and are published to no public catalog — and says they are
validated "out-of-band" with `kubectl apply --dry-run=server`.

Out-of-band is not a gate. A CR in this catalog can be missing a field its CRD
requires — `spec.agents[].image` on an AgentFleet, say — and every gate upstream
of admission stays green while the API server answers

    AgentFleet.agents.nanohype.dev "ops-fleet" is invalid:
      spec.agents[0].image: Required value

so the Application never reaches Healthy on any cluster syncing the addon. A
skip that records a gap is better than a green tick that pretends there is none,
but a gap nobody closes is still a gap — and this one covers manifests applied
to every cluster in the fleet.

WHAT THIS DOES

Resolves the CRDs from the operator chart at the version the catalog PINS —
`applicationsets/addons-agent-operator.yaml`'s targetRevision — and walks every
CR of those kinds in the tree:

  - every `required` property must be present, at every level
  - no property may be absent from the schema (the API server prunes it, so a
    field set here has never reached a cluster)
  - every value must carry the type the CRD declares. YAML decides that for you,
    and it is why `minACU: 0.5` is rejected where `minACU: "0.5"` is admitted —
    Kubernetes serialises fractional quantities as strings
  - a list declared `x-kubernetes-list-type: map` or `set` must hold unique
    entries, because a duplicate is a hard rejection of the whole object

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
import importlib.util
import pathlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent

# Seconds a child process may run before the gate gives up on it. A subprocess
# with no deadline turns an unreachable registry into a job that hangs until the
# CI runner's own ceiling, with no diagnostic naming the command that stalled.
# NETWORK_TIMEOUT covers commands that resolve a remote chart or registry;
# LOCAL_TIMEOUT covers commands that only read the working tree.
NETWORK_TIMEOUT = 300
OPERATOR_APPSET = ROOT / "applicationsets" / "addons-agent-operator.yaml"
CHART = "oci://ghcr.io/nanohype/eks-agent-platform/charts/operator"
# The API-group suffix the operator chart's CRDs share. Used to count candidate
# CRs independently of the schema set, so an empty schema resolution and an empty
# corpus are distinguishable from a clean one.
OPERATOR_API_SUFFIX = ".nanohype.dev"

# A floor on CRs found. Set low on purpose: `candidates` counts documents whose
# API group the operator owns, but the WALK keeps only kinds the pinned chart
# ships a schema for, so what a healthy run reports depends on what that chart
# resolves to where the gate runs — a reviewer measured four where this tree
# walks eight. A floor above the smallest resolution is red somewhere it should
# be green, which is what a floor above its corpus always is.
#
# A constant rather than a derivation, and the reason is worth stating rather
# than dressing up: every quantity this gate could derive a floor from comes out of
# the same walk over the same files, so a corpus that shrinks shrinks the floor
# with it. A completeness assertion — candidates by API group against candidates
# by schema kind — was written and is circular for exactly that reason: both
# filters read the documents the walk found. There is no second enumerator of
# this repo's custom resources, so the floor is a number, and
# scripts/tests/test_corpus_floors.py holds it against the tree from both sides.
MIN_CRS = 2

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
    if not OPERATOR_APPSET.is_file():
        print(f"Cannot run: {OPERATOR_APPSET.relative_to(ROOT)} does not exist, so the "
              f"operator chart version this gate resolves its CRDs from is unknown. "
              f"An unreadable pin is not the same as a catalog with no CRs in it.")
        sys.exit(gatelib.CANNOT_RUN)
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
    # An unreachable registry used to raise CalledProcessError here: exit 1 with
    # a traceback, which is the SAME status this gate uses for "a catalog CR is
    # inadmissible". The operator could not tell whether their manifests were
    # rejected or whether the chart never arrived — and helm's explanation was
    # captured and thrown away. Those are different worlds and the discrimination
    # is the fix.
    pull = subprocess.run(
        ["helm", "pull", CHART, "--version", version, "--untar", "--untardir", str(workdir)],
        capture_output=True,
        text=True,
        timeout=NETWORK_TIMEOUT,
    )
    if pull.returncode != 0:
        err = ((pull.stderr or "") + (pull.stdout or "")).strip()
        low = err.lower()
        unreachable = ("dial tcp", "no such host", "connection refused", "i/o timeout",
                       "timeout exceeded", "network is unreachable", "tls handshake",
                       "proxyconnect", "connect: ", "eof")
        if any(tok in low for tok in unreachable) or "not found" not in low:
            print(f"Cannot run: could not pull operator chart {version} from {CHART}.")
            print(err)
            print("No CR was checked. An unreachable registry is not a statement about")
            print("the catalog's admissibility.")
            sys.exit(gatelib.CANNOT_RUN)
        print(f"operator chart {version} does not exist at {CHART}:")
        print(err)
        print("The pin names a chart the registry does not have — a finding about this repo.")
        sys.exit(1)
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


# OpenAPI type -> the Python types a YAML load produces for it.
#
# bool before int deliberately: in Python `True` is an int, so an unquoted `true` would
# satisfy `integer` and a genuine type error would pass.
_JSON_TYPES = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "object": (dict,),
    "array": (list,),
}


def check_type(value, schema, path, kind, source, problems):
    """The type the CRD declares is enforced at admission, and YAML decides it for you.

    This is the half a required-and-pruning walker does not have, and it is the half that
    bites hardest on numbers. `minACU: 0.5` reads as a YAML float; the CRD declares
    minACU a STRING, because Kubernetes serialises fractional quantities as strings. The
    manifest looks obviously correct, every property is present, none is excess, and the
    API server rejects the whole object:

        spec.datastores[0].relational.minACU: Invalid value: "number":
          ... in body must be of type string: "number"

    Only scalars and containers are checked here — the recursion below already walks into
    objects and arrays, and a mistyped one is reported by this rule before it descends.
    """
    want = schema.get("type")
    allowed = _JSON_TYPES.get(want)
    if allowed is None or value is None:
        return
    # A bool is an int in Python; nothing else may borrow that.
    if want != "boolean" and isinstance(value, bool):
        problems.append(
            f"{source}: {kind} {path} is a boolean and the CRD declares {want} — the API "
            f"server rejects the object with `{path.lstrip('.')}: Invalid value`"
        )
        return
    if not isinstance(value, allowed):
        got = _json_type_name(value)
        hint = ""
        if want == "string" and isinstance(value, (int, float)):
            hint = (
                " — quote it. YAML makes an unquoted number a number, and Kubernetes "
                "serialises fractional quantities as strings"
            )
        # Phrased as the API server phrases it, including reporting the value's OWN type in
        # `Invalid value` rather than the wanted one, so the message can be searched for
        # verbatim after a failed apply.
        problems.append(
            f"{source}: {kind} {path} is {_article(got)} {got} and the CRD declares {want}{hint}. The API "
            f"server rejects the whole object with `{path.lstrip('.')}: Invalid value: "
            f'"{got}": ... in body must be of type {want}: "{got}"`, so nothing is applied'
        )


def _article(word: str) -> str:
    return "an" if word[:1] in "aeiou" else "a"


def _json_type_name(value) -> str:
    """The OpenAPI type name for a value, which is what the API server reports.

    bool first: a bool is an int in Python, and calling one an integer here would print a
    message that does not match what kubectl said.
    """
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def walk(value, schema, path, kind, source, problems):
    """Required present, nothing excess, types right, list identities unique.

    Stops descending wherever the schema declines to describe the shape
    (x-kubernetes-preserve-unknown-fields, or an object with no properties),
    because the API server does not prune there either.
    """
    if not isinstance(schema, dict):
        return

    check_type(value, schema, path, kind, source, problems)

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
        skipped_templates = 0
        # Every CR carrying an operator API group, and every one the walk
        # reached. Two filters over one corpus: the walk keeps kinds the chart
        # defines, this keeps the group the chart owns.
        candidates: set[str] = set()
        reached: set[str] = set()
        for f in manifests():
            # Chart source is Go-template text, identified structurally rather
            # than by whatever happens to break the parser. A manifest that will
            # not parse is a finding: skipping it removes a CR from the corpus
            # this gate reports on, and a smaller corpus passes for the same
            # reason a compliant one does.
            if gatelib.is_helm_template(f):
                skipped_templates += 1
                continue
            try:
                docs = list(yaml.safe_load_all(f.read_text()))
            except yaml.YAMLError as exc:
                first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
                print(f"Cannot run: {f} is not parseable YAML — {first}")
                print("It is not chart source, so this gate cannot skip it without")
                print("shrinking the set of CRs it claims to have checked.")
                return gatelib.CANNOT_RUN
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind")
                api = str(doc.get("apiVersion", ""))
                rel = f.relative_to(ROOT)
                name = (doc.get("metadata") or {}).get("name", "<unnamed>")
                ident = f"{rel}: {kind}/{name}"
                if (api.endswith("/" + CRD_VERSION)
                        and api.split("/", 1)[0].endswith(OPERATOR_API_SUFFIX)):
                    candidates.add(ident)
                if kind not in schemas:
                    continue
                if not api.endswith("/" + CRD_VERSION):
                    continue
                reached.add(ident)
                if listing:
                    print(f"  {ident}")
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

    # A completeness assertion rather than a floor. `candidates` is the same
    # corpus filtered by API GROUP, which is independent of the schema-kind
    # filter the walk uses — so a schema set that resolved short, a renamed kind
    # or a moved manifest shows up as candidates the walk did not reach, and an
    # empty corpus shows up as no candidates at all. A number picked here could
    # be wrong in either direction; this cannot.
    if len(candidates) < MIN_CRS:
        print(f"\nFAIL  {len(candidates)} custom resource(s) carry an operator API "
              f"group, below the floor of {MIN_CRS}. This gate walked almost nothing, "
              f"which is not the same as the catalog's CRs being admissible.",
              file=sys.stderr)
        return gatelib.CANNOT_RUN
    missed = sorted(candidates - reached)
    if missed:
        print(f"\nFAIL  {len(missed)} custom resource(s) carry an operator API group "
              f"and were not walked — the operator chart shipped no schema for their "
              f"kind, so nothing checked them:", file=sys.stderr)
        for item in missed:
            print(f"  - {item}", file=sys.stderr)
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
            "acu": {
                "type": "object",
                "properties": {
                    "minACU": {"type": "string"},
                    "retention": {"type": "integer"},
                    "paused": {"type": "boolean"},
                },
            },
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
        # The live failure this rule was added for: a CRD string carrying a YAML number.
        # Every property present, none excess, and the API server refuses the object.
        ("a number where the CRD wants a string", {"acu": {"minACU": 0.5}}, 1),
        ("an integer where the CRD wants a string", {"acu": {"minACU": 4}}, 1),
        ("the same value quoted", {"acu": {"minACU": "0.5"}}, 0),
        ("a string where the CRD wants an integer", {"acu": {"retention": "7"}}, 1),
        ("an integer where the CRD wants an integer", {"acu": {"retention": 7}}, 0),
        # A bool is an int in Python and must not satisfy `integer`.
        ("a boolean where the CRD wants an integer", {"acu": {"retention": True}}, 1),
        ("a boolean where the CRD wants a boolean", {"acu": {"paused": True}}, 0),
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
    gatelib.require('helm')
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
