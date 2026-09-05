#!/usr/bin/env python3
"""One place holds the secret-store name; everything else is compared to it.

WHY THIS EXISTS

This catalog declares one cluster-wide store — a `ClusterSecretStore` named in
`addons/bootstrap/secret-stores/`. Ten other places in this repository restate
that name, and five charts in four other repositories hardcode it as a chart
default. Nothing held any of them equal.

A name restated in eleven places is eleven chances to disagree, and the
disagreement is silent in every direction that matters:

  * An `ExternalSecret` naming a store that does not exist installs cleanly,
    syncs cleanly, and records `SecretSyncedError` on its own status while never
    creating the target Secret. The workload then mounts a Secret that is not
    there, and its symptom is a missing environment variable — a sentence that
    names neither the store nor the typo. One repository shipped
    `aws-secretsmanager` against `aws-secrets-manager` exactly this way.

  * An ApplicationSet patch whose `target` names a store that does not exist is
    worse, because kustomize does not consider it an error. `kustomize build`
    exits 0 and emits the unpatched base. The patch on the store here rewrites
    its AWS region per cluster; unmatched, every cluster silently keeps the
    base's `us-west-2` and looks its secrets up in the wrong region.

WHAT IT CHECKS

Everything is derived from the declaration, and nothing is listed here:

  * exactly one cluster-wide store is declared, because a contract naming one
    of several is a contract that has not decided;
  * every `secretStoreRef` in the tree names a store this catalog declares;
  * every ApplicationSet patch whose `target.kind` is a store kind names it too,
    which is the reference no render can fail on;
  * every `ExternalSecret` agrees on an apiVersion, so there is one to publish;
  * `contracts/secret-store.json` states what the tree states. That file is the
    published half — the four repositories this seat cannot edit read it to
    assert their chart defaults, the way the other cross-repo pins in this org
    work. Regenerate with `--write`; a hand-edit that disagrees with the
    manifest fails here rather than at a cluster.

The version is published beside the name because they go stale together and for
the same reason: a chart pinned to this catalog's store was pinned when the
catalog's shape was different. A declared-but-unserved apiVersion passes helm,
kubeconform and chart lint — the CRD really does list it — and fails only at a
live API server, so publishing the one this catalog uses is what a consumer can
check offline.

WHAT IT DOES NOT CHECK

  * Whether the consumers in other repositories read the contract. They are not
    in this repository and this gate cannot see them; publishing is the half
    that lives here.
  * Whether the store WORKS — that the region resolves, that Pod Identity is
    bound, that Secrets Manager holds the keys. Those are facts about a cluster
    and an AWS account.
  * Whether an apiVersion is SERVED. That is knowable only from a live API
    server; this asserts the catalog is internally consistent about which one it
    names.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import sys

_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSET_DIR = ROOT / "applicationsets"
CONTRACT = ROOT / "contracts" / "secret-store.json"
STORE_DIR = ROOT / "addons" / "bootstrap" / "secret-stores"

CLUSTER_STORE = "ClusterSecretStore"
NAMESPACED_STORE = "SecretStore"
STORE_KINDS = (CLUSTER_STORE, NAMESPACED_STORE)
EXTERNAL_SECRET = "ExternalSecret"

SKIP_DIRS = {"rendered", ".git", "node_modules"}

# What this gate is allowed to print out of a file it read.
#
# Every value here arrives from disk, and one of those files is named for
# secrets — `contracts/secret-store.json` is parsed as arbitrary JSON, so a
# value put there ends up in a message. "It only ever holds a store name" is
# the assumption that fails, and it fails into a log.
#
# So a value is echoed only once it is a Kubernetes object name or a group
# version, checked against the API server's own grammar. A string matching
# these is lowercase alphanumerics with hyphens and dots, at most 253
# characters and carrying no separator a credential needs; one that does not
# match is reported by its field rather than by its content.
OBJECT_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
KIND = re.compile(r"[A-Z][A-Za-z0-9]{0,62}")
GROUP_VERSION = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}/v[0-9]+(?:(?:alpha|beta)[0-9]+)?")
UNPRINTABLE = "<not a name this API server would accept>"

# A `secretStoreRef` in Go-template chart source. Half the consumers here are
# chart templates that do not parse as YAML, and dropping them would leave the
# gate reporting on the half that happens to be plain manifests.
HELM_REF = re.compile(
    r"^(?P<indent>\s*)secretStoreRef:\s*$\n"
    r"(?P<body>(?:(?P=indent)\s+\S.*$\n?)*)", re.M)
FIELD = re.compile(r"^\s*(?P<key>name|kind):\s*(?P<value>\S.*?)\s*$", re.M)
HELM_API = re.compile(r"^apiVersion:\s*(?P<api>external-secrets\.io/\S+)\s*$", re.M)
HELM_KIND = re.compile(r"^kind:\s*(?P<kind>\S+)\s*$", re.M)


def printable(value: object, grammar: re.Pattern[str] = OBJECT_NAME) -> str:
    """`value` if it is a name, else a fixed stand-in.

    The stand-in is a constant rather than a truncation: a prefix of a value
    that is not a name is still whatever that value was.
    """
    text = value if isinstance(value, str) else ""
    return text if grammar.fullmatch(text) else UNPRINTABLE


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def tracked_yaml() -> list[pathlib.Path]:
    out = []
    for path in sorted(ROOT.rglob("*.y*ml")):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        out.append(path)
    return out


def documents(path: pathlib.Path) -> list[dict]:
    """Parsed documents, or [] for chart source that is Go-template text."""
    if gatelib.is_helm_template(path):
        return []
    return [d for d in gatelib.read_yaml_all(path) if isinstance(d, dict)]


def store_refs(node, path: pathlib.Path, out: list):
    """Every `secretStoreRef` under a parsed document, at any depth."""
    if isinstance(node, dict):
        ref = node.get("secretStoreRef")
        if isinstance(ref, dict):
            out.append((path, str(ref.get("kind") or CLUSTER_STORE),
                        str(ref.get("name") or "")))
        for value in node.values():
            store_refs(value, path, out)
    elif isinstance(node, list):
        for item in node:
            store_refs(item, path, out)


def helm_store_refs(path: pathlib.Path) -> list[tuple[pathlib.Path, str, str]]:
    """The same reference, read out of chart source as text.

    Structure-aware rather than a bare grep for the name: the block is located
    by its key and the fields are read from inside it, so a `name:` belonging to
    some other object cannot be mistaken for the store.
    """
    out = []
    text = path.read_text(encoding="utf-8")
    for block in HELM_REF.finditer(text):
        fields = {m.group("key"): m.group("value")
                  for m in FIELD.finditer(block.group("body"))}
        out.append((path, fields.get("kind", CLUSTER_STORE),
                    fields.get("name", "")))
    return out


def patch_targets() -> list[tuple[pathlib.Path, str, str]]:
    """(appset, kind, name) for every kustomize patch target naming a store."""
    out = []
    for path in sorted(APPSET_DIR.rglob("*.y*ml")):
        for doc in documents(path):
            if doc.get("kind") != "ApplicationSet":
                continue
            spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
            sources = list(spec.get("sources") or [])
            if isinstance(spec.get("source"), dict):
                sources.append(spec["source"])
            for source in sources:
                if not isinstance(source, dict):
                    continue
                for patch in (source.get("kustomize") or {}).get("patches") or []:
                    target = (patch or {}).get("target") or {}
                    kind = str(target.get("kind") or "")
                    if kind in STORE_KINDS and target.get("name"):
                        out.append((path, kind, str(target["name"])))
    return out


def survey():
    """The whole population, both readers, in one walk."""
    declared: dict[tuple[str, str], tuple[pathlib.Path, str]] = {}
    consumers: list[tuple[pathlib.Path, str, str]] = []
    versions: dict[str, list[pathlib.Path]] = {}

    for path in tracked_yaml():
        if gatelib.is_helm_template(path):
            text = path.read_text(encoding="utf-8")
            if HELM_KIND.search(text) and "secretStoreRef" in text:
                consumers.extend(helm_store_refs(path))
            for m in HELM_API.finditer(text):
                head = text[:m.start()].rfind("\n---")
                block = text[max(head, 0):m.start() + 400]
                if re.search(rf"^kind:\s*{EXTERNAL_SECRET}\s*$", block, re.M):
                    versions.setdefault(m.group("api"), []).append(path)
            continue
        for doc in documents(path):
            kind = str(doc.get("kind") or "")
            name = str((doc.get("metadata") or {}).get("name") or "")
            api = str(doc.get("apiVersion") or "")
            if kind in STORE_KINDS and name:
                declared[(kind, name)] = (path, api)
            if kind == EXTERNAL_SECRET and api:
                versions.setdefault(api, []).append(path)
            store_refs(doc, path, consumers)
    return declared, consumers, versions


def rendered(contract: dict) -> str:
    """The contract's one canonical serialisation.

    `--write` emits this and the check compares against it byte for byte, so
    "the published contract" and "what the generator produces" are the same
    question. Comparing parsed objects field by field answers a weaker one: it
    passes a file carrying an extra key, a reordered object, or a rewritten
    comment, and a consumer reads the file rather than the four fields this gate
    happens to look at.
    """
    return json.dumps(contract, indent=2) + "\n"


def build_contract(declared, versions) -> dict:
    (kind, name), (_path, api) = next(iter(declared.items()))
    return {
        "_generated": "scripts/check-secret-store-refs.py --write; the source of "
                      "truth is the manifest under addons/bootstrap/secret-stores/. "
                      "Edit that, then regenerate.",
        "_purpose": "Consumers outside this repository assert their chart "
                    "defaults against these values instead of restating them.",
        "clusterSecretStore": {"apiVersion": api, "kind": kind, "name": name},
        "externalSecret": {"apiVersion": sorted(versions)[0]},
    }


def main(argv: list[str] | None = None) -> int:
    """`argv` is a parameter so this is callable as a library.

    Reading `sys.argv` directly makes the entry point untestable: under a test
    runner it parses the runner's own flags and exits.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help="regenerate the published contract from the tree")
    args = parser.parse_args(argv)

    declared, consumers, versions = survey()

    if not declared:
        print(f"Cannot run: no {' or '.join(STORE_KINDS)} is declared anywhere "
              f"under {rel(ROOT)}, so there is no name for anything to be "
              f"compared against.")
        print("This gate examined nothing, which is not the same as finding nothing.")
        return gatelib.CANNOT_RUN
    if not consumers:
        print("Cannot run: no secretStoreRef found, so this gate read no "
              "consumer. A catalog whose references all resolve reports the "
              "same thing.")
        return gatelib.CANNOT_RUN

    failures: list[str] = []

    cluster_stores = {k: v for k, v in declared.items() if k[0] == CLUSTER_STORE}
    if len(cluster_stores) != 1:
        names = ", ".join(f"{printable(n)} ({rel(p)})" for (_k, n), (p, _a) in
                          sorted(cluster_stores.items()))
        print(f"FAIL  {len(cluster_stores)} {CLUSTER_STORE}(s) declared: "
              f"{names or 'none'}. The published contract names one store, so a "
              f"catalog declaring several has not decided which one a consumer "
              f"in another repository should pin to.")
        return 1

    for path, kind, name in consumers:
        if not name:
            failures.append(
                f"{rel(path)}: a secretStoreRef names no store at all, so the "
                f"ExternalSecret resolves against nothing.")
        elif (kind, name) not in declared:
            failures.append(
                f"{rel(path)}: secretStoreRef names {printable(kind, KIND)}/"
                f"{printable(name)} and this "
                f"catalog declares no such store. External Secrets accepts the "
                f"object, records SecretSyncedError on its status, and never "
                f"creates the target Secret — the workload mounts a Secret that "
                f"is not there.")

    for path, kind, name in patch_targets():
        if (kind, name) not in declared:
            failures.append(
                f"{rel(path)}: a kustomize patch targets {printable(kind, KIND)}/"
                f"{printable(name)} and this "
                f"catalog declares no such store. kustomize does not treat an "
                f"unmatched target as an error — the build exits 0 and emits the "
                f"unpatched base, so every cluster silently keeps whatever the "
                f"base said.")

    if len(versions) > 1:
        listed = "; ".join(
            f"{printable(api, GROUP_VERSION)} in "
            f"{', '.join(sorted({rel(p) for p in paths}))}"
            for api, paths in sorted(versions.items()))
        failures.append(
            f"{EXTERNAL_SECRET}s in this catalog declare {len(versions)} "
            f"apiVersions: {listed}. There is no single version to publish, and "
            f"a consumer pinning to one of them is pinning to a coin flip.")

    if failures:
        print(f"{len(failures)} secret-store reference problem(s):\n")
    # py/clear-text-logging-sensitive-data matches here on the NAMES of the
    # files this gate reads — addons/bootstrap/secret-stores/ and
    # contracts/secret-store.json — and treats a path containing "secret-store"
    # as secret material. A secret store is the thing that holds secrets, not a
    # secret: it is an address and a set of credentials-free provider settings,
    # and the values printed below are a Kubernetes object name, a kind, a group
    # version, a repository-relative path and a count. Every one read from a file
    # has been through printable(), which returns it only on a fullmatch against
    # the API server's own grammar and a fixed stand-in otherwise.
    #
    # This repository has now made the same distinction in two systems. The
    # secrets block in .gitignore carries !*secret*-store*.yaml and
    # !*secret*-store*.yml, and this file's contract added !*secret*-store*.json
    # to it. Both are about a name rather than a content, and the pattern will
    # recur in whatever tool comes third.
    #
    # The marker below does NOT suppress anything. Code scanning runs here as
    # default setup, which reads no suppression comment for this query: the
    # alerts stayed open with it in place and were closed by dismissing them in
    # the scanner's own database, which is not in this tree. So the marker
    # records the decision at the site and the decision takes effect somewhere a
    # reader of this file cannot see.
    #
    # It stays because the alternative leaves the site with no explanation at
    # all. Read it as a comment addressed to a person, not to the tool.
    #
    # Not worked around in the code either. A verified string can be rebuilt
    # character by character from a literal alphabet, which defeats the dataflow
    # and explains nothing — a reader can disagree with a comment, and cannot
    # even see a defeated dataflow.
    #
    # The placement is the one the marker would need if it were read: on the
    # line BEFORE the expression, covering that line only. On the same line it
    # is the older `lgtm[...]` form, which edits the line it annotates and so
    # changes the alert's hash — the original closes as fixed and an identical
    # one opens beside it.
        for f in failures:
            # codeql[py/clear-text-logging-sensitive-data]
            print(f"  {f}")
        return 1

    want = build_contract(cluster_stores, versions)
    if args.write:
        CONTRACT.parent.mkdir(parents=True, exist_ok=True)
        CONTRACT.write_text(rendered(want), encoding="utf-8")
        print(f"✓ wrote {rel(CONTRACT)}")
        return 0

    if not CONTRACT.exists():
        print(f"FAIL  {rel(CONTRACT)} does not exist. It is the half of this "
              f"that consumers outside this repository can read; without it they "
              f"have nothing to compare their chart defaults against. Run "
              f"`{rel(pathlib.Path(__file__))} --write`.")
        return 1

    # Compared as bytes, and deliberately not parsed for the message. What is in
    # that file is whatever somebody put there, so a message quoting it back
    # repeats it into a log; the reader already has the file open, and the fix is
    # the same whatever the difference is.
    if CONTRACT.read_text(encoding="utf-8") != rendered(want):
        print(f"FAIL  {rel(CONTRACT)} is not what this tree declares.")
        print(f"      The manifest under {rel(STORE_DIR)} is the source of "
              f"truth and the contract is generated from it, so a difference "
              f"means the file was hand-edited or the manifest moved under it.")
        print("      A contract that has drifted is worse than none: the "
              "repositories asserting against it pass.")
        print(f"      Regenerate with `{rel(pathlib.Path(__file__))} --write` "
              f"and read the diff.")
        return 1

    store = want["clusterSecretStore"]
    # Same match, same reason as the failure path above.
    # codeql[py/clear-text-logging-sensitive-data]
    print(f"✓ every secret-store reference resolves to the one store this "
          f"catalog declares: {printable(store['kind'], KIND)}/"
          f"{printable(store['name'])} "
          f"({printable(store['apiVersion'], GROUP_VERSION)}), named by "
          f"{len(consumers)} secretStoreRef(s) "
          f"and {len(patch_targets())} ApplicationSet patch target(s), published "
          f"in {rel(CONTRACT)}")
    print("  whether repositories outside this one read that contract, and "
          "whether the store works against a real account, are outside this claim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
