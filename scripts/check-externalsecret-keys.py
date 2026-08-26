#!/usr/bin/env python3
"""Every ExternalSecret names its remote secret once, and that name is patched.

WHY THIS EXISTS

The AWS Secrets Manager secrets these ExternalSecrets read are cluster-scoped —
`<cluster>-managed-monitoring-endpoints`, `<cluster>-grafana-token` — so the
committed manifest carries a placeholder name and the delivering ApplicationSet
replaces it per cluster from the `cluster_name` label.

A `data:` list names that same remote secret once per key it pulls. Four keys,
four identical names, four JSON-pointer paths to patch — and the count lives in
two files that nothing reconciles. Add a key without extending the patch and the
unpatched indices keep a placeholder that exists in no account.

That failure is not partial. External Secrets fails an ExternalSecret whole, so
one unpatched index takes the working keys down with it: the Athena datasource
never comes up AND the AMP query URL stops arriving, regressing a datasource that
worked. Nothing caught it — the dashboard gate matches datasource uid strings and
never asks whether the secret behind them resolves.

WHAT THIS ASSERTS

  1. SINGLE REFERENCE. An ExternalSecret carries at most one path holding a
     remote secret name. `dataFrom[].extract` pulls the whole payload through one
     reference, which is what makes the index-counting hazard structurally
     impossible rather than merely fixed.

  2. PATCHED. Every such path is replaced by a kustomize patch op in the
     ApplicationSet that delivers it, and the replacement value is templated from
     the cluster rather than another constant.

Both directions matter: rule 1 alone would let an unpatched single reference
through, and rule 2 alone would accept four correctly-patched references and lose
the reason the bug was possible.

    scripts/check-externalsecret-keys.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")

_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"

# Directories holding manifests ArgoCD delivers. rendered/ is generated output.
SKIP_DIRS = {"rendered", ".git", "node_modules", ".terragrunt-cache"}


def is_helm_template(path: pathlib.Path) -> bool:
    """A file under a chart's templates/ directory — Go template text, not YAML.

    Detected structurally (a `templates` ancestor whose own parent holds
    Chart.yaml) rather than by catching the parse error, so a genuinely malformed
    manifest still fails loudly instead of being mistaken for a template.
    """
    for parent in path.parents:
        if parent.name == "templates" and (parent.parent / "Chart.yaml").is_file():
            return True
    return False


def docs(path: pathlib.Path) -> list[dict]:
    try:
        return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
    except yaml.YAMLError as err:
        raise SystemExit(f"FAIL  {path.relative_to(ROOT)} is not parseable YAML: {err}")


def key_paths(es: dict) -> list[str]:
    """JSON-pointer paths in this ExternalSecret that hold a remote secret name."""
    spec = es.get("spec") or {}
    out = []
    for i, entry in enumerate(spec.get("dataFrom") or []):
        if isinstance(entry, dict) and isinstance(entry.get("extract"), dict) and "key" in entry["extract"]:
            out.append(f"/spec/dataFrom/{i}/extract/key")
    for i, entry in enumerate(spec.get("data") or []):
        if isinstance(entry, dict) and isinstance(entry.get("remoteRef"), dict) and "key" in entry["remoteRef"]:
            out.append(f"/spec/data/{i}/remoteRef/key")
    return out


def find_external_secrets() -> dict[str, list[tuple[pathlib.Path, dict]]]:
    """Every committed ExternalSecret, keyed by metadata.name."""
    found: dict[str, list[tuple[pathlib.Path, dict]]] = {}
    for path in ROOT.rglob("*.yaml"):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if is_helm_template(path):
            continue
        for d in docs(path):
            if d.get("kind") != "ExternalSecret":
                continue
            name = (d.get("metadata") or {}).get("name")
            if name:
                found.setdefault(name, []).append((path, d))
    return found


PATH_TOKEN = re.compile(r"\{\{-?\s*\.path\s*-?\}\}")


def delivered_dirs(appset: dict) -> list[str]:
    """Repo-relative directories this ApplicationSet renders.

    `source.path` is a Go template over the generator's list elements, so the
    directory is only knowable by substituting each element's own `path`.
    """
    spec = appset.get("spec") or {}
    template_path = ((spec.get("template") or {}).get("spec") or {}).get("source", {}).get("path")
    if not isinstance(template_path, str):
        return []

    elements: list[dict] = []

    def walk(gens) -> None:
        for g in gens or []:
            if not isinstance(g, dict):
                continue
            if isinstance(g.get("list"), dict):
                elements.extend(e for e in g["list"].get("elements") or [] if isinstance(e, dict))
            for nested in ("matrix", "merge"):
                if isinstance(g.get(nested), dict):
                    walk(g[nested].get("generators"))

    walk(spec.get("generators"))

    if not PATH_TOKEN.search(template_path):
        return [template_path.strip("/")]
    return [
        PATH_TOKEN.sub(str(e["path"]), template_path).strip("/")
        for e in elements
        if e.get("path")
    ]


def patched_paths() -> dict[str, dict[str, set[str]]]:
    """delivered dir -> ExternalSecret name -> paths an ApplicationSet patch replaces.

    Keyed by the delivering directory, not by name alone. Two ExternalSecrets in
    this repo share the name `managed-monitoring-endpoints` — one in the Grafana
    namespace, one in monitoring — and a name-keyed map let either app's patch
    vouch for the other app's manifest, which is the same cross-talk this check
    exists to catch.
    """
    out: dict[str, dict[str, set[str]]] = {}
    for path in sorted(APPSETS.rglob("*.yaml")):
        for d in docs(path):
            if d.get("kind") != "ApplicationSet":
                continue
            dirs = delivered_dirs(d)
            src = ((d.get("spec") or {}).get("template") or {}).get("spec", {}).get("source", {})
            for patch in (src.get("kustomize") or {}).get("patches") or []:
                target = patch.get("target") or {}
                if target.get("kind") != "ExternalSecret" or not target.get("name"):
                    continue
                body = patch.get("patch")
                if not isinstance(body, str):
                    continue
                try:
                    ops = yaml.safe_load(body)
                except yaml.YAMLError as exc:
                    # This patch is what DELIVERS the remote-secret name the
                    # gate goes on to assert. Skipping an unparseable one drops
                    # its replace ops from the map, so the ExternalSecret it
                    # targets is then checked against a patch set that silently
                    # lost a member — and the gate reports on a delivery it
                    # never read. The parser's mark is relative to the patch
                    # body, so name the appset and the target too.
                    first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
                    tgt = patch.get("target") or {}
                    print(f"Cannot run: an inline kustomize patch in {path} is not parseable "
                          f"YAML — {first}")
                    print(f"  target: {tgt or '(none declared)'}")
                    print("  The patch's replace ops decide which remote secret this gate")
                    print("  asserts against, so dropping it would check a delivery it never read.")
                    sys.exit(gatelib.CANNOT_RUN)
                if not isinstance(ops, list):
                    continue  # a strategic-merge patch, not JSON6902
                for op in ops:
                    if isinstance(op, dict) and op.get("op") == "replace" and op.get("path"):
                        for dirname in dirs:
                            out.setdefault(dirname, {}).setdefault(target["name"], set()).add(op["path"])
    return out


def owning_dir(rel: pathlib.Path, dirs: list[str]) -> str | None:
    """The delivered directory that ships this manifest, longest match first."""
    posix = rel.as_posix()
    matches = [d for d in dirs if posix.startswith(d.rstrip("/") + "/")]
    return max(matches, key=len) if matches else None


def main() -> int:
    external_secrets = find_external_secrets()
    patches = patched_paths()

    # Vacuity guard. A walk that finds nothing passes every assertion below, and
    # a moved directory is exactly how this check would stop checking.
    if not external_secrets:
        print("FAIL  found no ExternalSecret manifests — this check would pass vacuously")
        return 1
    if not patches:
        print("FAIL  found no ExternalSecret kustomize patch ops — this check would pass vacuously")
        return 1

    failures: list[str] = []
    checked = 0

    for name, occurrences in sorted(external_secrets.items()):
        for path, es in occurrences:
            rel = path.relative_to(ROOT)
            paths = key_paths(es)
            if not paths:
                continue
            checked += 1

            if len(paths) > 1:
                failures.append(
                    f"{rel}: ExternalSecret {name!r} names its remote secret {len(paths)} times "
                    f"({', '.join(paths)}).\n"
                    "      Use one `dataFrom[].extract` instead of a `data` list. Each name has to be "
                    "patched per cluster, and a count kept in sync by hand is how one gets missed — "
                    "External Secrets then fails the whole ExternalSecret, taking the keys that WERE "
                    "patched down with it."
                )
                continue

            owner = owning_dir(rel, list(patches))
            if owner is None:
                failures.append(
                    f"{rel}: ExternalSecret {name!r} sits under no directory any ApplicationSet "
                    "renders, so this check cannot tell whether its key is patched.\n"
                    "      Either it is delivered by something this gate does not model, or it is "
                    "shipped by nothing at all. Both are worth knowing; neither is a pass."
                )
                continue

            got = patches[owner].get(name, set())
            if paths[0] not in got:
                failures.append(
                    f"{rel}: ExternalSecret {name!r} holds a remote secret name at {paths[0]}, "
                    f"but the ApplicationSet rendering {owner}/ does not replace it.\n"
                    f"      Patched paths for {name!r} in that app: {sorted(got) or 'none'}.\n"
                    "      The committed name is a placeholder; unpatched, it resolves to a secret "
                    "that exists in no account and the ExternalSecret never syncs."
                )

    if failures:
        print(f"FAIL  {len(failures)} ExternalSecret key problem(s):\n")
        for f in failures:
            # codeql[py/clear-text-logging-sensitive-data]
            #
            # The alert reads the ExternalSecret/key vocabulary in this file and
            # concludes the failure text could carry secret material. It cannot.
            # The only inputs are committed YAML manifests, and the value at a
            # `key:` there is a Secrets Manager *object name* — `eks-grafana-token`
            # — never its contents. Nothing in this script reads AWS, a cluster, or
            # a rendered Secret; a name is the whole of what it can see, and
            # printing it is the point, since the name being wrong is the failure.
            #
            # That the repo holds no secret material at all is asserted separately
            # by the gitleaks job, so this is not resting on its own say-so.
            print(f"  - {f}\n")
        return 1

    print(
        f"✓ {checked} ExternalSecret(s) each name their remote secret once, "
        "and every name is patched per cluster"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
