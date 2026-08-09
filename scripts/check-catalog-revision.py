#!/usr/bin/env python3
"""A catalog source must read its revision from the cluster, not hardcode one.

WHY THIS EXISTS

`cluster-bootstrap` stamps two sibling annotations on every ArgoCD cluster
Secret: `gitops/repo-url` and `gitops/repo-branch`. The comment above them says
appsets template their own source off these so no org is hardcoded in the
manifests. That was true of `repo-url` — 33 files read it — and false of
`repo-branch`, which had exactly one reference in the entire org: the line that
writes it.

Meanwhile 28 applied ApplicationSets carried `targetRevision: main` as a literal,
directly beneath a `repoURL` templated off the annotation.

So a cluster bootstrapped against any other revision ran `app-of-apps` at that
revision — the Application honours `var.gitops_repo_branch` — and every child
Application at `main`. **Both report Synced and Healthy.** ArgoCD is telling the
truth about each Application individually, and the cluster is running two
revisions of the catalog at once with nothing anywhere to say so.

Two things that makes impossible. Testing a catalog change on a branch: the
cluster syncs `main`'s values while `app-of-apps` displays the branch name, which
is exactly the evidence someone would check. And pinning a release: a platform
installed from a tag gets a tagged app-of-apps over an unpinned fleet, so
"deploy the known-good version" quietly deploys HEAD.

WHAT THIS CHECKS

For every APPLIED ApplicationSet (top level only — app-of-apps does not recurse),
every source whose `repoURL` resolves from the `gitops/repo-url` annotation must
take its `targetRevision` from the `gitops/repo-branch` annotation.

Chart sources are untouched and must be: their `repoURL` is a Helm or OCI
registry and their `targetRevision` is a chart version, which is a different
thing that happens to share a field name.

    scripts/check-catalog-revision.py
    scripts/check-catalog-revision.py --list
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"

URL_ANNOTATION = 'gitops/repo-url'
REV_ANNOTATION = 'gitops/repo-branch'


def sources_of(doc):
    """Every source block an ApplicationSet template declares."""
    spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    out = list(spec.get("sources") or [])
    if isinstance(spec.get("source"), dict):
        out.append(spec["source"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print every catalog source found")
    args = ap.parse_args()

    if not APPSETS.is_dir():
        print(f"no applicationsets/ under {ROOT}")
        return 0

    # Non-recursive, matching check-hardcoded-org.py: app-of-apps applies only the
    # top level, so only the top level can put a cluster on two revisions.
    files = sorted(p for p in APPSETS.glob("*.y*ml") if p.is_file())

    problems: list[str] = []
    found = 0
    for path in files:
        try:
            docs = list(yaml.safe_load_all(path.read_text()))
        except yaml.YAMLError as e:
            problems.append(f"{path.relative_to(ROOT)}: not loadable as YAML ({e})")
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
                continue
            for src in sources_of(doc):
                if not isinstance(src, dict):
                    continue
                url = str(src.get("repoURL", ""))
                if URL_ANNOTATION not in url:
                    continue  # a chart registry, not this catalog
                found += 1
                rev = str(src.get("targetRevision", ""))
                rel = path.relative_to(ROOT)
                if args.list:
                    print(f"  {rel}: targetRevision {rev!r}")
                if REV_ANNOTATION not in rev:
                    problems.append(
                        f"{rel}: a source reading {URL_ANNOTATION} pins "
                        f"targetRevision: {rev!r} instead of reading {REV_ANNOTATION}"
                    )

    if found == 0:
        # A gate that finds nothing to check has stopped checking. The catalog's
        # own sources are how every addon gets its values files; zero of them means
        # the parse is wrong, not that the repo is clean.
        print(
            f"error: no source in applicationsets/ reads the {URL_ANNOTATION} annotation. "
            "This gate found nothing to validate, which is a broken gate rather than a "
            "clean repo.",
            file=sys.stderr,
        )
        return 2

    if problems:
        print(
            "\napplied ApplicationSets pin a catalog revision instead of reading it:\n",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            f"\n  Each must become:\n"
            f"    targetRevision: '{{{{ index .metadata.annotations \"{REV_ANNOTATION}\" }}}}'\n"
            f"\n  cluster-bootstrap stamps that annotation beside gitops/repo-url on every\n"
            f"  cluster Secret. Without it, app-of-apps honours the revision it was\n"
            f"  bootstrapped with and every child Application syncs main — two revisions of\n"
            f"  the catalog on one cluster, both reporting Synced and Healthy.",
            file=sys.stderr,
        )
        return 1

    print(f"\nok: all {found} catalog source(s) read their revision from {REV_ANNOTATION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
