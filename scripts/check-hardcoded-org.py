#!/usr/bin/env python3
"""Fork-safety gate — ApplicationSets must not hardcode the `nanohype` GitHub
org in a gitops `repoURL`.

This catalog is vended: a customer forks it into their own org and points their
hub cluster at THEIR fork. Any ApplicationSet that names github.com/nanohype in
a repoURL keeps syncing from nanohype's copy after the fork, so the customer's
edits never take effect and their clusters silently track upstream instead of
their own gitops. Every gitops repoURL must be templated (a cluster-secret
field, an ApplicationSet parameter) so it follows the fork.

IN SCOPE — gitops source repositories only:
    repoURL: https://github.com/nanohype/<repo>.git
    repoURL: git@github.com:nanohype/<repo>.git

DELIBERATELY NOT FLAGGED — these are nanohype's PUBLISHED ARTIFACTS, which a
vended org correctly keeps consuming from nanohype (they are the product, not
the customer's gitops):
    ghcr.io/nanohype/*                image references
    oci://ghcr.io/nanohype/...        Helm chart repositories
    subjectRegExp: ...github.com/nanohype/...   Kyverno keyless-signing identity
Only `repoURL:` values are considered at all, so those never even get looked at.

    ####################################################################
    # TODO: FLIP TO BLOCKING (exit 1) ONCE THE TEMPLATING PR LANDS.
    # The catalog currently HAS these violations — 19 ApplicationSets
    # hardcode `repoURL: https://github.com/nanohype/eks-gitops.git` — and a
    # separate PR is replacing them with a templated repoURL. Until that PR
    # merges this gate REPORTS ONLY: it prints every violation and exits 0
    # with a warning, so it cannot block the very PR that fixes it. When that
    # PR lands, delete the `--warn-only` default below (or drop the flag from
    # .github/workflows/ci.yml) so a reintroduced hardcoded org fails CI.
    ####################################################################

Stdlib only — CI runs this on a bare ubuntu-latest with no pip install.

Usage:  scripts/check-hardcoded-org.py [--root DIR] [--blocking]
Exit:   0 clean, or violations found while in warn-only mode (current default)
        1 violations found with --blocking
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ORG = "nanohype"

# A repoURL whose value points at a github.com repo in the nanohype org, over
# either transport ArgoCD accepts. Anchored on `repoURL:` so ghcr.io image refs,
# oci:// chart repos, and the Kyverno subjectRegExp are structurally out of scope.
HARDCODED_REPO_URL = re.compile(
    rf"^\s*-?\s*repoURL:\s*['\"]?(?:https://github\.com/{ORG}/|git@github\.com:{ORG}/)\S+",
    re.IGNORECASE,
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
        help="repo root to scan (default: the repo this script lives in)",
    )
    ap.add_argument(
        "--blocking",
        action="store_true",
        help="exit 1 on violations (default: report and exit 0 — see the TODO above)",
    )
    args = ap.parse_args()

    appsets = args.root / "applicationsets"
    if not appsets.is_dir():
        print(f"No applicationsets/ directory under {args.root} — nothing to check.")
        return 0

    violations: list[tuple[pathlib.Path, int, str]] = []
    scanned = 0
    for path in sorted(appsets.rglob("*.y*ml")):
        scanned += 1
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            # A commented-out line is prose, not an applied source.
            if line.lstrip().startswith("#"):
                continue
            if HARDCODED_REPO_URL.match(line):
                violations.append((path.relative_to(args.root), lineno, line.strip()))

    print(f"Scanned {scanned} ApplicationSet file(s) under applicationsets/\n")

    if not violations:
        print(f"✓ no ApplicationSet hardcodes the {ORG} org in a gitops repoURL")
        return 0

    files = sorted({str(p) for p, _, _ in violations})
    print(
        f"Found {len(violations)} hardcoded-org gitops repoURL(s) "
        f"across {len(files)} file(s):\n"
    )
    current = None
    for path, lineno, line in violations:
        if path != current:
            print(f"  {path}")
            current = path
        print(f"    {lineno}: {line}")

    print(
        f"\n  A fork of this catalog into a customer org would keep syncing these\n"
        f"  sources from github.com/{ORG}, so the fork's own edits never take effect.\n"
        f"  Template the repoURL (cluster-secret field / ApplicationSet parameter) so it\n"
        f"  follows the fork. Published artifacts — ghcr.io/{ORG}/* images, oci://ghcr.io/{ORG}\n"
        f"  charts, the Kyverno subjectRegExp — are correctly consumed from {ORG} and are\n"
        f"  not flagged here."
    )

    if args.blocking:
        return 1

    print(
        "\n  WARNING (non-blocking): this gate is in report-only mode while the\n"
        "  repoURL-templating PR is in flight. It will be flipped to blocking once\n"
        "  that lands — see the TODO in scripts/check-hardcoded-org.py."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
