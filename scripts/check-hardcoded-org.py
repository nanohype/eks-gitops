#!/usr/bin/env python3
"""Fork-safety gate — an applied ApplicationSet must not hardcode the nanohype
org in a repoURL pointing at THIS CATALOG (nanohype/eks-gitops).

    ┌─────────────────────────────────────────────────────────────────────┐
    │ THE DISTINCTION THIS GATE IS BUILT ON — read before widening it.    │
    │                                                                     │
    │ CATALOG  = the org's OWN gitops, which a customer FORKS.            │
    │            Must be templated, or the fork is inert.                 │
    │ ARTIFACT = something nanohype PUBLISHES, which a customer CONSUMES  │
    │            from upstream. Correctly hardcoded — exactly like a Helm │
    │            repo URL or a container registry. Not a bug.             │
    │                                                                     │
    │ A customer org does not fork the product. It consumes the product.  │
    └─────────────────────────────────────────────────────────────────────┘

IN SCOPE — the catalog repo, in an APPLIED ApplicationSet:

    repoURL: https://github.com/nanohype/eks-gitops.git   (or git@github.com:...)

This repo is vended: a customer forks it into their own org and points their hub
cluster at THEIR fork. An ApplicationSet that names github.com/nanohype/eks-gitops
keeps syncing from upstream after the fork, so the customer's edits never take
effect and their clusters silently track nanohype's copy. Every such repoURL must
resolve from the ArgoCD cluster Secret --

    repoURL: '{{ index .metadata.annotations "gitops/repo-url" }}'

-- the same mechanism applicationsets/dashboards.yaml already uses to inject the
per-cluster Amazon Managed Grafana URL via the monitoring/grafana-url annotation.

OUT OF SCOPE -- DELIBERATELY, each for a specific reason. Do not "fix" these:

  * nanohype/eks-agent-platform (and any other product repo)
        The agent operator's own source/chart repo -- a PUBLISHED ARTIFACT. A
        vended org consumes the operator from nanohype; it does not fork it.
        Templating this would point a customer's cluster at a fork of the
        product that does not exist. Only the CATALOG repo is matched below.

  * ghcr.io/nanohype/* images and oci://ghcr.io/nanohype/... chart repos
        Published artifacts, same argument. Structurally excluded: only
        `repoURL:` lines are inspected at all, and only for the catalog repo.

  * The Kyverno keyless-signing subjectRegExp (policies/kyverno/supply-chain/)
        github.com/nanohype there is a SIGNING IDENTITY to verify against, not
        a source to sync from. Rewriting it would break signature verification.
        Structurally excluded -- this gate only reads applicationsets/.

  * EVERYTHING under applicationsets/opt-in/
        Those ApplicationSets are not applied by a default install: app-of-apps
        sources `path: applicationsets` WITHOUT directory.recurse, so ArgoCD
        never descends into that subdirectory. They are parked there precisely
        BECAUSE they cannot be satisfied generically (private SSH repos, the hub
        cluster, per-tenant AppProjects), and applicationsets/opt-in/README.md
        documents repointing their org-specific URLs as a prerequisite to
        enabling them. A hardcoded org in a manifest nothing applies is not a
        fork hazard -- it is documented, inert configuration. Hence the scan is
        non-recursive: top-level applicationsets/*.yaml only.

    ####################################################################
    # TODO: FLIP TO BLOCKING ONCE THE repoURL-TEMPLATING PR LANDS.
    # The catalog currently HAS these violations -- 19 catalog repoURLs across
    # the applied ApplicationSets -- and a companion PR is replacing them with
    # `{{ index .metadata.annotations "gitops/repo-url" }}`. Until that merges
    # this gate REPORTS ONLY: it prints every violation and exits 0, so it
    # cannot red-light the very PR that fixes it. When that PR lands, pass
    # --blocking in .github/workflows/ci.yml (or flip the default here) so a
    # reintroduced hardcoded catalog ref fails CI. Expected count after: 0.
    ####################################################################

Stdlib only -- CI runs this on a bare ubuntu-latest with no pip install.

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
CATALOG = "eks-gitops"  # THIS repo — the vended catalog. NOT the product repos.

# A repoURL whose value points at the CATALOG repo, over either transport ArgoCD
# accepts. Anchored on `repoURL:` so image refs, oci:// chart repos, and the
# Kyverno subjectRegExp are structurally out of scope; pinned to the catalog repo
# name so nanohype's published product repos (eks-agent-platform et al.) are too.
CATALOG_REPO_URL = re.compile(
    rf"^\s*-?\s*repoURL:\s*['\"]?"
    rf"(?:https://github\.com/{ORG}/{CATALOG}|git@github\.com:{ORG}/{CATALOG})"
    rf"(?:\.git)?['\"]?\s*(?:#.*)?$",
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

    # NON-RECURSIVE by design: app-of-apps applies only the top level, so only
    # the top level can strand a fork. See the opt-in note in the docstring.
    files = sorted(p for p in appsets.glob("*.y*ml") if p.is_file())

    violations: list[tuple[pathlib.Path, int, str]] = []
    for path in files:
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            # A commented-out line is prose, not an applied source.
            if line.lstrip().startswith("#"):
                continue
            if CATALOG_REPO_URL.match(line):
                violations.append((path.relative_to(args.root), lineno, line.strip()))

    print(
        f"Scanned {len(files)} applied ApplicationSet(s) in applicationsets/ "
        f"(opt-in/ excluded — not applied by app-of-apps)\n"
    )

    if not violations:
        print(f"✓ no applied ApplicationSet hardcodes {ORG}/{CATALOG} in a repoURL")
        return 0

    n_files = len({str(p) for p, _, _ in violations})
    print(
        f"Found {len(violations)} hardcoded catalog repoURL(s) "
        f"across {n_files} applied ApplicationSet(s):\n"
    )
    current = None
    for path, lineno, line in violations:
        if path != current:
            print(f"  {path}")
            current = path
        print(f"    {lineno}: {line}")

    print(
        f'\n  Each must become: repoURL: \'{{{{ index .metadata.annotations "gitops/repo-url" }}}}\'\n'
        f"  read off the ArgoCD cluster Secret — the same mechanism dashboards.yaml uses\n"
        f"  for monitoring/grafana-url. A fork of this catalog into a customer org would\n"
        f"  otherwise keep syncing from github.com/{ORG}/{CATALOG}, so the fork's own edits\n"
        f"  never take effect.\n"
        f"\n"
        f"  Out of scope on purpose, and NOT counted above: nanohype's published artifacts\n"
        f"  (the {ORG}/eks-agent-platform product repo, ghcr.io/{ORG}/* images,\n"
        f"  oci://ghcr.io/{ORG} charts, the Kyverno signing subjectRegExp) — a vended org\n"
        f"  consumes those from upstream rather than forking them — and everything under\n"
        f"  applicationsets/opt-in/, which a default install never applies."
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
