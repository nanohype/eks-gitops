#!/usr/bin/env python3
"""Dashboard gate — every grafana.com dashboard this repo references must both
EXIST on grafana.com and be SAVEABLE by Amazon Managed Grafana.

Two bug classes reached a live cluster and neither was caught by CI. Both park
a GrafanaDashboard CR forever, and because ArgoCD aggregates health, one parked
CR holds the whole dashboards Application — and app-of-apps with it — Degraded.

  1. DEAD ID (InvalidSpec)
     grafana-operator resolves `spec.grafanaCom.id` by fetching
     https://grafana.com/api/dashboards/<id>/revisions. If grafana.com 404s
     (the dashboard was unpublished/renumbered) the operator marks the CR
     InvalidSpec and never renders it. Hit us on opencost 19625, karpenter
     21111, keda 15623 — all three 404.
     CHECK: /revisions must return HTTP 200 for every id.

  2. LEGACY DASHBOARD ALERTS (ApplyFailed)
     The platform's Grafana is Amazon Managed Grafana — unified alerting only.
     Grafana removed legacy dashboard alerting, so a dashboard whose panels
     still embed an `alert` block cannot be persisted: AMG answers
     POST /api/dashboards/db with 500 {"message":"Failed to save dashboard"}
     and the operator parks the CR ApplyFailed. Hit us on gnetId 16613
     ("Cilium v1.12 Hubble Metrics"), which carries four alert-bearing panels.
     CHECK: download the pinned revision's JSON and fail if ANY panel — including
     panels nested inside collapsed rows — carries an `alert` key.

Stdlib only (urllib): CI runs this on a bare ubuntu-latest with no pip install.
Every grafana.com call is retried with backoff so a flaky network reports as a
retry, not as a red build.

Usage:  scripts/validate-dashboards.py [--root DIR]
Exit:   0 all referenced dashboards exist and are AMG-saveable
        1 one or more dead ids or legacy-alert panels (BLOCKING)
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://grafana.com/api/dashboards"
RETRIES = 3
BACKOFF = 2.0  # seconds, multiplied by attempt number
TIMEOUT = 30

# spec.grafanaCom.id in a GrafanaDashboard CR. Matched textually rather than
# via a YAML parse so the gate needs no PyYAML on the runner: the CRs are flat,
# hand-written, and uniform (`grafanaCom:` then an indented `id: <int>`).
GRAFANA_COM_ID = re.compile(
    r"^\s*grafanaCom:\s*$\n(?:^\s*#.*$\n)*^\s+id:\s*(\d+)\s*$",
    re.MULTILINE,
)


def fetch(url: str) -> tuple[int, bytes]:
    """GET url, retrying transient failures. Returns (status, body).

    A 404 is an ANSWER, not a failure — it is exactly what check 1 looks for —
    so it is returned immediately and never retried. Only 5xx, timeouts, and
    connection errors are retried.
    """
    last = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "eks-gitops-ci"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return e.code, b""
            last = f"HTTP {e.code}"
        except Exception as e:  # timeout, DNS, reset, TLS
            last = f"{type(e).__name__}: {e}"
        if attempt < RETRIES:
            wait = BACKOFF * attempt
            print(f"    retry {attempt}/{RETRIES - 1} after {last} — waiting {wait:.0f}s")
            time.sleep(wait)
    raise RuntimeError(f"{url}: unreachable after {RETRIES} attempts ({last})")


def alert_panels(node, titles: list[str]) -> None:
    """Collect the titles of every panel carrying a legacy `alert` block.

    Recurses into `panels[]` because a collapsed row is itself a panel whose
    children hang off a nested `panels` list — 16613's four alert panels all
    lived one level down, so a flat scan would have missed them.
    """
    if isinstance(node, dict):
        if "alert" in node and node.get("alert") is not None:
            titles.append(node.get("title") or "<untitled panel>")
        for child in node.get("panels", []) or []:
            alert_panels(child, titles)
    elif isinstance(node, list):
        for child in node:
            alert_panels(child, titles)


def discover(root: pathlib.Path) -> list[tuple[int, pathlib.Path]]:
    found: list[tuple[int, pathlib.Path]] = []
    for path in sorted(root.rglob("*.yaml")):
        if ".git" in path.parts:
            continue
        for match in GRAFANA_COM_ID.finditer(path.read_text(encoding="utf-8", errors="replace")):
            found.append((int(match.group(1)), path))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
        help="repo root to scan (default: the repo this script lives in)",
    )
    args = ap.parse_args()

    refs = discover(args.root)
    if not refs:
        print("No grafanaCom.id references found — nothing to validate.")
        return 0

    print(f"Validating {len(refs)} grafana.com dashboard reference(s)\n")

    dead: list[str] = []
    legacy: list[str] = []

    for gnet_id, path in refs:
        rel = path.relative_to(args.root)
        print(f"  [{gnet_id}] {rel}")

        # ── Check 1: the id must exist (operator fetches exactly this URL) ──
        status, _ = fetch(f"{API}/{gnet_id}/revisions")
        if status != 200:
            print(f"    DEAD — /api/dashboards/{gnet_id}/revisions returned HTTP {status}")
            dead.append(f"{gnet_id}  ({rel})  /revisions -> HTTP {status}")
            continue

        # ── Check 2: AMG must be able to save it (no legacy dashboard alerts) ──
        status, body = fetch(f"{API}/{gnet_id}")
        if status != 200:
            print(f"    DEAD — /api/dashboards/{gnet_id} returned HTTP {status}")
            dead.append(f"{gnet_id}  ({rel})  metadata -> HTTP {status}")
            continue
        meta = json.loads(body)
        revision = meta.get("revision")
        name = meta.get("name", "?")

        status, body = fetch(f"{API}/{gnet_id}/revisions/{revision}/download")
        if status != 200:
            print(f"    DEAD — revision {revision} download returned HTTP {status}")
            dead.append(f"{gnet_id}  ({rel})  rev {revision} download -> HTTP {status}")
            continue

        titles: list[str] = []
        alert_panels(json.loads(body).get("panels", []), titles)
        if titles:
            print(f'    LEGACY ALERTS — "{name}" rev {revision}: {len(titles)} panel(s)')
            for t in titles:
                print(f"      - {t}")
            legacy.append(
                f'{gnet_id}  ({rel})  "{name}" rev {revision} — '
                f"{len(titles)} alert panel(s): {', '.join(titles)}"
            )
            continue

        print(f'    ok — "{name}" rev {revision}, no legacy alert panels')

    print()
    if dead:
        print("FAIL — dead grafana.com dashboard id(s):")
        for line in dead:
            print(f"  {line}")
        print(
            "\n  grafana-operator will park these CRs InvalidSpec and ArgoCD will hold\n"
            "  the dashboards Application Degraded. Repoint each to a live dashboard id."
        )
    if legacy:
        if dead:
            print()
        print("FAIL — dashboard(s) carrying legacy panel `alert` blocks:")
        for line in legacy:
            print(f"  {line}")
        print(
            "\n  Amazon Managed Grafana is unified-alerting only: POST /api/dashboards/db\n"
            '  returns 500 {"message":"Failed to save dashboard"} and grafana-operator parks\n'
            "  the CR ApplyFailed. Repoint to a dashboard with no legacy alerts."
        )
    if dead or legacy:
        return 1

    print(f"✓ all {len(refs)} grafana.com dashboards exist and are AMG-saveable")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        # Network unreachable after retries — infrastructure problem, not a
        # bad dashboard. Still non-zero: an unverified catalog is not a green one.
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
