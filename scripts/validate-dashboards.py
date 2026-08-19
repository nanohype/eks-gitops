#!/usr/bin/env python3
"""Dashboard gate — every grafana.com dashboard this repo references must both
EXIST on grafana.com and be SAVEABLE by Amazon Managed Grafana.
Two failure classes park
a GrafanaDashboard CR forever, and because ArgoCD aggregates health, one parked
CR holds the whole dashboards Application — and app-of-apps with it — Degraded.

  1. DEAD ID (InvalidSpec)
     grafana-operator resolves `spec.grafanaCom.id` by fetching
     https://grafana.com/api/dashboards/<id>/revisions. If grafana.com 404s
     (the dashboard was unpublished/renumbered) the operator marks the CR
     InvalidSpec and never renders it.
     CHECK: /revisions must return HTTP 200 for every id.
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

  3. RIGHT ID, WRONG DASHBOARD
     Checks 1 and 2 ask whether an id resolves and whether AMG can save it. A
     number that resolves to somebody else's board passes both, and nothing
     downstream disagrees — the operator applies it, Grafana renders it, and the
     board is simply about something else. `tempo` pinned 15473, which is
     "AKA SNMP Network(网络设备监控)"; an operator opening "tempo" got an SNMP
     device board with this gate green. Three more were the same: argo-events
     resolved to "Beyla RED Metrics", descheduler to "Query Insights", and
     aws-load-balancer-controller to "Kubernetes / Views / K3s Cluster".
     CHECK: every pin carries a `nanohype.dev/grafana-com-title` annotation and
     grafana.com's `name` must equal it. The annotation lives beside the id in
     the same file so the two cannot be changed apart, and a pin with no
     annotation fails rather than being skipped.

Stdlib only (urllib): CI runs this on a bare ubuntu-latest with no pip install.
Every grafana.com call is retried with backoff so a flaky network reports as a
retry, not as a red build.

Usage:  scripts/validate-dashboards.py [--root DIR]
Exit:   0 every reference exists, is AMG-saveable, and is the dashboard it claims
        1 a dead id, a legacy-alert panel, or an id naming another board (BLOCKING)
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

# The title an id is expected to resolve to, recorded beside the pin as an
# annotation. Parsed textually for the same reason the id is: this runs on a
# bare runner with no pyyaml. The value is a JSON string, so a title containing
# a comma, a slash or a non-ASCII character survives round-tripping.
EXPECTED_TITLE = re.compile(
    r'^\s*nanohype\.dev/grafana-com-title:\s*"((?:[^"\\]|\\.)*)"\s*$', re.M
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



# ─────────────────────── locally-authored dashboard checks ───────────────────────
#
# The two checks above cover dashboards PULLED from grafana.com. Nothing covered
# the ones this repo writes itself, and two defect classes lived in them for as
# long as they have existed:
#
#   3. PANEL NAMES A DATASOURCE NOTHING WIRES
#      agent-finance had four panels on "athena-cur". dashboards/base/datasources/
#      holds cloudwatch, loki, prometheus and tempo, and the kustomization wires
#      exactly those. The panels render an error forever. Nothing failed, because a
#      dashboard is data — the operator applies it happily and Grafana discovers the
#      missing datasource at view time, in front of whoever opened the board.
#
#   4. PANEL USES A TEMPLATE VARIABLE THE DASHBOARD DOES NOT DECLARE
#      the same file's SQL interpolated ${cost_database} with no templating block at
#      all, so the variable expands to nothing and the query is malformed. Its three
#      sibling boards each declare one; this one was simply missing it.
#
# Both are local and offline, so they run before the network checks and regardless
# of whether any grafana.com reference exists.

JSON_BLOCK = re.compile(r"^(\s*)json:\s*\|\s*$", re.M)
UID_LINE = re.compile(r"^\s+uid:\s*(\S+)\s*$", re.M)
NAME_LINE = re.compile(r"^\s+name:\s*(\S+)\s*$", re.M)
KUSTOMIZE_DS = re.compile(r"^\s*-\s*(datasources/[\w.-]+\.yaml)\s*$", re.M)
# Grafana writes a variable reference four ways and this must see all of them.
# Anchored on `${name}` alone, it saw NONE of the ones this repo actually uses —
# every dashboard here writes the bare `$namespace` / `$tenant` form — so the
# undeclared-variable check below compared an always-empty set against the
# declared list and passed on all 30 dashboards without examining anything.
TEMPLATE_VAR = re.compile(
    r"\$\{(\w+)(?::[^}]*)?\}"  # ${name} and ${name:csv}
    r"|\$(\w+)"  # $name
    r"|\[\[(\w+)(?::[^\]]*)?\]\]"  # [[name]] and [[name:csv]]
)

# Grafana supplies these itself; a dashboard is not expected to declare them.
# Without the allowlist, widening the regex above turns every `$__rate_interval`
# into a false positive and the gate becomes noise instead of signal.
GRAFANA_BUILTINS = frozenset(
    {
        "__interval",
        "__interval_ms",
        "__rate_interval",
        "__range",
        "__range_s",
        "__range_ms",
        "__from",
        "__to",
        "__timeFilter",
        "__timeGroup",
        "__name",
        "__field",
        "__series",
        "__value",
        "__dashboard",
        "__org",
        "__user",
        "__timezone",
        "timeFilter",
    }
)


def template_vars(text: str) -> set[str]:
    """Variable names referenced in `text`, minus the ones Grafana provides."""
    names = set()
    for m in TEMPLATE_VAR.finditer(text):
        name = next(g for g in m.groups() if g)
        if name not in GRAFANA_BUILTINS:
            names.add(name)
    return names


def wired_datasource_refs(root: pathlib.Path) -> set[str]:
    """Every string a panel could legally use to name a wired datasource.

    Grafana's string form resolves against the datasource NAME historically and the
    UID in current schemas, so both are accepted here — the point of the check is to
    catch a reference that matches NEITHER, which is a reference to nothing.

    Reading the kustomization rather than globbing the directory is deliberate: a
    GrafanaDatasource file that exists but is not in `resources` is never applied,
    so globbing would call a datasource wired when it is not.
    """
    kustom = root / "dashboards" / "base" / "kustomization.yaml"
    if not kustom.is_file():
        return set()
    refs: set[str] = set()
    for rel in KUSTOMIZE_DS.findall(kustom.read_text(encoding="utf-8")):
        ds = kustom.parent / rel
        if ds.is_file():
            text = ds.read_text(encoding="utf-8")
            refs.update(UID_LINE.findall(text))
            refs.update(NAME_LINE.findall(text))
    return refs


def extract_dashboard_json(text: str):
    """Pull the `json: |` literal block out of a GrafanaDashboard and parse it."""
    m = JSON_BLOCK.search(text)
    if not m:
        return None
    indent = len(m.group(1)) + 2
    body = []
    for line in text[m.end():].splitlines():
        if line.strip() and not line.startswith(" " * indent):
            break
        body.append(line[indent:] if len(line) >= indent else "")
    try:
        return json.loads("\n".join(body))
    except json.JSONDecodeError:
        return None


def walk_datasources(node, out: list[str]) -> None:
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, str):
            out.append(ds)
        elif isinstance(ds, dict) and isinstance(ds.get("uid"), str):
            out.append(ds["uid"])
        for v in node.values():
            walk_datasources(v, out)
    elif isinstance(node, list):
        for v in node:
            walk_datasources(v, out)


def declared_template_vars(dash) -> set[str]:
    tpl = dash.get("templating") or {}
    return {
        v["name"]
        for v in (tpl.get("list") or [])
        if isinstance(v, dict) and isinstance(v.get("name"), str)
    }


def check_local_dashboards(root: pathlib.Path) -> list[str]:
    wired = wired_datasource_refs(root)
    problems: list[str] = []
    total_declared = 0
    total_used = 0
    base = root / "dashboards"
    if not base.is_dir():
        return problems

    for path in sorted(base.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "kind: GrafanaDashboard" not in text:
            continue
        rel = path.relative_to(root)
        dash = extract_dashboard_json(text)
        if dash is None:
            # A grafana.com-sourced dashboard carries no inline JSON — its
            # content is a `grafanaCom.id` the checks above already validate
            # against the API. Nothing to read here, and that is correct.
            if "grafanaCom:" in text:
                continue
            # A LOCALLY-AUTHORED dashboard whose JSON this cannot read is a
            # dashboard this is not checking, and skipping it quietly is how the
            # check reports success having looked at nothing.
            #
            # It is not hypothetical. Round-tripping this file through
            # yaml.safe_dump replaced the `json: |` literal block with a quoted
            # scalar — semantically identical YAML, unreadable to the block
            # parser below — and every assertion here silently stopped applying
            # to it while the run stayed green.
            problems.append(
                f"{rel}: is a GrafanaDashboard but its dashboard JSON could not be read. "
                "Expected a `json: |` literal block holding valid JSON; a quoted or folded "
                "scalar parses as YAML and is invisible to every check below."
            )
            continue

        refs: list[str] = []
        walk_datasources(dash, refs)
        for name in sorted(set(refs)):
            if TEMPLATE_VAR.fullmatch(name):
                continue  # datasource chosen by a template variable
            if name not in wired:
                problems.append(
                    f"{rel}: panel datasource {name!r} is not wired — "
                    f"nothing wired answers to that name or uid; wired: {sorted(wired)}"
                )

        declared = declared_template_vars(dash)
        used = template_vars(json.dumps(dash))
        total_declared += len(declared)
        total_used += len(used)
        for name in sorted(used - declared):
            problems.append(
                f"{rel}: uses ${name} but declares no such template variable"
            )

    # An empty `used` satisfies `used - declared` on every dashboard, so a regex
    # that stops matching turns this check into a silent no-op. If anything
    # declares a variable, something must reference
    # one, or the parse is broken rather than the tree being clean.
    if total_declared and not total_used:
        problems.append(
            f"{total_declared} template variable(s) are declared across these dashboards and "
            "not one reference was found — TEMPLATE_VAR has stopped matching Grafana's syntax, "
            "so the undeclared-variable check is asserting nothing"
        )
    return problems


def discover(root: pathlib.Path) -> list[tuple[int, pathlib.Path, str | None]]:
    """Every pinned id, with the title its file says that id resolves to.

    The title is read from the same file as the id so the two cannot be updated
    apart: bumping a pin without touching the annotation fails check 3.
    """
    found: list[tuple[int, pathlib.Path, str | None]] = []
    for path in sorted(root.rglob("*.yaml")):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in GRAFANA_COM_ID.finditer(text):
            expected = EXPECTED_TITLE.search(text)
            found.append((int(match.group(1)), path, expected.group(1) if expected else None))
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

    local = check_local_dashboards(args.root)
    if local:
        print("Locally-authored dashboard problems:\n")
        for p in local:
            print(f"  {p}")
        print()
    else:
        print("Locally-authored dashboards: datasources wired, template variables declared.\n")

    refs = discover(args.root)
    if not refs:
        print("No grafanaCom.id references found — nothing further to validate.")
        return 1 if local else 0

    print(f"Validating {len(refs)} grafana.com dashboard reference(s)\n")

    dead: list[str] = []
    legacy: list[str] = []
    mismatched: list[str] = []

    for gnet_id, path, expected in refs:
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

        # ── Check 3: the id must be the RIGHT dashboard ──────────────────
        # Checks 1 and 2 ask whether an id resolves and whether AMG can save
        # it. A number that resolves to somebody else's board passes both. The
        # tempo pin resolved to "AKA SNMP Network", and an operator opening
        # "tempo" in Grafana got an SNMP device board with the gate green.
        if expected is None:
            print("    NO EXPECTED TITLE — the pin records nothing to check against")
            mismatched.append(
                f"{gnet_id}  ({rel})  has no nanohype.dev/grafana-com-title annotation; "
                f'grafana.com calls it "{name}"'
            )
            continue
        if json.loads(f'"{expected}"') != name:
            print(f'    WRONG BOARD — expected "{json.loads(chr(34)+expected+chr(34))}", grafana.com says "{name}"')
            mismatched.append(
                f'{gnet_id}  ({rel})  annotation says '
                f'"{json.loads(chr(34)+expected+chr(34))}", grafana.com says "{name}"'
            )
            continue

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
    if mismatched:
        print("FAIL — grafana.com id(s) that resolve to a different dashboard:")
        for line in mismatched:
            print(f"  {line}")
        print(
            "\n  An id that resolves is not an id that is right. Check the pin against\n"
            "  https://grafana.com/api/dashboards/<id> and update BOTH the id and the\n"
            "  nanohype.dev/grafana-com-title annotation, which travel together on purpose.\n"
        )

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
    if dead or legacy or mismatched or local:
        return 1

    print(f"✓ all {len(refs)} grafana.com dashboards exist, are AMG-saveable, and\n  resolve to the title their pin records")
    print("✓ every locally-authored panel names a wired datasource and a declared variable")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        # Network unreachable after retries — infrastructure problem, not a
        # bad dashboard. Still non-zero: an unverified catalog is not a green one.
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
