#!/usr/bin/env python3
"""Every column an Athena dashboard panel names is a column the CUR table delivers.

WHY THIS EXISTS

A CUR 2.0 export runs an explicit column projection, not `SELECT *`. This
system's export delivers six columns plus a projected partition key
(`dashboards/cur-columns.txt`), which is far narrower than the CUR
specification — so every column name in AWS's CUR documentation looks plausible
in a panel query and all but seven of them fail.

That has now happened twice, in two repos, with two different failure modes:
Two failure modes follow from that, and they fail differently:

* A missing MAP KEY resolves to NULL rather than failing, so a budget query
reading an undelivered key returns zero month-to-date spend and the kill
switch has nothing to act on. Silent.

* A missing COLUMN is resolved at parse time, so a panel naming one — say
`bill_billing_period_start_date`, which this export does not carry — fails
outright the moment the substrate exists. Loud, but only at query time, and
invisible here: `validate-dashboards.py` checks datasource refs, template
variables and grafana.com ids, and never opens `rawSQL`.
    delivered. Athena resolves a missing MAP KEY to NULL rather than failing, so
    every platform's month-to-date spend read zero and the kill switch had
    nothing to act on. Silent.

  * A missing COLUMN is resolved at parse time, so a panel naming one — say
    `bill_billing_period_start_date`, which this export does not carry — fails
    outright the moment the substrate exists. Loud, but only at query time,
    and nothing here could see it: `validate-dashboards.py` checks datasource
    refs, template variables and grafana.com ids, and never opens `rawSQL`.

The gate that caught the first one lives in eks-agent-platform, next to the
table definition. This is the same assertion on the consumer side of the repo
boundary, which is the side the second instance landed on.

WHAT THIS ASSERTS

For every panel target whose datasource is the Athena plugin, every identifier
its SQL references must appear in `dashboards/cur-columns.txt`. Identifiers are
matched conservatively — SQL keywords, function names, string literals, quoted
aliases and anything introduced by `AS` are excluded — so a false positive is a
name that genuinely looks like a column reference.

SCOPE, stated because the two historical failures differ and this covers one of
them completely and the other only in part: it checks COLUMN names. It does not
check MAP KEYS. `element_at(resource_tags, 'user_PlatformId')` is verified as far
as `resource_tags` being a delivered column; whether `user_PlatformId` is a tag
the export carries is not knowable from this repo, because it depends on which
cost-allocation tags are activated in the payer account — a live setting this
repo cannot see. (Activating late is repairable: AWS backfills up to twelve
months. A resource that ran untagged is not, because backfill applies an
activation status and invents no tag values.) The `tags`-vs-`resource_tags` half is caught
here; the `'resourceTags/PlatformId'`-vs-`'user_PlatformId'` half is not, and
that is the half that fails silently. Asserting it needs a live read.

    scripts/check-athena-panel-columns.py
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
COLUMNS_FILE = ROOT / "dashboards" / "cur-columns.txt"
DASHBOARD_DIR = ROOT / "dashboards"

ATHENA_DS_TYPE = "grafana-athena-datasource"

# Reserved words, functions and literals that may appear where an identifier
# would. Presto/Trino vocabulary, restricted to what a CUR panel plausibly uses.
SQL_VOCAB = {
    "select", "from", "where", "group", "by", "order", "having", "limit",
    "and", "or", "not", "is", "null", "as", "asc", "desc", "distinct",
    "case", "when", "then", "else", "end", "in", "between", "like", "on",
    "join", "left", "right", "inner", "outer", "union", "all", "with",
    "sum", "count", "avg", "min", "max", "coalesce", "cast", "try_cast",
    "element_at", "date_format", "date_trunc", "current_date", "current_timestamp",
    "substr", "substring", "concat", "lower", "upper", "abs", "round",
    "approx_distinct", "arbitrary", "if", "nullif", "greatest", "least",
    "interval", "day", "month", "year", "true", "false", "over", "partition",
}

# The table itself is named in FROM and is not a column.
TABLE_NAMES = {"cur"}


def delivered_columns() -> set[str]:
    """Column names the CUR table delivers, from the committed contract."""
    if not COLUMNS_FILE.is_file():
        sys.exit(f"FAIL  {COLUMNS_FILE.relative_to(ROOT)} is missing — the contract this gate reads")
    out = set()
    for line in COLUMNS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def athena_queries(dash: dict, path: pathlib.Path) -> list[tuple[str, str]]:
    """(panel title, rawSQL) for every target pointed at the Athena datasource."""
    out: list[tuple[str, str]] = []

    def is_athena(ds) -> bool:
        return isinstance(ds, dict) and ds.get("type") == ATHENA_DS_TYPE

    for panel in dash.get("panels") or []:
        if not isinstance(panel, dict):
            continue
        title = panel.get("title", "(untitled)")
        panel_ds_athena = is_athena(panel.get("datasource"))
        for target in panel.get("targets") or []:
            if not isinstance(target, dict):
                continue
            sql = target.get("rawSQL")
            if not isinstance(sql, str) or not sql.strip():
                continue
            if is_athena(target.get("datasource")) or panel_ds_athena:
                out.append((title, sql))
    return out


ALIAS_RE = re.compile(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
STRING_RE = re.compile(r"'[^']*'")
IDENT_RE = re.compile(r"\b[a-z_][a-z0-9_]*\b")


def referenced_identifiers(sql: str) -> set[str]:
    """Lower-case identifiers the query references that could be columns."""
    aliases = {m.lower() for m in ALIAS_RE.findall(sql)}
    # Strip string literals so map keys ('user_PlatformId') are not read as columns.
    stripped = STRING_RE.sub("''", sql)
    # Drop anything immediately followed by '(' — a function call, not a column.
    stripped = re.sub(r"\b([a-z_][a-z0-9_]*)\s*\(", " ", stripped, flags=re.IGNORECASE)
    idents = {m.lower() for m in IDENT_RE.findall(stripped)}
    return idents - SQL_VOCAB - TABLE_NAMES - aliases


def dashboards() -> list[tuple[pathlib.Path, dict]]:
    """Every committed GrafanaDashboard, with its embedded JSON parsed."""
    out = []
    for path in sorted(DASHBOARD_DIR.rglob("*.yaml")):
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError as err:
            sys.exit(f"FAIL  {path.relative_to(ROOT)} is not parseable YAML: {err}")
        for d in docs:
            if not isinstance(d, dict) or d.get("kind") != "GrafanaDashboard":
                continue
            raw = (d.get("spec") or {}).get("json")
            if not isinstance(raw, str):
                continue
            try:
                out.append((path, json.loads(raw)))
            except json.JSONDecodeError as err:
                # Refuse to skip a dashboard we cannot parse. A gate that
                # silently drops its subject reports success over nothing.
                sys.exit(f"FAIL  {path.relative_to(ROOT)} spec.json is not valid JSON: {err}")
    return out


def main() -> int:
    columns = delivered_columns()
    if not columns:
        print("FAIL  the CUR column contract is empty — this check would pass vacuously")
        return 1

    # The verdict below is derived from a FILTERED set: referenced_identifiers()
    # subtracts SQL vocabulary, table names and query aliases before comparing.
    # A filter that removes everything dies loudly; this one leaves survivors, so
    # a delivered column that collides with a subtracted name is dropped from the
    # comparison and the remaining identifiers still resolve. The gate then
    # reports success over a column it never examined.
    #
    # The collision is the assertion, not a warning: if the export ever delivers
    # a column named like SQL vocabulary, no verdict about that column is founded
    # and the exclusion list has to be narrowed before this check means anything.
    shadowed = sorted((columns & SQL_VOCAB) | (columns & TABLE_NAMES))
    if shadowed:
        print(f"FAIL  the CUR export delivers {', '.join(repr(c) for c in shadowed)}, "
              f"which this gate subtracts as SQL vocabulary or a table name before "
              f"comparing. Those columns are excluded from every panel check, so a "
              f"panel referencing one is neither confirmed nor reported. Narrow the "
              f"exclusion list.")
        return 1

    failures: list[str] = []
    queries_checked = 0

    for path, dash in dashboards():
        for title, sql in athena_queries(dash, path):
            queries_checked += 1
            unknown = sorted(referenced_identifiers(sql) - columns)
            if unknown:
                failures.append(
                    f"{path.relative_to(ROOT)}: panel {title!r} references "
                    f"{', '.join(repr(u) for u in unknown)}, which the CUR table does not deliver.\n"
                    f"      Delivered: {', '.join(sorted(columns))}\n"
                    "      A missing column fails the query outright at parse time; a missing MAP\n"
                    "      KEY resolves to NULL and reports zero instead. Neither is visible until\n"
                    "      the panel is opened against a real workgroup."
                )

    # Vacuity guard. This repo ships Athena panels today; a walk that finds none
    # means the discovery moved, not that the assertion holds.
    if queries_checked == 0:
        print("FAIL  found no Athena panel queries — this check would pass vacuously")
        return 1

    print(f"  contract: {len(columns)} delivered columns; exclusions applied "
          f"per query: {len(SQL_VOCAB)} SQL vocabulary, {len(TABLE_NAMES)} table "
          f"name(s), plus each query's own aliases")

    if failures:
        print(f"FAIL  {len(failures)} Athena panel(s) reference undelivered columns:\n")
        for f in failures:
            print(f"  - {f}\n")
        return 1

    print(
        f"✓ {queries_checked} Athena panel quer(ies) reference only the "
        f"{len(columns)} columns the CUR table delivers"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
