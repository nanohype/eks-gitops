#!/usr/bin/env python3
"""The budget a burn-rate alert claims is the one its own expression spends.

WHY THIS EXISTS

A multi-window burn-rate rule fires on a rate of spend, and its summary is the
alert TITLE — the sentence that reaches a human first and often the only one
they read. One ticket-tier rule said:

    summary: operator reconcile latency budget burning (100% over 3d)

for an expression comparing against a burn factor of 1 over a 3d window. Factor
1 spends the budget at exactly the rate that exhausts it over the SLO window, so
three days of it consumes three days' worth: 10% of a 30d budget, not 100%. The
title described total exhaustion — the most urgent condition an SLO has — on the
least urgent tier the file ships.

Both readings of that title are damaging. Escalated, it is an outage that is not
happening. Recognised as wrong, it teaches on-call that these titles are not to
be trusted, which spends the credibility of the three tiers that are right.

Nothing could see it. The expression is correct; only the sentence describing it
is wrong, so every rule-level validation passes. kubeconform SKIPs the
grafana.integreatly.org CRDs, no gate executes PromQL, and a summary is
free-text that nothing parses.

WHAT IT CHECKS

The claim is checked against arithmetic, not against a table of expected
figures. For a burn rule with factor `f` over long window `w`, against an SLO
window `W`:

    budget consumed = f * w / W

Every term comes from the tree:

  * `f` and `w` from the rule's own expression — the `> bool f` threshold and
    the longest range selector in it;
  * `W` from the dashboard panel measuring the same metric selector over its
    longest explicit range. That is the panel that displays the objective this
    rule burns against, in a different file, edited by different work.

So there is no constant here to agree with the standard today and be compared to
nothing tomorrow. A figure that drifts fails against the expression that
produces it, and an SLO window that moves fails against the panel that measures
it.

Every rule whose expression is a burn-rate expression must carry the claim. A
burn-rate title that does not say how much budget is at stake tells the reader
nothing they can act on, and leaving the claim out would otherwise remove the
rule from this gate's corpus without removing the rule.

WHAT IT DOES NOT CHECK

  * Whether the SLO objective is the right one. `W` is read from the panel that
    measures it; that the business wants 30d rather than 28d is not a fact in
    this repository.
  * Whether the factors implement the alerting policy correctly. That 14.4 over
    1h is the intended fast tier is a design decision; this asserts only that
    the sentence and the expression describe the same spend.
  * Whether the rule fires. The expression is read, never executed.
  * The `description` under each summary, which states the same thing in prose
    and in a different shape per file. The summary is checked because it is the
    title — the sentence that reaches a human whether or not they open the rule.
  * Agreement with the org SLO standard. The standard is the authority for these
    figures and it is not in this repository, so what is asserted here is that
    the catalog agrees with ITSELF: the sentence, the expression, and the panel
    measuring the objective all describe one spend. A window that moved in the
    standard and nowhere else would leave this green.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
from fractions import Fraction

_here = pathlib.Path(__file__).resolve().parent

_gl = _here / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

# The dashboard walk lives in the gate that already owns it. Copying it here
# would give this gate a second walk to keep in step with the first, and a
# dashboard silently dropped from either corpus reports the same as a clean run.
_ap = _here / "check-athena-panel-columns.py"
_as = importlib.util.spec_from_file_location("check_athena_panel_columns", _ap)
assert _as and _as.loader, f"{_ap} is not loadable as a module"
panels = importlib.util.module_from_spec(_as)
_as.loader.exec_module(panels)

ROOT = _here.parent
ALERT_DIR = ROOT / "dashboards" / "base" / "alerting"
RULE_GROUP = "GrafanaAlertRuleGroup"

UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# `metric{labels}[range]` — the labels are kept because they are part of what a
# panel has to match to be measuring the same thing.
SELECTOR = re.compile(
    r"(?P<sel>[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?)\[(?P<range>\d+[smhdw])\]")
# The burn factor, and what separates it from every other `> bool` in a rule.
# A burn comparison is made against the error ratio NORMALISED by the budget:
# `<error ratio> / <budget> > bool <factor>`. Matching `> bool` alone also
# matches the traffic guard these rules carry — `sum(rate(...)) > bool 0.0167`,
# roughly one request a minute, there to stop an idle service alerting on a
# ratio computed from nothing. Read as a factor it makes a rule look like two
# contradictory claims about one rate of spend.
FACTOR = re.compile(
    r"/\s*(?P<budget>0\.\d+)\s*>\s*bool\s+(?P<factor>\d+(?:\.\d+)?)")
# The claim in the summary: a percentage of budget over a window.
CLAIM = re.compile(
    r"(?P<pct>\d+(?:\.(?P<frac>\d+))?)%\s+(?:in|over)\s+(?P<window>\d+[smhdw])")


def seconds(duration: str) -> int:
    """A PromQL duration in seconds. The grammar here is a single unit, which
    is what every range in this catalog uses; a compound `1h30m` would not match
    SELECTOR and so would never reach this."""
    return int(duration[:-1]) * UNIT_SECONDS[duration[-1]]


def human(total: int) -> str:
    """Seconds as the largest whole unit that divides them, for messages that a
    reader compares against a duration written in the file."""
    for unit in ("w", "d", "h", "m"):
        size = UNIT_SECONDS[unit]
        if total >= size and total % size == 0:
            return f"{total // size}{unit}"
    return f"{total}s"


def rule_expr(rule: dict) -> str:
    """The rule's query, as one string.

    A Grafana rule carries a list of `data` stages; the burn arithmetic is in
    the datasource query, and the later stages are threshold expressions over
    its result.
    """
    for stage in rule.get("data") or []:
        if not isinstance(stage, dict):
            continue
        expr = (stage.get("model") or {}).get("expr")
        if isinstance(expr, str) and expr.strip():
            return expr
    return ""


def burn_rules(alert_dir: pathlib.Path):
    """(path, group, rule, expr) for every rule whose query is a burn-rate one.

    Selected on the EXPRESSION rather than on the summary. Selecting on the
    sentence would let a rule leave this gate's corpus by having its claim
    deleted, which is the one edit most likely to accompany a wrong figure.
    """
    for path in sorted(alert_dir.glob("*.yaml")):
        for doc in gatelib.read_yaml_all(path):
            if not isinstance(doc, dict) or doc.get("kind") != RULE_GROUP:
                continue
            group = (doc.get("metadata") or {}).get("name", path.stem)
            for rule in (doc.get("spec") or {}).get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                expr = rule_expr(rule)
                if FACTOR.search(expr) and SELECTOR.search(expr):
                    yield path, str(group), rule, expr


def long_window(expr: str) -> tuple[int, set[str]]:
    """The longest range in `expr`, and the selectors carrying it.

    A dual-window burn rule ANDs a long window against a short confirmation
    window. The long one is the period the claim is about; the short one exists
    to stop the alert firing on a spike that has already stopped.
    """
    ranges: dict[int, set[str]] = {}
    for m in SELECTOR.finditer(expr):
        ranges.setdefault(seconds(m.group("range")), set()).add(
            re.sub(r"\s+", "", m.group("sel")))
    longest = max(ranges)
    return longest, ranges[longest]


def factors(expr: str) -> set[Fraction]:
    """Every burn factor the expression compares against.

    A set, because a dual-window rule states the same factor twice and a rule
    stating two different ones is not a single claim about a rate of spend.
    """
    return {Fraction(m.group("factor")) for m in FACTOR.finditer(expr)}


def objective_windows() -> dict[str, int]:
    """selector -> the longest explicit range a dashboard panel applies to it.

    The SLO window, read from the panel that displays the objective. A burn
    window is by construction shorter than the window it burns against, so the
    longest range a panel measures this selector over is the objective's.
    """
    out: dict[str, int] = {}
    for _path, dash in panels.dashboards():
        for expr in panel_exprs(dash):
            for m in SELECTOR.finditer(expr):
                sel = re.sub(r"\s+", "", m.group("sel"))
                out[sel] = max(out.get(sel, 0), seconds(m.group("range")))
    return out


def panel_exprs(node) -> list[str]:
    """Every `expr` under a dashboard, rows and nested panels included."""
    found: list[str] = []
    if isinstance(node, dict):
        expr = node.get("expr")
        if isinstance(expr, str) and expr.strip():
            found.append(expr)
        for value in node.values():
            found.extend(panel_exprs(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(panel_exprs(item))
    return found


def decimal(value: Fraction) -> str:
    """A Fraction as the decimal a reader will find in the expression.

    Exact arithmetic is what lets the comparison be an equality rather than a
    tolerance, but `72/5` is not the string anyone can search the file for.
    """
    if value.denominator == 1:
        return str(value.numerator)
    return f"{float(value):g}"


def as_percent(value: Fraction, places: int) -> str:
    """`value` as a percentage string with `places` decimals, no float."""
    scaled = value * 100
    if places == 0:
        return str(round(scaled))
    quantum = Fraction(10) ** places
    return f"{float(round(scaled * quantum) / quantum):.{places}f}"


def main() -> int:
    if not ALERT_DIR.is_dir():
        print(f"Cannot run: {ALERT_DIR.relative_to(ROOT)} does not exist, so the "
              f"burn-rate rules whose claims this gate checks are not there.")
        print("This gate examined nothing, which is not the same as finding nothing.")
        return gatelib.CANNOT_RUN

    rules = list(burn_rules(ALERT_DIR))
    if not rules:
        print(f"Cannot run: no burn-rate rule found under "
              f"{ALERT_DIR.relative_to(ROOT)}. A run over no rule reports what a "
              f"catalog of correct claims reports.")
        return gatelib.CANNOT_RUN

    windows = objective_windows()
    failures: list[str] = []
    checked = 0

    for path, group, rule, expr in rules:
        title = str(rule.get("title") or rule.get("uid") or "<unnamed>")
        where = f"{path.name}: {group}/{title}"

        seen = factors(expr)
        if len(seen) != 1:
            failures.append(
                f"{where} compares against {len(seen)} different burn factors "
                f"({', '.join(decimal(f) for f in sorted(seen))}), so there is no one "
                f"rate of spend for its summary to be describing.")
            continue
        factor = seen.pop()

        window, selectors = long_window(expr)

        summary = str((rule.get("annotations") or {}).get("summary") or "")
        claim = CLAIM.search(summary)
        if not claim:
            failures.append(
                f"{where} is a burn-rate rule and its summary states no budget "
                f"figure: {summary!r}. The summary is the alert title, and a burn "
                f"title that does not say how much budget is at stake gives the "
                f"reader nothing to act on.")
            continue

        stated_window = seconds(claim.group("window"))
        if stated_window != window:
            failures.append(
                f"{where} says {claim.group(0)!r} and its expression measures over "
                f"{human(window)}. The sentence and the query describe different "
                f"periods, so one of them is about an alert that does not exist.")
            continue

        objective = {windows[sel] for sel in selectors if sel in windows}
        if not objective:
            failures.append(
                f"{where} claims {claim.group(0)!r} and no dashboard panel measures "
                f"{' or '.join(sorted(selectors))} over an explicit range. The "
                f"figure is compared to nothing, which is how the last wrong one "
                f"survived.")
            continue
        if len(objective) > 1:
            failures.append(
                f"{where} burns against selectors whose panels measure them over "
                f"{', '.join(human(w) for w in sorted(objective))}. Which of those "
                f"is the SLO window decides the figure, and the tree states both.")
            continue
        slo = objective.pop()

        places = len(claim.group("frac") or "")
        derived = factor * Fraction(window, slo)
        stated = Fraction(claim.group("pct")) / 100
        if as_percent(derived, places) != as_percent(stated, places):
            failures.append(
                f"{where} claims {claim.group(0)!r} and its expression spends "
                f"{as_percent(derived, places)}% over {human(window)}: burn factor "
                f"{decimal(factor)} against a {human(slo)} objective is "
                f"{decimal(factor)} x {human(window)} / {human(slo)}. This "
                f"sentence is the alert title.")
            continue
        checked += 1

    if failures:
        print(f"{len(failures)} burn-rate budget claim(s) the expression does not "
              f"support:\n")
        for f in failures:
            print(f"  {f}")
        return 1

    objectives = sorted({human(windows[sel])
                         for _p, _g, _r, e in rules
                         for sel in long_window(e)[1] if sel in windows})
    print(f"✓ every burn-rate summary states the budget its expression spends: "
          f"{checked} rule(s) across {len({g for _p, g, _r, _e in rules})} group(s), "
          f"each derived from its own factor and window against the "
          f"{', '.join(objectives)} objective(s) the dashboards measure")
    print("  the objective itself, the choice of factors, and whether any rule "
          "fires are outside this claim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
