#!/usr/bin/env python3
"""Assert no alert rule excludes a state that nothing else reports.

WHY THIS EXISTS

Two eval alerts each excluded the never-run state, each explaining in a comment
that the OTHER one covered it:

    AgentEvalBelowThreshold — "the score/threshold are absent until a suite has
      actually run, so never-run suites do not false-fire here (they are caught
      by AgentEvalStale instead)"

    AgentEvalStale — the `!= 0` guard "drops never-run suites (lastRunAt is
      nilIsZero, so 0 means 'never ran', a different condition than 'stopped
      running')"

Both are individually correct. Between them the state was reported by nobody —
and it was the only state the fleet had ever been in, because the in-cluster eval
path could not run at all. A suite that had never executed looked exactly like a
healthy one to every alert on the board.

Nothing could catch that. kubeconform SKIPs the grafana.integreatly.org CRDs and
no gate executes the PromQL, so an alert that can never fire is indistinguishable
from one that simply has not fired.

WHAT IT CHECKS

A rule that writes `<selector> != 0` is stating that zero is a DIFFERENT
condition, not an impossible one — otherwise the guard would be unnecessary. So
for every such guard, some rule in the same group must key on that same selector
with `== bool 0`. The excluded state has to be somebody's job.

`== bool 0`, specifically. A bare `== 0` yields a sample carrying the value 0,
and Grafana's threshold reducer trips on `gt 0`, so the rule would match the
right series and still never fire. Requiring the bool modifier is the difference
between covering the state and appearing to.

This is deliberately narrow: it checks one mechanical property of one idiom,
rather than pretending to reason about alert semantics in general. What it buys
is that deleting the covering rule fails, and that the next `!= 0` guard someone
writes has to be paired.
"""

from __future__ import annotations

import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ALERT_DIR = REPO_ROOT / "dashboards" / "base" / "alerting"

# Guards where zero is the HEALTHY state, so there is nothing to cover.
#
# `!= 0` carries two different meanings and the expression cannot tell them
# apart. On lastRunAt it EXCLUDES a broken state (zero = never ran, a real
# problem nobody was reporting). On killSwitchFiredAt it SELECTS the interesting
# state (zero = never fired, which is the normal condition of every healthy
# tenant). Demanding a `== bool 0` partner for the second would page on health.
#
# Keyed by (file, rule title, field). Every entry must name a rule that exists,
# so a rename cannot leave a stale exemption quietly satisfying the check.
ZERO_IS_HEALTHY = {
    ("agent-platform.yaml", "AgentKillSwitchFired", "killSwitchFiredAt"):
        "zero means the kill switch has never fired, which is the normal state "
        "of every healthy BudgetPolicy — the guard selects the alert condition "
        "rather than excluding a broken one",
}

# kube_customresource_status_field{...} != 0   — the exclusion
GUARD = re.compile(
    r"(kube_customresource_status_field\{[^}]*\})\s*!=\s*0")
# kube_customresource_status_field{...} == bool 0   — the coverage
COVER = re.compile(
    r"(kube_customresource_status_field\{[^}]*\})\s*==\s*bool\s+0")
# The same, but without the bool modifier — matches the series, never fires.
COVER_NO_BOOL = re.compile(
    r"(kube_customresource_status_field\{[^}]*\})\s*==\s*0(?!\s*\))")


def selectors(text: str, pattern: re.Pattern) -> set[str]:
    """Normalised label selectors matched by `pattern`, whitespace-insensitive."""
    return {re.sub(r"\s+", "", m.group(1)) for m in pattern.finditer(text)}


def rule_exprs(group: dict) -> list[tuple[str, str]]:
    """(rule title, expr) for every Prometheus query in a GrafanaAlertRuleGroup."""
    out = []
    for rule in group.get("spec", {}).get("rules", []) or []:
        for datum in rule.get("data", []) or []:
            expr = (datum.get("model") or {}).get("expr")
            if expr:
                out.append((rule.get("title", rule.get("uid", "?")), expr))
    return out


def main() -> int:
    files = sorted(ALERT_DIR.glob("*.yaml"))
    if not files:
        sys.exit(f"FAIL  no alert files under {ALERT_DIR.relative_to(REPO_ROOT)}")

    errors: list[str] = []
    guards_seen = 0
    print("── Alert state coverage ──")

    for path in files:
        groups = [d for d in yaml.safe_load_all(path.read_text())
                  if isinstance(d, dict) and d.get("kind") == "GrafanaAlertRuleGroup"]
        for group in groups:
            exprs = rule_exprs(group)
            if not exprs:
                continue
            all_text = "\n".join(e for _, e in exprs)
            covered = selectors(all_text, COVER)
            covered_no_bool = selectors(all_text, COVER_NO_BOOL)

            titles = {t for t, _ in exprs}
            for (fname, rule_title, _field), reason in ZERO_IS_HEALTHY.items():
                if fname == path.name and rule_title not in titles and groups:
                    errors.append(
                        f"{fname}: ZERO_IS_HEALTHY exempts rule '{rule_title}', "
                        f"which no longer exists in this file — a stale "
                        f"exemption silently satisfies the check ({reason})"
                    )
                    print(f"  STALE     exemption for missing rule {rule_title}")

            for title, expr in exprs:
                for sel in selectors(expr, GUARD):
                    guards_seen += 1
                    name = f"{path.name}:{title}"
                    field = re.search(r'field="([^"]+)"', sel)
                    key = (path.name, title, field.group(1) if field else "")
                    if key in ZERO_IS_HEALTHY:
                        print(f"  healthy   {title}: zero is the healthy state "
                              f"({key[2]}), no coverage required")
                        continue
                    if sel in covered:
                        print(f"  ok        {title}: `!= 0` guard on "
                              f"{sel[:56]}… is covered by a `== bool 0` rule")
                    elif sel in covered_no_bool:
                        errors.append(
                            f"{name}: the rule covering the excluded zero state "
                            f"uses `== 0` without the bool modifier, so it "
                            f"reports the value 0 and Grafana's `gt 0` threshold "
                            f"can never trip. Use `== bool 0`."
                        )
                        print(f"  CONFLICT  {title}: covering rule lacks `bool`")
                    else:
                        errors.append(
                            f"{name}: excludes the zero state with `!= 0` on "
                            f"{sel}, and no rule in this group covers it with "
                            f"`== bool 0`. An excluded state has to be somebody's "
                            f"job — either cover it or stop guarding for it."
                        )
                        print(f"  UNCOVERED {title}: `!= 0` on {sel[:56]}…")

    if not guards_seen:
        print("  FAIL  no `!= 0` guards found — this gate would pass vacuously; "
              "if the idiom is gone, delete the gate")
        return 1

    if errors:
        print(f"\n{len(errors)} uncovered alert state(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"\nAll {guards_seen} excluded alert state(s) are covered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
