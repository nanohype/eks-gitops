#!/usr/bin/env bash
# Revert one gate behaviour at a time and require the suite to NAME it.
#
# scripts/tests/reverify-gates.sh proves a GATE rejects a planted defect. This
# proves the TESTS reject a reverted behaviour, which is the other half and the
# one a passing suite cannot supply on its own: a test that asserts what it just
# constructed passes forever, and so does a test whose subject was quietly
# rewritten underneath it.
#
# Each probe below names the test ids that must fail. Requiring a non-zero exit
# alone is not enough — it proves the suite noticed something, not that the
# assertion which noticed is the one that describes the behaviour. A suite can
# catch a mutant by accident through an unrelated fixture, and then the mutant
# has demonstrated detection without demonstrating coverage.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
SP="$(mktemp -d)"

# Backups live outside $SP, for the reason reverify-gates.sh records: between
# planting and restoring, the backup is the only copy of the original, and
# keeping it in the directory the cleanup removes means an interrupt destroys
# the means of restoration.
BK="$(mktemp -d)"
OUT="$SP/rt.out"

MUT_FILES=()

_slot() { printf '%s' "$1" | tr '/' '_'; }

mut() {
  local f="$1" s
  s="$(_slot "$f")"
  [ -e "$BK/$s" ] || cp "$f" "$BK/$s"
  case " ${MUT_FILES[*]:-} " in
    *" $f "*) ;;
    *) MUT_FILES+=("$f") ;;
  esac
}

res() {
  local f="$1" s
  s="$(_slot "$f")"
  [ -e "$BK/$s" ] && cp "$BK/$s" "$f"
  return 0
}

restore_all() {
  [ "${#MUT_FILES[@]}" -eq 0 ] && return 0
  local f
  for f in "${MUT_FILES[@]}"; do res "$f"; done
}

cleanup() { restore_all; rm -rf "$SP" "$BK"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

pass=0; fail=0

# Every module this harness plants against. Named rather than discovered: a
# module that stops being loaded would otherwise drop out of the clean-tree and
# restored-tree checks without either of them failing.
ALL_MODULES="test_policy_admission test_platform_crs test_dashboards \
  test_render_addons test_image_pins test_log_volume_budget"

# Bytecode caching keys on (mtime, size). A restore and the next mutation inside
# the same second can hand the run the PREVIOUS mutant's module, and the suite
# then reports the previous mutant's failing test against this mutant's label —
# a green line naming the wrong assertion, which is worse than a red one.
_suite() {
  rm -rf "$ROOT/scripts/__pycache__" "$ROOT/scripts/tests/__pycache__"
  ( cd "$ROOT/scripts/tests" \
    && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest "$@" ) >"$OUT" 2>&1
}

# rejects <label> <module> <test-id>...
#
# The suite must exit non-zero AND every named test id must appear on a FAIL: or
# ERROR: line. A mutant caught only by tests other than the ones that name the
# behaviour is reported as a miss, because the assertion that was supposed to
# hold the behaviour did not.
rejects() {
  local label="$1" module="$2"; shift 2
  _suite "$module"
  local rc=$?
  if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
    printf "  HARNESS %-56s rc=%s — python did not run; not a verdict\n" "$label" "$rc"
    fail=$((fail+1)); return
  fi
  if [ "$rc" -eq 0 ]; then
    printf "  MISS  %-56s the suite passed the mutant\n" "$label"
    fail=$((fail+1)); return
  fi
  local missing=() t
  for t in "$@"; do
    grep -qE "^(FAIL|ERROR): ${t} " "$OUT" || missing+=("$t")
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    printf "  MISS  %-56s rejected, but not by %s\n" "$label" "${missing[*]}"
    grep -E "^(FAIL|ERROR): " "$OUT" | sed 's/^/          /'
    fail=$((fail+1)); return
  fi
  printf "  ok    %-56s\n" "$label"
  for t in "$@"; do printf "          %s\n" "$(grep -m1 -E "^(FAIL|ERROR): ${t} " "$OUT")"; done
  pass=$((pass+1))
}

# edit <file> <<'PY' … PY
#
# The mutation is a Python string replacement over a backed-up copy, and it
# asserts its own anchor. scripts/tests/controls.py records why: sed address
# ranges, in-place flags and character classes differ between BSD and GNU, so a
# mutation written with them lands on one platform and no-ops on the other while
# reporting the same result on both. A mutation that silently fails to apply
# hands the suite an unchanged file, the suite correctly passes, and the pass is
# recorded as evidence the probe worked.
edit() {
  local f="$1"
  mut "$f"
  python3 - "$f" || { echo "HARNESS mutation script failed for $f"; fail=$((fail+1)); }
}

echo "── Clean tree: the suite must PASS before anything is planted ──"
_suite $ALL_MODULES
if [ $? -ne 0 ]; then
  echo "  FAIL  the suite is already red, so a red result below would prove nothing"
  sed -n '1,40p' "$OUT" | sed 's/^/          /'
  exit 1
fi
echo "  ok    all $(echo $ALL_MODULES | wc -w | tr -d ' ') modules green on the unmodified tree"
echo

echo "── One behaviour reverted at a time; the suite must name it ──"

F=scripts/check-policy-admission.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('for prefix in ("autogen-cronjob-", "autogen-"):',
              'for prefix in ("autogen-", "autogen-cronjob-"):', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "autogen: strip the shorter prefix first" test_policy_admission \
  test_the_cronjob_prefix_is_stripped_whole
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('if not isinstance(doc, dict) or not doc.get("kind"):',
              'if not isinstance(doc, dict):', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "prepare: keep kind-less documents" test_policy_admission \
  test_a_kindless_document_is_dropped
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    if not passes:\n", "    if False:\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "runtime pod: admit on absence of denials alone" test_policy_admission \
  test_a_pod_no_rule_evaluated_is_not_admitted \
  test_a_skip_is_neither_a_pass_nor_a_denial \
  test_a_clean_canary_cannot_carry_a_missing_runtime_pod
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("               if not _is_canary(r) and not _is_runtime_pod(r)",
              "               if not _is_canary(r)", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "judge: count the runtime pod as a foreign addon" test_policy_admission \
  test_the_runtime_pod_is_not_counted_among_flagged_addons
res $F

F=scripts/check-platform-crs.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if want != "boolean" and isinstance(value, bool):',
              "    if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "types: let a bool satisfy integer, as Python does" test_platform_crs \
  test_a_bool_does_not_satisfy_integer
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if "default" in (props.get(name) or {}):', "        if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "required: drop the defaulting exemption" test_platform_crs \
  test_a_missing_required_property_that_declares_a_default_is_admitted
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("        check_list_uniqueness(value, schema, path, kind, source, problems)",
              "        pass", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "list identity: check only the top level" test_platform_crs \
  test_a_set_list_identifies_a_scalar_by_itself \
  test_an_absent_key_participates_in_the_identity \
  test_three_entries_sharing_an_identity_report_each_repeat
res $F

F=scripts/validate-dashboards.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    r"|\\$(\\w+)"  # $name\n'
              '    r"|\\[\\[(\\w+)(?::[^\\]]*)?\\]\\]"  # [[name]] and [[name:csv]]\n', "", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "variables: match only the braced form" test_dashboards \
  test_the_bare_form_every_dashboard_here_uses \
  test_the_bracket_form \
  test_a_builtin_beside_a_real_variable_leaves_the_real_one
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        for child in node.get("panels", []) or []:\n'
              "            alert_panels(child, titles)", "        pass", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "alerts: scan panels flat, skipping collapsed rows" test_dashboards \
  test_an_alert_inside_a_collapsed_row_is_found \
  test_a_top_level_alert_panel_is_found \
  test_an_untitled_alert_panel_is_still_reported
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    for rel in KUSTOMIZE_DS.findall(kustom.read_text(encoding="utf-8")):\n'
              "        ds = kustom.parent / rel",
              '    for ds in sorted((kustom.parent / "datasources").glob("*.yaml")):\n'
              "        rel = ds.name", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "datasources: glob the directory, not the kustomization" test_dashboards \
  test_a_datasource_file_absent_from_resources_is_not_wired
res $F

# The verdicts, as opposed to the extractors they compose. Each of these empties
# a decision rather than changing how a helper behaves, which is the shape a
# coverage figure cannot see and a return-nothing assertion does not catch.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("def check_local_dashboards(root: pathlib.Path) -> list[str]:\n"
              "    wired = wired_datasource_refs(root)",
              "def check_local_dashboards(root: pathlib.Path) -> list[str]:\n"
              "    return []\n"
              "    wired = wired_datasource_refs(root)", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "offline verdict: report nothing, whatever the tree holds" test_dashboards \
  test_a_panel_naming_an_unwired_datasource_is_reported \
  test_an_undeclared_template_variable_is_reported \
  test_a_locally_authored_board_whose_json_cannot_be_read_is_reported \
  test_a_declared_variable_nothing_references_reports_a_broken_parser \
  test_every_detection_is_reported_from_one_pass
res $F

F=scripts/render-addons.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    return (any(t in low for t in _NOT_FOUND)\n"
              "            and not any(t in low for t in _UNREACHABLE))",
              "    return any(t in low for t in _NOT_FOUND)", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "helm failure: call every missing-chart message a finding" test_render_addons \
  test_a_message_naming_both_is_read_as_unreachable
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if self.repo.rsplit("/", 1)[-1] == self.chart:', "        if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "oci: append the chart name to every repoURL" test_render_addons \
  test_a_repo_url_ending_in_the_chart_name_is_used_as_is
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(r'm = re.match(r"\$values/(.+)/values\.yaml$", vf)',
              r'm = re.match(r"\$values/(.+)/values.*\.yaml$", vf)', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "addon path: take it from any values file" test_render_addons \
  test_a_per_environment_file_alone_does_not_supply_the_path
res $F

F=scripts/check-policy-admission.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
line = [ln for ln in s.splitlines() if "Exclusion-list parity" in ln][0]
m = s.replace(line, line + "\n    return True, set(), set()", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "parity verdict: agree, whatever the four policies hold" test_policy_admission \
  test_four_identical_lists_agree \
  test_one_list_missing_a_namespace_is_a_mismatch \
  test_one_list_carrying_an_extra_namespace_is_a_mismatch \
  test_the_namespaces_returned_are_the_shared_baseline \
  test_the_shipped_policies_agree
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('for entry in rule["exclude"]["any"]:',
              'for entry in rule["exclude"]["any"][:1]:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "parity: read only the first exclude.any entry" test_policy_admission \
  test_the_union_of_both_entries_is_the_list
res $F

F=scripts/check-image-pins.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    name = ref.rsplit("/", 1)[-1]\n    if ":" not in name:',
              "    name = ref\n    if \":\" not in name:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "classify: find the tag colon anywhere in the reference" test_image_pins \
  test_a_registry_port_is_not_read_as_a_tag
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    for bare, reason in sorted(allowed.items()):\n"
              "        if bare not in mutable_seen:",
              "    for bare, reason in sorted(allowed.items()):\n        if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "exemptions: stop re-checking them against the render" test_image_pins \
  test_an_exemption_the_fleet_no_longer_renders_mutably_fails \
  test_an_exemption_for_an_image_now_pinned_by_tag_fails
res $F

F=scripts/check-log-volume-budget.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    elif warn is not None and not warn < float(cutoff):",
              "    elif warn is not None and warn > float(cutoff):", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "cutoff: let the alert fire AT it rather than before" test_log_volume_budget \
  test_a_warning_at_the_cutoff_leaves_no_window
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("            if EDGE_COUNTER in joined:", "            if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "alert: accept a rule keyed on the edge counter" test_log_volume_budget \
  test_a_rule_querying_the_edge_counter_fails_twice \
  test_a_rule_querying_both_still_fails_on_the_edge_counter
res $F

echo
echo "── Restored tree must be green again ──"
_suite $ALL_MODULES
if [ $? -ne 0 ]; then
  echo "  FAIL  the suite is red after restoration — a mutation was left in the tree"
  sed -n '1,40p' "$OUT" | sed 's/^/          /'
  fail=$((fail+1))
else
  echo "  ok    all $(echo $ALL_MODULES | wc -w | tr -d ' ') modules green again"
fi

echo
echo "RESULT pass=$pass fail=$fail"

# The floor this harness owes for the same reason the gates owe theirs: with
# every `rejects` line deleted it would report pass=0 fail=0 and exit 0, which is
# a green run over nothing planted.
MIN_PROBES=20
total=$((pass + fail))
if [ "$total" -lt "$MIN_PROBES" ]; then
  echo "FAIL  ran $total probe(s), under the floor of $MIN_PROBES — this harness"
  echo "      planted almost nothing, which is not the same as every test holding."
  exit 2
fi

[ "$fail" -eq 0 ]
