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
# The modules whose assertions this harness reverts behaviour against, plus the
# one holding the vacuity floors those same gates carry. check-platform-crs.py,
# check-policy-admission.py and validate-dashboards.py each assert a floor under
# their corpus AND the verdict over it; a mutant reverting the floor half is held
# by test_corpus_floors and by nothing in the list below, so without it that
# mutant reads as a miss when a test does in fact catch it.
ALL_MODULES="test_policy_admission test_platform_crs test_dashboards \
  test_render_addons test_image_pins test_log_volume_budget test_controls \
  test_corpus_floors test_registry test_chart_deprecation test_falco_rule_floor \
  test_image_vulnerabilities test_renovate_coverage test_lb_scheme_inputs"

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
echo "  ok    all $(echo $ALL_MODULES | wc -w | tr -d ' ') module(s) this harness mutates against are green on the unmodified tree"
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

# The version the pin resolves is upstream of every schema assertion above: read
# the wrong source and the CRDs come from a chart the fleet does not install,
# read no source and there is nothing to check against. Both are refusals rather
# than empty answers, and an emptied corpus produces the first.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    if not OPERATOR_APPSET.is_file():", "    if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pin: an absent ApplicationSet resolves nothing and walks on" test_platform_crs \
  test_an_absent_appset_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('''              f"An unreadable pin is not the same as a catalog with no CRs in it.")
        sys.exit(gatelib.CANNOT_RUN)''',
              '''              f"An unreadable pin is not the same as a catalog with no CRs in it.")
        sys.exit(1)''', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pin: an absent ApplicationSet is the tree's fault, not a refusal" test_platform_crs \
  test_an_absent_appset_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(r'        r"repoURL:\s*\S*ghcr\.io/nanohype/eks-agent-platform/charts.*?targetRevision:\s*(\S+)",',
              r'        r"targetRevision:\s*(\S+)",', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pin: read any source's targetRevision, not the operator's" test_platform_crs \
  test_the_operator_source_is_the_one_read \
  test_an_appset_with_no_operator_source_stops
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('''    return m.group(1).strip().strip("\\"'")''', "    return m.group(1).strip()", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pin: keep the quotes a YAML scalar carries" test_platform_crs \
  test_a_quoted_revision_is_unquoted
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
m = s.replace("        return self.oci_ref() if self.is_oci else self.repo",
              "        return self.repo", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "source: fetch an OCI chart from its bare repoURL" test_render_addons \
  test_an_oci_chart_is_fetched_from_its_reference
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    cmd = ["helm", "template", unit.chart, str(archive)]',
              '    cmd = ["helm", "template", unit.chart, unit.source, "--version", unit.version]', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "render: hand helm the registry reference, not the archive" test_render_addons \
  test_the_archive_is_fetched_from_the_unit_source_and_rendered
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("            for u in units if u.chart not in SKIP_CHARTS}",
              "            for u in units}", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "fetch: fetch the charts SKIP_CHARTS says cannot be fetched" test_render_addons \
  test_a_skipped_chart_is_neither_fetched_nor_kept
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

F=scripts/registry.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('            if err.code != 429:\n                raise\n',
              '            if err.code >= 500:\n                raise\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "429: retry every client error too" test_registry \
  test_other_statuses_are_reported_on_the_first_attempt
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('if attempt == RETRY_ATTEMPTS:', 'if attempt == RETRY_ATTEMPTS + 1:')
assert m.count('if attempt == RETRY_ATTEMPTS + 1:') == 2, "mutation did not land"
p.write_text(m)
PY
rejects "bound: allow one request past RETRY_ATTEMPTS" test_registry \
  test_a_registry_that_never_relents_is_reported_after_the_bound \
  test_a_rate_limit_after_the_challenge_is_reported_at_the_bound
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('            if asked is not None and asked > RETRY_MAX_WAIT_SECONDS:',
              '            if False:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "cap: sleep however long Retry-After asks" test_registry \
  test_a_wait_beyond_the_cap_is_reported_not_slept
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('                                clock())\n            err.close()\n',
              '                                clock())\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "close: sleep holding the refused response" test_registry \
  test_the_refused_response_is_closed_before_the_wait
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        when = when.replace(tzinfo=datetime.UTC)',
              '        pass', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "Retry-After: read a zoneless date in the local zone" test_registry \
  test_a_naive_http_date_is_read_as_utc
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)',
              '    query = []', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "token: drop the query the realm carries" test_registry \
  test_a_realm_that_already_carries_a_query_keeps_it
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        return self._get(url, headers, f"Bearer {self.token}")',
              '        return self._get(url, headers, f"Bearer {self.token}", challenge=self._authorize)', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "token: answer a 401 on a read that already carries one" test_registry \
  test_a_401_on_the_blob_read_is_reported_not_answered_again
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if hashlib.sha256(data).hexdigest() != expected:',
              '        if False:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "blob: keep bytes that do not match their digest" test_registry \
  test_a_blob_that_does_not_match_its_digest_is_refused
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('answered=err.code == 404)',
              'answered=True)', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "unavailable: call every HTTP status an answer" test_registry \
  test_a_server_fault_or_network_error_was_not_answered
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("        if path.resolve() not in kept:", "        if False:", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "prune: carry every archive ever pinned" test_registry \
  test_archives_no_pin_names_are_dropped_and_pinned_ones_kept
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if algorithm != "sha256" or not expected:', '        if False:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "blob: read by a digest there is nothing to check against" test_registry \
  test_a_digest_that_is_not_sha256_is_refused_before_anything_is_read
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('                if attempt == RETRY_ATTEMPTS:\n'
              '                    raise RegistryError(\n'
              '                        f"{host} asked for a token',
              '                if False:\n'
              '                    raise RegistryError(\n'
              '                        f"{host} asked for a token', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "token: answer a challenge with no attempt left to repeat it" test_registry \
  test_a_challenge_on_the_last_attempt_is_reported_not_answered
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('READ_FAILURES = (OSError, http.client.HTTPException, RegistryError, ValueError)',
              'READ_FAILURES = (OSError, http.client.HTTPException, RegistryError)', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "read failures: let a body that is not JSON escape" test_registry \
  test_a_body_that_is_not_the_json_the_api_promises_was_not_answered \
  test_a_realm_that_answers_something_other_than_json_raises_a_read_failure
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    bare = version.removeprefix("v")', '    bare = version', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "index: match a v-prefixed pin only to a v-prefixed entry" test_registry \
  test_a_v_prefixed_pin_matches_a_bare_index_entry
res $F

# The digest is the only thing that makes a fetched archive the pinned one. An
# entry publishing none, and a cached archive nobody re-checked, each render
# bytes nothing verified while the run reads the same as one that did.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if not digest:\n        raise ChartUnavailable(f"{index} publishes no digest',
              '    if False:\n        raise ChartUnavailable(f"{index} publishes no digest', 1)
m = m.replace('    if hashlib.sha256(data).hexdigest() != digest:',
              '    if digest and hashlib.sha256(data).hexdigest() != digest:', 1)
assert m.count("    if False:\n") == 1 and "if digest and hashlib" in m, "mutation did not land"
p.write_text(m)
PY
rejects "digest: keep an archive its index publishes no digest for" test_registry \
  test_an_entry_that_publishes_no_digest_is_refused_unfetched
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if _intact(path):\n        return path\n',
              '    if path.is_file():\n        return path\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "cache: hand out a cached archive on existence alone" test_registry \
  test_an_archive_whose_bytes_changed_is_fetched_again \
  test_an_archive_kept_with_no_record_is_fetched_again \
  test_a_record_that_is_not_the_archives_digest_is_not_trusted
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    return hashlib.sha256(data).hexdigest() == recorded\n',
              '    return bool(recorded)\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "cache: trust a record without hashing the archive" test_registry \
  test_an_archive_whose_bytes_changed_is_fetched_again \
  test_a_record_that_is_not_the_archives_digest_is_not_trusted
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    for target, content in ((archive, data), (digest_path(archive), digest)):',
              '    for target, content in ((archive, data),):', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "keep: record no digest beside the archive" test_registry \
  test_the_archive_is_fetched_relative_to_the_repository_and_kept \
  test_an_oci_archive_is_kept_under_its_reference
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('root.glob("*/*")', 'root.glob("*/[!.]*")', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "prune: leave the partial an interrupted fetch wrote" test_registry \
  test_a_partial_left_by_an_interrupted_fetch_is_dropped
res $F


F=scripts/check-chart-deprecation.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    except registry.ChartUnavailable as err:',
              '    except KeyError as err:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "fetch: let an unreadable chart raise" test_chart_deprecation \
  test_an_http_status_names_the_status_and_the_url \
  test_an_exhausted_rate_limit_is_reported_in_its_own_words \
  test_a_network_error_is_reported
res $F


F=scripts/check-falco-rule-floor.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if exc.code == 404:',
              '        if exc.code == 0:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: read a 404 as the network's fault" test_falco_rule_floor \
  test_a_ref_the_registry_does_not_have_is_a_finding
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    except registry.READ_FAILURES as exc:',
              '    except (OSError, registry.RegistryError, ValueError) as exc:')
assert m.count('except (OSError, registry.RegistryError, ValueError) as exc:') == 2, \
    "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: catch a narrower tuple than READ_FAILURES" test_falco_rule_floor \
  test_a_manifest_cut_off_mid_body_cannot_run \
  test_a_layer_cut_off_mid_body_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        cannot_run(f"Cannot run: {REGISTRY} answered {exc.code} for {repo}:{tag}.")',
              '        fail(f"{REGISTRY} answered {exc.code} for {repo}:{tag}.")\n'
              '        return None', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: read every manifest status as a finding" test_falco_rule_floor \
  test_a_manifest_status_other_than_404_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if (manifest.get("config") or {}).get("mediaType") != RULESFILE_CONFIG:',
              '    if False:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: unpack a plugin as if it carried rules" test_falco_rule_floor \
  test_an_artifact_that_is_not_a_rulesfile_installs_no_rules
res $F


# A chart repository that could not be read says nothing about the controller
# this catalog pins. Exiting 1 for it hands a network failure to whoever reads
# the run as a finding about the pin.
F=scripts/check-lb-scheme-inputs.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if exc.answered:\n            die(', '        if True:\n            die(', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "metadata: read every unreadable chart as a finding" test_lb_scheme_inputs \
  test_metadata_that_could_not_be_read_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(
    '    archive = registry.chart_archive_or_exit(pin["chartRepo"], pin["chart"], '
    'pin["chartVersion"])\n',
    '    try:\n'
    '        archive = registry.chart_archive(pin["chartRepo"], pin["chart"], '
    'pin["chartVersion"])\n'
    '    except registry.ChartUnavailable as exc:\n'
    '        die(f"would not resolve — {exc}")\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "archive: read every unreadable chart as a finding" test_lb_scheme_inputs \
  test_an_archive_that_could_not_be_read_cannot_run
res $F


F=scripts/check-image-vulnerabilities.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        today = datetime.datetime.now(datetime.UTC).date()',
              '        today = datetime.date.today()', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "review_by: count days on the runner's local calendar" test_image_vulnerabilities \
  test_an_entry_dated_the_local_day_is_due_on_the_utc_day
res $F


F=scripts/check-renovate-coverage.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        AnnotatedPins(ANNOTATED_REF),',
              '        AnnotatedPins(ANNOTATED),', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "schema refs: read their annotation as a CI tool's" test_renovate_coverage \
  test_an_annotated_ref_is_claimed_by_the_git_refs_manager \
  test_the_shipped_scan_pins_both_catalogs
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        check_gomod_pins,\n',
              '        check_git_pins,\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "Go modules: check them as git-pinned directories" test_renovate_coverage \
  test_a_go_module_needs_the_gomod_manager
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

# The harness layer. controls.py excuses four executables from a positive
# control on the grounds that each asserts its own outcome when it runs, and
# these revert the reader that decides whether anything runs them.
F=scripts/tests/controls.py
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    wanted = {f"scripts/{rel}", f"./scripts/{rel}"}\n'
              '    commands, _unreadable = caller_commands(root)\n'
              '    return any(word in wanted for command in commands '
              'for word in command_words(command))\n',
              '    return bool(rel)\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "invocation: answer yes for any name at all" test_controls \
  test_a_yaml_comment_in_the_taskfile_does_not_count \
  test_a_task_description_does_not_count \
  test_a_step_name_does_not_count \
  test_a_harness_this_repo_does_not_run_is_reported
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    wanted = {f"scripts/{rel}", f"./scripts/{rel}"}\n'
              '    commands, _unreadable = caller_commands(root)\n'
              '    return any(word in wanted for command in commands '
              'for word in command_words(command))\n',
              '    needle = f"scripts/{rel}"\n'
              '    return any(needle in c.read_text() for c in caller_files(root))\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "invocation: search the caller's text, not its commands" test_controls \
  test_a_yaml_comment_in_the_taskfile_does_not_count \
  test_a_task_description_does_not_count \
  test_a_step_name_does_not_count \
  test_a_shell_comment_inside_a_run_block_does_not_count \
  test_a_quoted_mention_inside_a_command_does_not_count
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('                for step in job.get("steps") or []:',
              '                for step in []:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "callers: read the Taskfile's commands and no workflow's" test_controls \
  test_a_workflow_run_step_counts \
  test_a_command_below_a_comment_naming_it_still_counts
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    text = blank_comments(command)\n', '    text = command\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "words: read a run block's shell comments as command text" test_controls \
  test_a_shell_comment_inside_a_run_block_does_not_count
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        return shlex.split(text)\n', '        return text.split()\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "words: split on whitespace, ignoring quoting" test_controls \
  test_a_quoted_mention_inside_a_command_does_not_count
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        except yaml.YAMLError as exc:\n',
              '        except yaml.YAMLError:\n            continue\n        if False:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "callers: read an unparseable caller as one running nothing" test_controls \
  test_the_unparseable_caller_is_named
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    invoked = invoked_anywhere if invoked is None else invoked\n',
              '    invoked = (lambda _name: True) if invoked is None else invoked\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rule: reach a constant instead of the reader" test_controls \
  test_a_harness_this_repo_does_not_run_is_reported
res $F

echo
echo "── Restored tree must be green again ──"
_suite $ALL_MODULES
if [ $? -ne 0 ]; then
  echo "  FAIL  the suite is red after restoration — a mutation was left in the tree"
  sed -n '1,40p' "$OUT" | sed 's/^/          /'
  fail=$((fail+1))
else
  echo "  ok    all $(echo $ALL_MODULES | wc -w | tr -d ' ') module(s) green again"
fi

echo
echo "RESULT pass=$pass fail=$fail"

# The floor this harness owes for the same reason the gates owe theirs: with
# every `rejects` line deleted it would report pass=0 fail=0 and exit 0, which is
# a green run over nothing planted.
MIN_PROBES=48
total=$((pass + fail))
if [ "$total" -lt "$MIN_PROBES" ]; then
  echo "FAIL  ran $total probe(s), under the floor of $MIN_PROBES — this harness"
  echo "      planted almost nothing, which is not the same as every test holding."
  exit 2
fi

[ "$fail" -eq 0 ]
