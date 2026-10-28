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
cd "$ROOT" || exit 2
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
ALL_MODULES=(test_policy_admission test_platform_crs test_dashboards
  test_render_addons test_image_pins test_log_volume_budget test_controls
  test_corpus_floors test_registry test_chart_deprecation test_falco_rule_floor
  test_image_vulnerabilities test_renovate_coverage test_lb_scheme_inputs
  test_kubeconform_scan test_image_extraction test_image_verification
  test_policy_validity test_kyverno_test test_digest_rewrite)

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
if ! _suite "${ALL_MODULES[@]}"; then
  echo "  FAIL  the suite is already red, so a red result below would prove nothing"
  sed -n '1,40p' "$OUT" | sed 's/^/          /'
  exit 1
fi
echo "  ok    all ${#ALL_MODULES[@]} module(s) this harness mutates against are green on the unmodified tree"
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

# stale_skips is the only thing that re-reads a skip's stated reason. Read
# wrong one way, every skip is reported expired; the other, none ever is.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        except registry.ChartUnavailable:\n            continue\n'
              '        stale.append(',
              '        except registry.ChartUnavailable:\n            pass\n'
              '        stale.append(', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "stale skips: call an unreachable chart fetchable" test_render_addons \
  test_a_skipped_chart_that_still_cannot_be_fetched_stays
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        stale.append((u.chart, SKIP_CHARTS[u.chart]))', '        pass', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "stale skips: never report one" test_render_addons \
  test_a_skipped_chart_that_fetches_is_stale
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    dropped = registry.prune_archives(kept)', '    dropped = 0', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "fetch: carry the files no pin names" test_render_addons \
  test_the_pinned_archives_and_their_records_are_what_the_cache_holds
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
m = s.replace('            if err.code not in RETRYABLE:\n',
              '            if err.code >= 500 and err.code not in RETRYABLE:\n', 1)
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

# CALL_BOUND_SECONDS is what every CI job that reads through this client is held
# above. A bound that leaves out a wait the client can take lets a job be
# cancelled mid-wait, with nothing reported about the registry that refused it.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    + (RETRY_ATTEMPTS - 1) * (1 + RETRY_JITTER)\n',
              '    + (RETRY_ATTEMPTS - 1)\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: leave the jitter out of a call's worst case" test_registry \
  test_a_call_throttled_at_every_retry_ends_inside_the_bound
res $F

# One deadline covers a call and the token request its challenge leads to. A
# token request given a deadline of its own, a wait taken past the deadline, or
# a request given longer than the call has left each let one call outlast the
# job reading through it, which is then cancelled with nothing reported.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        get = functools.partial(self._get, deadline=deadline)\n',
              '        get = self._get\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "deadline: give the token request one of its own" test_registry \
  test_a_challenged_call_throttled_everywhere_ends_inside_the_bound
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('            if timer() + wait >= deadline:\n', '            if False:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "deadline: take a wait that ends past it" test_registry \
  test_a_wait_that_would_end_past_the_deadline_is_reported_not_slept \
  test_a_challenged_call_throttled_everywhere_ends_inside_the_bound
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('timeout=min(HTTP_TIMEOUT, left)', 'timeout=HTTP_TIMEOUT', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "deadline: give a request longer than the call has left" test_registry \
  test_no_request_is_given_longer_than_the_call_has_left
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if left <= 0:\n', '        if False:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "deadline: make a request after it has passed" test_registry \
  test_a_call_whose_deadline_has_passed_makes_no_request
res $F

# urlopen's timeout bounds one wait on the socket, not a body. Read in one call,
# or with one check covering several socket reads, a body that keeps arriving
# inside that timeout runs the call past its deadline and every job timeout
# above it. A bound that leaves out the read under way when the deadline passes
# is one a call cut off mid-body exceeds.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('                resp.fp = io.BufferedReader(_Paced(resp.fp, deadline, timer, host, url))\n',
              '', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "body: read it in one call, whatever the deadline" test_registry \
  test_a_body_that_trickles_past_the_deadline_is_cut_off_and_reported
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        data = self._beneath.read1(len(view))\n',
              '        data = self._beneath.read(len(view))\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "body: let one check cover many socket reads" test_registry \
  test_a_body_that_trickles_past_the_deadline_is_cut_off_and_reported
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('CALL_BOUND_SECONDS = CALL_DEADLINE_SECONDS + HTTP_TIMEOUT\n',
              'CALL_BOUND_SECONDS = CALL_DEADLINE_SECONDS\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: leave out the socket read under way at the deadline" test_registry \
  test_a_body_that_trickles_past_the_deadline_is_cut_off_and_reported
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('RETRYABLE = frozenset({429, 502, 503, 504})', 'RETRYABLE = frozenset({429})', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "retryable: report a gateway or unavailable server at once" test_registry \
  test_a_gateway_or_an_unavailable_server_is_retried \
  test_a_503_waits_as_long_as_its_retry_after_asks
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('asked > RETRY_MAX_WAIT_SECONDS:', 'asked >= RETRY_MAX_WAIT_SECONDS:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "cap: report a Retry-After of exactly the cap" test_registry \
  test_a_retry_after_at_the_cap_is_slept
res $F

# The token realm issues tokens and holds no charts. Its status passed through
# as an HTTPError reaches _unavailable as if the registry had answered for the
# pin, and a realm's 404 then reads as a pin that does not exist.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    except urllib.error.HTTPError as err:\n'
              '        err.close()\n'
              '        raise RegistryError(f"{realm} answered HTTP',
              '    except KeyError as err:\n'
              '        raise RegistryError(f"{realm} answered HTTP', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "realm: let its status read as the registry's answer" test_registry \
  test_a_404_from_the_token_realm_was_not_answered
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    for target, content in ((archive, data), (digest_path(archive), digest)):',
              '    for target, content in ((digest_path(archive), digest), (archive, data)):', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "keep: record the digest before the archive is in place" test_registry \
  test_an_archive_cut_off_before_its_rename_leaves_no_record
res $F

# A job that reads through the client and allows no longer than one call is
# cancelled mid-call. The scheduled reads of upstream are held to it as much as
# the jobs that restore the chart cache.
F=.github/workflows/chart-provenance.yml
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
assert s.count('    timeout-minutes: 20\n') == 2, "mutation did not land"
p.write_text(s.replace('    timeout-minutes: 20\n', ''))
PY
rejects "jobs: leave a scheduled upstream read on the runner default" test_registry \
  test_each_allows_longer_than_one_call
res $F



F=scripts/check-chart-deprecation.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        except registry.ChartUnavailable as exc:\n            if exc.answered:\n',
              '        except KeyError as exc:\n            if exc.answered:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "live: let an unreadable chart raise" test_chart_deprecation \
  test_a_404_names_the_status_and_the_url_as_a_finding \
  test_an_exhausted_rate_limit_cannot_run_in_its_own_words \
  test_a_network_error_cannot_run
res $F

# A chart upstream could not be read for says nothing about the pin. Filing it
# as a finding hands a network failure to whoever reads the scheduled run.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('            if exc.answered:\n                problems.append(',
              '            if True:\n                problems.append(', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "live: read every unreadable chart as a finding" test_chart_deprecation \
  test_an_unreadable_chart_cannot_run \
  test_a_finding_outweighs_a_chart_that_could_not_be_read \
  test_an_exhausted_rate_limit_cannot_run_in_its_own_words
res $F

# The same holds for --sync: a pin it could not read stops it with the status
# for a read that was not made, and an exit of 1 there reads as a finding.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('            gatelib.refuse_chart(chart, pin["version"], pin["repo"], exc)\n',
              '            die(f"{chart}: {exc}")\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "sync: read every unreadable chart as a finding" test_chart_deprecation \
  test_an_unreadable_chart_stops_the_sync_and_cannot_run
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
m = s.replace('            return None\n'
              '        _unreachable(f"{REGISTRY}/{repo}:{tag}", exc)\n',
              '            return None\n'
              '        fail(f"{REGISTRY} answered {exc.code} for {repo}:{tag}.")\n'
              '        return None\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: read every manifest status as a finding" test_falco_rule_floor \
  test_a_manifest_status_other_than_404_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if (config or {}).get("mediaType") != RULESFILE_CONFIG:',
              '    if False:', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: unpack a plugin as if it carried rules" test_falco_rule_floor \
  test_an_artifact_that_is_not_a_rulesfile_installs_no_rules
res $F

# The manifest and the layer are upstream's. Indexed into unchecked, a shape the
# OCI image spec does not describe escapes as a traceback with exit status 1,
# the status this gate gives a finding about a ref in this repo.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if not isinstance(digest, str) or not digest:\n', '    if False:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: read a rule set with no layer digest" test_falco_rule_floor \
  test_a_manifest_of_the_wrong_shape_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    if config is not None and not isinstance(config, dict):\n', '    if False:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: read a config that is not an object" test_falco_rule_floor \
  test_a_manifest_of_the_wrong_shape_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    except (tarfile.TarError, UnicodeDecodeError) as exc:\n',
              '    except UnicodeDecodeError as exc:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "rulesfile: unpack a layer that is not an archive" test_falco_rule_floor \
  test_a_layer_that_is_not_a_rule_set_archive_cannot_run
res $F


# A chart repository that could not be read says nothing about the controller
# this catalog pins. Exiting 1 for it hands a network failure to whoever reads
# the run as a finding about the pin.
F=scripts/check-lb-scheme-inputs.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(
    '        gatelib.refuse_chart(pin["chart"], pin["chartVersion"], pin["chartRepo"], exc)\n',
    '        die(f"{pin[\'chart\']} {pin[\'chartVersion\']} does not resolve — {exc}")\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "metadata: read every unreadable chart as a finding" test_lb_scheme_inputs \
  test_metadata_that_could_not_be_read_cannot_run
res $F

# urlopen's timeout bounds each wait on the socket, not a whole response. A
# source file read with urlopen alone keeps reading a server that trickles its
# body inside every timeout, and the scheduled job is cancelled saying nothing.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        return get(url, {}, None).decode("utf-8")\n',
              '        with urllib.request.urlopen(url, timeout=120) as resp:\n'
              '            return resp.read().decode("utf-8")\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "source: read a controller file with urlopen alone" test_lb_scheme_inputs \
  test_a_body_that_trickles_past_the_deadline_cannot_run \
  test_a_rate_limit_is_waited_out_as_the_host_asks
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if isinstance(exc, urllib.error.HTTPError) and exc.code == 404:\n',
              '        if isinstance(exc, urllib.error.HTTPError) and exc.code == 0:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "source: read a 404 as the network's fault" test_lb_scheme_inputs \
  test_a_file_the_ref_does_not_hold_is_a_finding
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        sys.exit(gatelib.cannot_read(url, [f"{type(exc).__name__}: {exc}"]))\n',
              '        die(f"could not read {path} at {ref} — {exc}")\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "source: read every unreadable file as a finding" test_lb_scheme_inputs \
  test_a_source_that_could_not_be_read_cannot_run \
  test_a_body_that_trickles_past_the_deadline_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(
    '    archive = gatelib.chart_archive_or_exit(pin["chartRepo"], pin["chart"], '
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


# What a failed scan leaves in the log is the script's doing: it captures
# kubeconform's output to read the summary, and an EXIT trap names the two
# catalog commits. Under `set -e` an assignment from a failing substitution
# exits before the capture is printed.
F=scripts/kubeconform-scan.sh

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('out="$(kubeconform "${args[@]}" "$@" 2>&1)" || rc=$?',
              'out="$(kubeconform "${args[@]}" "$@" 2>&1)"', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "scan: let set -e exit before the output is printed" test_kubeconform_scan \
  test_a_rejected_manifest_reaches_the_log_with_the_refs \
  test_a_status_other_than_1_is_passed_through
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
start = s.index("trap '[ \"$?\" -eq 0 ]")
end = s.index("' EXIT\n", start) + len("' EXIT\n")
p.write_text(s[:start] + s[end:])
PY
rejects "scan: fail without naming the catalog commits" test_kubeconform_scan \
  test_a_rejected_manifest_reaches_the_log_with_the_refs \
  test_a_scan_that_validated_nothing_names_the_refs_too
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('-schema-location "$K8S_SCHEMAS"', '-schema-location default', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "scan: validate against the unpinned default catalog" test_kubeconform_scan \
  test_kubeconform_reads_only_the_pinned_catalogs
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
m = s.replace('(?P<ver>[0-9a-f]{40})\\"?\\s*$", re.M),\n        AnnotatedPins(ANNOTATED_REF),',
              '(?P<ver>[0-9a-f]{7,40})\\"?\\s*$", re.M),\n        AnnotatedPins(ANNOTATED_REF),', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "schema refs: read a short commit as a ref" test_renovate_coverage \
  test_only_a_full_commit_is_read_as_a_ref
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

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('            if exc.answered:\n'
              '                gatelib.refuse_chart(u.chart, u.version, u.source, exc)\n', '', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "inventory: file a pin the registry ruled out as unrendered" test_image_extraction \
  test_a_pin_the_registry_ruled_out_is_a_finding
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

# The signing-identity contract. A validation is compared whole, so one that
# names the call and every field and still passes every image is refused; and
# the contract is held on each rendered overlay, because that is what a cluster
# installs.
F=scripts/check-image-verification.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("        if any(canonical(x) in present for x in expected):\n",
              "        if any(call in e for e in exprs):\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "validations: accept any expression making the call" test_image_verification \
  test_a_validation_neutralised_with_or_true \
  test_a_count_that_passes_an_unverified_image \
  test_a_signature_validation_over_containers_only
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    return "".join(expr.split())\n', "    return expr\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "validations: compare with the YAML's whitespace kept" test_image_verification \
  test_the_same_expression_wrapped_differently_passes
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("        for overlay in overlays:\n", "        for overlay in overlays[:0]:\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "overlays: hold the base alone to the contract" test_image_verification \
  test_an_overlay_widening_the_subject \
  test_an_overlay_swapping_the_issuer \
  test_an_overlay_growing_the_namespace_exclusion
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("            check_actions(overlay.name, doc)\n", "", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "actions: leave a tier's validationActions unread" test_image_verification \
  test_an_enforcing_tier_that_only_reports
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    if absent:\n", "    if absent and False:\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "overlays: render whichever environments exist" test_image_verification \
  test_an_environment_with_no_overlay
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("    if globs != {SCOPE}:\n", "    if not globs:\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "scope: accept any glob under ghcr.io/nanohype/" test_image_verification \
  test_a_narrower_nanohype_glob
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('        if set(ctlog) - {"url"}:\n', '        if set(ctlog) - {"url"} - {"rekorPubKey", "ctLogPubKey", "tsaCertChain"}:\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "ctlog: trust a log key or timestamp chain of its own" test_image_verification \
  test_a_log_key_or_timestamp_chain_of_its_own
res $F

# The digest pin on every rendered ImageValidatingPolicy. The CRD defaults both
# fields to true, so an absent field is the pin and not a finding.
F=scripts/check-policy-validity.py

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("            if cfg.get(field, True) is not True:\n",
              "            if cfg.get(field) is not True:\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "digest pin: read an absent field as false" test_policy_validity \
  test_an_absent_field_reads_as_the_crd_default
res $F

# A transport failure on the image-verification path decides no row: reading
# the image reports it as the row's error, and anything after that reports the
# policy's own message with only the verifier's log naming the cause.
F=scripts/kyverno-test.sh

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  [ -z "$transport" ] && break\n', "  break\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "transport: decide a run that met one on its rows" test_kyverno_test \
  test_one_that_clears_is_run_again \
  test_one_behind_the_policy_message_is_not_a_regression \
  test_an_expected_failure_it_produced_is_not_a_pass
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('kyverno test "$TESTS" --detailed-results -v 1 2>&1',
              'kyverno test "$TESTS" --detailed-results 2>&1', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "kyverno: run without the verifier's log" test_kyverno_test \
  test_the_suite_is_asked_for_the_reasons_it_is_classified_by
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("\nATTEMPTS=3\n", "\nATTEMPTS=1\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "attempts: report the first transport failure as final" test_kyverno_test \
  test_one_that_clears_is_run_again
res $F

# Each run is bounded, and one still going after the bound is killed: a read
# that stops answering holds the CLI, and the job's timeout would otherwise end
# the run with no diagnostic at all. A run the bound ended or killed is a
# transport failure.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('out="$("$TIMEOUT_CMD" -k "$KILL_TIMEOUT" "$RUN_TIMEOUT" kyverno test ', 'out="$(kyverno test ', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: run the suite unbounded" test_kyverno_test \
  test_each_run_is_bounded_and_killed_if_it_outlasts_the_bound \
  test_gtimeout_bounds_the_run_where_timeout_is_absent
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(' -k "$KILL_TIMEOUT" "$RUN_TIMEOUT" kyverno test ', ' "$RUN_TIMEOUT" kyverno test ', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: never kill a run that ignores the bound" test_kyverno_test \
  test_each_run_is_bounded_and_killed_if_it_outlasts_the_bound \
  test_gtimeout_bounds_the_run_where_timeout_is_absent
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    124) transport=', '    124000) transport=', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: decide a run the bound ended on its rows" test_kyverno_test \
  test_one_cut_off_is_run_again \
  test_one_cut_off_every_time_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    137) transport=', '    137000) transport=', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: decide a run the kill ended on its rows" test_kyverno_test \
  test_one_killed_is_run_again \
  test_one_killed_every_time_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('if [ -z "$TIMEOUT_CMD" ]; then\n', 'if false; then\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: run with neither timeout nor gtimeout" test_kyverno_test \
  test_no_bound_cannot_run_and_tests_nothing
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('\nRUN_TIMEOUT=240\n', '\nRUN_TIMEOUT=600\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: let every attempt outlast the job" test_kyverno_test \
  test_every_attempt_fits_inside_the_jobs_timeout
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('\nKILL_TIMEOUT=10\n', '\nKILL_TIMEOUT=200\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: let the kill grace outlast the job" test_kyverno_test \
  test_every_attempt_fits_inside_the_jobs_timeout
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('. "$ROOT/scripts/transport-failure.sh"\n', '. "$ROOT/scripts/transport-failure.sh"\ntransport_failures() { uncoloured | grep -oiE \'.{0,60}(no such host|i/o timeout).*\'; }\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pattern: classify with phrases of its own after the shared ones" test_digest_rewrite \
  test_no_gate_words_a_transport_failure_of_its_own
res $F

# The verdict on a foreign identity, one function for the pod and the
# ephemeral container alike.
F=scripts/check-digest-rewrite.sh

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  if [ "$outcome" = admitted ]; then\n    case ",$actions," in\n', '  if [ "$outcome" = admitted ]; then\n    case ",Deny," in\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "foreign: fail an admission under any action" test_digest_rewrite \
  test_admitted_under_audit_is_reported_not_blocked
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  require_known_cause "$what"\n  if ! grep -qF "$IDENTITY_MESSAGE"', '  if ! grep -qF "$IDENTITY_MESSAGE"', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "foreign: read a transport refusal as a regression" test_digest_rewrite \
  test_refused_for_a_transport_failure_cannot_run
res $F

# A transport failure inside verification refuses with the policy's identity
# message, which under Deny is what a correct denial says. Only the verifier's
# log names the cause, and only a log carrying a verifier line is the
# verifier's. Every refusal, foreign or release-signed, is decided on that one
# rule, whichever step made the request.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    read_verifier_log\n    cause="$(transport_failures <"$WORK/log")"\n', '    read_verifier_log\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: read the refusal text and not the verifier's log" test_digest_rewrite \
  test_a_trusted_root_that_could_not_be_fetched_is_not_a_denial \
  test_a_rekor_5xx_is_not_a_denial
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  if grep -qF "$IDENTITY_MESSAGE" "$WORK/err" && [ ! -s "$WORK/log" ]; then\n', '  if false; then\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: decide an identity refusal with no verifier line behind it" test_digest_rewrite \
  test_a_log_without_the_verifiers_line_decides_no_denial \
  test_a_log_without_the_verifiers_line_decides_no_audit_verdict \
  test_a_signed_pod_refused_with_no_verifier_line_cannot_decide \
  test_a_signed_ephemeral_container_refused_with_no_verifier_line_cannot_decide \
  test_a_deployment_refused_with_no_verifier_line_cannot_decide \
  test_a_deployments_pod_refused_with_no_verifier_line_cannot_decide
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  require_known_cause "$1"\n  fail=1\n', '  fail=1\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: fail a release-signed refusal whose cause is unknown" test_digest_rewrite \
  test_a_signed_pod_refused_with_no_verifier_line_cannot_decide \
  test_a_signed_ephemeral_container_refused_with_no_verifier_line_cannot_decide \
  test_a_deployment_refused_with_no_verifier_line_cannot_decide \
  test_a_deployments_pod_refused_with_no_verifier_line_cannot_decide
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    refused_release_signed "the signed pod" ', '    fail=1; show_err; : ', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: fail the signed pod past the rule" test_digest_rewrite \
  test_a_signed_pod_refused_with_no_verifier_line_cannot_decide
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    refused_release_signed "the signed ephemeral container" \\\n', '    fail=1; show_err; : \\\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: fail the signed ephemeral container past the rule" test_digest_rewrite \
  test_a_signed_ephemeral_container_refused_with_no_verifier_line_cannot_decide
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    refused_release_signed "the Deployment" ', '    fail=1; show_err; : ', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: fail the Deployment past the rule" test_digest_rewrite \
  test_a_deployment_refused_with_no_verifier_line_cannot_decide
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    refused_release_signed "the Deployment\'s pod" \\\n', '    fail=1; show_err; : \\\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "refusal: fail the Deployment's pod past the rule" test_digest_rewrite \
  test_a_deployments_pod_refused_with_no_verifier_line_cannot_decide
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(' -l "$VERIFIER_PODS" --tail=-1 \\\n', ' -l "$VERIFIER_PODS" \\\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "log: read ten lines a replica" test_digest_rewrite \
  test_the_log_is_read_whole_from_every_admission_controller_replica
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('uncoloured <"$WORK/log.raw" | grep -F "$VERIFIER_FAILED" >"$WORK/log"\n', 'uncoloured <"$WORK/log.raw" >"$WORK/log"\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "log: read the controller's own errors as the verifier's" test_digest_rewrite \
  test_a_connection_the_webhook_server_dropped_is_not_the_verifiers
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace(' >"$WORK/log.raw" 2>"$WORK/log.err"; then\n', ' >"$WORK/log.raw" 2>"$WORK/log.err" || true; then\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "log: decide over a log that could not be read" test_digest_rewrite \
  test_a_log_that_cannot_be_read_decides_no_refusal \
  test_a_log_read_that_times_out_decides_no_refusal
res $F

# Each request is marked before it is sent, and the log is read from before
# the mark, so the window holds the line the verifier logged as it refused.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  mark_sent\n  if ! admitted="$(kube create', '  if ! admitted="$(kube create', 1)
m = m.replace('    refused_release_signed "the signed pod" ', '    mark_sent\n    refused_release_signed "the signed pod" ', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "window: mark the signed pod after its create" test_digest_rewrite \
  test_the_signed_pods_window_opens_before_its_create
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  mark_sent\n  if ephemeral="$(kube patch', '  if ephemeral="$(kube patch', 1)
m = m.replace('    refused_release_signed "the signed ephemeral container"', '    mark_sent\n    refused_release_signed "the signed ephemeral container"', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "window: mark the signed ephemeral container after its patch" test_digest_rewrite \
  test_the_signed_ephemeral_containers_window_opens_before_its_patch
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  local outcome=refused\n  mark_sent\n', '  local outcome=refused\n', 1)
m = m.replace('  decide_foreign "the branch-signed ephemeral container"', '  mark_sent\n  decide_foreign "the branch-signed ephemeral container"', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "window: mark the branch-signed ephemeral container after its patch" test_digest_rewrite \
  test_the_branch_signed_ephemeral_containers_window_opens_before_its_patch
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  mark_sent\n  if ! stored="$(kube create', '  if ! stored="$(kube create', 1)
m = m.replace('    refused_release_signed "the Deployment" ', '    mark_sent\n    refused_release_signed "the Deployment" ', 1)
m = m.replace('  if [ "$stored" = "$TAGGED" ]; then\n', '  mark_sent\n  if [ "$stored" = "$TAGGED" ]; then\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "window: mark the Deployment after its create" test_digest_rewrite \
  test_the_deployments_window_opens_before_its_create \
  test_the_deployments_pods_window_opens_before_the_deployment_was_created
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  mark_sent\n  if kube create -f "$SUITE/branch-signed.yaml"', '  if kube create -f "$SUITE/branch-signed.yaml"', 1)
m = m.replace('    decide_foreign "the branch-signed image" refused\n', '    mark_sent\n    decide_foreign "the branch-signed image" refused\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "window: mark the branch-signed pod after its create" test_digest_rewrite \
  test_the_branch_signed_pods_window_opens_before_its_create
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('\nLOG_SLACK=5\n', '\nLOG_SLACK=0\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "window: open it at the second the request was marked" test_digest_rewrite \
  test_the_signed_pods_window_opens_before_its_create \
  test_the_signed_ephemeral_containers_window_opens_before_its_patch \
  test_the_branch_signed_ephemeral_containers_window_opens_before_its_patch \
  test_the_deployments_window_opens_before_its_create \
  test_the_deployments_pods_window_opens_before_the_deployment_was_created \
  test_the_branch_signed_pods_window_opens_before_its_create
res $F

# Every step is bounded under the job's timeout, so a step that stops answering
# ends on the gate's diagnostic.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  kubectl --request-timeout="${REQUEST_TIMEOUT}s" "$@"\n', '  kubectl "$@"\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: send each request with no timeout" test_digest_rewrite \
  test_the_log_is_read_whole_from_every_admission_controller_replica \
  test_every_kubectl_call_goes_through_the_bounded_wrapper
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  if kube logs -n ', '  if kubectl logs -n ', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: read the verifier's log past the wrapper" test_digest_rewrite \
  test_the_log_is_read_whole_from_every_admission_controller_replica \
  test_every_kubectl_call_goes_through_the_bounded_wrapper
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('\nHELM_TIMEOUT=600\n', '\nHELM_TIMEOUT=3600\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: let a step outlast the job" test_digest_rewrite \
  test_every_bound_is_named_and_under_the_jobs_timeout
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('--timeout="${READY_TIMEOUT}s"', '--timeout=180s', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: bound a step by a literal" test_digest_rewrite \
  test_every_bound_is_named_and_under_the_jobs_timeout
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('deadline=$(( $(date +%s) + CREATE_TIMEOUT ))', 'deadline=$(( $(date +%s) + 2 * CREATE_TIMEOUT ))', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "bound: wait for the Deployment's pod past its bound" test_digest_rewrite \
  test_a_deployments_pod_is_waited_for_until_the_bound_and_no_longer
res $F

# An object still present after the delete's bound ends the run: the next
# overlay would meet it.
edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('  delete_within "its policy" -f "$rendered"\n', '  kube delete -f "$rendered" >/dev/null 2>&1\n', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "delete: retire a policy without waiting for it to go" test_digest_rewrite \
  test_a_policy_not_deleted_in_time_cannot_run \
  test_a_policy_is_deleted_and_waited_for
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('    || cannot_run "$rel: $what was not deleted within', '    || true "$rel: $what was not deleted within', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "delete: carry on past an object still present" test_digest_rewrite \
  test_a_policy_not_deleted_in_time_cannot_run \
  test_an_admitted_signed_pod_not_deleted_in_time_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('. "$ROOT/scripts/transport-failure.sh"\n', "uncoloured() { cat; }\ntransport_failures() { grep -iE 'no such host|i/o timeout|connection refused|context deadline|TLS handshake|unexpected status code 5[0-9][0-9]|toomanyrequests'; }\n", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pattern: classify with a list of its own" test_digest_rewrite \
  test_both_gates_source_the_shared_pattern \
  test_no_gate_words_a_transport_failure_of_its_own \
  test_a_trusted_root_that_could_not_be_fetched_is_not_a_denial \
  test_a_registry_429_refusal_cannot_run
res $F

# The one pattern both gates read. Each phrase a fixture carries alone is held
# by the test naming that outage.
F=scripts/transport-failure.sh

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('|tuf: failed to download|', '|', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pattern: miss a trusted root that could not be fetched" test_digest_rewrite \
  test_a_trusted_root_that_could_not_be_fetched_is_not_a_denial
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace('|unexpected status code (429|5[0-9][0-9])|', '|unexpected status code 5[0-9][0-9]|', 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pattern: miss a throttled registry" test_digest_rewrite \
  test_a_registry_429_refusal_cannot_run
res $F

edit $F <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = s.replace("|\\]\\[(429|5[0-9][0-9])\\]'", "'", 1)
assert m != s, "mutation did not land"
p.write_text(m)
PY
rejects "pattern: miss a Rekor 5xx" test_digest_rewrite \
  test_a_rekor_5xx_is_not_a_denial
res $F

echo
echo "── Restored tree must be green again ──"
if ! _suite "${ALL_MODULES[@]}"; then
  echo "  FAIL  the suite is red after restoration — a mutation was left in the tree"
  sed -n '1,40p' "$OUT" | sed 's/^/          /'
  fail=$((fail+1))
else
  echo "  ok    all ${#ALL_MODULES[@]} module(s) green again"
fi

echo
echo "RESULT pass=$pass fail=$fail"

# The floor this harness owes for the same reason the gates owe theirs: with
# every `rejects` line deleted it would report pass=0 fail=0 and exit 0, which is
# a green run over nothing planted.
MIN_PROBES=126
total=$((pass + fail))
if [ "$total" -lt "$MIN_PROBES" ]; then
  echo "FAIL  ran $total probe(s), under the floor of $MIN_PROBES — this harness"
  echo "      planted almost nothing, which is not the same as every test holding."
  exit 2
fi

[ "$fail" -eq 0 ]
