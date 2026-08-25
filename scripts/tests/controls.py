#!/usr/bin/env python3
"""Positive controls: prove each gate rejects the violation it exists to catch.

A gate that has never been shown to fail is an assertion about the tree that
nobody has tested. Reading one is not enough — a check can match on text that
still contains comments, collapse a search error into a clean result, or iterate
an empty enumeration, and every one of those failures prints success.

So each gate here ships a control that introduces the exact violation the gate
names, and the gate must exit non-zero on it. Four properties make that proof
rather than ceremony:

  * **Clean before mutating.** The control asserts the gate passes on the
    unmodified tree first. Without that, a non-zero exit afterwards proves only
    that the gate was already failing.

  * **The mutation is verified by inspecting the mutated text, not the verdict.**
    A mutation that silently fails to apply hands the gate an unchanged fixture,
    the gate correctly passes it, and the pass gets recorded as evidence the
    control worked. That failure looks exactly like success, so the text is read
    back and compared before any verdict is believed.

  * **Mutations are Python string edits over a copied tree.** `sed` address
    ranges, in-place flags and character classes differ between BSD and GNU, so
    a control written with them can mutate on one platform and no-op on the
    other while reporting the same result on both.

  * **Anti-vacuity.** A gate with neither a control nor an asserted exemption
    fails this run, as does a control or exemption naming a gate that no longer
    exists. The suite cannot shrink quietly.

`NEEDS_NETWORK` is an exemption list, and an exemption that matches nothing is a
description that rots toward permissive — so each entry is asserted: naming a
gate that does not exist, or one whose source no longer reaches the network,
fails here.

LIMIT — what a positive control does NOT establish.

A control proves that a gate and its control agree: supply this input, get a
rejection that names this file. It cannot prove the gate checks the property its
NAME claims. A gate that greps for exactly the token its own control plants
satisfies every assertion here — clean before, rejects after, names the file —
while checking nothing. That was demonstrated against this harness rather than
reasoned about: a four-line `check-liar.py` doing no work passed the floor
before the naming assertion was added, and the naming assertion raises the cost
of the deception without removing it.

So "proven to reject" here means observed to reject a supplied input, which is
strictly more than "wired into CI" and strictly less than "checks what it says".
The second still needs a reader, and the gates in this repo have not all had
one. Do not upgrade the claim.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPTS = ROOT / "scripts"

# Seconds one gate may run inside a control before the harness gives up on it.
GATE_TIMEOUT = 300

# What each gate's rejection must NAME, where the right operand is not the file
# the control edited. Several gates correctly name the affected OBJECT instead —
# the chart, the policy rule, the unwatched pin — and demanding the file path
# would be demanding a worse diagnostic. The requirement is that the rejection
# identifies something specific; these say what "specific" means per gate.
#
# The detector fired on all five when it demanded the file, and that was the
# rule being wrong rather than five gates being wrong.
IDENTIFIES = {
    "check-chart-deprecation.py": "chart-no-appset-pins",
    "check-image-verification.py": "verify-images",
    "check-policy-validity.py": "best-practices",
    "check-renovate-coverage.py": "customManager",
    "check-serviceaccount-bindings.py": "druid",
}

# Sentinel for a mutation that removes a file rather than editing one. Some
# gates ask whether a path exists, and for those an emptied file is a mutation
# that changes bytes without changing meaning.
DELETED = object()

# Every planted marker carries this prefix. A marker that looks like real
# syntax may already exist somewhere in the tree — gate docstrings in
# particular are written out of the very shapes the gates catch — and a
# marker that was already present proves nothing by being present after.
# A synthetic token cannot collide, and the harness asserts it was absent
# beforehand regardless.
MARKER = "zzcontrolzz"

# Gates whose default invocation resolves a remote chart, registry or API. A
# control for one of these would need the network, which the testing standard
# forbids in the default run.
#
# Each entry names the DOTTED CALL that reaches the network, and the exemption
# is asserted against the parsed syntax tree rather than the file's text. A
# substring check cannot tell an implementation from a docstring that mentions
# one or a commented-out import, and this exemption list is exactly where that
# distinction decides whether a stale excuse survives. Shell gates carry no AST,
# so theirs is a command word checked against the comments-blanked view — a
# weaker check, and named as weaker below.
NEEDS_NETWORK_PY = {
    "check-platform-crs.py": "subprocess.run",
    "validate-dashboards.py": "urllib.request.urlopen",
    "render-addons.py": "subprocess.run",
    "check-policy-admission.py": "subprocess.run",
    "check-image-pins.py": "subprocess.run",
}

# Shell gates: no syntax tree available, so this is a text check over the
# comments-blanked view. It cannot distinguish a command word inside a string
# from an invocation, which is a real gap and not a design choice.
NEEDS_NETWORK_SH = {
    "kubeconform-scan.sh": "kubeconform",
}

NEEDS_NETWORK = {**NEEDS_NETWORK_PY, **NEEDS_NETWORK_SH}


def blank_comments(text: str) -> str:
    """Return `text` with comment BODIES blanked, quote-aware.

    Which view a check reads is part of the check. Asking "does this source
    still make a network call" against the raw text lets a commented-out import
    answer yes — a comment standing in for the implementation that was removed,
    which is the shape that has blinded gates in four repositories now.

    The inverse view is equally legitimate: a check hunting for something that
    lives only in commentary must read the comments. So this blanks rather than
    deletes and callers choose, and it blanks space-for-space so every line
    number and column survives — a file:line taken from this view resolves in
    the real file.
    """
    out = []
    i, n = 0, len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote is not None:
            out.append(ch)
            if ch == chr(92) and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if text.startswith(quote, i):
                out.append(text[i + 1:i + len(quote)])
                i += len(quote)
                quote = None
                continue
            i += 1
            continue
        opened = False
        for q in (chr(34) * 3, chr(39) * 3, chr(34), chr(39)):
            if text.startswith(q, i):
                quote = q
                out.append(q)
                i += len(q)
                opened = True
                break
        if opened:
            continue
        if ch == "#":
            j = text.find(chr(10), i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def called_names(src: str) -> set[str]:
    """Every dotted callee name actually invoked in `src`.

    Parsed, not matched. A docstring that names a function, a commented-out
    import, and a string carrying a command word all mention an implementation
    without being one — and this set is what decides whether an exemption still
    has a reason, which is precisely where that difference matters.
    """
    import ast

    def dotted(node) -> str | None:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    return {name for n in ast.walk(tree)
            if isinstance(n, ast.Call) and (name := dotted(n.func))}


# The harnesses, which cannot control themselves: a suite asserting its own
# ability to reject would be the thing under test and the thing testing it. Both
# are covered instead by their own self-tests, which run on every ordinary
# invocation. Asserted like every other exemption — an entry naming a file that
# no longer exists fails.
NOT_GATES = {
    "tests/controls.py": "the control harness; self_test() runs on every invocation",
    "tests/run.py": "the unit-test runner; asserts its own module list and floors",
    "tests/reverify-gates.sh": "the Tier-1 re-verification harness; it drives the "
                               "gates rather than checking the tree, and asserts "
                               "its own pass/fail totals",
}


def gate_files() -> list[str]:
    """Every gate script under scripts/, relative to it.

    rglob, not iterdir. A per-directory enumeration cannot make a per-file
    claim: with iterdir a gate added in any subdirectory of scripts/ was never
    enumerated, so it escaped the anti-vacuity floor entirely — the floor would
    report full coverage of a set that did not contain it. The delta today is
    two files, both harnesses, so the class was open and no gate was actually
    escaping; the fix closes the class rather than the instance.
    """
    return sorted(
        str(p.relative_to(SCRIPTS))
        for p in SCRIPTS.rglob("*")
        if p.is_file() and os.access(p, os.X_OK) and p.suffix in {".py", ".sh"}
    )


# ── mutations ────────────────────────────────────────────────────────────────
#
# Each takes the copied tree's root and returns (path, before, after) for the
# one file it edited, so the harness can read the file back and confirm the edit
# landed. Raising is a control failure, not a gate failure.


def _sub(root: pathlib.Path, rel: str, old: str, new: str, marker: str | None = None):
    """Replace `old` with `new` once in `rel`, declaring the text it plants.

    `marker` is the substring the mutation claims to introduce. The harness
    checks it is present afterwards AND absent beforehand, which is what
    separates a mutation that changed the meaning from one that merely changed
    bytes — planting a value the file already carried edits the text and asserts
    nothing.
    """
    p = root / rel
    before = p.read_text()
    if old not in before:
        raise AssertionError(f"control cannot mutate {rel}: anchor absent -> {old[:70]!r}")
    after = before.replace(old, new, 1)
    p.write_text(after)
    return p, before, after, (marker if marker is not None else new)


def m_label_values(root):
    """A label value the API server's grammar rejects (leading dash)."""
    return _sub(root, "applicationsets/addons-karpenter.yaml",
                "platform.nanohype.dev/team: platform-engineering",
                f"platform.nanohype.dev/team: -{MARKER}",
                marker=f"-{MARKER}".lstrip("-"))


def m_sync_waves(root):
    """An operations addon syncing inside the bootstrap band.

    Targets velero rather than karpenter: karpenter is the documented cross-band
    exception, so a wave written onto it tests the exception list rather than the
    band check. And it targets the TEMPLATE annotation — the per-Application wave
    the gate classifies — not the ApplicationSet's own, which carries the same
    literal one indent level out and is not what the band check reads.
    """
    return _sub(root, "applicationsets/addons-velero.yaml",
                '        argocd.argoproj.io/sync-wave: "40"',
                f'        argocd.argoproj.io/sync-wave: "0"  # {MARKER}',
                marker=MARKER)


def m_hardcoded_org(root):
    """A repoURL pinned to this org in an applied ApplicationSet."""
    return _sub(root, "applicationsets/addons-karpenter.yaml",
                "repoURL: '{{ index .metadata.annotations \"gitops/repo-url\" }}'",
                f"repoURL: 'https://github.com/nanohype/eks-gitops'  # {MARKER}",
                marker=MARKER)


def m_renovate_coverage(root):
    """Delete a customManager, so the pins it watched are watched by nothing."""
    p = root / "renovate.json"
    before = p.read_text()
    marker = '"description": "OCI Helm chart pins in ApplicationSet matrix list elements.'
    i = before.index(marker)
    start = before.rindex("{", 0, i)
    depth, j = 0, start
    while True:
        if before[j] == "{":
            depth += 1
        elif before[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    end = before.find(",", j) + 1
    after = before[:start] + before[end:]
    p.write_text(after)
    # A deletion plants nothing, so the assertion runs in the other direction:
    # a leading "-" tells the harness this marker must have DISAPPEARED.
    return p, before, after, "-" + marker


def m_no_placeholders(root):
    """An unfilled fill-me sentinel in applied deploy config."""
    p = root / "addons/operations/karpenter/values-development.yaml"
    before = p.read_text()
    after = before + f"\n{MARKER}Probe: REPLACE_ME\n"
    p.write_text(after)
    return p, before, after, f"{MARKER}Probe: REPLACE_ME"


def m_externalsecret_keys(root):
    """An ExternalSecret naming its remote secret a second time.

    The gate asserts each ExternalSecret names its remote secret exactly once
    and that the delivering ApplicationSet patches that name per cluster. A
    second `key:` under `extract` is the shape that breaks it: two names where
    the per-cluster patch can only rewrite one, so one cluster reads a secret
    meant for another.
    """
    return _sub(root, "dashboards/base/grafana-token.yaml",
                "  dataFrom:\n    - extract:\n        key: eks-grafana-token",
                "  dataFrom:\n    - extract:\n        key: eks-grafana-token\n"
                f"    - extract:\n        key: {MARKER}-second-remote-name",
                marker=f"{MARKER}-second-remote-name")


def m_athena_columns(root):
    """A CUR panel querying a column the export does not deliver."""
    import glob
    for h in sorted(glob.glob(str(root / "dashboards/**/*.yaml"), recursive=True)):
        p = pathlib.Path(h)
        before = p.read_text()
        if "line_item_unblended_cost" in before:
            after = before.replace("line_item_unblended_cost",
                                   f"{MARKER}_undelivered_column", 1)
            p.write_text(after)
            return p, before, after, f"{MARKER}_undelivered_column"
    raise AssertionError("control found no Athena panel referencing a CUR column")


def m_image_verification(root):
    """Change the signing identity the verify-images policy trusts.

    The gate asserts the policy's signing-identity contract, so rewriting the
    trusted issuer is the violation it exists to catch: a policy that verifies
    signatures against an identity nobody signs with admits everything while
    reading as enforced.
    """
    p = root / "policies/kyverno/supply-chain/base/verify-images.yaml"
    before = p.read_text()
    for old, new in (
        ("https://token.actions.githubusercontent.com", f"https://{MARKER}.invalid"),
        ("ghcr.io/nanohype/*", f"ghcr.io/{MARKER}/*"),
    ):
        if old in before:
            after = before.replace(old, new, 1)
            p.write_text(after)
            return p, before, after, new
    raise AssertionError("control found no signing identity or registry glob to rewrite")


def m_catalog_revision(root):
    """A catalog source pinning a revision instead of reading one."""
    import glob
    for h in sorted(glob.glob(str(root / "applicationsets/*.yaml"))):
        p = pathlib.Path(h)
        before = p.read_text()
        if "gitops/repo-branch" in before:
            after = before.replace(
                "targetRevision: '{{ index .metadata.annotations \"gitops/repo-branch\" }}'",
                f"targetRevision: main  # {MARKER}", 1)
            if after != before:
                p.write_text(after)
                return p, before, after, MARKER
    raise AssertionError("control found no catalog source reading its revision")


def m_policy_validity(root):
    """A ClusterPolicy kyverno silently discards, while staying valid YAML.

    An apiVersion kyverno does not recognise: the document renders, kyverno
    drops it, and the run reports `error: 0` for a policy that will never be
    installed. That silence is what the gate's rule-count assertion catches.

    Deliberately NOT a structural break. Injecting a bogus top-level key made
    the document unparseable, so check-externalsecret-keys rejected the same
    tree too — the fixture then carried two violations and a rejection scored
    here could have been for the other one. Verified: this mutation trips this
    gate and no other.
    """
    return _sub(root, "policies/kyverno/best-practices/base/require-labels.yaml",
                "apiVersion: kyverno.io/v1",
                f"apiVersion: kyverno.io/v1{MARKER}",
                marker=MARKER)


def m_serviceaccount_bindings(root):
    """Remove a ServiceAccount the rendered pods still name.

    The gate renders catalog/*/chart and asserts every pod's ServiceAccount is
    one the chart creates. Renaming the created account leaves the pods pointing
    at a name that no longer exists — the association silently binds nothing.
    """
    return _sub(root, "catalog/druid/chart/templates/serviceaccount.yaml",
                "  name: druid-{{ $sa }}",
                "  name: " + MARKER + "-{{ $sa }}",
                marker=MARKER + "-{{ $sa }}")


def m_alert_coverage(root):
    """Break the `== bool 0` rule that covers a sibling's `!= 0` guard.

    The gate checks one mechanical property: a rule excluding zero with `!= 0`
    must have a sibling keying on the same selector with `== bool 0`. Dropping
    the bool modifier is the exact failure it names — the rule still matches the
    right series and Grafana's `gt 0` reducer never trips, so the state looks
    covered and is not.
    """
    return _sub(root, "dashboards/base/alerting/agent-platform.yaml",
                'field=\\"lastRunAt\\"} == bool 0',
                'field=\\"lastRunAt\\"} == 0',
                marker='lastRunAt\\"} == 0')


def m_chart_deprecation(root):
    """A recorded chart that nothing pins, which the offline gate must reject."""
    import json
    p = root / "scripts/chart-provenance.json"
    before = p.read_text()
    doc = json.loads(before)
    doc["charts"][f"{MARKER}-chart-no-appset-pins"] = {
        "repo": "https://example.invalid",
        "description": "introduced by the positive control",
        "deprecated": False,
    }
    after = json.dumps(doc, indent=2) + "\n"
    p.write_text(after)
    return p, before, after, f"{MARKER}-chart-no-appset-pins"


def m_named_things(root):
    """A runbook naming a task target the Taskfile does not define."""
    return _sub(root, "docs/runbooks/troubleshooting.md",
                "```bash",
                f"```bash\ntask {MARKER}-not-a-target",
                marker=f"task {MARKER}-not-a-target")


def m_ai_config(root):
    """A ModelGateway route naming a model the Platform allowlist omits."""
    return _sub(root, "addons/ai-platform/agent-platform/base/platform.yaml",
                "      modelId: us.anthropic.claude-sonnet-5",
                f"      modelId: us.anthropic.claude-opus-5  # {MARKER}",
                marker=MARKER)


def m_workflows(root):
    """A checkout that persists the job token into the working tree."""
    return _sub(root, ".github/workflows/diff.yml",
                "        with:\n          persist-credentials: false",
                f"        with:\n          fetch-depth: 0  # {MARKER}",
                marker=MARKER)


def m_env_coverage(root):
    """Delete a hub delta from an addon whose appset reaches the hub.

    Deleted, not emptied. The gate asks whether the file EXISTS, so an emptied
    file is a mutation that changes bytes and not meaning — the gate correctly
    accepts it and the acceptance reads as the gate failing to reject. The
    DELETED sentinel tells the harness to assert the file is gone instead of
    comparing its text.
    """
    p = root / "addons/bootstrap/cert-manager/values-hub.yaml"
    before = p.read_text()
    p.unlink()
    return p, before, DELETED, DELETED


CONTROLS = {
    "check-env-coverage.py": ("an addon selected for an environment it cannot render", m_env_coverage),
    "check-workflows.sh": ("a checkout persisting the job token", m_workflows),
    "check-ai-config.py": ("a route naming a model outside the allowlist", m_ai_config),
    "check-named-things.py": ("prose naming a target that does not exist", m_named_things),
    "check-chart-deprecation.py": ("a provenance record no pin claims", m_chart_deprecation),
    "check-label-values.py": ("a label value the API server rejects", m_label_values),
    "check-sync-waves.py": ("a category syncing ahead of its band", m_sync_waves),
    "check-hardcoded-org.py": ("an org-pinned repoURL in an applied appset", m_hardcoded_org),
    "check-renovate-coverage.py": ("a deleted customManager leaving pins unwatched", m_renovate_coverage),
    "no-placeholders.sh": ("an unfilled sentinel in deploy config", m_no_placeholders),
    "check-externalsecret-keys.py": ("a duplicated remote secret name", m_externalsecret_keys),
    "check-athena-panel-columns.py": ("a panel naming an undelivered CUR column", m_athena_columns),
    "check-image-verification.py": ("Enforce without its paired digest mutation", m_image_verification),
    "check-catalog-revision.py": ("a catalog source pinning a revision", m_catalog_revision),
    "check-policy-validity.py": ("a structurally invalid ClusterPolicy", m_policy_validity),
    "check-serviceaccount-bindings.py": ("a pod naming an absent ServiceAccount", m_serviceaccount_bindings),
    "check-alert-coverage.py": ("an alert on an unexported KSM field", m_alert_coverage),
}


# ── harness ──────────────────────────────────────────────────────────────────


def copy_tree(dest: pathlib.Path) -> None:
    """The tracked tree only — generated output and .git stay out.

    WHICH TREE THIS IS, precisely: the file LIST comes from the git index, and
    the CONTENT comes from the working tree. So an uncommitted edit to a tracked
    file IS under test, and an untracked new file is NOT — which is why a gate
    added but not yet `git add`ed fails the anti-vacuity floor rather than being
    silently skipped. A floor materialising fixtures purely from the index would
    grade a different tree than the one being edited; this one does not, for
    modifications, and says so for additions.
    """
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                            text=True, check=True, timeout=GATE_TIMEOUT)
    for rel in listed.stdout.split("\0"):
        if not rel:
            continue
        src, dst = ROOT / rel, dest / rel
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


# Flags a gate needs to be invoked the way CI invokes it. check-hardcoded-org
# reports and exits 0 without --blocking, so a control that omitted the flag
# would be testing the report-only mode and could never see a rejection.
GATE_ARGS = {"check-hardcoded-org.py": ["--blocking"]}


def run_gate(gate: str, cwd: pathlib.Path) -> subprocess.CompletedProcess:
    path = cwd / "scripts" / gate
    cmd = [sys.executable, str(path)] if gate.endswith(".py") else ["bash", str(path)]
    cmd += GATE_ARGS.get(gate, [])
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=GATE_TIMEOUT)


def check_vacuity() -> list[str]:
    """The suite cannot shrink quietly, and no exemption may match nothing."""
    problems = []
    present = set(gate_files())

    for name, reason in sorted(NOT_GATES.items()):
        if name not in present:
            problems.append(
                f"{name} is exempted as a harness rather than a gate, but no such "
                f"executable exists under scripts/ — the exemption outlived its file. "
                f"(recorded: {reason})")

    for gate in sorted(present):
        if gate in NOT_GATES:
            continue
        if gate not in CONTROLS and gate not in NEEDS_NETWORK:
            problems.append(
                f"{gate} ships no positive control and is on no exemption list. A gate "
                f"nobody has shown to fail is an untested assertion about the tree.")

    for gate in sorted(set(CONTROLS) | set(NEEDS_NETWORK)):
        if gate not in present:
            problems.append(
                f"{gate} is named by a control or an exemption but no longer exists in "
                f"scripts/ — the reference outlived the gate.")

    for gate, call in sorted(NEEDS_NETWORK_PY.items()):
        p = SCRIPTS / gate
        if not p.exists():
            continue
        if call not in called_names(p.read_text()):
            problems.append(
                f"{gate} is exempted as network-dependent, but its syntax tree contains "
                f"no call to {call}(). If the remote call is gone the gate is testable "
                f"and the exemption must go with it.")

    for gate, word in sorted(NEEDS_NETWORK_SH.items()):
        p = SCRIPTS / gate
        if p.exists() and word not in blank_comments(p.read_text()):
            problems.append(
                f"{gate} is exempted as network-dependent, but {word!r} appears nowhere "
                f"outside its comments. If the remote call is gone the gate is testable "
                f"and the exemption must go with it.")
    return problems


def mutation_landed(rel, before: str, after: str, on_disk: str,
                    marker: str) -> str | None:
    """Why this mutation does not count as landed, or None if it does.

    Three ways a mutation reports success without having changed the meaning,
    each of which reads as a working control:

      * it no-ops — the file is byte-identical and the gate passes an unchanged
        tree
      * it lands off-target — bytes changed, but not the ones the control
        claimed to write
      * it plants a marker the file already carried — the edit applies and
        asserts nothing, because the condition was already true

    So the file must differ, the write must match what the control intended, and
    the declared marker must be present now and absent before. A leading "-"
    inverts the last pair for mutations that delete rather than plant.
    """
    if after is DELETED:
        if on_disk is not DELETED:
            return (f"control claims to delete {rel}, but the file is still present — "
                    f"the mutation proved nothing.")
        return None

    if on_disk is DELETED:
        return f"{rel} was deleted, but the control did not declare a deletion."

    if on_disk == before:
        return (f"mutation did not change {rel} — the control proved nothing, in the "
                f"direction that looks like success.")
    if on_disk != after:
        return f"{rel} on disk differs from what the control intended to write."

    if marker.startswith("-"):
        gone = marker[1:]
        if gone not in before:
            return (f"control claims to remove {gone[:60]!r} from {rel}, but it was never "
                    f"there — the mutation asserts nothing.")
        if gone in on_disk:
            return f"control claims to remove {gone[:60]!r} from {rel}, but it is still present."
        return None

    if marker in before:
        return (f"control plants {marker[:60]!r} into {rel}, but the file already carried it "
                f"— the edit landed and the meaning did not change.")
    if marker not in on_disk:
        return (f"control claims to plant {marker[:60]!r} into {rel}, but it is absent from "
                f"the written file.")
    return None


def self_test() -> int:
    """Try to fool the mutation contract. A harness untested is a harness trusted."""
    cases = [
        ("no-op", "a: 1\n", "a: 1\n", "a: 1\n", "b: 2", "did not change"),
        ("off-target", "a: 1\n", "a: 2\n", "a: 3\n", "a: 2", "differs from what"),
        ("pre-existing marker", "a: 1\nb: 2\n", "a: 9\nb: 2\n", "a: 9\nb: 2\n", "b: 2",
         "already carried it"),
        ("honest plant", "a: 1\n", "a: 9\n", "a: 9\n", "a: 9", None),
        ("honest removal", "a: 1\nb: 2\n", "a: 1\n", "a: 1\n", "-b: 2", None),
        ("removal that never removed", "a: 1\n", "a: 2\n", "a: 2\n", "-b: 2", "never"),
    ]
    view_cases = [
        ("comment cannot satisfy a code reference",
         "# import urllib.request" + chr(10) + "x = 1" + chr(10), "urllib", False),
        ("real code still satisfies it",
         "import urllib.request" + chr(10) + "x = 1" + chr(10), "urllib", True),
        ("a hash inside a string is not a comment",
         "sep = " + chr(34) + "# not a comment" + chr(34) + chr(10) + "import urllib" + chr(10),
         "urllib", True),
    ]
    bad = 0
    print("\u2500\u2500 Comment-view self-test \u2500\u2500")
    for name, src, needle, want in view_cases:
        got = needle in blank_comments(src)
        ok = got is want
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}: {needle!r} "
              f"{'found' if got else 'absent'}")
        bad += 0 if ok else 1
    # The property, not the mechanism: a token below blanked comment lines must
    # still be findable at its own line number. Asserting the property rather
    # than the current implementation means a refactor to joined text, or an
    # anchor that lets \\s cross a newline, fails here instead of silently
    # shifting every citation up by the number of blanked lines above it.
    raw = ("# aaaa" + chr(10)) * 3 + "import urllib" + chr(10)
    view = blank_comments(raw)
    raw_line = raw.splitlines().index("import urllib")
    ok_lines = (len(view) == len(raw)
                and len(view.splitlines()) == len(raw.splitlines())
                and view.splitlines()[raw_line].strip() == "import urllib")
    print(f"  {'ok  ' if ok_lines else 'FAIL'}  a token under blanked comments keeps its own "
          f"line number ({raw_line})")
    bad += 0 if ok_lines else 1
    print()

    # The AST view, which is why the Python exemptions do not use a textual one.
    # Comment-blanking cannot help here: a docstring is a string, not a comment,
    # so a gate documenting the call it makes would read its own documentation
    # as an implementation. And a dead declaration commented out above a live
    # one must not win a first-match search.
    ast_cases = [
        ("a docstring naming the call", '"""Calls subprocess.run."""' + chr(10), False),
        ("a comment naming the call", "# subprocess.run(x)" + chr(10), False),
        ("a string literal naming the call", 'm = "use subprocess.run"' + chr(10), False),
        ("a real call", "subprocess.run([1])" + chr(10), True),
        ("a dead copy above a live one",
         "# subprocess.run([0])" + chr(10) + "subprocess.run([1])" + chr(10), True),
    ]
    print("\u2500\u2500 AST-view self-test \u2500\u2500")
    for name, src, want in ast_cases:
        got = "subprocess.run" in called_names(src)
        ok = got is want
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}: "
              f"{'found' if got else 'absent'}")
        bad += 0 if ok else 1
    print()

    print("\u2500\u2500 Mutation-contract self-test \u2500\u2500")
    for name, before, after, disk, marker, want in cases:
        got = mutation_landed("fixture.yaml", before, after, disk, marker)
        ok = (got is None) if want is None else (got is not None and want in got)
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}: {got or 'accepted'}")
        bad += 0 if ok else 1
    print()
    if bad:
        print(f"Mutation contract FAILED its own self-test: {bad} case(s).")
        return 1
    print(f"✓ the mutation contract rejects every way a mutation can look landed "
          f"without being ({len(cases)} cases)")
    return 0


def run_control(gate: str, what: str, mutate) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        tree = pathlib.Path(td) / "tree"
        tree.mkdir()
        copy_tree(tree)

        clean = run_gate(gate, tree)
        if clean.returncode != 0:
            return False, (f"gate is not clean before mutation (exit {clean.returncode}); a "
                           f"rejection afterwards would prove nothing.\n"
                           f"{(clean.stdout + clean.stderr).strip()[:600]}")

        try:
            path, before, after, marker = mutate(tree)
        except AssertionError as exc:
            return False, str(exc)

        rel = path.relative_to(tree)
        on_disk = path.read_text() if path.exists() else DELETED
        problem = mutation_landed(rel, before, after, on_disk, marker)
        if problem:
            return False, problem

        dirty = run_gate(gate, tree)
        if dirty.returncode == 0:
            return False, (f"gate ACCEPTED {what} — it cannot reject the violation it exists "
                           f"to catch.\n{(dirty.stdout + dirty.stderr).strip()[:600]}")

        # The rejection must NAME what was mutated. A non-zero exit alone only
        # says the gate behaved differently on a different tree, which a gate
        # doing no real work can also do — a four-line script that greps for
        # whatever its own control plants exits 1 on cue and tells you nothing.
        # Requiring the path in the diagnostic is not proof the gate checks the
        # property its name claims (see the LIMIT note in this module), but it
        # does separate a gate that located something from one that merely
        # noticed the tree changed.
        said = dirty.stdout + dirty.stderr

        # A CRASH exits non-zero too, so a floor reading exit status alone
        # records a stack trace as a successful rejection — exit-code-conflates-
        # causes, occurring inside the machinery built to catch it. Demonstrated
        # against this floor with a gate that raises after printing the path it
        # was processing, which satisfied both the exit check and the naming
        # check below.
        for crash in ("Traceback (most recent call last)", "panic: ",
                      "goroutine 1 [running]"):
            if crash in said:
                return False, (f"gate exited {dirty.returncode} by CRASHING, not by "
                               f"rejecting — a stack trace is not a verdict.\n"
                               f"{said.strip()[:400]}")

        want = IDENTIFIES.get(gate)
        names = [want] if want else [str(rel), rel.name]
        hit = next((n for n in names if n in said), None)
        if hit is None:
            return False, (f"gate exited {dirty.returncode} but its output never names "
                           f"{want or rel} — a rejection that cannot say what it rejected "
                           f"is indistinguishable from a gate reacting to any change at "
                           f"all.\n{said.strip()[:400]}")
        return True, f"rejected {what} (exit {dirty.returncode}, names {hit.split('/')[-1]})"


def main() -> int:
    if self_test():
        return 1
    problems = check_vacuity()
    if problems:
        print("── Control coverage ──")
        for p in problems:
            print(f"  FAIL  {p}")
        print("\nPositive-control gate FAILED before running anything.")
        return 1

    only = sys.argv[1] if len(sys.argv) > 1 else None
    items = [(g, w, m) for g, (w, m) in sorted(CONTROLS.items()) if not only or g == only]
    if not items:
        print(f"FAIL  no control matches {only!r}")
        return 1

    print(f"── Positive controls ── {len(items)} gate(s), "
          f"{len(NEEDS_NETWORK)} exempted as network-dependent\n")
    failed = 0
    for gate, what, mutate in items:
        ok, detail = run_control(gate, what, mutate)
        print(f"  {'ok  ' if ok else 'FAIL'}  {gate}: {detail}")
        failed += 0 if ok else 1

    print()
    if failed:
        print(f"Positive-control gate FAILED: {failed} of {len(items)} controls did not hold.")
        return 1
    print(f"✓ every gate with a control rejects the violation it names ({len(items)} controls)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
