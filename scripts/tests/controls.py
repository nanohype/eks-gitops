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

# Exit code for "this did not run", shared with the gates (scripts/gatelib.py).
CANNOT_RUN = 2

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
#
# A named class rather than a bare object() so the "deleted" case is a type the
# reader and the checker can both see: mutation_landed guards on it before
# treating its argument as text, and that guard is what makes the rest of the
# function total.
class _Deleted:
    __slots__ = ()

    def __repr__(self) -> str:
        return "DELETED"


DELETED = _Deleted()

# A floor on CONTROLS ACTUALLY EXECUTED, not on registry keys being present.
#
# Those are different quantities, and only the second was ever asserted. The
# anti-vacuity floor asks whether each gate HAS an entry; this asks how many
# controls RAN. A registry can satisfy the first while contributing almost
# nothing to the second — entries move into an exemption list, or a filter
# narrows the set — and the suite would still print that the invariants hold.
#
# The count was printed and never gated. Set below the real number so a single
# deliberate removal does not trip it, and far enough above zero that a gutted
# registry cannot report success.
MIN_CONTROLS_RUN = 14

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
    "check-log-volume-budget.py": "subprocess.run",
    "check-falco-rule-floor.py": "subprocess.run",
    "check-image-vulnerabilities.py": "subprocess.run",
}

# Shell gates: no syntax tree available, so this is a text check over the
# comments-blanked view. It cannot distinguish a command word inside a string
# from an invocation, which is a real gap and not a design choice.
NEEDS_NETWORK_SH = {
    "kubeconform-scan.sh": "kubeconform",
    "kyverno-test.sh": "kyverno",
    # Reaches the registry for the image manifest and Rekor for the
    # transparency-log entry, because that round trip IS what it executes: it
    # admits a signed pod through the enforcing rendition and reads back what
    # was admitted. A control for it offline would be a control for a
    # verification that did not happen.
    "check-digest-rewrite.sh": "kyverno",
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

    # A SyntaxError here used to become an empty set, and that set is the SOLE
    # input to the network-exemption assertion. So a gate this harness could not
    # parse was a gate whose exempted network call "was not present" — the
    # exemption then read as stale and the floor went blind to the very file it
    # could not read. Let it out: an unparseable gate is a fact about the tree,
    # not an empty answer about its contents.
    return {name for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.Call) and (name := dotted(n.func))}


# The harnesses, which cannot control themselves: a suite asserting its own
# ability to reject would be the thing under test and the thing testing it. Each
# is covered instead by its own self-assertions, which run on every ordinary
# invocation. Asserted like every other exemption — an entry naming a file that
# no longer exists fails, a present executable on no list fails, and an entry
# nothing in the repo invokes fails.
NOT_GATES = {
    "tests/controls.py": "the control harness; self_test() runs on every "
                         "invocation, and test_controls.py holds the reader "
                         "this rule asks",
    "tests/run.py": "the unit-test runner; asserts its own module list and floors",
    "tests/reverify-gates.sh": "the Tier-1 re-verification harness; it drives the "
                               "gates rather than checking the tree, and asserts "
                               "its own pass/fail totals",
    "tests/empty-corpus.py": "the vacuity harness; it runs every gate against an "
                             "emptied corpus rather than checking the tree, and "
                             "asserts its own probe floor and exemptions",
    "tests/reverify-tests.sh": "the unit-test re-verification harness; it reverts a "
                               "gate behaviour and requires the suite to name it, "
                               "asserts the tree is green before and after, and "
                               "carries its own probe floor",
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


def m_alert_severity_routes(root):
    """Relabel one rule with a severity the notification policy does not route.

    The exact defect: the rule still parses, still evaluates, still changes
    state in the Grafana alert list — and its label selects no route, so it
    falls to the tree's root receiver instead of the destination it asked for.
    Nothing else in the tree can see that, because the rule and the policy never
    name each other.
    """
    return _sub(root, "dashboards/base/alerting/agent-operator.yaml",
                "        severity: page\n",
                f"        severity: {MARKER}-urgent\n",
                marker=f"severity: {MARKER}-urgent")


def m_burn_rate_budgets(root):
    """Put back the figure this gate was written for.

    A ticket-tier rule whose expression compares against a burn factor of 1 over
    3d, claiming the budget is fully consumed. Factor 1 spends at exactly the
    rate that exhausts the budget over the SLO window, so 3d of it is 10% of a
    30d budget. The expression stays correct and only the sentence changes,
    which is what every rule-level validation passes.
    """
    return _sub(root, "dashboards/base/alerting/agent-operator.yaml",
                "budget burning slowest (10% in 3d)",
                "budget burning (100% over 3d)",
                marker="100% over 3d")


def m_secret_store_refs(root):
    """Typo the store in the chart source that does not parse as YAML.

    The half of the corpus a gate written against `yaml.safe_load_all` drops
    while reporting a clean run over the rest, and the exact shape one repo in
    this org shipped: `aws-secretsmanager` against `aws-secrets-manager`. The
    ExternalSecret installs, syncs, records SecretSyncedError on its own status,
    and never creates the Secret the workload mounts.
    """
    return _sub(root, "catalog/druid/chart/templates/externalsecret.yaml",
                "    name: aws-secrets-manager\n",
                "    name: aws-secretsmanager\n",
                marker="aws-secretsmanager")


def m_directory_manifest_size(root):
    """Lower the contracted ceiling to the one argocd-repo-server ships with.

    Which is the configuration the incident happened under: the Argo Workflows
    `crds/full` directory is over 10M, so at the stock ceiling the repo-server
    refuses to generate that Application and it reports ComparisonError. Nothing
    about the source changes — the same eight files, the same pin — so this is
    the violation as it actually arrives, from a host configured lower than the
    catalog needs rather than from a manifest anyone edited.
    """
    return _sub(root, "contracts/repo-server.json",
                '"maxCombinedDirectoryManifestsSize": "20M"',
                '"maxCombinedDirectoryManifestsSize": "10M"',
                marker='"maxCombinedDirectoryManifestsSize": "10M"')


def m_lb_scheme_inputs(root):
    """Stop the policy reading the legacy scheme annotation.

    Which is the defect as it was: aws-load-balancer-internal is still honoured
    by the controller and still ahead of its default, so a Service setting it and
    nothing else is internet-facing to the controller and internal to a policy
    that reads only the newer spelling — the private-subnet list on a load
    balancer the controller puts on public subnets. Renamed rather than deleted,
    because a policy that reads an annotation nobody sets is the same silence.
    """
    rel = "policies/kyverno/networking/base/inject-adopt-lb-subnets.yaml"
    path = root / rel
    before = path.read_text()
    marker = f"aws-load-balancer-internal-{MARKER}"
    after = before.replace("aws-load-balancer-internal", marker)
    assert after != before, f"{rel} carries no legacy scheme annotation to rename"
    path.write_text(after)
    return path, before, after, marker


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
    "check-alert-severity-routes.py": ("a severity label that routes nowhere",
                                       m_alert_severity_routes),
    "check-burn-rate-budgets.py": ("a summary claiming a budget its expression "
                                   "does not spend", m_burn_rate_budgets),
    "check-secret-store-refs.py": ("a reference to a store the catalog does not "
                                   "declare", m_secret_store_refs),
    "check-directory-manifest-size.py": ("a directory source over the ceiling the "
                                         "repo-server is configured for",
                                         m_directory_manifest_size),
    "check-lb-scheme-inputs.py": ("a scheme the controller decides on that the policy "
                                  "stopped reading", m_lb_scheme_inputs),
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
    copied: list[str] = []
    for rel in listed.stdout.split("\0"):
        if not rel:
            continue
        src, dst = ROOT / rel, dest / rel
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)

    # The fixture is made a real git repository carrying exactly the files that
    # were copied. Gates scoped to `git ls-files` — which is how a gate avoids
    # grading a sibling checkout CI drops in the workspace — see nothing in a
    # plain directory, so a fixture that is not a repo makes them report an
    # empty tree and the control then proves nothing about them.
    #
    # `git add` takes the explicit list rather than `-A`: the fixture must
    # contain what the harness put there, not whatever else a run left behind.
    subprocess.run(["git", "init", "-q"], cwd=dest, capture_output=True,
                   text=True, timeout=GATE_TIMEOUT)
    for chunk in (copied[i:i + 500] for i in range(0, len(copied), 500)):
        subprocess.run(["git", "add", "--", *chunk], cwd=dest,
                       capture_output=True, text=True, timeout=GATE_TIMEOUT)


# Flags a gate needs to be invoked the way CI invokes it. check-hardcoded-org
# reports and exits 0 without --blocking, so a control that omitted the flag
# would be testing the report-only mode and could never see a rejection.
GATE_ARGS = {"check-hardcoded-org.py": ["--blocking"]}


def run_gate(gate: str, cwd: pathlib.Path) -> subprocess.CompletedProcess:
    path = cwd / "scripts" / gate
    cmd = [sys.executable, str(path)] if gate.endswith(".py") else ["bash", str(path)]
    cmd += GATE_ARGS.get(gate, [])
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=GATE_TIMEOUT)


def caller_files(root: pathlib.Path) -> list[pathlib.Path]:
    """The files that decide what runs: the Taskfile and every workflow."""
    return [p for p in (root / "Taskfile.yaml",
                        *sorted((root / ".github" / "workflows").glob("*.y*ml")))
            if p.is_file()]


def _task_commands(task) -> list[str]:
    """The command strings one Taskfile task executes.

    `{task: other}` is not one: it names another task, whose own commands are
    read when that task is walked. `{cmd: ...}` and `{defer: ...}` are.
    """
    if isinstance(task, str):
        return [task]
    if isinstance(task, list):
        entries = task
    elif isinstance(task, dict):
        entries = task.get("cmds") or []
    else:
        return []
    out = []
    for entry in entries:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict):
            for key in ("cmd", "defer"):
                if isinstance(entry.get(key), str):
                    out.append(entry[key])
    return out


def caller_commands(root: pathlib.Path) -> tuple[list[str], list[str]]:
    """(every command the callers execute, callers that would not parse).

    Taken from the parsed documents at the positions a runner reads a command
    from — a task's `cmds:` entries, a workflow step's `run:` script. Every
    other string in either file is prose as far as this reader is concerned,
    and a comment is not in the parse at all.

    `status:` and `preconditions:` hold commands too and are deliberately
    absent. They decide whether a task's work runs; a harness reached only
    through one of them asserts nothing about the tree.

    A caller that will not parse is returned as its own fact rather than as a
    caller with no commands in it. Those are the same value to `any()` and
    different facts to a reader: one says nothing runs the harness, the other
    says this file could not be asked.
    """
    import yaml

    commands: list[str] = []
    unreadable: list[str] = []
    for path in caller_files(root):
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            detail = str(exc).strip().splitlines()
            unreadable.append(f"{path.relative_to(root)}: "
                              f"{detail[0] if detail else exc.__class__.__name__}")
            continue
        if not isinstance(doc, dict):
            continue
        tasks = doc.get("tasks")
        if isinstance(tasks, dict):
            for task in tasks.values():
                commands += _task_commands(task)
        jobs = doc.get("jobs")
        if isinstance(jobs, dict):
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps") or []:
                    if isinstance(step, dict) and isinstance(step.get("run"), str):
                        commands.append(step["run"])
    return commands, unreadable


def command_words(command: str) -> list[str]:
    """The words `command` would execute, shell comments and quoting resolved.

    A second parse, for the reason the first one happened: inside a `run: |`
    block the runner is a shell, and a `#` comment there is prose exactly as a
    YAML comment is. Quoting is read too, so a path inside a quoted string is a
    word of that string rather than a word of the command.
    """
    import shlex

    text = blank_comments(command)
    try:
        return shlex.split(text)
    except ValueError:
        # An unbalanced quote leaves no argv to read. Splitting on whitespace is
        # a weaker view — it cannot tell a word from part of a quoted string —
        # and it is named as weaker here rather than handed back as the same
        # answer.
        return text.split()


def invoked_anywhere(rel: str, root: pathlib.Path = ROOT) -> bool:
    """Whether a command the task runner or a workflow executes runs `scripts/<rel>`.

    Asked of the commands, not of the files. The callers are parsed, the
    commands are taken from the positions a runner takes them from, and each
    command is split into the words it would execute. A comment naming the
    path, a `desc:` describing it and a quoted mention inside a command reach
    none of those — which is the point, because this rule exists to reject a
    harness nothing runs and text naming a harness is the cheapest way to look
    like running one.

    Two limits, both toward reporting a harness as UN-invoked. A path assembled
    at run time from a variable is not resolved, so a caller that built one
    fails here. And a word this finds is not proved to be the command's
    executable — an unquoted `echo scripts/x.sh` counts — so what it separates
    is prose from command text, not one word of a command from another.
    """
    wanted = {f"scripts/{rel}", f"./scripts/{rel}"}
    commands, _unreadable = caller_commands(root)
    return any(word in wanted for command in commands for word in command_words(command))


def vacuity_problems(present: set[str], controls, network, not_gates,
                     invoked=None) -> list[str]:
    """The list rules, over lists supplied rather than read off the tree.

    Separated from check_vacuity so each rule can be planted against: every one
    is a statement about which name appears on which list, and supplying the
    lists is how a violation is introduced without editing the repository the
    rest of this file is running inside.
    """
    invoked = invoked_anywhere if invoked is None else invoked
    problems = []

    for name, reason in sorted(not_gates.items()):
        if name not in present:
            problems.append(
                f"{name} is exempted as a harness rather than a gate, but no such "
                f"executable exists under scripts/ — the exemption outlived its file. "
                f"(recorded: {reason})")
            continue
        # A harness excuses itself by asserting its own outcome on every ordinary
        # invocation, which is a claim about a thing that gets invoked. One
        # nothing runs makes the exemption an excuse for an executable that never
        # executes, and its recorded reason is free text nothing else checks.
        if not invoked(name):
            problems.append(
                f"{name} is exempted as a harness that asserts its own outcome, but "
                f"neither Taskfile.yaml nor a workflow under .github/workflows/ runs "
                f"it. A harness nothing invokes asserts nothing. (recorded: {reason})")

    for gate in sorted(present):
        if gate in not_gates:
            continue
        if gate not in controls and gate not in network:
            problems.append(
                f"{gate} ships no positive control and is on no exemption list. A gate "
                f"nobody has shown to fail is an untested assertion about the tree.")

    for gate in sorted(set(controls) | set(network)):
        if gate not in present:
            problems.append(
                f"{gate} is named by a control or an exemption but no longer exists in "
                f"scripts/ — the reference outlived the gate.")
    return problems


def check_vacuity() -> list[str]:
    """The suite cannot shrink quietly, and no exemption may match nothing."""
    present = set(gate_files())
    problems = vacuity_problems(present, CONTROLS, NEEDS_NETWORK, NOT_GATES)

    # The harness-invocation rule reads what the callers run. A caller that will
    # not parse runs nothing as far as that rule can tell, and every harness in
    # it then reads as one nobody invokes — which points the reader at the
    # exemption list instead of at the one file to fix.
    for unreadable in caller_commands(ROOT)[1]:
        problems.append(
            f"{unreadable} — this file decides what runs, and it could not be "
            f"parsed. The harness-invocation rule examined nothing in it, which "
            f"is not the same as it invoking nothing.")

    for gate, call in sorted(NEEDS_NETWORK_PY.items()):
        p = SCRIPTS / gate
        if not p.exists():
            continue
        try:
            calls = called_names(p.read_text())
        except SyntaxError as exc:
            # Reported as its own problem rather than as an absent call. These
            # are different facts and they used to print the same sentence: an
            # unparseable gate yielded an empty call set, which read as "the
            # exemption is stale" and pointed the reader at the exemption list
            # instead of at the file that will not parse.
            problems.append(
                f"{gate} could not be parsed ({exc.msg} at line {exc.lineno}), so its "
                f"network exemption could not be checked. That is not the same as the "
                f"exemption being stale.")
            continue
        if call not in calls:
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


def mutation_landed(rel, before: str, after: str | _Deleted,
                    on_disk: str | _Deleted, marker: str) -> str | None:
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
    if isinstance(after, _Deleted):
        if not isinstance(on_disk, _Deleted):
            return (f"control claims to delete {rel}, but the file is still present — "
                    f"the mutation proved nothing.")
        return None

    if isinstance(on_disk, _Deleted):
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
    cases: list[tuple[str, str, str, str, str, str | None]] = [
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

    # check_vacuity's own verdicts, which decide this file's exit code and which
    # nothing else reaches. Each is a rule about a LIST \u2014 a gate on no list, an
    # exemption naming a file that is gone, a harness nothing runs \u2014 so each is
    # planted by supplying the lists rather than by editing the tree.
    #
    # This is the shape one level down from the one the harness-invocation rule
    # was added to reject: a branch that is correct and asserted by nobody. The
    # NOT_GATES reason for this file says its self-test runs on every invocation,
    # and until these cases existed that sentence covered everything except the
    # branch it was written beside.
    print("\u2500\u2500 Vacuity-rule self-test \u2500\u2500")
    vacuity_cases: list[tuple[str, set[str], set[str], dict, dict, str | None]] = [
        ("a gate on no list at all",
         {"check-x.py"}, set(), {}, {}, "ships no positive control"),
        ("a control naming a gate that is gone",
         set(), {"check-x.py"}, {}, {}, "the reference outlived the gate"),
        ("an exemption naming a harness that is gone",
         set(), set(), {}, {"tests/gone.py": "a reason"},
         "the exemption outlived its file"),
        ("a harness nothing invokes",
         {"tests/gone.py"}, set(), {}, {"tests/gone.py": "a reason"},
         "A harness nothing invokes asserts nothing"),
        ("a gate covered by a control",
         {"check-x.py"}, {"check-x.py"}, {}, {}, None),
    ]
    for name, present_, controls_, network_, not_gates_, expect_ in vacuity_cases:
        found = vacuity_problems(present_, controls_, network_, not_gates_,
                                 invoked=lambda _name: False)
        shown = " ".join(found)
        ok = (not found) if expect_ is None else any(expect_ in p for p in found)
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}: "
              f"{(shown[:70] + chr(8230)) if shown else 'accepted'}")
        bad += 0 if ok else 1
    print()

    print("\u2500\u2500 Mutation-contract self-test \u2500\u2500")
    for case, before, after, disk, marker, expect in cases:
        why = mutation_landed("fixture.yaml", before, after, disk, marker)
        ok = (why is None) if expect is None else (why is not None and expect in why)
        print(f"  {'ok  ' if ok else 'FAIL'}  {case}: {why or 'accepted'}")
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


def population_authority() -> str | None:
    """Why this run cannot establish its own corpus, or None.

    git is not a tool these controls merely shell out to. copy_tree() takes the
    file LIST from the index, and the gates under control scope themselves to
    the tracked set — so git decides WHICH FILES every control in this run
    examines. A tool that defines the population sits above the gates that read
    it, and asserting it inside each gate is too late: by then the fixture is
    already built, and a fixture built from an empty enumeration is a tree on
    which every control passes for the same reason a clean one does.

    Hence before the loop, once, for the whole run.
    """
    if shutil.which("git") is None:
        return ("git is not on PATH. copy_tree() takes its file list from the index "
                "and the gates scope to the tracked set, so without git this run "
                "cannot say what population it exercised anything over.")
    probe = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                           text=True, timeout=GATE_TIMEOUT)
    if probe.returncode != 0:
        err = (probe.stderr or "").strip().splitlines()
        return (f"`git ls-files` failed in {ROOT} — "
                f"{err[0] if err else f'exit {probe.returncode}'}. The corpus every "
                f"fixture is cut from is unknown.")
    if not [r for r in probe.stdout.split("\0") if r]:
        return (f"`git ls-files` reports no tracked files in {ROOT}. Every fixture "
                f"would be empty and every control would pass over nothing.")
    return None


def main() -> int:
    if self_test():
        return 1
    blocked = population_authority()
    if blocked:
        print("── Population authority ──")
        print(f"  CANNOT RUN  {blocked}")
        print("\nPositive-control gate did NOT run. That is not a pass.")
        return CANNOT_RUN
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

    # Counted at the END of the loop body, after run_control has returned a
    # verdict — so `proven` is cases that completed a proof, not entries the
    # registry happened to name.
    #
    # Those are different quantities and only the second used to be gated, from
    # BEFORE the loop ran. `len(items)` is what the registry selected; a control
    # that left the loop without proving or failing anything would not move it,
    # and the summary would read the same either way.
    proven = 0
    failed = 0
    for gate, what, mutate in items:
        ok, detail = run_control(gate, what, mutate)
        print(f"  {'ok  ' if ok else 'FAIL'}  {gate}: {detail}")
        if ok:
            proven += 1
        else:
            failed += 1

    print()
    silent = len(items) - (proven + failed)
    if silent:
        print(f"FAIL  {silent} control(s) left the loop without proving or failing "
              f"anything, so this run licenses nothing.")
        return 1
    if failed:
        print(f"Positive-control gate FAILED: {failed} of {len(items)} controls did not hold.")
        return 1
    if not only and proven < MIN_CONTROLS_RUN:
        print(f"FAIL  only {proven} control(s) completed a proof, under the floor of "
              f"{MIN_CONTROLS_RUN}. The registry naming a gate for every entry is a "
              f"different claim from having exercised them.")
        return 1
    print(f"✓ every gate with a control rejects the violation it names "
          f"({proven} control(s) completed a proof)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
