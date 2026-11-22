#!/usr/bin/env python3
"""Every workflow reads AWS account ids and role ARNs as secrets, and masks them first.

Ported from nanohype/landing-zone's scripts/check-workflow-id-masking.py at
8c3c76c10e4cc3c3f5edd95c23714166bfbc00d9 (landing-zone#286). The expression
reader, the id recognition, the sinks, the mask-step shape, the literal-id and
derived-value rules and the anti-vacuity floor are that gate's. What differs is
where a secret lives, and the floor's numbers; both are marked below.

WHY THIS EXISTS

The repository is public, and so are its Actions logs. ci.yml's `charts` and
`image-vulnerabilities` jobs read the ECR Public pull role's ARN, which carries
the AWS account id that owns the role, to log in to public.ecr.aws.

Masking cannot rescue a VARIABLE. The runner prints a variable in the env block
of every step that receives it, and an action prints it among its inputs
(`role-to-assume`), before any step of the job can register a mask. Only a
SECRET is masked from the job's first line, and only whole: the account id
inside a role ARN, an ARN in an STS AccessDenied message, a value an expression
computes from the secret (`fromJSON(secrets.MAP).dev`) all print in the clear
unless the job registers them. So the rule has four parts, and an edit can break
any one of them while every other gate stays green and the first symptom is an
account id in a public log:

  - the value is a secret, at the level its consumer's trust requires (below);
  - the first step in the job that receives it runs the mask script as its
    first command, unconditionally, so every derived piece is masked before
    anything prints;
  - it reaches a step only whole, as `${{ secrets.NAME }}`, and pieces of it
    are cut out in shell after the mask and handed on as step outputs;
  - it reaches nothing that runs earlier: no workflow- or job-level env, no
    `run:` text, no action input ahead of the mask.

WHERE A SECRET LIVES (this repository's departure from landing-zone)

landing-zone keeps every id on the GitHub Environment its job declares, and a
no-environment job refuses the same name at repository level. That does not fit
the one id this repository reads. ECR_PUBLIC_PULL_ROLE_ARN names a role whose
OIDC trust is this repository's `pull_request` and `ref:refs/heads/main`
subjects (landing-zone's github-oidc `ecr_public_pull_subject_claims` default,
applied by its ecr-public-pull leaf). A job that declares an environment is
issued a token whose `sub` is `repo:<owner>/<repo>:environment:<name>`, which
the role does not trust, and the jobs that read it run on every pull request.
So it is a REPOSITORY secret, and REPOSITORY_LEVEL_IDS names it as one.

  - A name on REPOSITORY_LEVEL_IDS may be read by a job with no environment, and
    may not be read by a job that declares one: there the secrets context would
    hand it the environment's same-named secret first, and the role would refuse
    the token anyway.
  - Any other id is held to landing-zone's rule: the job reading it declares an
    environment and needs a no-environment job comparing `secrets.NAME` against
    '' (refuse-inherited-config). No workflow here does that today; the rule is
    kept so the next id arrives under it rather than under this exception.

HOW AN EXPRESSION IS READ

Each `${{ }}` (and each bare `if:`) is tokenised, not pattern-matched, because
the expression language has more than one spelling for a read: context names
are case-insensitive (`Secrets.X`, `VARS.X`), a property can be indexed
(`secrets['X']`, `github.event.inputs['x']`), and a whole context can be read
at once (`toJSON(secrets)`). A literal index resolves to its name. A read of a
whole `secrets`, `vars` or `inputs` context, or one through a computed index
(`vars[format('{0}_ACCOUNT_ID', matrix.env)]`) or a `*` filter, is a finding
wherever it appears: the gate cannot tell what it names, so it cannot prove it
names no id. An expression the tokeniser cannot read is a finding when it
mentions one of those contexts. Secret, variable and input names are compared
case-insensitively, as GitHub resolves them.

HOW AN ID IS RECOGNISED

By name, by use, and by where it goes.

  - By name. A name whose `_`- or `-`-separated words include ROLE_ARN(S),
    ARN(S), ACCOUNT_ID(S), ACCOUNT_NUMBER(S), AWS_ACCOUNT(S), STATE_BUCKET(S)
    or TFSTATE is an id (ECR_PUBLIC_PULL_ROLE_ARN, aws_account). THIS IS A
    NAMING RULE for the repository, not only a heuristic: a secret, variable or
    input that carries an account id or a role ARN is named so that it matches.
    CLAUDE.md states it.
  - By use. Any secret or variable, whatever its name, that some workflow
    passes as `role-to-assume`, puts whole into an env or `with:` key whose own
    name is an id (ACCOUNT_ID, E2E_ACCOUNT_ID), or hands a mask step to mask, is
    an id everywhere.
  - By where it goes (the sinks). Such a key, a mask step's masked env keys and
    `role-to-assume` accept only a secret read whole, an output of a mask step
    earlier in the job, the guard form, or a literal (which rule 9 reads).
    Never a variable, an input, a matrix value or another job's output,
    whatever its name.
  - In a job that can hold AWS credentials (it uses configure-aws-credentials
    or may mint an OIDC token), no variable is read at all except in the guard
    form or by name from VARS_ALLOWED, which is empty: such a job has no reason
    to read configuration that is not a secret, and a variable named outside
    the rule is still printed.

WHAT IT CHECKS, in every workflow under .github/workflows

  1. No id is read from `vars.`, and an AWS job reads no variable (above). The
     one exception is the guard form, which compares against '' and passes only
     `true` or `false`: `${{ vars.NAME != '' }}` (and the same for `secrets.`).
     No `secrets`, `vars` or `inputs` context is read whole or through a
     computed index.
  2. No workflow_dispatch or workflow_call input is an id, and no expression
     reads an input with an id's name.
  3. An id secret's value appears only as the ENTIRE value of a step's `env:`
     entry or `with:` input: `${{ secrets.NAME }}` and nothing else. Anything
     that computes from it (`fromJSON(...)`, `toJSON(...)`, `format(...)`, an
     index, a concatenation) yields a value the runner does not know to mask,
     printed in the env block of that step before its first command can mask
     it. Not in a workflow- or job-level `env:` either: a job-level env is in
     the process environment of every step from the first one, checkout and
     third-party setup actions included, so no step ordering can put the mask
     ahead of it. Not in `run:` text, `if:`, `name:`, `working-directory:`,
     job outputs or a reusable workflow's `with:`/`secrets:`, and no job passes
     `secrets: inherit`, which hands every id to a callee this gate cannot read.
  4. Where the secret lives (WHERE A SECRET LIVES above): a REPOSITORY_LEVEL_IDS
     name only in jobs with no environment; any other id only in a job that
     declares an environment and needs a no-environment job refusing the
     inherited name. A job with no environment may otherwise only use the
     guard form.
  5. For each id secret, the first step in the job that receives it (in `env:`
     or `with:`) is a `run` step whose first command is the mask script, in the
     script's own grammar, naming every env key in that step that carries the
     secret:
       bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" [--optional] NAME...
     with --optional only first and each NAME an environment variable name. The
     script must be in the tree and byte-identical to the landing-zone copy
     scripts/vendored.json records (by SHA-256), and every key the command
     names must be in the step's env holding `${{ secrets.X }}`. A mask step
     must run whenever the job does and stop it on failure: no `if:`, no
     `continue-on-error`, and a shell (the step's, else the job's
     `defaults.run.shell`, else the workflow's) that is unset or `bash`. A
     later step that receives the secret may not run after a failure
     (`always()`, `failure()`, `cancelled()` in its `if:`): a step before the
     mask failing skips the mask, and such a step would then run unmasked.
  6. `role-to-assume` (an input name, so matched case-insensitively, as the
     runner reads it) is `${{ secrets.NAME }}` read after rule 5's mask, or
     `${{ steps.ID.outputs.X }}` from a mask step earlier in the same job. Never
     a variable, a matrix value, an input or a literal.
  7. Every aws-actions/configure-aws-credentials step (owner and repository
     compared case-insensitively, as GitHub resolves them) sets
     `mask-aws-account-id: true` (the input name compared case-insensitively).
  8. For every id a workflow reads as a secret, the workflow also compares
     `vars.NAME` against '' (the guard), so a value left behind as a variable
     from before it became a secret fails the run instead of sitting there
     until the next edit prints it.
  9. No string in a workflow other than a `uses:` reference carries a literal
     twelve-digit account id or an ARN with one, except the tree's synthetic
     placeholders (one digit repeated, or 123456789012). An unquoted number
     counts: YAML reads it as an int, the runner prints it as text. It is read
     as the text it was written as, so an id YAML 1.1 takes for octal (digits
     0-7 behind a leading 0) is still seen.

No finding repeats an account id it quotes from a workflow: a run of twelve or
more digits other than a placeholder is printed as <account id>, because a
finding is an annotation that outlives the diff it came from. Quoted text is
redacted before it is cut, and a YAML parse error is reported as the parser's
problem, context, line and column, without the excerpt PyYAML has already cut
to length before the redaction could see it. The self-test fails a mutation
whose findings carry an id, or the head or tail of one it planted.

Rules 4 and 8 check that the comparison exists, not what the shell does with
it; the workflow's step fails on `true`, and its message names the `gh` command
that removes the value.

THE MASK SCRIPT IS VENDORED

scripts/mask-aws-ids.sh is landing-zone's, byte for byte. scripts/vendored.json
records the repository, path, commit and SHA-256 it was taken at, and this gate
fails when the bytes on disk stop hashing to that record: a weakened copy here
(a narrower id pattern, a refusal moved ahead of the masks) would otherwise pass
every check that only asks whether the script is run. A change to the script
lands in landing-zone first, with its self-test, and is re-vendored here with
the record moved in the same commit. The script's own `--self-test` runs in CI
(the `workflow-id-masking` job) and locally under `task validate:workflow-id-masking`.

USAGE

  check-workflow-id-masking.py              check .github/workflows
  check-workflow-id-masking.py --self-test  mutate copies of the workflows in
                                            ways the rules forbid and require
                                            each to be rejected, citing the file
                                            and the mutated line, with no
                                            account id (nor the head or tail of
                                            one it planted) in any finding

Exit 0 = clean. Exit 1 = a violation. Exit 2 = a scan that could not see its
inputs (CANNOT_RUN, as every gate in this repository reports it).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import gatelib

CANNOT_RUN = gatelib.CANNOT_RUN

try:
    import yaml
except ImportError:
    print(
        "Cannot run: PyYAML is not installed, so this gate cannot read the workflows. "
        "Refusing to report a pass over files it could not parse.",
        file=sys.stderr,
    )
    sys.exit(CANNOT_RUN)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_REL = ".github/workflows"
MASK_SCRIPT = "scripts/mask-aws-ids.sh"
VENDORED_REL = "scripts/vendored.json"

ID_NAME = re.compile(
    r"(?:^|[_-])(?:ROLE[_-]ARNS?|ARNS?|ACCOUNT[_-]IDS?|ACCOUNT[_-]NUMBERS?|AWS[_-]ACCOUNTS?"
    r"|STATE[_-]BUCKETS?|TFSTATE)(?:[_-]|$)",
    re.IGNORECASE,
)
# with: keys that look like an id by name and hold a switch, not an id.
NOT_A_SINK = {"mask-aws-account-id"}
EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
WS = r'"?\$(?:\{GITHUB_WORKSPACE\}|GITHUB_WORKSPACE)'
# The script's own grammar: --optional only first, then environment variable names.
MASK_AWS = re.compile(
    rf"^bash\s+{WS}/(scripts/mask-aws-ids\.sh)\"?(\s+--optional)?((?:\s+[A-Za-z_][A-Za-z0-9_]*)+)\s*$"
)
CONFIGURE_AWS = "aws-actions/configure-aws-credentials"
AFTER_FAILURE = re.compile(r"\b(?:always|failure|cancelled)\s*\(", re.IGNORECASE)
ARN_LITERAL = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12})(?![0-9])")
ID_LITERAL = re.compile(r"(?<![0-9A-Za-z])([0-9]{12})(?![0-9A-Za-z])")
# Variable names a job holding AWS credentials may read other than in the guard
# form. Empty: add a name here only with the reason it can never carry an id.
VARS_ALLOWED: set[str] = set()
# Id secrets that live at REPOSITORY level, each with the reason an environment
# cannot hold it (see WHERE A SECRET LIVES above). Upper-case names.
REPOSITORY_LEVEL_IDS = {
    "ECR_PUBLIC_PULL_ROLE_ARN": (
        "the ECR Public pull role trusts this repository's pull_request and "
        "ref:refs/heads/main OIDC subjects, and a job declaring an environment is "
        "issued an environment subject the role does not trust"
    ),
}
# The ids the workflows read today. The floor requires the scan to have seen
# each one read as a secret, so a tokeniser that stops recognising reads cannot
# report a clean tree.
KNOWN_ID_READS = {"ECR_PUBLIC_PULL_ROLE_ARN"}
# The floor's other half: the workflows and mask steps the tree holds today, set
# at today's count (ci.yml, chart-provenance.yml, diff.yml; one mask step in
# each of ci.yml's charts and image-vulnerabilities jobs). A reader that stops
# seeing either reports a clean tree; a count under these cannot.
MIN_WORKFLOWS = 3
MIN_MASK_STEPS = 2


# --- YAML with line numbers ---------------------------------------------------


class LDict(dict):
    line = 0

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.key_lines: dict = {}
        self.value_lines: dict = {}


class LList(list):
    line = 0


class LineLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    d = LDict()
    d.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        d[key] = loader.construct_object(value_node, deep=True)
        d.key_lines[key] = key_node.start_mark.line + 1
        block = isinstance(value_node, yaml.ScalarNode) and value_node.style in ("|", ">")
        d.value_lines[key] = value_node.start_mark.line + 1 + (1 if block else 0)
    return d


def _sequence(loader, node):
    s = LList(loader.construct_sequence(node, deep=True))
    s.line = node.start_mark.line + 1
    return s


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _sequence)


class LInt(int):
    """An int that keeps the text YAML read it from, in `raw`."""

    raw = ""


class LFloat(float):
    """A float that keeps the text YAML read it from, in `raw`."""

    raw = ""


def _int(loader, node):
    v = LInt(loader.construct_yaml_int(node))
    v.raw = node.value
    return v


def _float(loader, node):
    v = LFloat(loader.construct_yaml_float(node))
    v.raw = node.value
    return v


# The loader resolves YAML 1.1, where an unquoted run of digits 0-7 with a
# leading 0 is octal: `012345670123` constructs as 1402433619, and its decimal
# text no longer looks like an account id. Keeping the source text lets the
# literal-id rule read what the file says.
LineLoader.add_constructor("tag:yaml.org,2002:int", _int)
LineLoader.add_constructor("tag:yaml.org,2002:float", _float)


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def number_texts(value) -> list[str]:
    """The text a number was written as, then its value's text where that differs.

    The source text is what the public file carries (`012345670123`, octal to
    YAML 1.1); the value's text covers a spelling the source text hides
    (`222_233_334_444`, which YAML 1.1 reads as 222233334444)."""
    return list(dict.fromkeys(t for t in (getattr(value, "raw", ""), str(value)) if t))


def strings_with_lines(value, line: int, skip_keys: tuple = (), numbers: bool = False):
    """(string, line) for every string inside a parsed value, keys included.

    numbers: also yield each integer and float scalar, and each such key, as
    the text it was written as and as its value's text. An unquoted
    `OWNER: 222233334444` is an int to YAML and a string to the runner, which
    prints it in the env block like any other value, so the literal-id rule
    has to see it; the expression rules have nothing to read in a number."""
    if isinstance(value, str):
        yield value, line
    elif numbers and _number(value):
        for t in number_texts(value):
            yield t, line
    elif isinstance(value, LDict):
        for k, v in value.items():
            kl = value.key_lines.get(k, value.line)
            if isinstance(k, str):
                yield k, kl
            elif numbers and _number(k):
                for t in number_texts(k):
                    yield t, kl
            if k in skip_keys:
                continue
            yield from strings_with_lines(v, value.value_lines.get(k, kl), skip_keys, numbers)
    elif isinstance(value, list):
        base = getattr(value, "line", line)
        for v in value:
            yield from strings_with_lines(v, getattr(v, "line", base), skip_keys, numbers)


def line_in(text: str, start_line: int, needle_index: int) -> int:
    return start_line + text.count("\n", 0, needle_index)


def first_command(run: str) -> tuple[str, int]:
    """The first command of a run block and its offset in lines."""
    for i, raw in enumerate(run.splitlines()):
        line = raw.strip()
        if line and not line.startswith("#"):
            return line, i
    return "", 0


def is_id_name(name: str) -> bool:
    return bool(ID_NAME.search(name))


def is_sink_key(key) -> bool:
    return isinstance(key, str) and key.lower() not in NOT_A_SINK and is_id_name(key)


def placeholder(digits: str) -> bool:
    return len(set(digits)) == 1 or digits == "123456789012"


ID_RUN = re.compile(r"(?<![0-9])[0-9]{12,}(?![0-9])")


def redact(text: str) -> str:
    """text with every run of twelve or more digits, other than a placeholder, replaced.

    A finding quotes workflow text (an expression, an input's value, a step
    name) and is printed as an `::error` annotation, which stays on the pull
    request and in the run log after the diff that carried the text is gone.
    The gate that rejects an account id written into a workflow must not be
    what publishes it a second time."""
    return ID_RUN.sub(
        lambda m: (
            m.group(0) if len(m.group(0)) == 12 and placeholder(m.group(0)) else "<account id>"
        ),
        text,
    )


def quote(text, limit: int) -> str:
    """repr of the first `limit` characters of text, redacted before it is cut.

    Cutting first could leave the head of an account id under twelve digits,
    where the redaction no longer recognises it."""
    return repr(redact(str(text))[:limit])


def parse_error(e) -> str:
    """A YAML load failure as a finding: what the parser objected to and where.

    Not str(e): PyYAML's message for a marked error quotes the offending line,
    already cut to about 75 characters around the column with ` ... `. That
    cut happens before redact() sees the text, so the head or tail of an id at
    the cut is too short to recognise and is published. The problem, its
    context and their line and column say everything the excerpt does; the
    line itself is in the file."""
    if isinstance(e, yaml.MarkedYAMLError):
        parts = [
            what + (f" (line {mark.line + 1}, column {mark.column + 1})" if mark else "")
            for what, mark in ((e.context, e.context_mark), (e.problem, e.problem_mark))
            if what
        ]
        if e.note:
            parts.append(e.note)
        text = "; ".join(parts) or type(e).__name__
    else:
        text = str(e)
    return redact(f"could not be parsed: {text}")


def with_key(block, key: str):
    """(spelling, value) of `key` in a `with:` map, compared case-insensitively.

    The runner hands an action its inputs as INPUT_<NAME upper-cased>, so
    `Role-To-Assume` configures the action exactly as `role-to-assume` does."""
    if isinstance(block, dict):
        for k in block:
            if isinstance(k, str) and k.lower() == key:
                return k, block[k]
    return None


# --- expressions --------------------------------------------------------------

TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^']|'')*')
  | (?P<num>-?(?:0x[0-9A-Fa-f]+|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?))
  | (?P<ident>[A-Za-z_][A-Za-z0-9_-]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||[!<>().,\[\]*])
""",
    re.VERBOSE,
)
CONTEXT_WORDS = re.compile(r"(?i)\b(?:secrets|vars|inputs)\b")


def tokenize(expr: str):
    toks, i = [], 0
    while i < len(expr):
        m = TOKEN.match(expr, i)
        if not m:
            return None
        i = m.end()
        if m.lastgroup != "ws":
            toks.append((m.lastgroup, m.group()))
    return toks


class Ref:
    """A context read: its name (lower-cased), the accessor chain, and its span."""

    def __init__(self, ctx: str, path: list, start: int, end: int):
        self.ctx, self.path, self.start, self.end = ctx, path, start, end


def refs(toks) -> list[Ref]:
    out, n = [], len(toks)
    for i, (kind, value) in enumerate(toks):
        if (
            kind != "ident"
            or (i and toks[i - 1][1] == ".")
            or (i + 1 < n and toks[i + 1][1] == "(")
        ):
            continue
        if value.lower() in ("true", "false", "null"):
            continue
        path, j = [], i + 1
        while j < n:
            if toks[j][1] == "." and j + 1 < n:
                k, v = toks[j + 1]
                if k == "ident":
                    path.append(("name", v))
                elif v == "*":
                    path.append(("star", None))
                else:
                    break
                j += 2
            elif toks[j][1] == "[":
                depth, m = 1, j + 1
                while m < n and depth:
                    depth += {"[": 1, "]": -1}.get(toks[m][1], 0)
                    m += 1
                inner = toks[j + 1 : m - 1]
                if len(inner) == 1 and inner[0][0] == "str":
                    path.append(("name", inner[0][1][1:-1].replace("''", "'")))
                else:
                    path.append(("dynamic", None))
                j = m
            else:
                break
        out.append(Ref(value.lower(), path, i, j))
    return out


def resolve(r: Ref):
    """(context, name, problem) for a secrets/vars/inputs read, else None.

    context is 'secrets', 'vars' or 'inputs'; problem is None, 'whole' (the
    context itself) or 'computed' (a dynamic index or a filter)."""
    path = r.path
    if r.ctx == "github":
        if (
            len(path) >= 2
            and path[0][0] == "name"
            and path[0][1].lower() == "event"
            and path[1][0] == "name"
            and path[1][1].lower() == "inputs"
        ):
            ctx, path = "inputs", path[2:]
        else:
            return None
    elif r.ctx in ("secrets", "vars", "inputs"):
        ctx = r.ctx
    else:
        return None
    if not path:
        return ctx, None, "whole"
    if path[0][0] != "name":
        return ctx, None, "computed"
    return ctx, path[0][1], None


def sole(toks, rs) -> Ref | None:
    """The one read that is the whole expression, with a single accessor."""
    if len(rs) == 1 and rs[0].start == 0 and rs[0].end == len(toks):
        return rs[0]
    return None


def guard_ref(toks, rs) -> Ref | None:
    """The read in `ctx.NAME != ''` (or ==, either order), else None."""
    if len(rs) != 1:
        return None
    r = rs[0]
    before, after = toks[: r.start], toks[r.end :]
    cmp = ("==", "!=")
    if not before and len(after) == 2 and after[0][1] in cmp and after[1] == ("str", "''"):
        return r
    if not after and len(before) == 2 and before[0] == ("str", "''") and before[1][1] in cmp:
        return r
    return None


def expressions(text: str, is_if: bool):
    """(expression, offset) for each `${{ }}` in text; a bare `if:` is one."""
    spans = [(m.group(1), m.start()) for m in EXPR.finditer(text)]
    if is_if and "${{" not in text:
        spans = [(text, 0)]
    return spans


def exact_expr(text) -> str | None:
    """The expression when the whole string is one `${{ }}`, else None."""
    if not isinstance(text, str):
        return None
    m = EXPR.fullmatch(text.strip())
    return m.group(1) if m else None


def whole_read_name(text) -> str | None:
    """NAME when the whole string is `${{ secrets.NAME }}` (any spelling)."""
    expr = exact_expr(text)
    toks = tokenize(expr) if expr is not None else None
    if not toks:
        return None
    r = sole(toks, refs(toks))
    got = resolve(r) if r else None
    if r is not None and got and got[0] == "secrets" and got[2] is None and len(r.path) == 1:
        return got[1]
    return None


def named_reads(text) -> set[str]:
    """Upper-cased secret and variable names a string reads by name."""
    names: set[str] = set()
    if not isinstance(text, str):
        return names
    for expr, _ in expressions(text, False):
        toks = tokenize(expr) or []
        for r in refs(toks):
            got = resolve(r)
            if got and got[0] in ("secrets", "vars") and got[1]:
                names.add(got[1].upper())
    return names


def step_output_whole(text) -> str | None:
    """ID when the whole string is `${{ steps.ID.outputs.X }}`."""
    expr = exact_expr(text)
    toks = tokenize(expr) if expr is not None else None
    if not toks:
        return None
    r = sole(toks, refs(toks))
    if (
        r
        and r.ctx == "steps"
        and len(r.path) == 3
        and all(k == "name" for k, _ in r.path)
        and r.path[1][1].lower() == "outputs"
    ):
        return r.path[0][1].lower()
    return None


def is_guard(text) -> bool:
    expr = exact_expr(text)
    toks = tokenize(expr) if expr is not None else None
    if not toks:
        return False
    r = guard_ref(toks, refs(toks))
    got = resolve(r) if r else None
    return bool(
        r is not None
        and got
        and got[0] in ("secrets", "vars")
        and got[2] is None
        and len(r.path) == 1
    )


def mask_command(step) -> tuple[str | None, set[str] | None, int]:
    """(script, names it masks, line offset) when the step's first command masks."""
    raw = step.get("run") if isinstance(step, dict) else None
    run = raw if isinstance(raw, str) else ""
    cmd, offset = first_command(run)
    m = MASK_AWS.match(cmd)
    if m:
        return m.group(1), set(m.group(3).split()), offset
    return None, None, offset


def uses_configure_aws(step) -> bool:
    uses = step.get("uses") if isinstance(step, dict) else None
    return isinstance(uses, str) and uses.split("@")[0].strip().lower() == CONFIGURE_AWS


def job_steps(job):
    steps = job.get("steps") if isinstance(job, dict) else None
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def shell_of(node) -> str | None:
    d = node.get("defaults") if isinstance(node, dict) else None
    r = d.get("run") if isinstance(d, dict) else None
    s = r.get("shell") if isinstance(r, dict) else None
    return s if isinstance(s, str) else None


def holds_aws(doc, job) -> bool:
    if any(uses_configure_aws(s) for s in job_steps(job)):
        return True
    perms = job.get("permissions", doc.get("permissions"))
    if perms == "write-all":
        return True
    return isinstance(perms, dict) and str(perms.get("id-token", "")).lower() == "write"


def collect_ids_by_use(docs) -> set[str]:
    """Upper-cased secret/variable names that reach an id sink, in any workflow."""
    names = set()
    for doc in docs.values():
        if not isinstance(doc, dict):
            continue
        blocks = [doc.get("env")]
        for job in (doc.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            blocks.append(job.get("env"))
            for step in job_steps(job):
                _, covers, _ = mask_command(step)
                for key in ("env", "with"):
                    block = step.get(key)
                    if not isinstance(block, dict):
                        continue
                    for k, v in block.items():
                        if (
                            str(k).lower() == "role-to-assume"
                            or is_sink_key(k)
                            or (key == "env" and covers and k in covers)
                        ):
                            names |= named_reads(v)
        for block in blocks:
            if isinstance(block, dict):
                for k, v in block.items():
                    if is_sink_key(k):
                        names |= named_reads(v)
    return names


# --- the check ----------------------------------------------------------------


class Result:
    def __init__(self):
        self.findings: list[tuple[str, int, str]] = []
        self.mask_steps = 0
        self.id_reads = 0
        self.id_names: set[str] = set()
        self.workflows = 0


def vendored_findings(root: Path) -> list[tuple[str, int, str]]:
    """The mask script is the copy scripts/vendored.json records, byte for byte.

    The record holds the source repository, path and commit and the SHA-256 of
    the bytes taken from there. A copy edited here (a narrower id pattern, a
    refusal moved ahead of the masks, a stray echo) would pass every rule that
    only asks whether the script runs, and first show itself as an id in a log.
    """
    record_path = root / VENDORED_REL
    try:
        record = json.loads(record_path.read_text())
    except (OSError, ValueError) as e:
        return [
            (
                VENDORED_REL,
                1,
                f"could not be read as JSON ({e}), so the mask script "
                "cannot be shown to be the copy it was taken as.",
            )
        ]
    entry = record.get(MASK_SCRIPT) if isinstance(record, dict) else None
    if not isinstance(entry, dict) or not all(
        isinstance(entry.get(k), str) and entry.get(k) for k in ("repo", "path", "commit", "sha256")
    ):
        return [
            (
                VENDORED_REL,
                1,
                f"has no complete record for {MASK_SCRIPT} (repo, path, "
                "commit and sha256), so nothing says which bytes the "
                "mask script must be.",
            )
        ]
    script = root / MASK_SCRIPT
    if not script.is_file():
        return [
            (MASK_SCRIPT, 1, "is not in the tree, so nothing masks the ids the workflows read.")
        ]
    want = entry["sha256"]
    got = hashlib.sha256(script.read_bytes()).hexdigest()
    if got != want:
        return [
            (
                MASK_SCRIPT,
                1,
                f"hashes to {got[:12]}, not the {want[:12]} {VENDORED_REL} records for "
                f"{entry['repo']}:{entry['path']} at {entry['commit'][:12]}. It is "
                "vendored byte for byte: change it in that repository, with its "
                "self-test, then copy it here and move the record in the same commit.",
            )
        ]
    return []


def check(root: Path) -> Result:
    res = Result()
    wf_dir = root / WORKFLOWS_REL
    paths = (
        sorted(p for p in wf_dir.glob("*") if p.suffix in (".yml", ".yaml") and p.is_file())
        if wf_dir.is_dir()
        else []
    )
    res.workflows = len(paths)
    res.findings.extend(vendored_findings(root))
    docs = {}
    for p in paths:
        try:
            docs[p] = yaml.load(p.read_text(), Loader=LineLoader)
        except (OSError, yaml.YAMLError) as e:
            res.findings.append((p.relative_to(root).as_posix(), 1, parse_error(e)))
    by_use = collect_ids_by_use(docs)

    def ident(name: str) -> bool:
        return is_id_name(name) or name.upper() in by_use

    for path, doc in docs.items():
        if not isinstance(doc, dict):
            continue
        rel = path.relative_to(root).as_posix()
        out: list[tuple[str, int, str]] = []
        sub = Result()
        check_workflow(root, rel, doc, ident, out, sub)
        res.findings.extend(out)
        res.mask_steps += sub.mask_steps
        res.id_reads += sub.id_reads
        res.id_names |= sub.id_names
    return res


def check_workflow(root, rel, doc, ident, out, res) -> None:
    def bad(line: int, msg: str) -> None:
        out.append((rel, line, redact(msg)))

    raw_jobs = doc.get("jobs")
    jobs: LDict = raw_jobs if isinstance(raw_jobs, LDict) else LDict()
    guarded_vars: set[str] = set()  # vars.NAME compared against ''
    id_reads: dict[str, tuple[str, int]] = {}  # NAME -> (spelling, first line)
    wf_shell = shell_of(doc)

    def literal_ids(value, line):
        for text, ln in strings_with_lines(value, line, skip_keys=("uses",), numbers=True):
            for pat, what in (
                (ARN_LITERAL, "an ARN naming an account"),
                (ID_LITERAL, "an account id"),
            ):
                for m in pat.finditer(text):
                    if not placeholder(m.group(1)):
                        bad(
                            line_in(text, ln, m.start()),
                            f"carries {what} as a literal (not repeated here). A literal is printed "
                            "wherever it is used and kept in the public repository besides; it "
                            "belongs in a secret (see WHERE A SECRET LIVES in this gate). Only the tree's "
                            "synthetic placeholders (one digit repeated, or 123456789012) may "
                            "appear in a workflow.",
                        )

    def scan(
        value,
        line,
        where: str,
        *,
        aws_job: bool,
        guards: set | None = None,
        entry: bool = False,
        is_if: bool = False,
    ) -> set[str]:
        """Apply rules 1-3 to every expression in value. Returns {id secret} read.

        entry: value is one step env/with entry, where an id secret may appear
        whole. guards: collects the secrets this job compares against ''."""
        found = set()
        for text, ln in strings_with_lines(value, line):
            whole = exact_expr(text)
            for expr, idx in expressions(text, is_if):
                at = line_in(text, ln, idx)
                toks = tokenize(expr)
                if toks is None:
                    if CONTEXT_WORDS.search(expr):
                        bad(
                            at,
                            f"has an expression in its {where} this gate cannot read "
                            f"({quote(expr.strip(), 60)}) that mentions the secrets, vars or "
                            "inputs context. Write it in a form the gate can read, so it "
                            "can prove it names no account id or role ARN.",
                        )
                    continue
                rs = refs(toks)
                g = guard_ref(toks, rs)
                s = sole(toks, rs)
                for r in rs:
                    got = resolve(r)
                    if not got:
                        continue
                    ctx, name, problem = got
                    if problem:
                        how = (
                            "the whole"
                            if problem == "whole"
                            else "a computed index or filter of the"
                        )
                        bad(
                            at,
                            f"reads {how} `{ctx}` context in its {where} "
                            f"({quote(expr.strip(), 60)}). This gate cannot tell what that "
                            "names, so it cannot prove it names no account id or role ARN; "
                            "a whole context printed or passed on carries every id in it. "
                            f"Read each value by its literal name (`{ctx}.NAME`).",
                        )
                        continue
                    key = name.upper()
                    if r is g and len(r.path) == 1 and ctx in ("secrets", "vars"):
                        if ctx == "vars":
                            guarded_vars.add(key)
                        elif guards is not None:
                            guards.add(key)
                        continue
                    if ctx == "inputs":
                        if ident(name):
                            bad(
                                at,
                                f"reads the input {name}, an AWS account id or role ARN. An "
                                "input cannot be masked before it is printed; take it from "
                                "a secret instead.",
                            )
                        continue
                    if ctx == "vars":
                        if ident(name):
                            bad(
                                at,
                                f"reads {name}, an AWS account id or role ARN, from "
                                "`vars.` in its " + where + ". A variable is never masked: "
                                "the runner prints it in the env block and the inputs of every "
                                "step that receives it, before any step can mask it. Make it a "
                                "secret (see docs/runbooks/render-gate-failures.md for "
                                "ECR_PUBLIC_PULL_ROLE_ARN); only the guard form "
                                f"`${{{{ vars.{name} != '' }}}}` may name the variable.",
                            )
                        elif aws_job and key not in VARS_ALLOWED:
                            bad(
                                at,
                                f"reads the variable {name} in its {where}, in a job that can "
                                "hold AWS credentials. Such a job reads no variable except in "
                                "the guard form: a variable is printed unmasked, and one named "
                                "outside the id naming rule (a state bucket, an account under "
                                "another name) still carries an account id. Make it a secret, or "
                                "add the name to VARS_ALLOWED with the reason it can never "
                                "carry an id.",
                            )
                        continue
                    if not ident(name):
                        continue
                    res.id_reads += 1
                    res.id_names.add(key)
                    id_reads.setdefault(key, (name, at))
                    found.add(key)
                    whole_value = (
                        entry
                        and whole is not None
                        and whole == expr
                        and s is r
                        and len(r.path) == 1
                    )
                    if whole_value:
                        continue
                    if entry:
                        bad(
                            at,
                            f"computes from the id secret {name} in its {where} "
                            f"({quote(expr.strip(), 60)}). The runner masks a secret only "
                            "whole: a value derived from it (fromJSON, toJSON, format, an "
                            "index, a concatenation) is printed in the clear in this step's "
                            "env block, before its first command can mask it. Pass "
                            f"`${{{{ secrets.{name} }}}}` whole, and cut pieces out in shell "
                            "after the mask command, handing them on as step outputs.",
                        )
                    else:
                        bad(
                            at,
                            f"passes the id secret {name} through its {where}. It may "
                            "reach a step only through that step's `env:` map or `with:` "
                            "inputs, whole, after the job's mask step: anywhere else it "
                            "reaches steps that run before the mask, or is expanded into "
                            "text where its pieces are printed unmasked.",
                        )
        return found

    def sink_check(key, value, line, where, mask_ids: set | None):
        """An id-named key takes only a whole secret, a mask-step output or a guard."""
        for text, ln in strings_with_lines(value, line):
            for expr, idx in expressions(text, False):
                if mask_ids is not None and whole_read_name(text) is not None:
                    continue
                if is_guard(text):
                    continue
                sid = step_output_whole(text)
                if mask_ids is not None and sid is not None and sid in mask_ids:
                    continue
                allowed = (
                    (
                        "`${{ secrets.NAME }}` whole, an output of a mask step earlier in "
                        "this job, or the guard form"
                    )
                    if mask_ids is not None
                    else "only the guard form (a secret or a mask-step output cannot be here)"
                )
                bad(
                    line_in(text, ln, idx),
                    f"sets {key}, which by its name carries an account id or role ARN, from "
                    f"{quote(expr.strip(), 60)} in its {where}. Such a key takes {allowed}: a "
                    "variable, an input, a matrix value or another job's output is printed "
                    "unmasked in this step's env block or inputs, whatever it is called.",
                )

    # Workflow-level: triggers' inputs and everything but jobs.
    on = doc.get("on", doc.get(True))
    if isinstance(on, dict):
        for trig in ("workflow_dispatch", "workflow_call"):
            spec = on.get(trig)
            inputs = spec.get("inputs") if isinstance(spec, dict) else None
            if isinstance(inputs, LDict):
                for name in inputs:
                    if isinstance(name, str) and ident(name):
                        bad(
                            inputs.key_lines.get(name, inputs.line),
                            f"declares the {trig} input '{name}', an AWS account id or "
                            "role ARN. An input is typed into the dispatch form, kept in the "
                            "run's event payload and printed in the env block of the first "
                            "step that reads it, so no step can mask it first. Take it from "
                            "a secret (or derive it from one).",
                        )
    literal_ids(doc, 1)
    for key in doc:
        if key in ("on", True, "jobs"):
            continue
        kl = doc.key_lines.get(key, 1)
        scan(doc[key], kl, f"workflow-level `{key}`", aws_job=False)
        if key == "env" and isinstance(doc[key], LDict):
            for k, v in doc[key].items():
                if is_sink_key(k):
                    sink_check(k, v, doc[key].value_lines.get(k, kl), "workflow-level `env`", None)

    no_env_guards: dict[str, set[str]] = {}  # job without environment -> secrets guarded
    env_reads: dict[str, tuple[str, int]] = {}  # job with environment -> (first id, line)
    for job_id, job in jobs.items():
        if not isinstance(job, LDict):
            continue
        job_line = jobs.key_lines.get(job_id, job.line)
        aws_job = holds_aws(doc, job)
        guards: set[str] = set()
        reads_value: dict[str, int] = {}  # id secret name -> first line in this job
        job_shell = shell_of(job)
        for key in job:
            if key == "steps":
                continue
            kl = job.key_lines.get(key, job.line)
            if (
                key == "secrets"
                and isinstance(job[key], str)
                and job[key].strip().lower() == "inherit"
            ):
                bad(
                    kl,
                    f"job '{job_id}' passes `secrets: inherit`, which hands every "
                    "secret, account ids and role ARNs included, to a reusable workflow "
                    "this gate cannot read. Pass the secrets it needs by name.",
                )
                continue
            for name in scan(
                job[key],
                job.value_lines.get(key, kl),
                f"job-level `{key}`",
                aws_job=aws_job,
                guards=guards,
                is_if=(key == "if"),
            ):
                reads_value.setdefault(name, kl)
            if key == "env" and isinstance(job[key], LDict):
                for k, v in job[key].items():
                    if is_sink_key(k):
                        sink_check(k, v, job[key].value_lines.get(k, kl), "job-level `env`", None)

        masked: set[str] = set()
        mask_step_ids: set[str] = set()
        for step in job.get("steps") or []:
            if not isinstance(step, LDict):
                continue
            step_name = step.get("name", step.get("uses", "?"))
            receives: dict[str, list[tuple[str, int]]] = {}  # name -> [(where, line)]
            for key in step:
                kl = step.key_lines.get(key, step.line)
                vl = step.value_lines.get(key, kl)
                if key in ("env", "with") and isinstance(step[key], LDict):
                    block = step[key]
                    for k, v in block.items():
                        kline = block.key_lines.get(k, block.line)
                        for name in scan(
                            v,
                            block.value_lines.get(k, kline),
                            f"`{key}.{k}`",
                            aws_job=aws_job,
                            guards=guards,
                            entry=True,
                        ):
                            receives.setdefault(name, []).append((f"{key}.{k}", kline))
                        if is_sink_key(k):
                            sink_check(
                                k, v, block.value_lines.get(k, kline), f"`{key}`", mask_step_ids
                            )
                else:
                    scan(
                        step[key],
                        vl,
                        f"step `{key}`",
                        aws_job=aws_job,
                        guards=guards,
                        is_if=(key == "if"),
                    )
            for name, places in receives.items():
                reads_value.setdefault(name, places[0][1])

            run = step.get("run") if isinstance(step.get("run"), str) else None
            script, covers, offset = mask_command(step)
            cmd = first_command(run or "")[0]
            cmd_line = step.value_lines.get("run", step.line) + offset
            if script:
                res.mask_steps += 1
                ok = True
                if not (root / script).is_file():
                    bad(cmd_line, f"runs {script}, which is not in the tree, so nothing is masked.")
                    ok = False
                if "if" in step:
                    bad(
                        step.key_lines["if"],
                        f"job '{job_id}', mask step '{step_name}' has an "
                        "`if:`. A mask step runs whenever its job does: skipped, every later "
                        "step still receives the secret and nothing has masked its pieces.",
                    )
                    ok = False
                coe = step.get("continue-on-error")
                if coe is not None and str(coe).strip().lower() != "false":
                    bad(
                        step.key_lines["continue-on-error"],
                        f"job '{job_id}', mask step "
                        f"'{step_name}' sets `continue-on-error`. A mask step that fails must "
                        "stop the job: the masks may not have been registered.",
                    )
                    ok = False
                for shell, where, ln in (
                    (step.get("shell"), "step", step.key_lines.get("shell")),
                    (job_shell, "job's `defaults.run`", job.key_lines.get("defaults")),
                    (wf_shell, "workflow's `defaults.run`", doc.key_lines.get("defaults")),
                ):
                    if shell is not None and str(shell).strip() != "bash":
                        bad(
                            ln or step.line,
                            f"job '{job_id}', mask step '{step_name}' runs under "
                            f"the {where} shell {quote(str(shell), 30)}. The mask command is bash, "
                            "and only the default shell or `bash` (both `-e`) stops the step "
                            "when it fails; another shell runs on with nothing masked.",
                        )
                        ok = False
                    if shell is not None:
                        break
                raw_env = step.get("env")
                env: LDict = raw_env if isinstance(raw_env, LDict) else LDict()
                for k in sorted(covers or ()):
                    if k not in env:
                        bad(
                            cmd_line,
                            f"job '{job_id}', mask step '{step_name}' names {k}, "
                            "which this step's env does not carry, so it masks nothing "
                            "for it.",
                        )
                        ok = False
                    elif whole_read_name(env[k]) is None:
                        bad(
                            env.key_lines.get(k, env.line),
                            f"job '{job_id}', mask step '{step_name}' masks {k}, which holds "
                            f"{quote(str(env[k]), 60)}. What a mask step masks, and what it hands on "
                            "as step outputs, is a secret read whole: anything else was printed "
                            "unmasked in this step's env block before the mask ran.",
                        )
                        ok = False
                if ok and isinstance(step.get("id"), str):
                    mask_step_ids.add(step["id"].lower())

            for name, places in receives.items():
                if name in masked:
                    if AFTER_FAILURE.search(str(step.get("if", ""))):
                        bad(
                            step.key_lines["if"],
                            f"job '{job_id}', step '{step_name}' receives "
                            f"{name} and runs after a failure ({quote(str(step['if']), 50)}). If a "
                            "step ahead of the mask step fails, the mask step is skipped and "
                            "this one runs with nothing masked.",
                        )
                    continue
                masked.add(name)
                env_keys = [w.split(".", 1)[1] for w, _ in places if w.startswith("env.")]
                with_places = [(w, ln) for w, ln in places if w.startswith("with.")]
                if with_places or not run:
                    where, ln = (with_places or places)[0]
                    bad(
                        ln,
                        f"job '{job_id}', step '{step_name}' is the first to receive "
                        f"{name} ({where}), and it is not a mask step. The first step "
                        "that receives an id secret must be a `run` step whose first "
                        'command is `bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" '
                        f"{name}`; an action prints its inputs before it runs.",
                    )
                elif covers is None:
                    bad(
                        cmd_line,
                        f"job '{job_id}', step '{step_name}' is the first to "
                        f"receive {name}, and its first command is {quote(cmd, 70)}, "
                        'not `bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" '
                        f"[--optional] {' '.join(env_keys)}`. Masks take effect from "
                        "the line after `::add-mask::`, so anything before it can "
                        "print a piece of the value.",
                    )
                else:
                    missing = [k for k in env_keys if k not in covers]
                    if missing:
                        bad(
                            cmd_line,
                            f"job '{job_id}', step '{step_name}': the mask "
                            f"command does not name {', '.join(missing)}, which "
                            f"carries {name} into this step, so its pieces are "
                            "never masked.",
                        )

            w = step.get("with")
            role = with_key(w, "role-to-assume") if isinstance(w, LDict) else None
            if role is not None and isinstance(w, LDict):
                spelt, v = role
                ln = w.key_lines.get(spelt, w.line)
                sid = step_output_whole(v)
                if not (
                    whole_read_name(v) is not None or (sid is not None and sid in mask_step_ids)
                ):
                    bad(
                        ln,
                        f"job '{job_id}': role-to-assume is {quote(str(v), 60)}. It must be "
                        "`${{ secrets.NAME }}`, read after the job's mask step, or "
                        "`${{ steps.ID.outputs.X }}` from that mask step. The action "
                        "prints this input, so a variable, matrix value, input or literal "
                        "here publishes the role ARN and its account id.",
                    )
            if uses_configure_aws(step):
                found = with_key(w, "mask-aws-account-id")
                if found is None or str(found[1]).lower() != "true":
                    bad(
                        step.key_lines.get("uses", step.line),
                        f"job '{job_id}': {CONFIGURE_AWS} without `mask-aws-account-id: "
                        "true`. The job's mask step registers the id already; stating it "
                        "keeps the action's own handling of the account id it reads back "
                        "from being the one place it is not.",
                    )

        # Rule 4, where the secret lives. A REPOSITORY_LEVEL_IDS name is read only
        # by jobs with no environment; any other id only by a job that declares
        # one (and, below, needs a job refusing the inherited name).
        environment = job.get("environment")
        for name, ln in sorted(reads_value.items(), key=lambda kv: kv[1]):
            if name in REPOSITORY_LEVEL_IDS:
                if environment:
                    bad(
                        job.key_lines.get("environment", job_line),
                        f"job '{job_id}' declares an environment and reads {name}, which "
                        "is a repository secret here: "
                        f"{REPOSITORY_LEVEL_IDS[name]}. In this job the secrets context "
                        "would hand it the environment's same-named secret first, and the "
                        "OIDC token would carry an environment subject. Read it from a "
                        "job with no environment.",
                    )
            elif not environment:
                bad(
                    ln,
                    f"job '{job_id}' (line {job_line}) reads the value of {name} but "
                    "declares no environment. An id other than the repository secrets "
                    f"this gate names ({', '.join(sorted(REPOSITORY_LEVEL_IDS))}) is a "
                    "secret on the GitHub Environment its job declares; a job with no "
                    "environment sees only repository and organization secrets, and may "
                    "only compare them against '' (the guard form). Add the name to "
                    "REPOSITORY_LEVEL_IDS only with the reason an environment cannot "
                    "hold it.",
                )
        if environment:
            for name, ln in reads_value.items():
                if name not in REPOSITORY_LEVEL_IDS:
                    env_reads.setdefault(f"{job_id}\0{name}", (name, ln))
        else:
            no_env_guards[job_id] = guards

    # Rule 4: a no-environment job this one needs refuses the inherited secret.
    def needs_of(job_id: str) -> set[str]:
        seen, todo = set(), [job_id]
        while todo:
            j = jobs.get(todo.pop())
            n = j.get("needs") if isinstance(j, dict) else None
            for dep in [n] if isinstance(n, str) else n if isinstance(n, list) else []:
                if isinstance(dep, str) and dep not in seen:
                    seen.add(dep)
                    todo.append(dep)
        return seen

    for key, (name, ln) in sorted(env_reads.items(), key=lambda kv: kv[1][1]):
        job_id = key.split("\0", 1)[0]
        if not any(name in no_env_guards.get(dep, ()) for dep in needs_of(job_id)):
            bad(
                ln,
                f"job '{job_id}' reads the id secret {name} from its environment, but no "
                f"job it needs, with no environment, compares `secrets.{name}` against ''. "
                "The secrets context falls back from the environment to the repository and "
                "the organization, so a value stored at repository level (a migration that "
                "left off --env) is read here, and by every workflow in the repository, "
                "while the run stays green. Add a refuse-inherited-config job with no "
                "environment and `permissions: {}` that fails when "
                f"`${{{{ secrets.{name} != '' }}}}`, and make this job need it.",
            )

    for key, (name, ln) in sorted(id_reads.items(), key=lambda kv: kv[1][1]):
        if key not in guarded_vars:
            bad(
                ln,
                f"reads the id secret {name}, and nothing in this workflow compares "
                f"`vars.{name}` against ''. A value left behind as a variable from before "
                "it became a secret must fail the run (it is never masked, and the next "
                f"edit that reads it prints it): add `${{{{ vars.{name} != '' }}}}` to "
                "the env of the first step that receives the secret, and fail on true.",
            )


def report(res: Result) -> int:
    if res.findings:
        for rel, line, msg in res.findings:
            print(f"::error file={rel},line={line}::{rel}:{line}: {msg}")
        print(
            f"\n{len(res.findings)} finding(s). See the docstring of "
            "scripts/check-workflow-id-masking.py and the ECR Public login section of "
            "docs/runbooks/render-gate-failures.md."
        )
        return 1
    print(
        f"OK: {res.workflows} workflow(s) read; {res.id_reads} id secret read(s) of "
        f"{len(res.id_names)} name(s), each masked first by one of {res.mask_steps} mask "
        f"step(s), none from vars; {MASK_SCRIPT} is the copy {VENDORED_REL} records."
    )
    return 0


def repo_is_visible(root: Path) -> tuple[bool, str]:
    """(True, "") when the tracked tree is more than the gate scripts.

    A gate that reports on a tree it cannot see reports a pass, and a count of
    matched files says the pattern matched, not that the repository is there.
    """
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return False, (
            "`git ls-files` failed, so the tracked set could not be read; "
            "there is nothing to check rather than nothing to report."
        )
    tracked = [p for p in proc.stdout.split("\n") if p]
    if not any(not p.startswith("scripts/") for p in tracked):
        return False, (
            f"the {len(tracked)} tracked file(s) are all under scripts/ (or "
            "there are none), so this is not a checkout of the repository."
        )
    return True, ""


def floor_problem(res: Result) -> str | None:
    """Why a scan did not see what it checks, or None."""
    unseen = sorted(KNOWN_ID_READS - res.id_names)
    if res.workflows < MIN_WORKFLOWS or res.mask_steps < MIN_MASK_STEPS or unseen:
        return (
            f"read {res.workflows} workflow(s) and {res.mask_steps} mask step(s) under "
            f"{WORKFLOWS_REL} (expected at least {MIN_WORKFLOWS} and {MIN_MASK_STEPS}), "
            f"and saw no read of {', '.join(unseen) or 'nothing missing'} among the id "
            "secrets the workflows read today. This gate did not see what it checks "
            "and refuses to report a pass."
        )
    return None


def main_check() -> int:
    ok, why = repo_is_visible(ROOT)
    if not ok:
        print(f"::error::Cannot run: {why} Refusing to report a pass.")
        return CANNOT_RUN
    res = check(ROOT)
    problem = floor_problem(res)
    if problem:
        # The findings first, when there are any: a floor that is not met because
        # a reader broke says less than what that reader did find.
        if res.findings:
            report(res)
        print(f"::error::Cannot run: {problem}")
        return CANNOT_RUN
    return report(res)


# --- self-test ----------------------------------------------------------------

# Anchors in the workflows as they are. Each must occur exactly once in its file;
# the steps ci.yml reuses through YAML aliases occur once in the text.
MASK_STEP = (
    "      - &ecr-public-role\n"
    "        name: Mask the ECR Public pull role and decide whether to log in\n"
)
MASK_STEP_ID = MASK_STEP + "        id: ecr-public-role\n"
MASK_ENV = (
    "          ECR_PUBLIC_PULL_ROLE_ARN: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}"
    " # zizmor: ignore[secrets-outside-env]\n          ROLE_ARN_VARIABLE"
)
MASK_CMD = 'bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" --optional ECR_PUBLIC_PULL_ROLE_ARN\n'
ROLE = "role-to-assume: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}"
GUARD = "ROLE_ARN_VARIABLE: ${{ vars.ECR_PUBLIC_PULL_ROLE_ARN != '' }}"
CREDS_WITH = "          aws-region: &ecr-public-region us-east-1\n"
FETCH = "      - name: Fetch every pinned chart\n        id: fetch\n"
FETCH_RUN = "        run: ./scripts/render-addons.py --fetch\n"
CHARTS_JOB = (
    "  charts:\n    name: Pinned chart archives\n    runs-on: ubuntu-latest\n"
    "    timeout-minutes: 20\n"
)
DIFF_INPUT = "    inputs:\n      environment:\n"
DIFF_STEP = "      - name: Install Helm\n        uses: azure/setup-helm@"
MERGE_GATE = "  merge-gate:\n    name: merge gate\n"
EARLY = "      - name: Early\n        env:\n"
WORKFLOW_ENV = "env:\n  # renovate: datasource=github-releases depName=kyverno/kyverno\n"

# (name, file, old, new, expected line, message): expected line None = a changed
# line inside `new`, else a regex naming the line in the mutated file the finding
# must cite. old and new may be tuples of the same length, each pair applied
# once. message, when given, must appear in the finding cited at that line, so a
# mutation is rejected for the rule it plants against rather than a neighbour.
MUTATIONS: list[tuple] = [
    # Rule 1: variables, and the ways an expression spells a read.
    (
        "role-to-assume from a variable",
        "ci.yml",
        ROLE,
        "role-to-assume: ${{ vars.ECR_PUBLIC_PULL_ROLE_ARN }}",
        None,
        "from `vars.`",
    ),
    (
        "the mask step fed from a variable",
        "ci.yml",
        MASK_ENV,
        MASK_ENV.replace("secrets.ECR_PUBLIC_PULL_ROLE_ARN", "vars.ECR_PUBLIC_PULL_ROLE_ARN"),
        None,
        None,
    ),
    (
        "a variable read with index syntax",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          R: ${{ vars['ECR_PUBLIC_PULL_ROLE_ARN'] }}\n" + FETCH_RUN,
        None,
        "from `vars.`",
    ),
    (
        "a variable read through a mixed-case context name",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          R: ${{ Vars.ECR_PUBLIC_PULL_ROLE_ARN }}\n" + FETCH_RUN,
        None,
        "from `vars.`",
    ),
    (
        "a variable read through a computed index",
        "ci.yml",
        CREDS_WITH,
        CREDS_WITH + "          role-session-name: ${{ vars[format('ECR_{0}', 'ROLE_ARN')] }}\n",
        None,
        "computed index",
    ),
    (
        "every variable read at once",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          ALL: ${{ toJSON(vars) }}\n" + FETCH_RUN,
        None,
        "the whole `vars`",
    ),
    (
        "every secret in a job-level env",
        "ci.yml",
        CHARTS_JOB,
        CHARTS_JOB + "    env:\n      ALL: ${{ toJSON(secrets) }}\n",
        None,
        "the whole `secrets`",
    ),
    (
        "a variable of a name outside the rule in an AWS job",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          BUCKET: ${{ vars.CHART_BUCKET }}\n" + FETCH_RUN,
        None,
        "can hold AWS credentials",
    ),
    (
        "an id-named key fed from a variable of another name",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          ACCOUNT_ID: ${{ vars.AWS_OWNER }}\n" + FETCH_RUN,
        None,
        "sets ACCOUNT_ID",
    ),
    # Rule 2: inputs.
    (
        "an account id as a dispatch input",
        "diff.yml",
        DIFF_INPUT,
        "    inputs:\n      account_id:\n        description: 'Target AWS account ID'\n"
        "      environment:\n",
        None,
        "declares the workflow_dispatch input",
    ),
    (
        "an account as a dispatch input under another name",
        "diff.yml",
        DIFF_INPUT,
        "    inputs:\n      aws_account:\n        description: 'Target AWS account (12 digits)'\n"
        "      environment:\n",
        None,
        "declares the workflow_dispatch input",
    ),
    (
        "an id input read through github.event.inputs with index syntax",
        "diff.yml",
        DIFF_STEP,
        "      - name: Early\n        env:\n          ACCT: ${{ github.event.inputs['account_id'] }}\n"
        "        run: echo early\n" + DIFF_STEP,
        None,
        "reads the input",
    ),
    (
        "an id input read through an upper-case context name",
        "diff.yml",
        DIFF_STEP,
        "      - name: Early\n        env:\n          ACCT: ${{ INPUTS.role_arn }}\n"
        "        run: echo early\n" + DIFF_STEP,
        None,
        "reads the input",
    ),
    # Rule 3: whole, in a step's env or with, and nowhere else.
    (
        "a piece of the secret computed in the mask step's env",
        "ci.yml",
        MASK_ENV,
        MASK_ENV.replace(
            "          ROLE_ARN_VARIABLE",
            "          ROLE_NAME: ${{ format('{0}', secrets.ECR_PUBLIC_PULL_ROLE_ARN) }}\n"
            "          ROLE_ARN_VARIABLE",
        ),
        None,
        "computes from the id secret",
    ),
    (
        "the secret re-serialised in a later step's env",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          R: ${{ toJSON(secrets.ECR_PUBLIC_PULL_ROLE_ARN) }}\n" + FETCH_RUN,
        None,
        "computes from the id secret",
    ),
    (
        "the secret expanded into run text",
        "ci.yml",
        FETCH_RUN,
        "        run: ./scripts/render-addons.py --fetch --role ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}\n",
        None,
        "passes the id secret",
    ),
    (
        "the secret in a workflow-level env",
        "ci.yml",
        WORKFLOW_ENV,
        WORKFLOW_ENV + "  ROLE: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}\n",
        None,
        "passes the id secret",
    ),
    (
        "the secret in a job-level env",
        "ci.yml",
        CHARTS_JOB,
        CHARTS_JOB
        + "    env:\n      ECR_PUBLIC_PULL_ROLE_ARN: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}\n",
        None,
        "passes the id secret",
    ),
    (
        "secrets: inherit",
        "ci.yml",
        CHARTS_JOB,
        CHARTS_JOB + "    secrets: inherit\n",
        None,
        "secrets: inherit",
    ),
    # Rule 4: where the secret lives.
    (
        "the repository secret read in a job declaring an environment",
        "ci.yml",
        CHARTS_JOB,
        CHARTS_JOB + "    environment: ecr-public\n",
        None,
        "is a repository secret here",
    ),
    (
        "another id read in a job with no environment",
        "ci.yml",
        MASK_ENV,
        MASK_ENV.replace(
            "          ROLE_ARN_VARIABLE",
            "          DEPLOY_ROLE_ARN: ${{ secrets.DEPLOY_ROLE_ARN }}\n"
            "          ROLE_ARN_VARIABLE",
        ),
        None,
        "declares no environment",
    ),
    (
        "an environment id with no job refusing the inherited name",
        "ci.yml",
        MERGE_GATE,
        (
            "  deploy-probe:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    environment: probe\n    steps:\n      - name: Mask\n        env:\n"
            "          DEPLOY_ROLE_ARN: ${{ secrets.DEPLOY_ROLE_ARN }}\n"
            "          ROLE_ARN_VARIABLE: ${{ vars.DEPLOY_ROLE_ARN != '' }}\n"
            "        run: |\n"
            '          bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" DEPLOY_ROLE_ARN\n\n'
            + MERGE_GATE
        ),
        r"^\s+DEPLOY_ROLE_ARN: \$\{\{ secrets\.DEPLOY_ROLE_ARN \}\}",
        "no job it needs",
    ),
    # Rule 5: the mask step comes first, and has the shape that stops the job.
    (
        "a step receives the secret before the mask step",
        "ci.yml",
        MASK_STEP,
        EARLY + "          EARLY: ${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}\n"
        "        run: echo early\n" + MASK_STEP,
        None,
        "not `bash",
    ),
    (
        "an early step reads the secret with index syntax",
        "ci.yml",
        MASK_STEP,
        EARLY + "          EARLY: ${{ secrets['ECR_PUBLIC_PULL_ROLE_ARN'] }}\n"
        '        run: echo "${EARLY#arn:aws:iam::}"\n' + MASK_STEP,
        None,
        None,
    ),
    (
        "an early step reads the secret through a mixed-case context name",
        "ci.yml",
        MASK_STEP,
        EARLY + "          EARLY: ${{ Secrets.ECR_PUBLIC_PULL_ROLE_ARN }}\n"
        '        run: echo "${EARLY#arn:aws:iam::}"\n' + MASK_STEP,
        None,
        None,
    ),
    (
        "an action is the first step to receive the secret",
        "ci.yml",
        MASK_ENV,
        MASK_ENV.replace(
            "${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}", "${{ steps.none.outputs.none }}"
        ),
        r"^\s+role-to-assume: \$\{\{ secrets\.ECR_PUBLIC_PULL_ROLE_ARN \}\}",
        "not a mask step",
    ),
    (
        "the mask is not the first command",
        "ci.yml",
        "        run: |\n          " + MASK_CMD,
        '        run: |\n          echo "starting"\n          ' + MASK_CMD,
        None,
        None,
    ),
    (
        "the mask step is conditional",
        "ci.yml",
        MASK_STEP_ID,
        MASK_STEP_ID + "        if: github.event_name == 'push'\n",
        None,
        "has an `if:`",
    ),
    (
        "the mask step continues on error",
        "ci.yml",
        MASK_STEP_ID,
        MASK_STEP_ID + "        continue-on-error: true\n",
        None,
        "continue-on-error",
    ),
    (
        "the mask step runs under pwsh",
        "ci.yml",
        MASK_STEP_ID,
        MASK_STEP_ID + "        shell: pwsh\n",
        None,
        "shell",
    ),
    (
        "the job's default shell does not stop on failure",
        "ci.yml",
        CHARTS_JOB,
        CHARTS_JOB + "    defaults:\n      run:\n        shell: bash {0}\n",
        None,
        "shell",
    ),
    (
        "the workflow's default shell does not stop on failure",
        "ci.yml",
        "permissions:\n  contents: read\n\n# Tool versions",
        "permissions:\n  contents: read\n\ndefaults:\n  run:\n    shell: sh\n\n# Tool versions",
        None,
        "shell",
    ),
    (
        "the mask command carries an argument the script refuses",
        "ci.yml",
        MASK_CMD,
        MASK_CMD.replace("ECR_PUBLIC_PULL_ROLE_ARN\n", "ECR_PUBLIC_PULL_ROLE_ARN --bogus\n"),
        None,
        None,
    ),
    (
        "--optional after a name",
        "ci.yml",
        MASK_CMD,
        MASK_CMD.replace(
            "--optional ECR_PUBLIC_PULL_ROLE_ARN", "ECR_PUBLIC_PULL_ROLE_ARN --optional"
        ),
        None,
        None,
    ),
    (
        "the mask command omits the key the step carries the secret in",
        "ci.yml",
        MASK_CMD,
        MASK_CMD.replace("--optional ECR_PUBLIC_PULL_ROLE_ARN", "--optional ROLE_ARN"),
        None,
        "does not carry",
    ),
    (
        "the mask step masks a variable it hands on",
        "ci.yml",
        MASK_ENV,
        MASK_ENV.replace("${{ secrets.ECR_PUBLIC_PULL_ROLE_ARN }}", "${{ vars.ECR_ROLE }}"),
        None,
        None,
    ),
    (
        "a receiving step runs after a failure",
        "ci.yml",
        "        if: steps.ecr-public-role.outputs.configured == 'true' && (",
        "        if: always() && steps.ecr-public-role.outputs.configured == 'true' && (",
        None,
        "runs after a failure",
    ),
    # Rules 6 and 7: role-to-assume and configure-aws-credentials.
    (
        "role-to-assume from the matrix",
        "ci.yml",
        ROLE,
        "role-to-assume: ${{ matrix.role_arn }}",
        None,
        "role-to-assume is",
    ),
    (
        "role-to-assume as a literal",
        "ci.yml",
        ROLE,
        "role-to-assume: arn:aws:iam::222233334444:role/ecr-public-pull",
        None,
        "role-to-assume is",
    ),
    (
        "role-to-assume spelt in mixed case, from a secret named outside the rule",
        "ci.yml",
        ROLE,
        "Role-To-Assume: ${{ secrets.PULL_ROLE }}",
        None,
        "not a mask step",
    ),
    (
        "configure-aws-credentials without mask-aws-account-id",
        "ci.yml",
        "          mask-aws-account-id: true\n",
        "",
        r"^\s+uses: aws-actions/configure-aws-credentials@",
        "mask-aws-account-id",
    ),
    (
        "configure-aws-credentials spelt in mixed case, unmasked",
        "ci.yml",
        (
            "        uses: aws-actions/configure-aws-credentials@",
            "          mask-aws-account-id: true\n",
        ),
        ("        uses: Aws-Actions/Configure-AWS-Credentials@", ""),
        r"^\s+uses: Aws-Actions/Configure-AWS-Credentials@",
        "mask-aws-account-id",
    ),
    # Rule 8: the leftover-variable guard.
    (
        "the leftover-variable guard removed",
        "ci.yml",
        GUARD,
        'ROLE_ARN_VARIABLE: "false"',
        r"^\s+ECR_PUBLIC_PULL_ROLE_ARN: \$\{\{ secrets\.ECR_PUBLIC_PULL_ROLE_ARN \}\}",
        "compares `vars.ECR_PUBLIC_PULL_ROLE_ARN`",
    ),
    (
        "the guard reads the variable's value",
        "ci.yml",
        GUARD,
        "ROLE_ARN_VARIABLE: ${{ vars.ECR_PUBLIC_PULL_ROLE_ARN }}",
        None,
        "from `vars.`",
    ),
    # Rule 9: literals.
    (
        "a literal account id",
        "ci.yml",
        FETCH_RUN,
        '        env:\n          OWNER: "222233334444"\n' + FETCH_RUN,
        None,
        "as a literal",
    ),
    (
        "a literal account id YAML reads as a number",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          OWNER: 222233334444\n" + FETCH_RUN,
        None,
        "as a literal",
    ),
    (
        "a literal account id as a number in an action input",
        "ci.yml",
        CREDS_WITH,
        CREDS_WITH + "          role-session-name: 222233334444\n",
        None,
        "as a literal",
    ),
    (
        "a literal account id as a number in an env key",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          222233334444: x\n" + FETCH_RUN,
        None,
        "as a literal",
    ),
    # Digits 0-7 behind a leading 0 are octal to YAML 1.1: the value is
    # 1402433619, and only the source text still reads as an account id.
    (
        "a literal account id YAML reads as octal",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          OWNER: 012345670123\n" + FETCH_RUN,
        None,
        "as a literal",
    ),
    (
        "a literal account id YAML reads as octal, as an env key",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          012345670123: x\n" + FETCH_RUN,
        None,
        "as a literal",
    ),
    # PyYAML cuts its excerpt to about 75 characters around the column; here
    # the cut falls inside the id, leaving a tail too short to redact.
    (
        "a workflow that does not parse, with an account id at the parser's excerpt cut",
        "ci.yml",
        FETCH_RUN,
        "        env:\n          OWNER: x 222233334444 qqqqqqqqqqqqqqqqqqqqq: y\n" + FETCH_RUN,
        r"^",
        "could not be parsed",
    ),
    (
        "a literal ARN in prose a step prints",
        "diff.yml",
        DIFF_STEP,
        "      - name: Early\n        run: echo arn:aws:iam::313131313131:role/x\n" + DIFF_STEP,
        None,
        "as a literal",
    ),
]

# The mask script itself: the vendored bytes are pinned by digest.
SCRIPT_MUTATIONS: list[tuple] = [
    (
        "the vendored mask script edited",
        MASK_SCRIPT,
        "ARN_PATTERN='arn:aws:iam::[0-9]{12}:",
        "ARN_PATTERN='arn:aws:iam::[0-9]{13}:",
        r"^",
        "vendored byte for byte",
    ),
]


def _apply(text: str, old, new) -> tuple[str | None, str]:
    """The mutated text, or None and the anchor that did not occur exactly once."""
    pairs = list(zip(old, new, strict=True)) if isinstance(old, tuple) else [(old, new)]
    for o, n in pairs:
        if text.count(o) != 1:
            return None, f"anchor {o[:50]!r} found {text.count(o)} time(s)"
        text = text.replace(o, n)
    return text, ""


def _wanted_lines(mutated: str, old, new, expect) -> set[int]:
    lines = mutated.splitlines()
    if expect is not None:
        return {i + 1 for i, ln in enumerate(lines) if re.search(expect, ln)}
    new_text = new[0] if isinstance(new, tuple) else new
    old_text = old[0] if isinstance(old, tuple) else old
    start = mutated.index(new_text) if new_text else 0
    first = mutated.count("\n", 0, start) + 1
    old_lines = set(old_text.splitlines())
    return {first + i for i, ln in enumerate(new_text.splitlines()) if ln not in old_lines} or {
        first
    }


def leaked_ids(findings, planted=frozenset()) -> list[tuple[str, int, str]]:
    """The findings whose message carries an account id.

    That is a non-placeholder run of twelve or more digits, or the first or
    last six digits of an id the mutation planted: a quote or a parser excerpt
    cut before it is redacted keeps a head or tail too short to look like an
    id, and still publishes it."""

    def leaks(msg: str) -> bool:
        return any(not (len(run) == 12 and placeholder(run)) for run in ID_RUN.findall(msg)) or any(
            i[:6] in msg or i[-6:] in msg for i in planted
        )

    return [f for f in findings if leaks(f[2])]


def self_test(root: Path = ROOT) -> int:
    failures = 0
    ran = 0
    with tempfile.TemporaryDirectory(prefix="id-masking-") as tmp:
        base = Path(tmp) / "base"
        (base / WORKFLOWS_REL).mkdir(parents=True)
        for p in (root / WORKFLOWS_REL).glob("*.y*ml"):
            shutil.copy(p, base / WORKFLOWS_REL / p.name)
        (base / "scripts").mkdir()
        for rel in (MASK_SCRIPT, VENDORED_REL):
            if (root / rel).is_file():
                shutil.copy(root / rel, base / rel)

        clean = check(base)
        if clean.findings:
            print("FAIL [unmutated]: the gate rejects the workflows as they are:", file=sys.stderr)
            for rel, ln, msg in clean.findings:
                print(f"  {rel}:{ln}: {msg[:120]}", file=sys.stderr)
            return 1
        problem = floor_problem(clean)
        if problem:
            print(f"FAIL [unmutated]: {problem}", file=sys.stderr)
            return 1

        cases = [(n, f"{WORKFLOWS_REL}/{f}", o, nw, e, m) for n, f, o, nw, e, m in MUTATIONS]
        cases += SCRIPT_MUTATIONS
        for name, rel, old, new, expect, must_say in cases:
            ran += 1
            target = base / rel
            text = target.read_text()
            mutated, missing = _apply(text, old, new)
            if mutated is None:
                print(f"FAIL [{name}]: {missing} in {rel}", file=sys.stderr)
                failures += 1
                continue
            target.write_text(mutated)
            try:
                res = check(base)
            finally:
                target.write_text(text)
            planted = {
                m.group(1) for m in ID_LITERAL.finditer(mutated) if not placeholder(m.group(1))
            } - set(ID_LITERAL.findall(text))
            leaked = leaked_ids(res.findings, planted)
            if leaked:
                # Not printed: the point is that the message carries an id.
                print(
                    f"FAIL [{name}]: {len(leaked)} finding(s) quote an account id, at "
                    f"{sorted({(r, ln) for r, ln, _ in leaked})}; a finding is published "
                    "as an annotation and must say <account id> instead",
                    file=sys.stderr,
                )
                failures += 1
                continue
            wanted = _wanted_lines(mutated, old, new, expect) if expect != r"^" else {1}
            cited = {ln for r, ln, _ in res.findings if r == rel}
            hits = [
                f
                for f in res.findings
                if f[0] == rel and f[1] in wanted and (must_say is None or must_say in f[2])
            ]
            if not res.findings:
                print(f"FAIL [{name}]: not rejected", file=sys.stderr)
                failures += 1
            elif not hits:
                print(
                    f"FAIL [{name}]: rejected, but cited {sorted(cited) or 'no line'} in "
                    f"{rel}, not the mutated line(s) {sorted(wanted)}"
                    + (f" saying {must_say!r}" if must_say else ""),
                    file=sys.stderr,
                )
                for r, ln, msg in res.findings:
                    print(f"    {r}:{ln}: {msg[:110]}", file=sys.stderr)
                failures += 1
            else:
                hit = hits[0]
                print(f"ok [{name}]: {hit[0]}:{hit[1]}: {hit[2][:90]}")

        # The floor: a tree with no workflows is a scan that saw nothing.
        ran += 1
        for p in (base / WORKFLOWS_REL).glob("*.y*ml"):
            p.unlink()
        if floor_problem(check(base)) is None:
            print("FAIL [no workflows]: the floor accepted a scan of no workflows", file=sys.stderr)
            failures += 1
        else:
            print("ok [no workflows]: the floor refuses a scan that read nothing")

    if failures:
        print(
            f"check-workflow-id-masking self-test FAILED: {failures} of {ran} mutation(s)",
            file=sys.stderr,
        )
        return 1
    if ran < len(MUTATIONS) + len(SCRIPT_MUTATIONS) + 1:
        print(
            "self-test ran fewer mutations than it lists; refusing to report a pass",
            file=sys.stderr,
        )
        return 1
    print(
        f"check-workflow-id-masking self-test passed ({ran} mutations rejected at the "
        "mutated line, unmutated workflows accepted)."
    )
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:]:
        print("usage: check-workflow-id-masking.py [--self-test]", file=sys.stderr)
        sys.exit(2)
    sys.exit(main_check())
