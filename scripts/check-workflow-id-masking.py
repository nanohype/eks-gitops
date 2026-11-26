#!/usr/bin/env python3
"""Every workflow reads AWS account ids and role ARNs as secrets, and masks them first.

WHY THIS EXISTS

A public repository's Actions logs are public too, and its workflows read AWS
account ids and IAM role ARNs. The repository's policy (A REPOSITORY'S POLICY,
below) names the ones its workflows read.

Masking cannot rescue a VARIABLE. The runner prints a variable in the env block
of every step that receives it, and an action prints it among its inputs
(`role-to-assume`), before any step of the job can register a mask. Only a
SECRET is masked from the job's first line, and only whole: the account id
inside a role ARN, a state bucket named after its account in a tool's error, an
ARN in an AccessDenied message, a value an expression computes from the secret
(`fromJSON(secrets.MAP).dev`) all print in the clear unless the job registers
them. So the rule has four parts, and an edit can break any one of them while
every other gate stays green and the first symptom is an account id in a public
log:

  - the value is a secret, at the level WHERE A SECRET LIVES gives it;
  - the first step in the job that receives it runs the mask script as its
    first command, unconditionally, so every derived piece is masked before
    anything prints;
  - it reaches a step only whole, as `${{ secrets.NAME }}`, and pieces of it
    are cut out in shell after the mask and handed on as step outputs;
  - it reaches nothing that runs earlier: no workflow- or job-level env, no
    `run:` text, no action input ahead of the mask.

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
    or TFSTATE is an id (DEPLOY_ROLE_ARN, TERRAGRUNT_ACCOUNT_ID,
    PLAN_ROLE_ARNS, TF_STATE_BUCKET, aws_account). THIS IS A NAMING RULE for
    every repository this gate checks, not only a heuristic: a secret,
    variable or input that carries an account id, a role ARN or a state bucket
    named after its account is named so that it matches. Each repository
    states it in its CLAUDE.md.
  - By use. Any secret or variable, whatever its name, that some workflow
    passes as `role-to-assume`, puts whole into an env or `with:` key whose own
    name is an id (TERRAGRUNT_ACCOUNT_ID, E2E_ACCOUNT_ID, ACCOUNT_ID), or hands
    a mask step to mask, is an id everywhere.
  - By where it goes (the sinks). Such a key, a mask step's masked env keys and
    `role-to-assume` accept only a secret read whole, an output of a mask step
    earlier in the job, the guard form, or a literal (which rule 9 reads).
    Never a variable, an input, a matrix value or another job's output,
    whatever its name.
  - In a job that can hold AWS credentials (it uses configure-aws-credentials
    or may mint an OIDC token), no variable is read at all except in the guard
    form or by a name the policy's [vars_allowed] gives with the reason it can
    never carry an id: such a job has no reason to read configuration that is
    not a secret, and a variable named outside the rule is still printed.

WHERE A SECRET LIVES

The secrets context resolves a name from the environment the job declares,
then the repository, then the organization. An id is a secret on the GitHub
Environment its job declares, and a job with no environment that the reading
job needs compares the same name against '' (refuse-inherited-config), so a
value stored at repository or organization level fails the run instead of
being read by every workflow in the repository.

A name the policy lists under [repository_level_ids] is the exception, each
with the reason an environment cannot hold it (for one, a role whose OIDC trust
names the repository's pull_request and branch subjects refuses the environment
subject a job declaring an environment is issued). Such a name is read only by
jobs with no environment: under an environment, the secrets context would hand
the job that environment's same-named secret first.

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
  4. Where the secret lives (above). A job that reads an id secret's value
     declares an `environment:`, and needs (directly or through other jobs) a
     job with NO environment that compares `secrets.NAME` against ''; a
     [repository_level_ids] name is read only by a job with no environment.
     A job with no environment may otherwise only use the guard form.
  5. For each id secret, the first step in the job that receives it (in `env:`
     or `with:`) is a `run` step whose first command is the mask script, in the
     script's own grammar, naming every env key in that step that carries the
     secret:
       bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" [--optional] NAME...
     with --optional only first and each NAME an environment variable name (a
     map of ids is one NAME, masked whole; there is no second mask script).
     The named script must be tracked, and every key it names must be in the
     step's env holding `${{ secrets.X }}`. A mask step must run whenever the
     job does and stop it on failure: no `if:`, no `continue-on-error`, and a
     shell (the step's, else the job's `defaults.run.shell`, else the
     workflow's) that is unset or `bash`. A later step that receives the
     secret may not run after a failure (`always()`, `failure()`, `cancelled()`
     in its `if:`): a step before the mask failing skips the mask, and such a
     step would then run unmasked.
  6. `role-to-assume` (an input name, so matched case-insensitively: the
     runner hands an action its inputs upper-cased, and `Role-To-Assume`
     configures it exactly as `role-to-assume` does) is `${{ secrets.NAME }}`
     read after rule 5's mask, or `${{ steps.ID.outputs.X }}` from a mask step
     earlier in the same job. Never a variable, a matrix value, an input or a
     literal. Recognising an id by use reads the input name the same way.
  7. Every aws-actions/configure-aws-credentials step (owner and repository
     compared case-insensitively, as GitHub resolves them) sets
     `mask-aws-account-id: true` (the input name compared case-insensitively).
  8. Every job that reads an id secret compares `vars.NAME` against '' (the
     guard), itself or through a job it needs on the same environment (or,
     for a [repository_level_ids] name, with none), so a value left behind as a
     variable from before it became a secret fails the run instead of sitting
     there until the next edit prints it. In that job, not elsewhere in the
     workflow: variables resolve from the environment first, and a variable on
     the environment itself is visible only to a job that declares it, so the
     no-environment guard job of rule 4 sees repository and organization
     variables alone.
  9. No string in a workflow other than a `uses:` reference carries a literal
     twelve-digit account id or an ARN with one, except synthetic placeholders
     (one digit repeated, or 123456789012). An unquoted number counts, as a
     value or as a key: YAML reads `OWNER: 222233334444` as an int, and the
     runner prints it as text. It is read as the text it was written as, so an
     id YAML 1.1 takes for octal (digits 0-7 behind a leading 0) is still seen.

And the files the checks depend on are the bytes they were taken as (VENDORED
FILES, below).

No finding repeats an account id. A finding is printed as an `::error`
annotation, which stays on the pull request and in the public run log after
the diff that carried the text is gone, so every message (a YAML parse error
included) is redacted on its way out: a run of twelve or more digits other than
a placeholder is printed as <account id>, and workflow text a finding quotes is
redacted before it is cut to length, so no truncated head of an id survives. A
parse error is reported as the parser's problem, context, line and column,
without the excerpt PyYAML quotes, which it has already cut to length before
this gate sees it.

Rules 4 and 8 check that the comparison exists where it can see the value,
not what the shell does with it; the workflow's step fails on `true`, and its
message names the `gh` command that removes the value.

VENDORED FILES

scripts/vendored.json maps each file copied byte for byte from another
repository to its source: the repository, path and commit it was taken at, and
the SHA-256 of the bytes taken. Every record must hold, and every path the
policy lists as `vendored` must have one. A copy edited in place (a narrower id
pattern, a refusal moved ahead of the masks, a rule relaxed) passes every check
that asks only whether the file runs; its digest is what shows that it changed.
A change is made in the source repository, with its self-test, then copied here
with the record moved in the same commit.

ONE GATE, MANY REPOSITORIES

The canonical copy of this file is nanohype/landing-zone's
scripts/check-workflow-id-masking.py, beside the mask script it holds the
workflows to: scripts/mask-aws-ids.sh, the command every mask step runs, and
scripts/mask-aws-ids.py, the core that command runs. A repository that runs the
gate vendors all three, byte for byte, and lists each as `vendored`, so each
rule holds the same way everywhere and a fix lands once. Nothing in this file
names a repository's workflows or ids.

A REPOSITORY'S POLICY

scripts/workflow-id-masking.toml, beside the gate, holds what is particular to
one repository:

  docs                    the document a finding's reader is sent to
  vendored                the paths taken from another repository; none in
                          the canonical one
  [floor]                 min_workflows, min_mask_steps and known_id_reads:
                          what a scan must have seen to report a pass. Each
                          minimum is at least 1, and known_id_reads names at
                          least one id
  [repository_level_ids]  NAME = the reason an environment cannot hold it
  [vars_allowed]          NAME = the reason it can never carry an id
  [[mutation]]            the self-test's cases anchored in the workflows:
                          name, file, old, new, line (optional; required
                          when old and new are arrays), must_say
  [[accepted]]            edits the rules permit: name, file, old, new

A policy that cannot be read, lacks a key, names a key the gate does not know,
or sets a floor of nothing stops the gate: a misspelt key is a control that is
not in force.

USAGE

  check-workflow-id-masking.py              check .github/workflows
  check-workflow-id-masking.py --self-test  mutate copies of the workflows in
                                            the ways the policy's [[mutation]]
                                            cases name, and require each to be
                                            rejected by the rule it plants (its
                                            must_say words), citing the file and
                                            the mutated line, with no account id
                                            (nor the head or tail of one it
                                            planted) in any finding; apply the
                                            [[accepted]] edits and require each
                                            to be accepted; require the floor
                                            to refuse each shortfall alone and a
                                            scan of no workflows; require each
                                            built-in workflow shape held to the
                                            rules, in a workflow of its own (the
                                            branches a repository's own
                                            workflows may never take); require
                                            each
                                            exception the policy can grant to be
                                            permitted where it applies and
                                            refused where it does not; require
                                            each
                                            way a vendored record can fail to
                                            hold to be reported, and a record
                                            that holds to be accepted; require
                                            each policy refusal; require main to
                                            refuse each tree git does not track
                                            as a repository or cannot list, and
                                            to exit 0, 1 and 2 where each
                                            applies, printing no id; and require
                                            the self-test's own checks to report
                                            a case that would pass vacuously (an
                                            anchor that no longer occurs, a
                                            mutation the gate accepts, a
                                            rejection at another line or by
                                            another rule, a finding quoting an
                                            id in a workflow case or a vendored
                                            one, a baseline the gate rejects, a
                                            vendored record never examined, an
                                            exception whose read was never seen);
                                            and require each stage made to fail,
                                            and the self-test over a failing
                                            stage, policy, baseline or count, to
                                            report it

Exit 0 = clean. Exit 1 = a violation. Exit 2 = the gate could not reach a
verdict: PyYAML or tomllib is missing, the policy cannot be used, the tree is
not a checkout git tracks, git cannot list it (not installed, or not done within
a minute), or the scan fell below the floor without finding a violation.
"""

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

# A verdict this gate could not reach, kept apart from a violation (1).
CANNOT_RUN = 2

try:
    import tomllib
except ImportError:
    print(
        "Cannot run: tomllib is not available (it is in the standard library from Python "
        "3.11), so this gate cannot read its policy. Refusing to report a pass without it.",
        file=sys.stderr,
    )
    sys.exit(CANNOT_RUN)
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
POLICY_REL = "scripts/workflow-id-masking.toml"
VENDORED_REL = "scripts/vendored.json"
MASK_SCRIPT = "scripts/mask-aws-ids.sh"

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
    rf"^bash\s+{WS}/(scripts/mask-aws-ids\.sh)\"?(\s+--optional)?((?:\s+[A-Za-z_][A-Za-z0-9_]*)+)\s*$")
CONFIGURE_AWS = "aws-actions/configure-aws-credentials"
AFTER_FAILURE = re.compile(r"\b(?:always|failure|cancelled)\s*\(", re.IGNORECASE)
ARN_LITERAL = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12})(?![0-9])")
ID_LITERAL = re.compile(r"(?<![0-9A-Za-z])([0-9]{12})(?![0-9A-Za-z])")

# A finding: (path relative to the root, line, message).
Finding = tuple[str, int, str]


# --- the policy ---------------------------------------------------------------

@dataclass(frozen=True)
class Mutation:
    """A self-test case: an edit of one workflow the gate must reject (A REPOSITORY'S POLICY)."""
    name: str
    file: str
    old: str | tuple[str, ...]
    new: str | tuple[str, ...]
    line: str | None
    must_say: str


@dataclass(frozen=True)
class Accepted:
    """An edit of one workflow the rules permit, which the gate must accept."""
    name: str
    file: str
    old: str
    new: str


@dataclass(frozen=True)
class Policy:
    docs: str
    vendored: tuple[str, ...]
    min_workflows: int
    min_mask_steps: int
    known_id_reads: frozenset[str]
    repository_level_ids: dict[str, str]  # NAME (upper-cased) -> why not an environment
    vars_allowed: dict[str, str]          # NAME (upper-cased) -> why it carries no id
    mutations: tuple[Mutation, ...]
    accepted: tuple[Accepted, ...]


class PolicyError(Exception):
    """Why the policy cannot be used, in words a refusal can print."""


POLICY_KEYS = {"docs": True, "vendored": True, "floor": True, "repository_level_ids": False,
               "vars_allowed": False, "mutation": True, "accepted": False}  # key -> required
FLOOR_KEYS = {"min_workflows": True, "min_mask_steps": True, "known_id_reads": True}
MUTATION_KEYS = {"name": True, "file": True, "old": True, "new": True, "line": False,
                 "must_say": True}
ACCEPTED_KEYS = {"name": True, "file": True, "old": True, "new": True}


def _table(value, keys: dict[str, bool], where: str) -> dict:
    """value as a table holding every required key of keys and no other key."""
    if not isinstance(value, dict):
        raise PolicyError(f"{where} is not a table")
    unknown = sorted(set(value) - set(keys))
    if unknown:
        raise PolicyError(f"{where} has the unknown key(s) {', '.join(unknown)}; a key the "
                          "gate does not read is a control that is not in force")
    absent = sorted(k for k, required in keys.items() if required and k not in value)
    if absent:
        raise PolicyError(f"{where} has no {', '.join(absent)}")
    return value


def _text(value, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{where} is not a non-empty string")
    return value


def _inside(rel: str) -> bool:
    """Whether rel names a path inside the repository, read relative to its root."""
    return not Path(rel).is_absolute() and ".." not in Path(rel).parts


def _relative(value, where: str) -> str:
    path = _text(value, where)
    if not _inside(path):
        raise PolicyError(f"{where} ({path}) is not a path inside the repository")
    return path


def _minimum(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyError(f"{where} is {value!r}; a floor is a whole number of at least 1, "
                          "or it refuses nothing")
    return value


def _reasons(value, where: str) -> dict[str, str]:
    """NAME = reason entries, upper-cased as GitHub resolves names."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"{where} is not a table")
    return {name.upper(): _text(why, f"{where}.{name}") for name, why in value.items()}


def _workflow(value, where: str) -> str:
    name = _text(value, where)
    if "/" in name or not name.endswith((".yml", ".yaml")):
        raise PolicyError(f"{where} ({name}) is not a workflow file name under {WORKFLOWS_REL}")
    return name


def _edit(old, new, where: str) -> tuple[str | tuple[str, ...], str | tuple[str, ...]]:
    """old and new as two strings, or as two arrays of strings of the same length."""
    if isinstance(old, str) and isinstance(new, str):
        if not old:
            raise PolicyError(f"{where}.old is empty, and an empty anchor is everywhere")
        return old, new
    if isinstance(old, list) and isinstance(new, list) and old and len(old) == len(new) \
            and all(isinstance(x, str) and x for x in old) and all(isinstance(x, str) for x in new):
        return tuple(old), tuple(new)
    raise PolicyError(f"{where}: old and new are two strings, or two arrays of strings of the "
                      "same length, with no empty anchor")


def _mutation(entry, where: str) -> Mutation:
    t = _table(entry, MUTATION_KEYS, where)
    old, new = _edit(t["old"], t["new"], where)
    line = t.get("line")
    if line is None and isinstance(old, tuple):
        raise PolicyError(f"{where} edits arrays of anchors and names no line; such a case "
                          "names the line its finding must cite")
    if line is not None:
        try:
            re.compile(_text(line, f"{where}.line"))
        except re.error as e:
            raise PolicyError(f"{where}.line is not a regular expression ({e})") from e
    return Mutation(_text(t["name"], f"{where}.name"), _workflow(t["file"], f"{where}.file"),
                    old, new, line, _text(t["must_say"], f"{where}.must_say"))


def _accepted(entry, where: str) -> Accepted:
    t = _table(entry, ACCEPTED_KEYS, where)
    old, new = _edit(t["old"], t["new"], where)
    if not isinstance(old, str) or not isinstance(new, str):
        raise PolicyError(f"{where}: an accepted edit is one old string and one new string")
    return Accepted(_text(t["name"], f"{where}.name"), _workflow(t["file"], f"{where}.file"),
                    old, new)


def _cases(value, where: str, read) -> tuple:
    if not isinstance(value, list):
        raise PolicyError(f"{where} is not an array of tables")
    cases = tuple(read(entry, f"{where}[{i}]") for i, entry in enumerate(value))
    names = [c.name for c in cases]
    twice = sorted({n for n in names if names.count(n) > 1})
    if twice:
        raise PolicyError(f"{where} names {', '.join(map(repr, twice))} more than once")
    return cases


def load_policy(root: Path) -> Policy:
    """The policy at root, or PolicyError saying why it cannot be used."""
    try:
        data = tomllib.loads((root / POLICY_REL).read_text())
    except OSError as e:
        raise PolicyError(f"{POLICY_REL} could not be read ({e.strerror or e})") from e
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{POLICY_REL} is not valid TOML ({e})") from e
    top = _table(data, POLICY_KEYS, POLICY_REL)
    floor = _table(top["floor"], FLOOR_KEYS, f"{POLICY_REL} [floor]")
    known = floor["known_id_reads"]
    if not isinstance(known, list) or not known:
        raise PolicyError(f"{POLICY_REL} [floor] known_id_reads names no id; the floor "
                          "requires a read of each, so an empty list refuses nothing")
    vendored = top["vendored"]
    if not isinstance(vendored, list):
        raise PolicyError(f"{POLICY_REL} vendored is not an array of paths")
    mutations = _cases(top["mutation"], f"{POLICY_REL} mutation", _mutation)
    if not mutations:
        raise PolicyError(f"{POLICY_REL} has no [[mutation]] case, so the self-test would "
                          "plant nothing in these workflows")
    return Policy(
        docs=_relative(top["docs"], f"{POLICY_REL} docs"),
        vendored=tuple(_relative(p, f"{POLICY_REL} vendored[{i}]") for i, p in enumerate(vendored)),
        min_workflows=_minimum(floor["min_workflows"], f"{POLICY_REL} [floor] min_workflows"),
        min_mask_steps=_minimum(floor["min_mask_steps"], f"{POLICY_REL} [floor] min_mask_steps"),
        known_id_reads=frozenset(_text(n, f"{POLICY_REL} [floor] known_id_reads[{i}]").upper()
                                 for i, n in enumerate(known)),
        repository_level_ids=_reasons(top.get("repository_level_ids"),
                                      f"{POLICY_REL} [repository_level_ids]"),
        vars_allowed=_reasons(top.get("vars_allowed"), f"{POLICY_REL} [vars_allowed]"),
        mutations=mutations,
        accepted=_cases(top.get("accepted", []), f"{POLICY_REL} accepted", _accepted),
    )


def repo_is_visible(root: Path) -> tuple[bool, str]:
    """(True, "") when git tracks root as a repository holding more than its gate scripts.

    A gate that reports on a tree it cannot see reports a pass, and a count of
    matched files says the pattern matched, not that the repository is there.
    """
    try:
        proc = subprocess.run(["git", "-C", str(root), "ls-files"],
                              capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return False, (f"`git ls-files` could not run ({type(e).__name__}), so the tracked set "
                       "could not be read. This gate reads the repository through git; "
                       "without it there is nothing to check rather than nothing to report.")
    if proc.returncode != 0:
        return False, ("`git ls-files` failed, so the tracked set could not be read. This "
                       "gate reads the repository through git; without it there is nothing "
                       "to check rather than nothing to report.")
    tracked = [p for p in proc.stdout.split("\n") if p]
    if not tracked:
        return False, "the tracked set is empty: this is not a checkout of the repository."
    if all(p.startswith("scripts/") for p in tracked):
        return False, (f"every one of the {len(tracked)} tracked file(s) is under scripts/, "
                       "so the only thing here is the gates themselves.")
    return True, ""


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
    the text it was written as and as its value's text (booleans are not
    numbers here). An unquoted `OWNER: 222233334444` is an int to YAML and a
    string to the runner, which prints it in the env block like any other
    value, so the literal-id rule has to see it; the expression rules have
    nothing to read in a number."""
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
    name, a YAML parser's message) and is printed as an `::error` annotation,
    which stays on the pull request and in the public run log after the diff
    that carried the text is gone. The gate that rejects an account id written
    into a workflow must not be what publishes it a second time."""
    return ID_RUN.sub(
        lambda m: m.group(0) if len(m.group(0)) == 12 and placeholder(m.group(0))
        else "<account id>", text)


def emit(text: str, err: bool = False) -> None:
    """Print one message, redacted, to stdout (or stderr with err).

    Every line this gate prints goes through here. A message is assembled from
    policy values, paths, parser errors and workflow text, and redacting where
    each is built leaves any one built without it to print an id; the print is
    the one place they all pass."""
    print(redact(text), file=sys.stderr if err else sys.stdout)


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
        parts = [what + (f" (line {mark.line + 1}, column {mark.column + 1})" if mark else "")
                 for what, mark in ((e.context, e.context_mark), (e.problem, e.problem_mark))
                 if what]
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

TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^']|'')*')
  | (?P<num>-?(?:0x[0-9A-Fa-f]+|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?))
  | (?P<ident>[A-Za-z_][A-Za-z0-9_-]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||[!<>().,\[\]*])
""", re.VERBOSE)
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
        if kind != "ident" or (i and toks[i - 1][1] == ".") or (i + 1 < n and toks[i + 1][1] == "("):
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
                inner = toks[j + 1:m - 1]
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
        if len(path) >= 2 and path[0][0] == "name" and path[0][1].lower() == "event" \
                and path[1][0] == "name" and path[1][1].lower() == "inputs":
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
    before, after = toks[:r.start], toks[r.end:]
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
    if r and r.ctx == "steps" and len(r.path) == 3 and all(k == "name" for k, _ in r.path) \
            and r.path[1][1].lower() == "outputs":
        return r.path[0][1].lower()
    return None


def is_guard(text) -> bool:
    expr = exact_expr(text)
    toks = tokenize(expr) if expr is not None else None
    if not toks:
        return False
    r = guard_ref(toks, refs(toks))
    got = resolve(r) if r else None
    return bool(r is not None and got and got[0] in ("secrets", "vars") and got[2] is None
                and len(r.path) == 1)


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
    names: set[str] = set()
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
                        if str(k).lower() == "role-to-assume" or is_sink_key(k) or (key == "env" and covers and k in covers):
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
        self.findings: list[Finding] = []
        self.mask_steps = 0
        self.id_reads = 0
        self.id_names: set[str] = set()
        self.workflows = 0
        self.vendored = 0  # records in scripts/vendored.json that held


RECORD_KEYS = ("repo", "path", "commit", "sha256")


def vendored_findings(root: Path, policy: Policy) -> tuple[list[Finding], int]:
    """(findings, records that held): each record in scripts/vendored.json holds, and
    each path the policy lists as vendored has one (VENDORED FILES)."""
    record_path = root / VENDORED_REL
    if not record_path.is_file():
        if policy.vendored:
            return [(VENDORED_REL, 1, redact(f"is not in the tree, though {POLICY_REL} lists "
                                             f"{', '.join(policy.vendored)} as vendored: "
                                             "nothing records which bytes they must be."))], 0
        return [], 0
    try:
        record = json.loads(record_path.read_text())
    except (OSError, ValueError) as e:
        return [(VENDORED_REL, 1, redact(f"could not be read as JSON ({e}), so no vendored "
                                         "file can be shown to be the copy it was taken as."))], 0
    if not isinstance(record, dict):
        return [(VENDORED_REL, 1, ("is not a JSON object mapping each vendored path to its "
                                   "record, so no vendored file can be shown to be the copy it "
                                   "was taken as."))], 0
    out: list[Finding] = []
    for rel in policy.vendored:
        if rel not in record:
            out.append((VENDORED_REL, 1, redact(f"has no record for {rel}, which {POLICY_REL} "
                                                "lists as vendored, so nothing says which "
                                                "bytes it must be.")))
    held = 0
    for rel, entry in sorted(record.items()):
        if not (isinstance(entry, dict) and all(isinstance(entry.get(k), str) and entry[k]
                                                for k in RECORD_KEYS)):
            out.append((VENDORED_REL, 1, redact(
                f"the record for {rel} is incomplete: each record names its "
                f"{', '.join(RECORD_KEYS)}, so the bytes trace to where they were taken.")))
            continue
        target = root / rel
        if not (_inside(rel) and target.resolve().is_relative_to(root.resolve())):
            out.append((VENDORED_REL, 1, redact(f"records {rel}, which is not a path inside "
                                                "this repository.")))
            continue
        if not target.is_file():
            out.append((VENDORED_REL, 1, redact(f"records {rel}, which is not in the tree.")))
            continue
        want = entry["sha256"]
        got = hashlib.sha256(target.read_bytes()).hexdigest()
        if got != want:
            out.append((rel, 1, redact(
                f"hashes to {got[:12]}, not the {want[:12]} {VENDORED_REL} records for "
                f"{entry['repo']}:{entry['path']} at {entry['commit'][:12]}. It is vendored "
                f"byte for byte: change it in {entry['repo']}, with its self-test, then copy "
                "it here and move the record in the same commit.")))
            continue
        held += 1
    return out, held


def check(root: Path, policy: Policy) -> Result:
    res = Result()
    wf_dir = root / WORKFLOWS_REL
    paths = sorted(
        p for p in wf_dir.glob("*") if p.suffix in (".yml", ".yaml") and p.is_file()
    ) if wf_dir.is_dir() else []
    res.workflows = len(paths)
    vendored, res.vendored = vendored_findings(root, policy)
    res.findings.extend(vendored)
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
        out: list[Finding] = []
        sub = Result()
        check_workflow(root, rel, doc, ident, out, sub, policy)
        res.findings.extend(out)
        res.mask_steps += sub.mask_steps
        res.id_reads += sub.id_reads
        res.id_names |= sub.id_names
    return res


def check_workflow(root, rel, doc, ident, out, res, policy: Policy) -> None:
    def bad(line: int, msg: str) -> None:
        out.append((rel, line, redact(msg)))

    raw_jobs = doc.get("jobs")
    jobs: LDict = raw_jobs if isinstance(raw_jobs, LDict) else LDict()
    # The job being scanned's own vars.NAME guards (None outside a job). Rule 8
    # reads these: only a job declaring the environment sees its variables.
    job_vars: dict[str, set[str] | None] = {"current": None}
    id_reads: dict[str, tuple[str, int]] = {}  # NAME -> (spelling, first line)
    wf_shell = shell_of(doc)

    def literal_ids(value, line):
        for text, ln in strings_with_lines(value, line, skip_keys=("uses",), numbers=True):
            for pat, what in ((ARN_LITERAL, "an ARN naming an account"), (ID_LITERAL, "an account id")):
                for m in pat.finditer(text):
                    if not placeholder(m.group(1)):
                        bad(line_in(text, ln, m.start()),
                            f"carries {what} as a literal (not repeated here). A literal is printed "
                            "wherever it is used and kept in the public repository besides; it "
                            "belongs in a secret (WHERE A SECRET LIVES, in this gate, says at "
                            "which level). Only synthetic placeholders (one digit repeated, or "
                            "123456789012) may appear in a workflow.")

    def scan(value, line, where: str, *, aws_job: bool, guards: set | None = None,
             entry: bool = False, is_if: bool = False) -> set[str]:
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
                        bad(at, f"has an expression in its {where} this gate cannot read "
                                f"({quote(expr.strip(), 60)}) that mentions the secrets, vars or "
                                "inputs context. Write it in a form the gate can read, so it "
                                "can prove it names no account id or role ARN.")
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
                        how = "the whole" if problem == "whole" else "a computed index or filter of the"
                        bad(at, f"reads {how} `{ctx}` context in its {where} "
                                f"({quote(expr.strip(), 60)}). This gate cannot tell what that "
                                "names, so it cannot prove it names no account id or role ARN; "
                                "a whole context printed or passed on carries every id in it. "
                                f"Read each value by its literal name (`{ctx}.NAME`).")
                        continue
                    key = name.upper()
                    if r is g and len(r.path) == 1 and ctx in ("secrets", "vars"):
                        if ctx == "vars":
                            if job_vars["current"] is not None:
                                job_vars["current"].add(key)
                        elif guards is not None:
                            guards.add(key)
                        continue
                    if ctx == "inputs":
                        if ident(name):
                            bad(at, f"reads the input {name}, an AWS account id or role ARN. An "
                                    "input cannot be masked before it is printed; take it from "
                                    "a secret instead.")
                        continue
                    if ctx == "vars":
                        if ident(name):
                            bad(at, f"reads {name}, an AWS account id or role ARN, from "
                                    "`vars.` in its " + where + ". A variable is never masked: "
                                    "the runner prints it in the env block and the inputs of every "
                                    "step that receives it, before any step can mask it. Make it a "
                                    f"secret (see {policy.docs}); only the guard form "
                                    f"`${{{{ vars.{name} != '' }}}}` may name the variable.")
                        elif aws_job and key not in policy.vars_allowed:
                            bad(at, f"reads the variable {name} in its {where}, in a job that can "
                                    "hold AWS credentials. Such a job reads no variable except in "
                                    "the guard form: a variable is printed unmasked, and one named "
                                    "outside the id naming rule (a state bucket, an account under "
                                    "another name) still carries an account id. Make it a secret, or "
                                    f"add the name to [vars_allowed] in {POLICY_REL} with the "
                                    "reason it can never carry an id.")
                        continue
                    if not ident(name):
                        continue
                    res.id_reads += 1
                    res.id_names.add(key)
                    id_reads.setdefault(key, (name, at))
                    found.add(key)
                    whole_value = entry and whole is not None and whole == expr and s is r \
                        and len(r.path) == 1
                    if whole_value:
                        continue
                    if entry:
                        bad(at, f"computes from the id secret {name} in its {where} "
                                f"({quote(expr.strip(), 60)}). The runner masks a secret only "
                                "whole: a value derived from it (fromJSON, toJSON, format, an "
                                "index, a concatenation) is printed in the clear in this step's "
                                "env block, before its first command can mask it. Pass "
                                f"`${{{{ secrets.{name} }}}}` whole, and cut pieces out in shell "
                                "after the mask command, handing them on as step outputs.")
                    else:
                        bad(at, f"passes the id secret {name} through its {where}. It may "
                                "reach a step only through that step's `env:` map or `with:` "
                                "inputs, whole, after the job's mask step: anywhere else it "
                                "reaches steps that run before the mask, or is expanded into "
                                "text where its pieces are printed unmasked.")
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
                allowed = ("`${{ secrets.NAME }}` whole, an output of a mask step earlier in "
                           "this job, or the guard form") if mask_ids is not None else \
                    "only the guard form (a secret or a mask-step output cannot be here)"
                bad(line_in(text, ln, idx),
                    f"sets {key}, which by its name carries an account id or role ARN, from "
                    f"{quote(expr.strip(), 60)} in its {where}. Such a key takes {allowed}: a "
                    "variable, an input, a matrix value or another job's output is printed "
                    "unmasked in this step's env block or inputs, whatever it is called.")

    # Workflow-level: triggers' inputs and everything but jobs.
    on = doc.get("on", doc.get(True))
    if isinstance(on, dict):
        for trig in ("workflow_dispatch", "workflow_call"):
            spec = on.get(trig)
            inputs = spec.get("inputs") if isinstance(spec, dict) else None
            if isinstance(inputs, LDict):
                for name in inputs:
                    if isinstance(name, str) and ident(name):
                        bad(inputs.key_lines.get(name, inputs.line),
                            f"declares the {trig} input '{name}', an AWS account id or "
                            "role ARN. An input is typed into the dispatch form, kept in the "
                            "run's event payload and printed in the env block of the first "
                            "step that reads it, so no step can mask it first. Take it from "
                            "a secret (or derive it from one).")
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
    repo_reads: dict[str, tuple[str, int]] = {}  # job without one -> (repository-level id, line)
    var_guards: dict[str, set[str]] = {}  # job -> vars it compares against ''
    for job_id, job in jobs.items():
        if not isinstance(job, LDict):
            continue
        job_line = jobs.key_lines.get(job_id, job.line)
        aws_job = holds_aws(doc, job)
        guards: set[str] = set()
        var_guards[job_id] = job_vars["current"] = set()
        reads_value: dict[str, int] = {}  # id secret name -> first line in this job
        job_shell = shell_of(job)
        for key in job:
            if key == "steps":
                continue
            kl = job.key_lines.get(key, job.line)
            if key == "secrets" and isinstance(job[key], str) and job[key].strip().lower() == "inherit":
                bad(kl, f"job '{job_id}' passes `secrets: inherit`, which hands every "
                        "secret, account ids and role ARNs included, to a reusable workflow "
                        "this gate cannot read. Pass the secrets it needs by name.")
                continue
            for name in scan(job[key], job.value_lines.get(key, kl), f"job-level `{key}`",
                             aws_job=aws_job, guards=guards, is_if=(key == "if")):
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
                        for name in scan(v, block.value_lines.get(k, kline), f"`{key}.{k}`",
                                         aws_job=aws_job, guards=guards, entry=True):
                            receives.setdefault(name, []).append((f"{key}.{k}", kline))
                        if is_sink_key(k):
                            sink_check(k, v, block.value_lines.get(k, kline), f"`{key}`",
                                       mask_step_ids)
                else:
                    scan(step[key], vl, f"step `{key}`", aws_job=aws_job, guards=guards,
                         is_if=(key == "if"))
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
                    bad(cmd_line, f"runs {script}, which is not in the tree, so nothing "
                                  "is masked.")
                    ok = False
                if "if" in step:
                    bad(step.key_lines["if"], f"job '{job_id}', mask step '{step_name}' has an "
                        "`if:`. A mask step runs whenever its job does: skipped, every later "
                        "step still receives the secret and nothing has masked its pieces.")
                    ok = False
                coe = step.get("continue-on-error")
                if coe is not None and str(coe).strip().lower() != "false":
                    bad(step.key_lines["continue-on-error"], f"job '{job_id}', mask step "
                        f"'{step_name}' sets `continue-on-error`. A mask step that fails must "
                        "stop the job: the masks may not have been registered.")
                    ok = False
                for shell, where, ln in ((step.get("shell"), "step", step.key_lines.get("shell")),
                                         (job_shell, "job's `defaults.run`", job.key_lines.get("defaults")),
                                         (wf_shell, "workflow's `defaults.run`", doc.key_lines.get("defaults"))):
                    if shell is not None and str(shell).strip() != "bash":
                        bad(ln or step.line, f"job '{job_id}', mask step '{step_name}' runs under "
                            f"the {where} shell {quote(str(shell), 30)}. The mask command is bash, "
                            "and only the default shell or `bash` (both `-e`) stops the step "
                            "when it fails; another shell runs on with nothing masked.")
                        ok = False
                    if shell is not None:
                        break
                raw_env = step.get("env")
                env: LDict = raw_env if isinstance(raw_env, LDict) else LDict()
                for k in sorted(covers or ()):
                    if k not in env:
                        bad(cmd_line, f"job '{job_id}', mask step '{step_name}' names {k}, "
                                      "which this step's env does not carry, so it masks nothing "
                                      "for it.")
                        ok = False
                    elif whole_read_name(env[k]) is None:
                        bad(env.key_lines.get(k, env.line),
                            f"job '{job_id}', mask step '{step_name}' masks {k}, which holds "
                            f"{quote(str(env[k]), 60)}. What a mask step masks, and what it hands on "
                            "as step outputs, is a secret read whole: anything else was printed "
                            "unmasked in this step's env block before the mask ran.")
                        ok = False
                if ok and isinstance(step.get("id"), str):
                    mask_step_ids.add(step["id"].lower())

            for name, places in receives.items():
                if name in masked:
                    if AFTER_FAILURE.search(str(step.get("if", ""))):
                        bad(step.key_lines["if"], f"job '{job_id}', step '{step_name}' receives "
                            f"{name} and runs after a failure ({quote(str(step['if']), 50)}). If a "
                            "step ahead of the mask step fails, the mask step is skipped and "
                            "this one runs with nothing masked.")
                    continue
                masked.add(name)
                env_keys = [w.split(".", 1)[1] for w, _ in places if w.startswith("env.")]
                with_places = [(w, ln) for w, ln in places if w.startswith("with.")]
                if with_places or not run:
                    where, ln = (with_places or places)[0]
                    bad(ln, f"job '{job_id}', step '{step_name}' is the first to receive "
                            f"{name} ({where}), and it is not a mask step. The first step "
                            "that receives an id secret must be a `run` step whose first "
                            'command is `bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" '
                            f'{name}`; an action prints its inputs before it runs.')
                elif covers is None:
                    bad(cmd_line, f"job '{job_id}', step '{step_name}' is the first to "
                                  f"receive {name}, and its first command is {quote(cmd, 70)}, "
                                  'not `bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" '
                                  f'[--optional] {" ".join(env_keys)}`. Masks take effect from '
                                  "the line after `::add-mask::`, so anything before it can "
                                  "print a piece of the value.")
                else:
                    missing = [k for k in env_keys if k not in covers]
                    if missing:
                        bad(cmd_line, f"job '{job_id}', step '{step_name}': the mask "
                                      f"command does not name {', '.join(missing)}, which "
                                      f"carries {name} into this step, so its pieces are "
                                      "never masked.")

            w = step.get("with")
            role = with_key(w, "role-to-assume") if isinstance(w, LDict) else None
            if role is not None and isinstance(w, LDict):
                spelt, v = role
                ln = w.key_lines.get(spelt, w.line)
                sid = step_output_whole(v)
                if not (whole_read_name(v) is not None or (sid is not None and sid in mask_step_ids)):
                    bad(ln, f"job '{job_id}': role-to-assume is {quote(str(v), 60)}. It must be "
                            "`${{ secrets.NAME }}`, read after the job's mask step, or "
                            "`${{ steps.ID.outputs.X }}` from that mask step. The action "
                            "prints this input, so a variable, matrix value, input or literal "
                            "here publishes the role ARN and its account id.")
            if uses_configure_aws(step):
                found = with_key(w, "mask-aws-account-id")
                if found is None or str(found[1]).lower() != "true":
                    bad(step.key_lines.get("uses", step.line),
                        f"job '{job_id}': {CONFIGURE_AWS} without `mask-aws-account-id: "
                        "true`. The job's mask step registers the id already; stating it "
                        "keeps the action's own handling of the account id it reads back "
                        "from being the one place it is not.")

        # Rule 4, where the secret lives.
        environment = job.get("environment")
        repository_level = {n: ln for n, ln in reads_value.items()
                            if n in policy.repository_level_ids}
        environment_level = {n: ln for n, ln in reads_value.items() if n not in repository_level}
        if repository_level and environment:
            name = min(repository_level.items(), key=lambda kv: kv[1])[0]
            bad(job.key_lines.get("environment", job_line),
                f"job '{job_id}' declares an environment and reads {name}, which {POLICY_REL} "
                f"holds at repository level: {policy.repository_level_ids[name]}. Under an "
                "environment the secrets context hands the job that environment's same-named "
                "secret first. Read it from a job with no environment.")
        if environment_level and not environment:
            name, ln = min(environment_level.items(), key=lambda kv: kv[1])
            bad(ln, f"job '{job_id}' (line {job_line}) reads the value of {name} but "
                    "declares no environment. Each id is a secret on the GitHub "
                    "Environment its job declares"
                    + (f", but for the repository-level ids {POLICY_REL} names ("
                       f"{', '.join(sorted(policy.repository_level_ids))})"
                       if policy.repository_level_ids else "")
                    + "; a job with no environment sees only repository and organization "
                    "secrets, and may only compare them against '' (the guard form).")
        if environment:
            for name, ln in environment_level.items():
                env_reads.setdefault(f"{job_id}\0{name}", (name, ln))
        else:
            no_env_guards[job_id] = guards
            for name, ln in repository_level.items():
                repo_reads.setdefault(f"{job_id}\0{name}", (name, ln))
        job_vars["current"] = None

    # Rule 4: a no-environment job this one needs refuses the inherited secret.
    def needs_of(job_id: str) -> set[str]:
        seen, todo = set(), [job_id]
        while todo:
            j = jobs.get(todo.pop())
            n = j.get("needs") if isinstance(j, dict) else None
            for dep in ([n] if isinstance(n, str) else n if isinstance(n, list) else []):
                if isinstance(dep, str) and dep not in seen:
                    seen.add(dep)
                    todo.append(dep)
        return seen

    for key, (name, ln) in sorted(env_reads.items(), key=lambda kv: kv[1][1]):
        job_id = key.split("\0", 1)[0]
        if not any(name in no_env_guards.get(dep, ()) for dep in needs_of(job_id)):
            bad(ln, f"job '{job_id}' reads the id secret {name} from its environment, but no "
                    f"job it needs, with no environment, compares `secrets.{name}` against ''. "
                    "The secrets context falls back from the environment to the repository and "
                    "the organization, so a value stored at repository level (a migration that "
                    "left off --env) is read here, and by every workflow in the repository, "
                    "while the run stays green. Add a refuse-inherited-config job with no "
                    "environment and `permissions: {}` that fails when "
                    f"`${{{{ secrets.{name} != '' }}}}`, and make this job need it.")

    # Rule 8: the job reading the secret, or a job it needs on the same environment
    # (none, for a repository-level id), compares vars.NAME against ''. Variables
    # resolve like secrets (environment, then repository, then organization), and a
    # job declaring no environment sees only the last two: a variable left on the
    # environment itself is visible only to a job that declares it.
    def env_key(job_id: str) -> str:
        e = jobs[job_id].get("environment") if isinstance(jobs.get(job_id), dict) else None
        if isinstance(e, dict):
            e = e.get("name")
        return str(e).strip().lower() if e is not None else ""

    for key, (name, ln) in sorted({**env_reads, **repo_reads}.items(), key=lambda kv: kv[1][1]):
        job_id = key.split("\0", 1)[0]
        env_name = env_key(job_id)
        if name in var_guards.get(job_id, ()) or any(
                name in var_guards.get(dep, ()) and env_key(dep) == env_name
                for dep in needs_of(job_id)):
            continue
        bad(ln, f"job '{job_id}' reads the id secret {name}"
                + (" from its environment, and neither it nor a job it needs on the same "
                   "environment" if env_name else ", a repository secret, and neither it nor "
                   "a job"
                   " it needs with no environment")
                + f" compares `vars.{name}` against ''. A value left behind as a variable from "
                "before it became a secret must fail the run (it is never masked, and the next "
                "edit that reads it prints it)"
                + (", and a variable on the environment itself is visible only to a job "
                   "declaring that environment" if env_name else "")
                + f": add `${{{{ vars.{name} != '' }}}}` to the env of this job's mask step, "
                "and fail on true.")


def report(res: Result, policy: Policy) -> int:
    if res.findings:
        for rel, line, msg in res.findings:
            emit(f"::error file={rel},line={line}::{rel}:{line}: {msg}")
        emit(f"\n{len(res.findings)} finding(s). See the docstring of "
              f"scripts/check-workflow-id-masking.py and {policy.docs}.")
        return 1
    emit(f"OK: {res.workflows} workflow(s) read; {res.id_reads} id secret read(s) of "
          f"{len(res.id_names)} name(s), each masked first by one of {res.mask_steps} mask "
          "step(s), none from vars"
          + (f"; {res.vendored} vendored file(s), each the bytes {VENDORED_REL} records"
             if res.vendored else "") + ".")
    return 0


def floor_problem(res: Result, policy: Policy) -> str | None:
    """Why a scan did not see what this gate checks, or None when it met the floor."""
    unseen = sorted(policy.known_id_reads - res.id_names)
    if res.workflows >= policy.min_workflows and res.mask_steps >= policy.min_mask_steps \
            and not unseen:
        return None
    return (f"read {res.workflows} workflow(s) and {res.mask_steps} mask step(s) under "
            f"{WORKFLOWS_REL} (expected at least {policy.min_workflows} and "
            f"{policy.min_mask_steps})"
            + (f", and saw no read of {', '.join(unseen)}, which {POLICY_REL} lists as an id "
               "secret the workflows read" if unseen else "")
            + ". This gate did not see what it checks and refuses to report a pass.")


def main_check(root: Path = ROOT) -> int:
    ok, why = repo_is_visible(root)
    if not ok:
        emit(f"::error::Cannot run: {why} Refusing to report a pass.")
        return CANNOT_RUN
    try:
        policy = load_policy(root)
    except PolicyError as e:
        emit(f"::error::Cannot run: {e}. Refusing to report a pass.")
        return CANNOT_RUN
    res = check(root, policy)
    problem = floor_problem(res, policy)
    if res.findings:
        # A violation is a verdict even when the scan also fell below the floor (a
        # removed mask command does both), and the line it names is what the reader
        # needs.
        code = report(res, policy)
        if problem:
            emit(f"::error::{problem}")
        return code
    if problem:
        emit(f"::error::Cannot run: {problem}")
        return CANNOT_RUN
    return report(res, policy)


# --- self-test ----------------------------------------------------------------

def leaked_ids(findings, planted: set[str] | frozenset[str] = frozenset()) -> list[tuple[str, int]]:
    """(file, line) of each finding whose message carries an account id.

    That is a non-placeholder run of twelve or more digits, or the first or
    last six digits of an id the mutation planted: a quote cut before it is
    redacted keeps a head too short to look like an id, and still publishes it."""
    def leaks(msg: str) -> bool:
        return any(not (len(run) == 12 and placeholder(run)) for run in ID_RUN.findall(msg)) \
            or any(i[:6] in msg or i[-6:] in msg for i in planted)
    return sorted({(r, ln) for r, ln, msg in findings if leaks(msg)})


def _tree(root: Path, source: Path = ROOT) -> Path:
    """A copy at root of what the gate reads from source: the workflows, the mask script,
    the policy, scripts/vendored.json and each file it records."""
    (root / WORKFLOWS_REL).mkdir(parents=True)
    for p in (source / WORKFLOWS_REL).glob("*.y*ml"):
        shutil.copy(p, root / WORKFLOWS_REL / p.name)
    rels = [MASK_SCRIPT, POLICY_REL, VENDORED_REL]
    with contextlib.suppress(OSError, ValueError):
        # A record that cannot be read is copied as it is and refused by the baseline.
        record = json.loads((source / VENDORED_REL).read_text())
        rels += [r for r in record if isinstance(r, str)] if isinstance(record, dict) else []
    for rel in rels:
        if _inside(rel) and (source / rel).is_file():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source / rel, root / rel)
    return root


def _apply(text: str, old, new) -> tuple[str | None, str]:
    """The mutated text, or None and the anchor that does not occur exactly once."""
    pairs = list(zip(old, new, strict=True)) if isinstance(old, tuple) else [(old, new)]
    for o, n in pairs:
        if text.count(o) != 1:
            return None, f"anchor {o[:50]!r} found {text.count(o)} time(s)"
        text = text.replace(o, n)
    return text, ""


def _wanted_lines(mutated: str, old, new, expect) -> set[int]:
    """The lines of the mutated file a finding must cite."""
    if expect is not None:
        return {i + 1 for i, ln in enumerate(mutated.splitlines()) if re.search(expect, ln)}
    # The lines of `new` that differ from `old` (a tuple case names its line by regex).
    start = mutated.index(new) if new else 0
    first = mutated.count("\n", 0, start) + 1
    old_lines = set(old.splitlines())
    return {first + i for i, ln in enumerate(new.splitlines()) if ln not in old_lines} or {first}


def run_case(base: Path, case: Mutation, policy: Policy) -> tuple[str | None, list[str]]:
    """(None, [the finding that proves it]) when a mutation is rejected as it must be:
    at the mutated line, by the rule it names, with no account id in any finding.
    Otherwise (why not, the findings to show). A case whose file is not in the tree
    adds it, with an empty anchor."""
    rel = f"{WORKFLOWS_REL}/{case.file}"
    target = base / rel
    existed = target.is_file()
    text = target.read_text() if existed else ""
    mutated, missing = _apply(text, case.old, case.new)
    if mutated is None:
        return f"{missing} in {case.file}", []
    target.write_text(mutated)
    try:
        res = check(base, policy)
    finally:
        if existed:
            target.write_text(text)
        else:
            target.unlink()
    planted = {m.group(1) for m in ID_LITERAL.finditer(mutated)
               if not placeholder(m.group(1))} - set(ID_LITERAL.findall(text))
    leaked = leaked_ids(res.findings, planted)
    if leaked:
        # The messages are not shown: the point is that they carry an id.
        return (f"{len(leaked)} finding(s) quote an account id, at {leaked}; a finding is "
                "published as an annotation and must say <account id> instead"), []
    shown = [f"{r}:{ln}: {msg[:110]}" for r, ln, msg in res.findings]
    if not res.findings:
        return "not rejected", []
    wanted = _wanted_lines(mutated, case.old, case.new, case.line)
    at_line = [f for f in res.findings if f[0] == rel and f[1] in wanted]
    if not at_line:
        cited = sorted({ln for r, ln, _ in res.findings if r == rel}) or "no line"
        return f"rejected, but cited {cited} in {rel}, not the mutated line(s) {sorted(wanted)}", shown
    said = [f for f in at_line if case.must_say in f[2]]
    if not said:
        return (f"rejected at the mutated line, but by another rule: no finding there says "
                f"{case.must_say!r}"), shown
    r, ln, msg = said[0]
    return None, [f"{r}:{ln}: {msg[:90]}"]


def unmutated_problem(base: Path, policy: Policy) -> str | None:
    """Why a copy of the workflows as they are cannot be the self-test's baseline, or None."""
    clean = check(base, policy)
    if clean.findings:
        return "the gate rejects the workflows as they are: " + "; ".join(
            f"{rel}:{ln}: {msg[:120]}" for rel, ln, msg in clean.findings)
    return floor_problem(clean, policy)


def floor_shortfalls(met: Result, policy: Policy) -> list[tuple[str, Result, str]]:
    """Each way a scan falls below the floor, planted alone in a copy of a scan that met it,
    with the words floor_problem must refuse it in."""
    def short(**over) -> Result:
        r = Result()
        r.workflows, r.mask_steps = met.workflows, met.mask_steps
        r.id_reads, r.id_names = met.id_reads, set(met.id_names)
        for key, value in over.items():
            setattr(r, key, value)
        return r
    gone = min(policy.known_id_reads)
    return [
        ("one workflow fewer than the floor", short(workflows=policy.min_workflows - 1),
         f"read {policy.min_workflows - 1} workflow(s)"),
        ("one mask step fewer than the floor", short(mask_steps=policy.min_mask_steps - 1),
         f"and {policy.min_mask_steps - 1} mask step(s)"),
        (f"no read of {gone}", short(id_names=set(met.id_names) - {gone}),
         f"saw no read of {gone}"),
    ]


# A workflow the self-test adds to the tree: a step named with an account id is the
# first to receive an id secret, unmasked. Rule 9 rejects the literal in the name, and
# rule 5's finding names the step, so with redaction off that finding quotes the id.
QUOTING = Mutation(
    name="a step named with an account id receives an id secret unmasked",
    file="zz-id-masking-self-test.yml",
    old="",
    new=("on: push\n"
         "jobs:\n"
         "  quoting:\n"
         "    runs-on: ubuntu-latest\n"
         "    steps:\n"
         "      - name: deploy to 313131313131\n"
         "        env:\n"
         "          DEPLOY_ROLE_ARN: ${{ secrets.DEPLOY_ROLE_ARN }}\n"
         "        run: echo deploying\n"),
    line=r"name: deploy to",
    must_say="as a literal",
)

# Each way a vendored record can fail to hold: (name, the record file's text or None
# for no file, the vendored copy's text or None for no copy, the paths the policy
# lists as vendored, the file the finding must cite, what it must say). A must_say of
# None is a record that holds, which must be accepted.
VENDORED_COPY = "scripts/zz-vendored-self-test.sh"
VENDORED_BYTES = "#!/usr/bin/env bash\necho vendored\n"


def _record(**over) -> str:
    entry = {"repo": "example/source", "path": "scripts/source.sh", "commit": "0" * 40,
             "sha256": hashlib.sha256(VENDORED_BYTES.encode()).hexdigest()}
    entry.update(over)
    return json.dumps({VENDORED_COPY: {k: v for k, v in entry.items() if v is not None}})


# A vendored path carrying an account id: the two findings that quote the policy's
# vendored paths must print it as <account id>.
VENDORED_ID_PATH = "scripts/zz-vendored-222233334444.sh"

VENDORED_CASES = [
    ("a record that holds", _record(), VENDORED_BYTES, (VENDORED_COPY,), None, None),
    ("a vendored copy edited in place", _record(), VENDORED_BYTES + "echo edited\n", (),
     VENDORED_COPY, "It is vendored byte for byte"),
    ("a path listed as vendored with no record", "{}", VENDORED_BYTES, (VENDORED_COPY,),
     VENDORED_REL, "has no record for"),
    ("no record file, with a path listed as vendored", None, VENDORED_BYTES, (VENDORED_COPY,),
     VENDORED_REL, "nothing records which bytes"),
    ("a path listed as vendored with no record, carrying an account id", "{}", VENDORED_BYTES,
     (VENDORED_ID_PATH,), VENDORED_REL, "has no record for scripts/zz-vendored-<account id>"),
    ("no record file, with a listed path carrying an account id", None, VENDORED_BYTES,
     (VENDORED_ID_PATH,), VENDORED_REL, "lists scripts/zz-vendored-<account id>"),
    ("a record file that is not JSON", "{not json", VENDORED_BYTES, (), VENDORED_REL,
     "could not be read as JSON"),
    ("a record file that is not an object", "[]", VENDORED_BYTES, (), VENDORED_REL,
     "is not a JSON object"),
    ("a record with no digest", _record(sha256=None), VENDORED_BYTES, (), VENDORED_REL,
     "is incomplete"),
    ("a record of a file not in the tree", _record(), None, (), VENDORED_REL,
     "which is not in the tree"),
    ("a record of a path outside the repository",
     json.dumps({"../outside.sh": json.loads(_record())[VENDORED_COPY]}), VENDORED_BYTES, (),
     VENDORED_REL, "not a path inside this repository"),
]

# The smallest policy the gate accepts, and each way of breaking it the gate refuses:
# (name, old, new, what the refusal says). old None is a policy that is not there;
# old and new may be tuples, each pair applied once.
MIN_POLICY = """docs = "README.md"
vendored = []

[floor]
min_workflows = 1
min_mask_steps = 1
known_id_reads = ["DEPLOY_ROLE_ARN"]

[[mutation]]
name = "a case"
file = "deploy.yml"
old = "a"
new = "b"
must_say = "c"
"""
POLICY_CASES = [
    ("a policy that is not there", None, None, "could not be read"),
    ("a policy that is not TOML", 'docs = "README.md"', "docs = README.md", "is not valid TOML"),
    ("a key the gate does not read", "vendored = []", "vendored = []\nvendor = []",
     "unknown key(s) vendor"),
    ("a required key left out", 'docs = "README.md"\n', "", "has no docs"),
    ("a floor of nothing", "min_workflows = 1", "min_workflows = 0",
     "a floor is a whole number of at least 1"),
    ("no known id read", 'known_id_reads = ["DEPLOY_ROLE_ARN"]', "known_id_reads = []",
     "names no id"),
    ("a case with no must_say", 'must_say = "c"\n', "", "has no must_say"),
    ("anchors of different lengths", 'old = "a"\nnew = "b"', 'old = ["a", "b"]\nnew = ["c"]',
     "of the same length"),
    ("an empty anchor", 'old = "a"', 'old = ""', "an empty anchor is everywhere"),
    ("arrays of anchors with no line", 'old = "a"\nnew = "b"', 'old = ["a"]\nnew = ["b"]',
     "names no line"),
    ("a vendored path outside the repository", "vendored = []", 'vendored = ["../x"]',
     "not a path inside the repository"),
    ("an empty must_say", 'must_say = "c"', 'must_say = ""',
     "must_say is not a non-empty string"),
    ("a line that is not a regular expression", 'must_say = "c"', 'line = "("\nmust_say = "c"',
     "is not a regular expression"),
    ("a case file outside the workflows", 'file = "deploy.yml"', 'file = "../deploy.yml"',
     "is not a workflow file name"),
    ("an exception with no reason", "vendored = []\n",
     'vendored = []\n\n[repository_level_ids]\nX_ROLE_ARN = ""\n',
     "[repository_level_ids].X_ROLE_ARN is not a non-empty string"),
    ("a case named twice", 'must_say = "c"\n',
     ('must_say = "c"\n\n[[mutation]]\nname = "a case"\nfile = "deploy.yml"\nold = "a"\n'
      'new = "b"\nmust_say = "c"\n'), "more than once"),
    ("a floor that is not a table",
     '[floor]\nmin_workflows = 1\nmin_mask_steps = 1\nknown_id_reads = ["DEPLOY_ROLE_ARN"]\n',
     "floor = 1\n", "[floor] is not a table"),
    ("an exception table that is not a table", "vendored = []", "vendored = []\nvars_allowed = 1",
     "[vars_allowed] is not a table"),
    ("cases that are not an array of tables",
     ("vendored = []", ('[[mutation]]\nname = "a case"\nfile = "deploy.yml"\nold = "a"\n'
                        'new = "b"\nmust_say = "c"\n')),
     ("vendored = []\nmutation = 1", ""), "mutation is not an array of tables"),
    ("vendored paths that are not an array", "vendored = []", 'vendored = "scripts/x.sh"',
     "vendored is not an array of paths"),
    ("an accepted edit of arrays", 'must_say = "c"\n',
     ('must_say = "c"\n\n[[accepted]]\nname = "x"\nfile = "deploy.yml"\nold = ["a"]\n'
      'new = ["b"]\n'), "one old string and one new string"),
    ("no mutation case", ("vendored = []", ('[[mutation]]\nname = "a case"\nfile = "deploy.yml"\n'
                                           'old = "a"\nnew = "b"\nmust_say = "c"\n')),
     ("vendored = []\nmutation = []", ""), "has no [[mutation]] case"),
]

# Trees on disk that git does not track as a repository, each refused by main_check
# in the words repo_is_visible gives for it: (name, what git tracks, what the refusal
# says). Each holds the real workflows, so a main_check that skipped the refusal would
# scan them, find them clean and exit 0.
VISIBILITY_CASES = [
    ("a directory that is not a git checkout", None, "`git ls-files` failed"),
    ("a checkout that tracks nothing", (), "the tracked set is empty"),
    ("a checkout that tracks only the gate scripts", ("scripts",), "is under scripts/"),
]
# A checkout git tracks, with git failing to list it, refused the same way: (name, what
# running git raises, or None for a git that outlasts the timeout the call sets, what
# the refusal says).
GIT_FAILURES = [
    ("git is not installed", FileNotFoundError(2, "No such file or directory", "git"),
     "could not run (FileNotFoundError)"),
    ("git ls-files does not finish within its timeout", None, "could not run (TimeoutExpired)"),
]

# Trees git tracks, each with the status main_check must exit with and words it must
# print: (name, what is done to the tree after it is tracked, status, words).
STATUS_CASES = [
    ("a tracked tree as it is", "nothing", 0, "OK: "),
    ("a tracked tree with a violation", "plant", 1, "finding(s)"),
    ("a tracked tree with a violation, below the floor", "plant below the floor", 1,
     "did not see what it checks"),
    ("a tracked tree with no workflows left on disk", "no workflows", CANNOT_RUN,
     "did not see what it checks"),
    ("a tracked tree with no policy on disk", "no policy", CANNOT_RUN,
     f"{POLICY_REL} could not be read"),
    ("a tracked tree whose policy refusal quotes an account id", "policy quoting an id",
     CANNOT_RUN, "unknown key(s) x<account id>"),
]
# The id that case plants, as a key the policy does not read.
STATUS_ID = "222233334444"


# The policy's two exception tables, planted in a workflow the self-test adds, with the
# policy holding REPOSITORY_LEVEL at repository level: (name, the workflow, entries
# added to [vars_allowed], the line a finding must cite, what it must say). A must_say
# of None is a workflow the exceptions permit, which must be accepted.
EXCEPTION_FILE = "zz-id-masking-exceptions.yml"
REPOSITORY_LEVEL = "SELF_TEST_PULL_ROLE_ARN"
REPOSITORY_LEVEL_WHY = ("the self-test's stand-in for a role whose OIDC trust names only this "
                        "repository's branch subjects")


def _exception_workflow(name: str = REPOSITORY_LEVEL, environment: bool = False,
                        guard: bool = True, region: str = "us-east-1") -> str:
    return ("on: push\n"
            "permissions: {}\n"
            "jobs:\n"
            "  pull:\n"
            "    runs-on: ubuntu-latest\n"
            + ("    environment: dev\n" if environment else "")
            + "    permissions:\n"
            "      id-token: write\n"
            "    steps:\n"
            "      - name: Mask the pull role\n"
            "        env:\n"
            f"          {name}: ${{{{ secrets.{name} }}}}\n"
            + (f"          ROLE_ARN_VARIABLE: ${{{{ vars.{name} != '' }}}}\n" if guard else "")
            + f'        run: bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" {name}\n'
            f"      - uses: {CONFIGURE_AWS}@{'f' * 40}\n"
            "        with:\n"
            f"          role-to-assume: ${{{{ secrets.{name} }}}}\n"
            f"          aws-region: {region}\n"
            "          mask-aws-account-id: true\n")


EXCEPTION_CASES = [
    ("a repository-level id read by a job with no environment", _exception_workflow(), {},
     None, None),
    ("a repository-level id read under an environment", _exception_workflow(environment=True),
     {}, r"^    environment: dev", "holds at repository level"),
    ("a repository-level id read with no variable guard", _exception_workflow(guard=False), {},
     rf"^          {REPOSITORY_LEVEL}: ", "a job it needs with no environment compares"),
    ("an environment id read with no environment, beside repository-level ids",
     _exception_workflow(name="SELF_TEST_DEPLOY_ROLE_ARN"), {},
     r"^          SELF_TEST_DEPLOY_ROLE_ARN: ", "but for the repository-level ids"),
    ("a variable the policy allows, read in an AWS job",
     _exception_workflow(region="${{ vars.SELF_TEST_REGION }}"),
     {"SELF_TEST_REGION": "the self-test's stand-in for a region name"}, None, None),
    ("a variable the policy does not allow, read in an AWS job",
     _exception_workflow(region="${{ vars.SELF_TEST_REGION }}"), {},
     r"^          aws-region: ", "in a job that can hold AWS credentials"),
]


SHORTFALL = "a shortfall planted beside the violation: this gate did not see what it checks"

# Shapes a repository's own workflows may never take, each added to the tree as a
# workflow of its own: (name, the workflow, the line a finding must cite, what it must
# say, an id the workflow reads). A must_say of None is a shape the rules permit, which
# must be accepted with the workflow read and, where one is named, the id read seen.
SHAPES_FILE = "zz-id-masking-shapes.yml"
CONFIGURE = f"      - uses: {CONFIGURE_AWS}@{'f' * 40}\n"
ONE_JOB = "on: push\njobs:\n  only:\n    runs-on: ubuntu-latest\n    steps:\n"
SHAPES = [
    ("YAML the rules pass over",
     ("on: push\n"
     "env:\n"
     "  RATIO: 1.5\n"
     "  VARIABLE_SET: ${{ vars.SELF_TEST_X != '' }}\n"
     "  REVERSED_SET: ${{ '' != vars.SELF_TEST_Z }}\n"
     "  SECRET_SET: ${{ secrets.SELF_TEST_Y != '' }}\n"
     '  UNREADABLE: "${{ github.sha @ x }}"\n'
     "  LITERALS: ${{ true && !false && github.event.1 == null }}\n"
     "jobs:\n"
     "  not-a-mapping: 1\n"
     "  steps-not-mappings:\n"
     "    runs-on: ubuntu-latest\n"
     "    steps:\n"
     "      - just text\n"
     "      - run: echo ok\n"), None, None, None),
    ("a workflow that is not a mapping", "- not\n- a mapping\n", None, None, None),
    ("an environment written as a mapping",
     ("on: push\n"
     "permissions: {}\n"
     "jobs:\n"
     "  refuse:\n"
     "    runs-on: ubuntu-latest\n"
     "    steps:\n"
     "      - env:\n"
     "          SET: ${{ secrets.SELF_TEST_DEPLOY_ROLE_ARN != '' }}\n"
     '        run: test "$SET" = false\n'
     "  deploy:\n"
     "    needs: refuse\n"
     "    runs-on: ubuntu-latest\n"
     "    environment:\n"
     "      name: dev\n"
     "    permissions:\n"
     "      id-token: write\n"
     "    steps:\n"
     "      - name: Mask the deploy role\n"
     "        env:\n"
     "          SELF_TEST_DEPLOY_ROLE_ARN: ${{ secrets.SELF_TEST_DEPLOY_ROLE_ARN }}\n"
     "          ROLE_ARN_VARIABLE: ${{ vars.SELF_TEST_DEPLOY_ROLE_ARN != '' }}\n"
     '        run: bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" SELF_TEST_DEPLOY_ROLE_ARN\n'),
     None, None, "SELF_TEST_DEPLOY_ROLE_ARN"),
    ("an account id in an unquoted float", "on: push\nenv:\n  OWNER: 222233334444.5\n",
     r"^  OWNER:", "as a literal", None),
    ("credentials configured with no inputs", ONE_JOB + CONFIGURE, r"^      - uses:",
     "mask-aws-account-id: true", None),
    ("role-to-assume given a number",
     ONE_JOB + CONFIGURE + ("        with:\n          role-to-assume: 5\n"
                            "          mask-aws-account-id: true\n"),
     r"^          role-to-assume: 5", "role-to-assume is '5'", None),
    ("a mask step naming a key its env does not carry",
     ONE_JOB + ("      - name: Mask\n"
                '        run: bash "$GITHUB_WORKSPACE/scripts/mask-aws-ids.sh" MISSING\n'),
     r"^        run: bash", "names MISSING, which this step's env does not carry", None),
]


def meta_cases(planted: Mutation) -> list[tuple[str, Mutation, str]]:
    """The self-test's own refusals, each a case vacuous in one way, which run_case must
    report rather than pass: (name, case, what the report says). planted is a mutation
    the gate rejects at its own line."""
    return [
        ("an anchor that no longer occurs",
         Mutation("meta", planted.file, "this text is in no workflow", "", None, "-"),
         "found 0 time(s)"),
        ("a mutation the gate accepts", dataclasses.replace(planted, new=planted.old),
         "not rejected"),
        ("a rejection at another line", dataclasses.replace(planted, line="(?!)"),
         "not the mutated line"),
        ("a rejection by another rule",
         dataclasses.replace(planted, must_say="words in no finding of this gate"),
         "by another rule"),
    ]


def _main_check_output(root: Path) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main_check(root)
    return code, out.getvalue()


def _git(root: Path, *args: str) -> None:
    git = shutil.which("git")
    if git is None:
        raise OSError("git is not installed, so the case cannot be built")
    subprocess.run([git, "-C", str(root), *args], check=True, capture_output=True, timeout=60)


# One self-test case's result: (its name, why it failed or None, lines to show).
Outcome = tuple[str, str | None, list[str]]


def mutation_outcomes(base: Path, policy: Policy) -> list[Outcome]:
    """Every mutation, each to be rejected at its line by the rule it names."""
    out: list[Outcome] = []
    for case in policy.mutations + (QUOTING,):
        why, shown = run_case(base, case, policy)
        out.append((case.name, why, shown))
    return out


def accepted_outcomes(base: Path, policy: Policy) -> list[Outcome]:
    """Every edit the rules permit, each to be accepted."""
    out: list[Outcome] = []
    for case in policy.accepted:
        label = f"accepted: {case.name}"
        target = base / WORKFLOWS_REL / case.file
        text = target.read_text() if target.is_file() else ""
        if text.count(case.old) != 1:
            out.append((label, (f"anchor {case.old[:50]!r} found {text.count(case.old)} "
                                f"time(s) in {case.file}"), []))
            continue
        target.write_text(text.replace(case.old, case.new))
        try:
            res = check(base, policy)
        finally:
            target.write_text(text)
        out.append((label, "rejected:" if res.findings else None,
                    [f"{r}:{ln}: {msg[:110]}" for r, ln, msg in res.findings]))
    return out


def floor_outcomes(base: Path, scratch: Path, policy: Policy) -> list[Outcome]:
    """Each shortfall below the floor on its own, then a scan that read no workflow."""
    out: list[Outcome] = []
    for name, res, says in floor_shortfalls(check(base, policy), policy):
        problem = floor_problem(res, policy)
        ok = problem is not None and says in problem
        out.append((f"floor: {name}", None if ok else
                    f"floor_problem returned {problem!r}, not a refusal saying {says!r}", []))
    bare = scratch / "bare"
    (bare / WORKFLOWS_REL).mkdir(parents=True)
    problem = floor_problem(check(bare, policy), policy)
    ok = problem is not None and "read 0 workflow(s)" in problem
    out.append(("floor: no workflows", None if ok else
                f"floor_problem returned {problem!r} for a scan of none", []))
    return out


def holds_problem(res: Result) -> str | None:
    """Why a scan of a tree whose one vendored record holds did not show it holding, or None."""
    if res.findings or res.vendored != 1:
        return (f"a record that holds was not accepted as the one vendored file "
                f"({res.vendored} counted)")
    return None


def permitted_problem(res: Result) -> str | None:
    """Why a scan of a workflow the exceptions permit did not accept its read, or None."""
    if res.findings or REPOSITORY_LEVEL not in res.id_names:
        return "rejected, or the workflow's read of the id was not seen"
    return None


def vendored_outcomes(base: Path, scratch: Path, policy: Policy) -> list[Outcome]:
    """Each way a vendored record can fail to hold, planted in a copy of the tree with the
    policy listing what the case names, reported at its file in its words; and a record
    that holds, accepted and counted."""
    out: list[Outcome] = []
    for n, (name, record, copy, listed, rel, says) in enumerate(VENDORED_CASES):
        label = f"vendored: {name}"
        tree = scratch / f"vendored-{n}"
        shutil.copytree(base, tree)
        (tree / VENDORED_REL).unlink(missing_ok=True)
        if record is not None:
            (tree / VENDORED_REL).write_text(record)
        if copy is not None:
            (tree / VENDORED_COPY).write_text(copy)
        res = check(tree, dataclasses.replace(policy, vendored=listed))
        shown = [f"{r}:{ln}: {msg[:110]}" for r, ln, msg in res.findings]
        planted = {i for i in ID_LITERAL.findall(" ".join(listed) + (record or ""))
                   if not placeholder(i)}
        leaked = leaked_ids(res.findings, planted)
        if leaked:
            out.append((label, f"{len(leaked)} finding(s) quote an account id, at {leaked}", []))
            continue
        if says is None:
            # The self-test's trees carry each file a record names.
            carried = _tree(scratch / f"carried-{n}", source=tree)
            out.append((label, holds_problem(res) or (
                None if (carried / VENDORED_COPY).is_file() else
                f"_tree did not carry {VENDORED_COPY}, which the record names"), shown))
            continue
        hit = [f for f in res.findings if f[0] == rel and says in f[2]]
        out.append((label, None if hit else f"no finding at {rel} says {says!r}",
                    [f"{hit[0][0]}:{hit[0][1]}: {hit[0][2][:90]}"] if hit else shown))
    return out


def policy_outcomes(scratch: Path) -> list[Outcome]:
    """The smallest policy accepted, then each way of breaking it refused in its words."""
    smallest = scratch / "policy-smallest"
    (smallest / "scripts").mkdir(parents=True)
    (smallest / POLICY_REL).write_text(MIN_POLICY)
    try:
        load_policy(smallest)
        out: list[Outcome] = [("policy: the smallest policy", None, [])]
    except PolicyError as e:
        out = [("policy: the smallest policy", f"refused ({e})", [])]
    for n, (name, old, new, says) in enumerate(POLICY_CASES):
        label = f"policy: {name}"
        root = scratch / f"policy-{n}"
        (root / "scripts").mkdir(parents=True)
        if old is not None:
            text, missing = _apply(MIN_POLICY, old, new)
            if text is None:
                out.append((label, f"{missing} in the smallest policy", []))
                continue
            (root / POLICY_REL).write_text(text)
        try:
            load_policy(root)
            why: str | None = f"accepted, not refused saying {says!r}"
        except PolicyError as e:
            why = None if says in str(e) else f"refused, but saying {e}, not {says!r}"
        out.append((label, why, []))
    return out


def _outlasting_git(timeouts: list):
    """subprocess.run for a git that never finishes, recording in timeouts the timeout each
    call set: it raises as subprocess.run does once that timeout passes, where a call that
    set none would wait for ever."""
    def run(args, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout") or 0)
    return run


def visibility_outcomes(scratch: Path) -> list[Outcome]:
    """main_check refuses each tree git does not track as a repository, before scanning it."""
    out: list[Outcome] = []
    for n, (name, tracks, says) in enumerate(VISIBILITY_CASES):
        label = f"visible tree: {name}"
        root = _tree(scratch / f"visible-{n}")
        try:
            if tracks is not None:
                _git(root, "init", "-q")
                if tracks:
                    _git(root, "add", *tracks)
        except (OSError, subprocess.SubprocessError) as e:
            out.append((label, f"the tree could not be built: {e}", []))
            continue
        code, printed = _main_check_output(root)
        ok = code == CANNOT_RUN and says in printed and "Refusing to report a pass" in printed
        out.append((label, None if ok else
                    f"main_check exited {code}, and did not refuse saying {says!r}",
                    [] if ok else printed.strip().splitlines()[-3:]))
    for n, (name, raised, says) in enumerate(GIT_FAILURES):
        label = f"visible tree: {name}"
        root = _tree(scratch / f"git-fails-{n}")
        try:
            _git(root, "init", "-q")
            _git(root, "add", ".")
        except (OSError, subprocess.SubprocessError) as e:
            out.append((label, f"the tree could not be built: {e}", []))
            continue
        timeouts: list = []
        with mock.patch.object(subprocess, "run", side_effect=raised or _outlasting_git(timeouts)):
            code, printed = _main_check_output(root)
        bounded = raised is not None or (bool(timeouts) and None not in timeouts)
        ok = bounded and code == CANNOT_RUN and says in printed \
            and "Refusing to report a pass" in printed
        out.append((label, None if ok else "git ls-files ran with no timeout" if not bounded
                    else f"main_check exited {code}, and did not refuse saying {says!r}",
                    [] if ok else printed.strip().splitlines()[-3:]))
    return out


def status_outcomes(scratch: Path, policy: Policy) -> list[Outcome]:
    """main_check's exit status on trees git tracks: 0 clean, 1 rejected, 2 no verdict."""
    out: list[Outcome] = []
    planted = policy.mutations[0]
    for n, (name, change, status, says) in enumerate(STATUS_CASES):
        label = f"exit status: {name}"
        root = _tree(scratch / f"status-{n}")
        try:
            _git(root, "init", "-q")
            _git(root, "add", ".")
        except (OSError, subprocess.SubprocessError) as e:
            out.append((label, f"the tree could not be built: {e}", []))
            continue
        if change.startswith("plant"):
            target = root / WORKFLOWS_REL / planted.file
            mutated, missing = _apply(target.read_text(), planted.old, planted.new)
            if mutated is None:
                out.append((label, f"{missing} in {planted.file}", []))
                continue
            target.write_text(mutated)
        if change == "no workflows":
            for p in (root / WORKFLOWS_REL).glob("*.y*ml"):
                p.unlink()
        elif change == "no policy":
            (root / POLICY_REL).unlink()
        elif change == "policy quoting an id":
            policy_file = root / POLICY_REL
            policy_file.write_text(f"x{STATUS_ID} = 1\n" + policy_file.read_text())
        # A violation and a shortfall both there, the shortfall planted beside it: no edit
        # of a repository's own policy text says which floor its scan falls short of. The
        # violation is the verdict.
        shortfall = (mock.patch.dict(globals(), {"floor_problem": lambda res, policy: SHORTFALL})
                     if change == "plant below the floor" else contextlib.nullcontext())
        with shortfall:
            code, printed = _main_check_output(root)
        leaked = leaked_ids([("printed", 0, printed)], {STATUS_ID})
        ok = code == status and says in printed and not leaked
        out.append((label, None if ok else
                    "main_check printed an account id" if leaked else
                    f"main_check exited {code}, not {status} saying {says!r}",
                    [] if ok or leaked else printed.strip().splitlines()[-3:]))
    return out


def exception_outcomes(base: Path, policy: Policy) -> list[Outcome]:
    """Each exception the policy can grant, permitted where it applies and refused where it
    does not, in a workflow added to the tree."""
    out: list[Outcome] = []
    for name, workflow, allowed, line, says in EXCEPTION_CASES:
        label = f"exception: {name}"
        ruled = dataclasses.replace(
            policy,
            repository_level_ids={**policy.repository_level_ids,
                                  REPOSITORY_LEVEL: REPOSITORY_LEVEL_WHY},
            vars_allowed={**policy.vars_allowed, **allowed})
        if says is not None:
            why, shown = run_case(base, Mutation(name, EXCEPTION_FILE, "", workflow, line, says),
                                  ruled)
            out.append((label, why, shown))
            continue
        target = base / WORKFLOWS_REL / EXCEPTION_FILE
        target.write_text(workflow)
        try:
            res = check(base, ruled)
        finally:
            target.unlink()
        out.append((label, permitted_problem(res),
                    [f"{r}:{ln}: {msg[:110]}" for r, ln, msg in res.findings]))
    return out


def self_refusal_outcomes(base: Path, scratch: Path, policy: Policy) -> list[Outcome]:
    """The self-test's own refusals: each case is vacuous in one way and must be reported."""
    planted = policy.mutations[0]
    out: list[Outcome] = []
    for name, case, says in meta_cases(planted):
        why, _ = run_case(base, case, policy)
        ok = why is not None and says in why
        out.append((f"refuses: {name}", None if ok else
                    f"run_case reported {why!r}, not {says!r}", []))
    # A finding that quotes an account id: redaction switched off for a case whose
    # finding names a step called with the id it plants, which run_case must report.
    with mock.patch.dict(globals(), {"redact": lambda text: text}):
        why, _ = run_case(base, QUOTING, policy)
    ok = why is not None and "quote an account id" in why
    out.append(("refuses: a finding that quotes an account id", None if ok else
                f"run_case reported {why!r}", []))
    # The same for a vendored finding: redaction switched off for the vendored cases whose
    # listed path carries an id, each of which vendored_outcomes must report.
    carrying = [c for c in VENDORED_CASES if VENDORED_ID_PATH in c[3]]
    with mock.patch.dict(globals(), {"redact": lambda text: text, "VENDORED_CASES": carrying}):
        vend = vendored_outcomes(base, scratch / "refusals-vendored", policy)
    ok = len(vend) == len(carrying) > 0 and all(
        why is not None and "quote an account id" in why for _, why, _ in vend)
    out.append(("refuses: a vendored finding that quotes an account id", None if ok else
                f"vendored_outcomes reported {[why for _, why, _ in vend]}", []))
    # A case accepted without the scan having seen what it is about: a record never
    # examined, an exception's read never seen.
    for name, why, says in (
            ("a vendored record that was never examined", holds_problem(Result()), "0 counted"),
            ("a permitted exception whose read was never seen", permitted_problem(Result()),
             "was not seen")):
        ok = why is not None and says in why
        out.append((f"refuses: {name}", None if ok else f"reported {why!r}, not {says!r}", []))
    tree = _tree(scratch / "planted")
    workflow = tree / WORKFLOWS_REL / planted.file
    mutated, missing = _apply(workflow.read_text(), planted.old, planted.new)
    if mutated is None:
        out.append(("refuses: a baseline the gate already rejects",
                    f"{missing} in {planted.file}", []))
        return out
    workflow.write_text(mutated)
    problem = unmutated_problem(tree, policy)
    ok = problem is not None and "rejects the workflows as they are" in problem
    out.append(("refuses: a baseline the gate already rejects", None if ok else
                f"unmutated_problem returned {problem!r}", []))
    return out


def shape_problem(res: Result, baseline: int, reads: str | None) -> str | None:
    """Why a scan of a workflow the rules permit, added to a tree of baseline workflows,
    did not accept it having read it (and the id it reads, where one is named), or None."""
    if res.findings or res.workflows != baseline + 1 or (reads is not None
                                                          and reads not in res.id_names):
        return "rejected, or the workflow or its read was not seen"
    return None


def reported(outcomes: list[Outcome], says: str) -> bool:
    """Whether every one of outcomes, and at least one, failed saying says."""
    return bool(outcomes) and all(why is not None and says in why for _, why, _ in outcomes)


def failing(outcomes: list[Outcome]) -> list[Outcome]:
    """The outcomes that failed."""
    return [o for o in outcomes if o[1] is not None]


def shape_outcomes(base: Path, scratch: Path, policy: Policy) -> list[Outcome]:
    """Each shape in SHAPES, in a workflow added to the tree; a mask step whose script is
    gone from the tree; and the reader of a parse error."""
    out: list[Outcome] = []
    baseline = check(base, policy).workflows
    target = base / WORKFLOWS_REL / SHAPES_FILE
    for name, text, line, says, reads in SHAPES:
        label = f"shape: {name}"
        if says is not None:
            why, shown = run_case(base, Mutation(name, SHAPES_FILE, "", text, line, says), policy)
            out.append((label, why, shown))
            continue
        target.write_text(text)
        try:
            res = check(base, policy)
        finally:
            target.unlink()
        out.append((label, shape_problem(res, baseline, reads),
                    [f"{r}:{ln}: {msg[:110]}" for r, ln, msg in res.findings]))
    tree = scratch / "no-mask-script"
    shutil.copytree(base, tree)
    (tree / MASK_SCRIPT).unlink()
    says = f"runs {MASK_SCRIPT}, which is not in the tree"
    hits = [f for f in check(tree, policy).findings
            if f[0].startswith(WORKFLOWS_REL) and says in f[2]]
    out.append(("shape: a mask step whose script is not in the tree",
                None if hits else f"no finding in a workflow says {says!r}", []))
    noted = parse_error(yaml.MarkedYAMLError(problem="a problem", note="a note"))
    other = parse_error(ValueError("not a YAML error"))
    out.append(("shape: a parse error's note, and an error YAML did not raise",
                None if "a problem; a note" in noted and other.endswith("not a YAML error")
                else f"parse_error read them as {noted!r} and {other!r}", []))
    return out


GONE = "text in no workflow of this tree"


def meta_outcomes(base: Path, scratch: Path, policy: Policy) -> list[Outcome]:
    """Each stage of this self-test, made to fail one way, must report it, and the self-test
    over each must fail: a tree git cannot build, an anchor that is gone, a policy case the
    gate accepts, a smallest policy it refuses, and a policy, baseline, case or count that
    fails."""
    def fresh(name: str) -> Path:
        (scratch / "meta" / name).mkdir(parents=True)
        return scratch / "meta" / name

    gone = Mutation("an anchor that is gone", policy.mutations[0].file, GONE, "", None, "-")
    gone_policy = dataclasses.replace(policy, mutations=(gone,))
    checks: list[tuple[str, list[Outcome], str]] = []
    with mock.patch.object(shutil, "which", lambda _name: None):
        checks.append(("untracked trees git cannot build",
                       visibility_outcomes(fresh("no-git-visible"))[1:], "could not be built"))
        checks.append(("tracked trees git cannot build",
                       status_outcomes(fresh("no-git-status"), policy), "could not be built"))
    checks.append(("a permitted edit whose anchor is gone", accepted_outcomes(
        base, dataclasses.replace(policy, accepted=(Accepted("gone", gone.file, GONE, "x"),))),
        "found 0 time(s)"))
    with mock.patch.dict(globals(), {"MIN_POLICY": "["}):
        checks.append(("a smallest policy the gate refuses",
                       policy_outcomes(fresh("refused-smallest"))[:1], "refused"))
    with mock.patch.dict(globals(), {"POLICY_CASES": [("gone", GONE, "", "x")]}):
        checks.append(("a policy case whose anchor is gone",
                       policy_outcomes(fresh("gone-policy"))[1:], "found 0 time(s)"))
    with mock.patch.dict(globals(), {"POLICY_CASES": [
            ("kept", 'docs = "README.md"', 'docs = "README.md"', "x")]}):
        checks.append(("a policy case the gate accepts",
                       policy_outcomes(fresh("kept-policy"))[1:], "accepted, not refused"))
    checks.append(("exit statuses whose violation's anchor is gone",
                   [o for o in status_outcomes(fresh("gone-status"), gone_policy)
                    if "violation" in o[0]], "found 0 time(s)"))
    checks.append(("a refused baseline whose anchor is gone",
                   self_refusal_outcomes(base, fresh("gone-refusals"), gone_policy)[-1:],
                   "found 0 time(s)"))
    out: list[Outcome] = []
    for name, outcomes, says in checks:
        out.append((f"meta: {name}", None if reported(outcomes, says) else
                    f"reported {[why for _, why, _ in outcomes]}, not {says!r} for each", []))
    # The predicates above, and the shapes stage's, held to planted results.
    read = Result()
    read.workflows = 1
    seen = Result()
    seen.workflows, seen.id_names = 1, {"X_ROLE_ARN"}
    found = Result()
    found.workflows, found.findings = 1, [("x", 1, "planted")]
    planted = [
        reported([], "x"), reported([("n", None, [])], "x"), not reported([("n", "a x", [])], "x"),
        shape_problem(found, 0, None) is None, shape_problem(Result(), 0, None) is None,
        shape_problem(read, 0, "X_ROLE_ARN") is None, shape_problem(seen, 0, "X_ROLE_ARN") is not None,
    ]
    out.append(("meta: the self-test's own predicates", None if not any(planted) else
                f"wrong on planted results {[i for i, bad in enumerate(planted) if bad]}", []))

    # The self-test itself, with one thing broken at a time: (name, what is patched, its
    # exit status, words it must print).
    def stub(*outcomes: Outcome):
        return lambda *args, **kwargs: list(outcomes)

    stages = ("mutation_outcomes", "accepted_outcomes", "floor_outcomes", "shape_outcomes",
              "exception_outcomes", "vendored_outcomes", "policy_outcomes",
              "visibility_outcomes", "status_outcomes", "self_refusal_outcomes")
    passing = {name: stub(("stub", None, [])) for name in stages}

    def refused(root):
        raise PolicyError(f"planted {STATUS_ID}")

    for name, patches, status, says in (
            ("a policy the self-test cannot use, refused quoting an account id",
             {"load_policy": refused}, CANNOT_RUN, "Cannot run: planted <account id>"),
            ("a baseline the gate already rejects",
             {"unmutated_problem": lambda base, policy: "planted"}, 1, "FAIL [unmutated]: planted"),
            ("a stage with a failing case",
             {**passing, "mutation_outcomes": stub(("stub", "planted", ["shown"]))}, 1,
             "self-test FAILED"),
            ("stages that stopped early", passing, 1, "refusing to report a pass")):
        printed = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(globals(), patches))
            stack.enter_context(contextlib.redirect_stdout(printed))
            stack.enter_context(contextlib.redirect_stderr(printed))
            code = self_test(meta=False)
        leaked = leaked_ids([("printed", 0, printed.getvalue())], {STATUS_ID})
        ok = code == status and says in printed.getvalue() and not leaked
        out.append((f"meta: a self-test over {name} fails", None if ok else
                    "self_test printed an account id" if leaked else
                    f"self_test exited {code}, not {status} saying {says!r}", []))
    proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--no-such-flag"],
                          capture_output=True, text=True, timeout=60, check=False)
    ok = proc.returncode == CANNOT_RUN and "usage:" in proc.stderr
    out.append(("meta: an argument the gate does not take", None if ok else
                f"exited {proc.returncode} saying {proc.stderr.strip()[:80]!r}", []))
    for module, says in (("tomllib", "tomllib is not available"),
                         ("yaml", "PyYAML is not installed")):
        # The gate loaded in a process where the module cannot be imported.
        proc = subprocess.run(
            [sys.executable, "-c", (f"import runpy, sys; sys.modules[{module!r}] = None; "
                                    f"runpy.run_path({str(Path(__file__).resolve())!r}, "
                                    f"run_name='without_{module}')")],
            capture_output=True, text=True, timeout=60, check=False)
        ok = proc.returncode == CANNOT_RUN and says in proc.stderr
        out.append((f"meta: no {module}", None if ok else
                    f"the gate exited {proc.returncode} without {module}, not {CANNOT_RUN} "
                    f"saying {says!r}", []))
    return out


# What meta_outcomes reports: its eight stage checks, the predicates, four broken
# self-tests, the bad argument and the two missing modules.
META_OUTCOMES = 16


def self_test(meta: bool = True) -> int:
    try:
        policy = load_policy(ROOT)
    except PolicyError as e:
        emit(f"Cannot run: {e}. The self-test runs the cases the policy holds.", err=True)
        return CANNOT_RUN
    with tempfile.TemporaryDirectory(prefix="id-masking-") as tmp:
        scratch = Path(tmp)
        base = _tree(scratch / "base")
        problem = unmutated_problem(base, policy)
        if problem:
            emit(f"FAIL [unmutated]: {problem}", err=True)
            return 1
        # GIT_CEILING_DIRECTORIES keeps git from reading a repository that contains the
        # scratch directory as the one a case's tree is in.
        with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(scratch)}):
            stages = {
                "mutations": mutation_outcomes(base, policy),
                "accepted": accepted_outcomes(base, policy),
                "floor": floor_outcomes(base, scratch, policy),
                "shapes": shape_outcomes(base, scratch, policy),
                "exceptions": exception_outcomes(base, policy),
                "vendored": vendored_outcomes(base, scratch, policy),
                "policy": policy_outcomes(scratch),
                "visible": visibility_outcomes(scratch),
                "status": status_outcomes(scratch, policy),
                "refusals": self_refusal_outcomes(base, scratch, policy),
                "meta": meta_outcomes(base, scratch, policy) if meta else [],
            }

    outcomes = [o for stage in stages.values() for o in stage]
    for name, why, shown in outcomes:
        if why is None:
            emit(f"ok [{name}]" + (f": {shown[0]}" if shown else ""))
    # The verdict, checked without itself: a planted failed outcome must be failing.
    failed = failing(outcomes) + [("self-test", "failing() passes a failed outcome", [])] * (
        not failing([("planted", "planted", [])]))
    for name, why, shown in failed:
        emit(f"FAIL [{name}]: {why}", err=True)
        for line in shown:
            emit(f"    {line}", err=True)
    if failed:
        emit(f"check-workflow-id-masking self-test FAILED: {len(failed)} of {len(outcomes)} "
             "case(s)", err=True)
        return 1
    # Each stage reports one outcome per case its table lists, so a stage that
    # stopped early is a shortfall here rather than a pass.
    expected = (len(policy.mutations) + 1 + len(policy.accepted)
                + len(floor_shortfalls(Result(), policy)) + 1 + len(SHAPES) + 2
                + len(EXCEPTION_CASES)
                + len(VENDORED_CASES)
                + 1 + len(POLICY_CASES) + len(VISIBILITY_CASES) + len(GIT_FAILURES)
                + len(STATUS_CASES)
                + len(meta_cases(policy.mutations[0])) + 5 + (META_OUTCOMES if meta else 0))
    if len(outcomes) < expected:
        emit(f"self-test ran {len(outcomes)} of the {expected} cases it lists; refusing to "
             "report a pass", err=True)
        return 1
    emit(f"check-workflow-id-masking self-test passed ({len(stages['mutations'])} mutations "
         "rejected at the mutated line by the rule each names, with no account id in any "
         f"finding; {len(stages['accepted'])} permitted edits and the unmutated workflows "
         f"accepted; {len(stages['floor'])} floor shortfalls refused; "
         f"{len(stages['shapes'])} workflow shapes held to the rules; "
         f"{len(stages['exceptions'])} policy exceptions held to where they apply; "
         f"{len(stages['vendored'])} vendored records checked; {len(stages['policy'])} "
         f"policies checked; {len(stages['visible'])} trees git does not track or cannot "
         "list refused; "
         f"{len(stages['status'])} exit statuses; {len(stages['refusals'])} vacuous "
         f"self-test outcomes reported; {len(stages['meta'])} ways of breaking the self-test "
         "itself reported).")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:]:
        emit("usage: check-workflow-id-masking.py [--self-test]", err=True)
        sys.exit(CANNOT_RUN)
    sys.exit(main_check())
