#!/usr/bin/env python3
"""Registers every AWS account id and IAM ARN in the named environment variables
with the GitHub Actions runner's log masker, before anything else in the job prints.

WHY THIS EXISTS

A public repository's Actions logs are public too. A GitHub Actions VARIABLE is
never masked: the runner prints it in the env block of every step that receives
it, and an action prints it among its inputs, before any step of the job can mask
anything. So a workflow reads each account id and role ARN as a SECRET, which the
runner masks as a whole from the job's first line.

It does not mask a PART of one. The account id inside a role ARN, a role ARN
taken out of a JSON map, a state bucket named after its account in a tool's
error, an ARN in an AWS AccessDenied message: each would print in the clear. So
the first step in each job that receives such a secret runs this, through
scripts/mask-aws-ids.sh, as its first command, and every id and ARN is masked
from the next line on, for the rest of the job: later output in that step, and
every later step's env block, action inputs and output. Masks are per job, so
each job that reads one runs it. scripts/check-workflow-id-masking.py holds every
workflow to that.

WHAT IT MASKS, in every named value

  - every twelve-digit window of every run of twelve or more digits, whether or
    not the value is well formed: an id in a malformed value is still an id, and
    an id inside a longer run is masked at whatever offset it starts.
  - every IAM ARN (arn:aws:iam::<twelve digits>:<resource>), whole.
  - when the value is JSON (a map of role ARNs), the same two in every key and
    string after JSON decoding, so an ARN written with escapes is masked in the
    form an action prints it. The value is read as a stream of JSON documents:
    every document that parses is decoded, up to the first that does not.

All of it happens before any refusal below is printed. It prints nothing but
`::add-mask::` commands and, on refusal, `::error` annotations that name the
variable and never any part of its value, and nothing on stderr.

WHAT IT REFUSES (exit 1)

  - a value that spans more than one line, after leading and trailing whitespace
    is trimmed. The runner masks each line of a multi-line secret on its own, so a
    pretty-printed JSON map registers `{` and `}` as secrets and every brace in
    the log turns to `***`; and a role ARN or account id that carries a second
    line is not one. Store it on one line (`jq -c` for a JSON value).
  - an unset, empty or whitespace-only value, unless --optional is given.
    --optional is for a caller that decides what an absent value means itself.

Whitespace is POSIX's: space, tab, newline, vertical tab, form feed and carriage
return.

USAGE

  mask-aws-ids.sh NAME...              every NAME must be set
  mask-aws-ids.sh --optional NAME...   an unset NAME is passed over
  mask-aws-ids.sh --self-test          run the built-in cases (synthetic ids only)

NAME is the name of an environment variable, never a value: a workflow passes the
secret through the step's env map and names it here, so the value is never part
of a command line. Exit 2 is a usage error.

The self-test is what keeps this honest. It is the only thing keeping account ids
out of the public logs, and an edit that weakens it (a narrower id pattern, a
refusal moved ahead of the masks, a stray print) would otherwise pass every other
gate and first show itself as ids in a log. Each case runs twice: in this process,
and through scripts/mask-aws-ids.sh with nothing in the environment but PATH and
the case's own variables, so nothing in the caller's environment can stand in for
a value under test. The self-test also requires its own checks to report a result
that breaks each of them, and a run with a failing case or too few cases to fail.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping, NamedTuple, Sequence
from unittest import mock

# An IAM ARN, up to the first character no ARN resource carries (a quote, a
# backslash, whitespace). Anchored on the account segment, so a malformed resource
# part still masks the whole ARN-shaped run.
ARN_PATTERN = re.compile(r"arn:aws:iam::[0-9]{12}:[A-Za-z0-9+=,.@_/:-]+")
DIGIT_RUN = re.compile(r"[0-9]{12,}")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SPACE = " \t\n\v\f\r"
JSON_SPACE = " \t\n\r"
USAGE = ("::error title=mask-aws-ids.sh usage::usage: mask-aws-ids.sh [--optional] NAME... "
         "| --self-test (NAME is an environment variable name)")
SHIM = Path(__file__).resolve().parent / "mask-aws-ids.sh"


def masks_in(text: str) -> list[str]:
    """Every twelve-digit window of every run of twelve or more digits, and every IAM
    ARN whole: sorted, each once."""
    found = set(ARN_PATTERN.findall(text))
    for run in DIGIT_RUN.findall(text):
        found.update(run[i:i + 12] for i in range(len(run) - 11))
    return sorted(found)


def decoded_strings(raw: str) -> list[str]:
    """Every string and object key in raw read as a stream of JSON documents, from each
    document that parses, up to the first that does not."""
    decoder = json.JSONDecoder()
    out: list[str] = []
    at = 0
    while True:
        while at < len(raw) and raw[at] in JSON_SPACE:
            at += 1
        if at == len(raw):
            return out
        try:
            document, at = decoder.raw_decode(raw, at)
        except (ValueError, RecursionError):
            return out
        stack = [document]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                out.append(node)
            elif isinstance(node, dict):
                out.extend(node)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)


def run(args: Sequence[str], environ: Mapping[str, str]) -> tuple[int, list[str]]:
    """(exit status, the lines to print) for one invocation."""
    optional = bool(args) and args[0] == "--optional"
    names = list(args[1:] if optional else args)
    if not names or not all(NAME.fullmatch(name) for name in names):
        return 2, [USAGE]
    values = [(name, environ.get(name, "")) for name in names]
    lines: list[str] = []
    registered: set[str] = set()

    def register(masks: list[str]) -> None:
        for mask in masks:
            if mask not in registered:
                registered.add(mask)
                lines.append(f"::add-mask::{mask}")

    # Masks first: the raw text of every value, then every key and string of each
    # value that is JSON, all registered before any refusal is printed.
    register(masks_in("".join(value.strip(SPACE) + "\n" for _, value in values)))
    register(masks_in("\n".join(s for _, value in values for s in decoded_strings(value))))

    # Then the refusals, every one of them, naming the variable and nothing of its
    # value.
    status = 0
    for name, value in values:
        trimmed = value.strip(SPACE)
        if not trimmed:
            if not optional:
                lines.append(f"::error title={name} is not set::{name} is unset or empty, and "
                             "this step cannot run without it. Set the secret this job reads it "
                             "from.")
                status = 1
        elif "\n" in trimmed or "\r" in trimmed:
            lines.append(f"::error title={name} spans several lines::{name} holds more than one "
                         "line. The runner masks each line of a multi-line secret separately, and "
                         "no account id or role ARN spans lines. Store it on one line (pipe a "
                         "JSON value through jq -c).")
            status = 1
    return status, lines


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["--self-test"]:
        if len(args) != 1:
            print(USAGE)
            return 2
        return self_test()
    status, lines = run(args, os.environ)
    for line in lines:
        print(line)
    return status


# --- self-test ----------------------------------------------------------------

class Case(NamedTuple):
    """One invocation and what its output must show.

    masks: values each of which an ::add-mask:: line must register. counts: (regex,
    number of output lines it must match). absent: text the output must not carry.
    ordered: the masks come first and the refusal last."""
    name: str
    args: tuple[str, ...]
    env: dict[str, str]
    status: int
    masks: tuple[str, ...] = ()
    counts: tuple[tuple[str, int], ...] = ()
    absent: tuple[str, ...] = ()
    ordered: bool = False


MASK = r"^::add-mask::"
ERROR = r"^::error"
ANY = r"."
# Synthetic ids only. None is an account anyone holds.
ID1, ID2 = "222233334444", "555566667777"
ARN1 = f"arn:aws:iam::{ID1}:role/github-actions-deploy"
ARN2 = f"arn:aws:iam::{ID2}:role/github-actions-plan"
LONG = "314159265358979323846264"

CASES = [
    # A role ARN and the account id it names.
    Case("deploy pair", ("DEPLOY_ROLE_ARN", "DEPLOY_ACCOUNT_ID"),
         {"DEPLOY_ROLE_ARN": ARN1, "DEPLOY_ACCOUNT_ID": ID1}, 0,
         masks=(ID1, ARN1), counts=((MASK, 2), (ERROR, 0))),
    # Two accounts across two values: each id and each ARN, once.
    Case("two accounts", ("A_ROLE_ARN", "B_ROLE_ARN"), {"A_ROLE_ARN": ARN1, "B_ROLE_ARN": ARN2}, 0,
         masks=(ID1, ID2, ARN1, ARN2), counts=((MASK, 4),)),
    # A trailing newline (gh secret set reading a file) is not a second line.
    Case("trailing newline", ("E2E_AWS_ROLE_ARN",), {"E2E_AWS_ROLE_ARN": ARN2 + "\n"}, 0,
         masks=(ID2, ARN2), counts=((ERROR, 0),)),
    # A caller that skips when its pair is unset: nothing set, nothing to do.
    Case("optional, unset", ("--optional", "AWS_ROLE_ARN", "TERRAGRUNT_ACCOUNT_ID"), {}, 0,
         counts=((ANY, 0),)),
    Case("optional, half set", ("--optional", "AWS_ROLE_ARN", "TERRAGRUNT_ACCOUNT_ID"),
         {"TERRAGRUNT_ACCOUNT_ID": ID1}, 0, masks=(ID1,), counts=((MASK, 1), (ERROR, 0))),
    Case("required, unset", ("E2E_AWS_ROLE_ARN",), {}, 1, counts=((ERROR, 1), (MASK, 0))),
    Case("required, empty", ("DEPLOY_ROLE_ARN",), {"DEPLOY_ROLE_ARN": ""}, 1,
         counts=((ERROR, 1),)),
    Case("required, whitespace only", ("DEPLOY_ROLE_ARN",), {"DEPLOY_ROLE_ARN": " \n\t\v\f "}, 1,
         counts=((ERROR, 1),)),
    # Several refusals are all reported, after every mask.
    Case("two refusals", ("A_ROLE_ARN", "B_ACCOUNT_ID"), {"A_ROLE_ARN": ARN1 + "\nx"}, 1,
         masks=(ID1,), counts=((ERROR, 2),), ordered=True),
    Case("the same unset name twice", ("B_ACCOUNT_ID", "B_ACCOUNT_ID"), {}, 1,
         counts=((ERROR, 2),)),
    # A multi-line value is refused, and its ids are masked BEFORE the refusal,
    # optional or not.
    Case("multi-line", ("DRIFT_PLAN_ROLE_ARNS",),
         {"DRIFT_PLAN_ROLE_ARNS":
          '{\n  "network": "arn:aws:iam::313131313131:role/github-actions-plan"\n}'}, 1,
         masks=("313131313131", "arn:aws:iam::313131313131:role/github-actions-plan"),
         counts=((ERROR, 1),), ordered=True),
    Case("multi-line, optional", ("--optional", "AWS_ROLE_ARN"), {"AWS_ROLE_ARN": f"{ARN2}\n{ARN1}"},
         1, masks=(ID1, ID2), counts=((ERROR, 1),), ordered=True),
    Case("carriage return", ("DEPLOY_ACCOUNT_ID",), {"DEPLOY_ACCOUNT_ID": "414141414141\r1"}, 1,
         masks=("414141414141",), counts=((ERROR, 1),)),
    # An id at any offset inside a longer digit run: every twelve-digit window.
    Case("an id inside a longer digit run", ("TERRAGRUNT_ACCOUNT_ID",),
         {"TERRAGRUNT_ACCOUNT_ID": f"x{LONG}y"}, 0,
         masks=tuple(LONG[i:i + 12] for i in range(len(LONG) - 11)), counts=((MASK, 13),)),
    # A role map: ids in keys and values, each role ARN whole.
    Case("role map", ("DRIFT_PLAN_ROLE_ARNS",),
         {"DRIFT_PLAN_ROLE_ARNS": f'{{"workload-staging":"{ARN1}","444455556666":"{ARN2}"}}'}, 0,
         masks=(ID1, ID2, "444455556666", ARN1, ARN2), counts=((MASK, 5), (ERROR, 0))),
    # A role map that is a JSON array: still every id and every ARN in it.
    Case("role map as an array", ("DRIFT_PLAN_ROLE_ARNS",), {"DRIFT_PLAN_ROLE_ARNS": f'["{ARN1}"]'},
         0, masks=(ID1, ARN1), counts=((MASK, 2), (ERROR, 0))),
    # Entries a role map refuses (a user ARN, a bare id, a role ARN whose decoded form
    # carries a line break) are still masked: an id in a malformed entry is an id.
    Case("role map, malformed entries", ("DRIFT_PLAN_ROLE_ARNS",),
         {"DRIFT_PLAN_ROLE_ARNS": '{"backup":"arn:aws:iam::123412341234:user/someone",'
                                  '"x":"999988887777","y":"arn:aws:iam::121212121212:role/p\\nq"}'},
         0, masks=("123412341234", "999988887777", "121212121212",
                   "arn:aws:iam::123412341234:user/someone", "arn:aws:iam::121212121212:role/p"),
         counts=((ERROR, 0),)),
    Case("role map, unset", ("DRIFT_PLAN_ROLE_ARNS",), {}, 1, counts=((ERROR, 1), (MASK, 0))),
    # An ARN written with JSON escapes is masked in its decoded form too, the form an
    # action prints it in.
    Case("JSON escapes", ("DRIFT_PLAN_ROLE_ARNS",),
         {"DRIFT_PLAN_ROLE_ARNS":
          '{"network":"arn:aws:iam::616161616161:role\\/github-actions-plan"}'}, 0,
         masks=("616161616161", "arn:aws:iam::616161616161:role/github-actions-plan")),
    # Escapes in an object key, and in a list inside a list: only the decoded form is
    # the ARN an action prints.
    Case("JSON escapes in a key", ("DRIFT_PLAN_ROLE_ARNS",),
         {"DRIFT_PLAN_ROLE_ARNS": '{"arn:aws:iam::828282828282:role\\/k":"v"}'}, 0,
         masks=("arn:aws:iam::828282828282:role/k",)),
    Case("JSON escapes in a nested list", ("DRIFT_PLAN_ROLE_ARNS",),
         {"DRIFT_PLAN_ROLE_ARNS": '[["arn:aws:iam::838383838383:role\\/n"]]'}, 0,
         masks=("arn:aws:iam::838383838383:role/n",)),
    # Every document of a JSON stream that parses is decoded, up to the first that
    # does not; the raw text is masked whatever follows.
    Case("a JSON stream, broken after its first document", ("X_ROLE_ARN",),
         {"X_ROLE_ARN": '"arn:aws:iam::737373737373:role\\/a" {'}, 0,
         masks=("737373737373", "arn:aws:iam::737373737373:role/a",
                "arn:aws:iam::737373737373:role"), counts=((MASK, 3),)),
    # Nesting too deep for the decoder: the raw text is still masked.
    Case("JSON nested past the decoder's depth", ("X_ACCOUNT_ID",),
         {"X_ACCOUNT_ID": "[" * 40000 + "123456123456" + "]" * 40000}, 0,
         masks=("123456123456",), counts=((MASK, 1),)),
    # Every IAM ARN, not only roles, and an id in a value that is not JSON.
    Case("not JSON", ("X_ROLE_ARN",),
         {"X_ROLE_ARN": "see arn:aws:iam::717171717171:user/someone and 818181818181"}, 0,
         masks=("717171717171", "818181818181", "arn:aws:iam::717171717171:user/someone"),
         counts=((MASK, 3),)),
    # The value itself is never printed, even where it holds no id to mask.
    Case("never echoed", ("X_ACCOUNT_ID",), {"X_ACCOUNT_ID": "not-an-id-SENTINEL-value"}, 0,
         counts=((ANY, 0),), absent=("SENTINEL",)),
    Case("never echoed in a refusal", ("X_ACCOUNT_ID",), {"X_ACCOUNT_ID": "SENTINEL\nSENTINEL"}, 1,
         counts=((ERROR, 1),), absent=("SENTINEL",)),
    # Usage errors.
    Case("no names", (), {}, 2, counts=((ERROR, 1),)),
    Case("only the flag", ("--optional",), {}, 2, counts=((ERROR, 1),)),
    Case("a name that is not a variable name", ("DEPLOY_ROLE_ARN;echo",), {}, 2,
         counts=((ERROR, 1),)),
    Case("an unknown flag", ("--mask-everything", "DEPLOY_ROLE_ARN"), {}, 2,
         counts=((ERROR, 1),)),
    Case("the self-test with an argument", ("--self-test", "X"), {}, 2, counts=((ERROR, 1),)),
]
MIN_CASES = 20


def problems(case: Case, status: int, lines: list[str], stderr: str) -> list[str]:
    """What is wrong with one result of case, or nothing."""
    found: list[str] = []
    if status != case.status:
        found.append(f"exit {status}, want {case.status}")
    if stderr:
        found.append("wrote to stderr")
    if any(not re.match(r"::add-mask::|::error( title=[^:]*)?::", line) for line in lines):
        found.append("printed a line that is neither ::add-mask:: nor ::error")
    if any(line.startswith("::error") and re.search(r"[0-9]{12}|arn:aws", line)
           for line in lines):
        found.append("an ::error line carries a twelve-digit run or an ARN")
    for mask in case.masks:
        if f"::add-mask::{mask}" not in lines:
            found.append("no ::add-mask:: for a value that must be masked")
    for pattern, want in case.counts:
        got = sum(1 for line in lines if re.search(pattern, line))
        if got != want:
            found.append(f"{got} line(s) matching {pattern}, want {want}")
    if any(text in line for text in case.absent for line in lines):
        found.append("the output carries text it must never print")
    if case.ordered and not (lines and lines[0].startswith("::add-mask::")
                             and lines[-1].startswith("::error")):
        found.append("the masks must come first and the refusal last")
    return found


def in_process(case: Case) -> tuple[int, list[str], str]:
    """case run through main() in this process, with exactly its own environment."""
    out = io.StringIO()
    with mock.patch.dict(os.environ, case.env, clear=True), contextlib.redirect_stdout(out):
        status = main(list(case.args))
    return status, out.getvalue().splitlines(), ""


def through_shim(case: Case, path: str | None = None) -> tuple[int, list[str], str]:
    """case run through scripts/mask-aws-ids.sh with nothing in the environment but PATH
    and its own variables."""
    proc = subprocess.run(["bash", str(SHIM), *case.args],
                          env={"PATH": os.environ.get("PATH", "") if path is None else path,
                               **case.env},
                          capture_output=True, text=True, timeout=60, check=False)
    return proc.returncode, proc.stdout.splitlines(), proc.stderr


# Results that break one check each, which problems() must report: (name, result,
# the words its report says). Each is checked against the deploy pair.
BROKEN = [
    ("a wrong exit status", (1, ["::add-mask::" + ID1, "::add-mask::" + ARN1], ""), "want 0"),
    ("output on stderr", (0, ["::add-mask::" + ID1, "::add-mask::" + ARN1], "x"),
     "wrote to stderr"),
    ("a line that is not a command", (0, ["::add-mask::" + ID1, "::add-mask::" + ARN1, ID1], ""),
     "neither ::add-mask:: nor ::error"),
    ("an error quoting an id", (0, ["::add-mask::" + ID1, "::add-mask::" + ARN1,
                                    f"::error::{ID1}"], ""), "carries a twelve-digit run"),
    ("a mask left out", (0, ["::add-mask::" + ID1], ""), "no ::add-mask::"),
    ("a mask too many", (0, ["::add-mask::" + ID1, "::add-mask::" + ARN1, "::add-mask::x"], ""),
     "line(s) matching"),
]


def expect(ok: bool, message: str) -> list[str]:
    """[message] when a check of the self-test's own failed, else nothing."""
    return [] if ok else [message]


def self_test_checks() -> list[str]:
    """Why the self-test's own checks cannot be trusted, or nothing: each must report a
    result that breaks it."""
    deploy = CASES[0]
    failures = []
    for name, (status, lines, stderr), says in BROKEN:
        failures += expect(any(says in p for p in problems(deploy, status, lines, stderr)),
                           f"the check for {name} did not report it")
    failures += expect(bool(problems(Case("x", (), {}, 0, absent=("SENTINEL",)), 0,
                                     ["::add-mask::SENTINEL"], "")),
                       "the check for text the output must never print did not report it")
    failures += expect(bool(problems(Case("x", (), {}, 1, ordered=True), 1,
                                     ["::error::x", "::add-mask::" + ID1], "")),
                       "the check for masks ahead of the refusal did not report it")
    failures += expect(expect(False, "x") == ["x"], "a failed check was not reported")
    return failures


def shell_without_python() -> list[str]:
    """Why the shell entry point did not stop on a host with no python3, or nothing."""
    bash, dirname = shutil.which("bash"), shutil.which("dirname")
    if bash is None or dirname is None:
        return ["bash or dirname is not on PATH, so the case cannot be built"]
    with tempfile.TemporaryDirectory(prefix="mask-aws-ids-") as tmp:
        for tool in (bash, dirname):
            os.symlink(tool, Path(tmp) / Path(tool).name)
        case = Case("no python3", ("DEPLOY_ROLE_ARN",), {"DEPLOY_ROLE_ARN": ARN1}, 1,
                    counts=((ERROR, 1), (MASK, 0)))
        return problems(case, *through_shim(case, path=tmp))


def self_test(cases: Sequence[Case] = tuple(CASES), shim: bool = True) -> int:
    """0 when every case passes, in this process and (with shim) through the shell entry
    point, and there are at least MIN_CASES; 1 otherwise. The full run (shim) also
    requires the self-test's own checks to report what breaks them, a host with no
    python3 to stop, and a self-test over a failing case, or over too few cases, to
    fail."""
    failures = []
    ran = []
    for case in cases:
        results = [("in process", in_process(case))]
        if shim:
            results.append(("through the shell", through_shim(case)))
        for how, result in results:
            ran.append(how)
            failures += [f"[{case.name}, {how}]: {p}" for p in problems(case, *result)]
    if len(cases) < MIN_CASES:
        failures.append(f"ran only {len(cases)} case(s); refusing to report a pass")
    if shim:
        failures += expect(ran.count("through the shell") == len(cases),
                           f"ran {ran.count('through the shell')} of {len(cases)} case(s) through "
                           "the shell entry point")
        # The reporter itself, checked without it: a failed check must yield its message.
        failures += ["expect() does not report a failed check"] * (expect(False, "x") != ["x"])
        failures += self_test_checks() + shell_without_python()
        with mock.patch.object(shutil, "which", lambda _name: None):
            failures += expect(bool(shell_without_python()),
                               "the no-python3 case passed on a host with no bash to run it")
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            failing = self_test((CASES[0]._replace(status=1),) * MIN_CASES, shim=False)
            short = self_test(tuple(CASES[:1]), shim=False)
        failures += expect(failing == 1, "a self-test over a failing case passed")
        failures += expect(short == 1, f"a self-test over fewer than {MIN_CASES} cases passed")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        print(f"mask-aws-ids self-test FAILED: {len(failures)} problem(s) over {len(cases)} "
              "case(s)", file=sys.stderr)
        return 1
    print(f"mask-aws-ids self-test passed ({len(cases)} cases, each in this process and "
          "through scripts/mask-aws-ids.sh; a host with no python3 stops; the self-test's own "
          f"{len(BROKEN) + 3} checks report what breaks them, and a self-test over a failing "
          "case or too few cases fails).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
