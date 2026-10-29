"""Unit tests over the workflows themselves: what bounds a job, and what a job keeps.

A job with no timeout-minutes runs to the runner's six-hour default, and a
download with no bound of its own runs to the job's: either way a stalled
mirror or registry ends the job on the step it stalled in, with nothing said
about what it was waiting on. Both are a property of the YAML and nothing else
reads it, so these read it.

The chart cache is the third. The charts job keeps every archive it verified
for the next run, and the jobs that render a chart restore what it kept. Which
key a set is kept under, and whether it is kept at all, is decided by step
conditions over the outcome of the fetch, so KeepingTheChartCache evaluates
those conditions for every outcome rather than reading them as text.

The ECR Public login is the fourth, and LoggingInToEcrPublic evaluates its step
conditions the same way, runs its script against stand-ins for the CLIs it
calls, and holds the OIDC grant it needs to the jobs that log in.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

CHART_CACHE = "~/.cache/eks-gitops/charts"


def workflows() -> dict[str, dict]:
    found = {p.name: yaml.safe_load(p.read_text())
             for p in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])}
    assert found, f"no workflow under {WORKFLOWS}"
    return found


def jobs() -> dict[str, dict]:
    """{workflow:job: job} over every workflow."""
    return {f"{name}:{job}": body
            for name, doc in workflows().items()
            for job, body in (doc.get("jobs") or {}).items()}


# ── A small evaluator for the step conditions the chart cache rests on ──

_TOKEN = re.compile(r"""\s*(?:
    (?P<string>'(?:[^']|'')*')
  | (?P<op>&&|\|\||==|!=|\(|\))
  | (?P<call>[A-Za-z_]\w*)\(\)
  | (?P<name>[A-Za-z_][\w.-]*)
)""", re.X)

STATUS_FUNCTIONS = ("always", "success", "failure", "cancelled")


def evaluate(expression: str, context: dict[str, str], status: dict[str, bool]) -> object:
    """A GitHub Actions `if:` over `context`, for the operators these conditions use.

    `context` maps each dotted property the expression reads, steps.fetch.outcome
    say, to its value, and `status` each status function to what it returns. A
    property missing from `context` raises, so a misspelled step id fails here
    rather than evaluating to an empty string the way GitHub evaluates it. A
    condition naming no status function is evaluated under success(), as GitHub
    evaluates it. Strings compare ignoring case, as GitHub compares them.
    """
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    python: list[str] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot read {text[pos:]!r} in {expression!r}")
        pos = m.end()
        if m.group("string"):
            python.append(repr(m.group("string")[1:-1].replace("''", "'").lower()))
        elif m.group("op"):
            python.append({"&&": " and ", "||": " or "}.get(m.group("op"), m.group("op")))
        elif m.group("call"):
            python.append(repr(status[m.group("call")]))
        else:
            python.append(repr(context[m.group("name")].lower()))
    source = "".join(python)
    if not any(f"{fn}()" in text for fn in STATUS_FUNCTIONS):
        source = f"{status['success']!r} and ({source})"
    return eval(source, {"__builtins__": {}}, {})


def render(template: str, context: dict[str, str]) -> str:
    """`template` with each ${{ property }} replaced from `context`.

    A hashFiles() call becomes a token naming its arguments: what it hashes is
    the same on every branch, which is all a key comparison here needs.
    """
    def value(m: re.Match) -> str:
        expression = m.group(1).strip()
        if expression.startswith("hashFiles("):
            return f"<{expression}>"
        return context[expression]
    return re.sub(r"\$\{\{(.*?)\}\}", value, template)


class EveryJobEndsAtItsOwnTimeout(unittest.TestCase):
    def test_every_job_sets_a_timeout(self):
        found = jobs()
        self.assertGreater(len(found), 1, "no jobs were read")
        for name, job in found.items():
            with self.subTest(job=name):
                minutes = job.get("timeout-minutes")
                self.assertIsInstance(minutes, int, f"{name} sets no timeout-minutes")
                self.assertGreater(minutes, 0)


class EveryDownloadIsBounded(unittest.TestCase):
    """curl connects with no deadline and reads for as long as bytes arrive, and
    retries nothing, unless it is told otherwise."""

    BOUNDS = ("--connect-timeout", "--max-time", "--retry")

    def invocations(self) -> list[tuple[str, list[str]]]:
        """(workflow:job, curl's arguments) for every curl a run step makes."""
        found: list[tuple[str, list[str]]] = []
        for name, job in jobs().items():
            for step in job.get("steps") or []:
                script = re.sub(r"\\\n\s*", " ", str(step.get("run", "")))
                for line in script.splitlines():
                    words = line.split()
                    found.extend((name, words[i + 1:])
                                 for i, word in enumerate(words) if word == "curl")
        return found

    def test_every_curl_carries_each_bound(self):
        found = self.invocations()
        self.assertTrue(found, "no curl was read out of the workflows")
        for name, args in found:
            for flag in self.BOUNDS:
                with self.subTest(job=name, flag=flag, args=" ".join(args)):
                    self.assertIn(flag, args)
                    value = args[args.index(flag) + 1]
                    self.assertRegex(value, r"^[1-9]\d*$", f"{flag} takes no positive count")


class KeepingTheChartCache(unittest.TestCase):
    """The charts job keeps every archive it verified, whether or not every pin was.

    A combined actions/cache step saves only when the whole job succeeds, so a
    fetch that verified every chart but the one a registry throttled kept none
    of them, and the next run read every chart again. The key every rendering
    job restores must name only a complete set, though, because a saved key is
    never replaced: an incomplete set saved there is what every later run with
    the same pins restores. A restore that misses its key exactly takes the
    newest key that begins with it, so an incomplete set kept under a key that
    begins with it is restored as well. So the conditions on the save steps are
    evaluated for each outcome the fetch can have, and the keys they save under
    rendered.
    """

    RUN = {"github.run_id": "4242", "github.run_attempt": "2"}

    def setUp(self):
        doc = workflows()["ci.yml"]
        self.job = doc["jobs"]["charts"]
        steps = self.job["steps"]

        def on_cache(step, action):
            return (str(step.get("uses", "")).startswith(f"actions/{action}@")
                    and (step.get("with") or {}).get("path") == CHART_CACHE)

        self.combined = [s for s in steps if on_cache(s, "cache")]
        restores = [i for i, s in enumerate(steps) if on_cache(s, "cache/restore")]
        fetches = [i for i, s in enumerate(steps)
                   if "render-addons.py --fetch" in str(s.get("run", ""))]
        self.saves = [i for i, s in enumerate(steps) if on_cache(s, "cache/save")]
        self.assertEqual(len(restores), 1, "the charts job restores the cache once")
        self.assertEqual(len(fetches), 1, "the charts job fetches once")
        self.order = (restores[0], fetches[0], self.saves)
        self.restore = steps[restores[0]]
        self.fetch = steps[fetches[0]]
        self.save_steps = [steps[i] for i in self.saves]

    def saved(self, outcome: str, hit: bool) -> list[str]:
        """The keys the save steps save under, when the fetch ended in `outcome`."""
        primary = render(self.restore["with"]["key"], {})
        rid, fid = self.restore["id"], self.fetch["id"]
        context = {f"steps.{fid}.outcome": outcome,
                   f"steps.{rid}.outputs.cache-hit": "true" if hit else "false",
                   f"steps.{rid}.outputs.cache-primary-key": primary,
                   **self.RUN}
        status = {"always": True, "success": outcome == "success",
                  "failure": outcome in ("failure", "skipped"),
                  "cancelled": outcome == "cancelled"}
        return [render(step["with"]["key"], context) for step in self.save_steps
                if evaluate(str(step.get("if", "")), context, status)]

    def primary(self) -> str:
        return render(self.restore["with"]["key"], {})

    def pins(self) -> str:
        """The pins hash the primary key names, as render() writes it."""
        found = re.findall(r"<hashFiles\(.*?\)>", self.primary())
        self.assertEqual(len(found), 1, f"{self.primary()} names the pins once")
        return found[0]

    def restore_keys(self) -> list[str]:
        """The charts job's restore-keys, rendered, in the order a restore tries them."""
        text = str(self.restore["with"].get("restore-keys", ""))
        return [render(line.strip(), {}) for line in text.splitlines() if line.strip()]

    def test_the_cache_is_restored_and_saved_as_separate_steps_around_the_fetch(self):
        self.assertEqual(self.combined, [], "a combined cache step saves only on success")
        restore, fetch, saves = self.order
        self.assertTrue(saves, "the charts job saves nothing")
        self.assertLess(restore, fetch)
        self.assertTrue(all(fetch < i for i in saves))
        self.assertIn("id", self.restore)
        self.assertIn("id", self.fetch)

    def test_every_save_runs_whatever_the_job_did_before_it(self):
        """A condition with no status function runs only while the job is succeeding."""
        for step in self.save_steps:
            with self.subTest(step=step.get("name")):
                self.assertIn("always()", str(step.get("if", "")))

    def test_a_complete_set_is_kept_under_the_key_the_rendering_jobs_restore(self):
        self.assertEqual(self.saved("success", hit=False), [self.primary()])

    def test_a_set_restored_whole_is_not_saved_again(self):
        """Its key is already saved, and a saved key is never replaced."""
        self.assertEqual(self.saved("success", hit=True), [])

    def test_what_a_failed_or_cancelled_fetch_verified_is_kept_under_a_key_of_its_own(self):
        primary = self.primary()
        for outcome in ("failure", "cancelled"):
            for hit in (False, True):
                with self.subTest(outcome=outcome, hit=hit):
                    saved = self.saved(outcome, hit)
                    self.assertEqual(len(saved), 1, f"a {outcome} fetch keeps {saved}")
                    self.assertNotEqual(saved[0], primary,
                                        "an incomplete set under the key every rendering "
                                        "job restores")
                    for value in self.RUN.values():
                        self.assertIn(value, saved[0], "a key a later run can collide with")

    def test_a_fetch_that_never_ran_keeps_nothing(self):
        """The directory holds only what was restored, which is already saved."""
        self.assertEqual(self.saved("skipped", hit=False), [])

    def test_the_key_names_the_pins_and_not_the_branch_or_the_run(self):
        """So a pull request whose pins match main's restores main's set."""
        key = self.restore["with"]["key"]
        self.assertIn("hashFiles(", key)
        self.assertNotIn("github.", key)

    def test_no_incomplete_set_is_kept_under_a_key_the_rendering_jobs_restore(self):
        """Not under their key, and not under one beginning with it, which a
        rendering job restores whenever the complete set was never saved or was
        evicted."""
        primary = self.primary()
        for outcome in ("failure", "cancelled"):
            for hit in (False, True):
                with self.subTest(outcome=outcome, hit=hit):
                    saved = self.saved(outcome, hit)
                    self.assertTrue(saved, f"a {outcome} fetch keeps nothing")
                    for key in saved:
                        self.assertFalse(key.startswith(primary),
                                         f"{key} begins with the rendering jobs' {primary}")

    def test_restore_keys_try_the_incomplete_set_these_pins_left_first(self):
        """An earlier attempt at the same pins kept everything it verified, so a
        re-run starting from it fetches only what that attempt did not reach. The
        newest set kept under any key can be for other pins, missing every chart
        these moved."""
        keys = self.restore_keys()
        self.assertTrue(keys, "no restore-keys")
        self.assertIn(self.pins(), keys[0],
                      "the first restore key names no pins, so any pins' set can come first")
        self.assertTrue(self.saved("failure", hit=False)[0].startswith(keys[0]),
                        "the first restore key does not reach the set these pins left")

    def test_restore_keys_then_hand_a_pin_bump_the_newest_set_complete_or_not(self):
        """A restore key naming no pins reaches the sets every pin set kept, so a
        pin bump fetches only the chart it moved."""
        primary = self.primary()
        partial = self.saved("failure", hit=False)[0]
        broad = [key for key in self.restore_keys() if self.pins() not in key]
        self.assertTrue(broad, "every restore key names these pins, so a pin bump "
                               "starts from nothing")
        for prefix in broad:
            with self.subTest(prefix=prefix):
                self.assertTrue(primary.startswith(prefix))
                self.assertTrue(partial.startswith(prefix))

    def test_every_rendering_job_restores_the_key_a_complete_set_is_kept_under(self):
        """Each restores that key with no restore-keys, so the only other key it
        can restore is one beginning with that key, which no incomplete set is
        kept under."""
        readers = 0
        for name, job in jobs().items():
            for step in job.get("steps") or []:
                if (str(step.get("uses", "")).startswith("actions/cache/restore@")
                        and (step.get("with") or {}).get("path") == CHART_CACHE
                        and step is not self.restore and name != "ci.yml:charts"):
                    readers += 1
                    with self.subTest(job=name):
                        self.assertEqual(render(step["with"]["key"], {}), self.primary())
                        self.assertNotIn("restore-keys", step["with"])
        self.assertTrue(readers, "no job restores what the charts job keeps")


CREDENTIALS_ACTION = "aws-actions/configure-aws-credentials@"
ROLE_VARIABLE = "vars.ECR_PUBLIC_PULL_ROLE_ARN"


def step_shell(doc: dict, job: dict, step: dict) -> list[str]:
    """The command a Linux runner runs `step`'s script with, its path appended.

    The step's own `shell`, else its job's `defaults.run.shell`, else the
    workflow's. With none of them set the runner uses bash -e, which leaves a
    pipeline's status to its last command; `shell: bash` adds pipefail.
    """
    shell = (step.get("shell")
             or ((job.get("defaults") or {}).get("run") or {}).get("shell")
             or ((doc.get("defaults") or {}).get("run") or {}).get("shell"))
    if shell is None:
        return ["bash", "-e"]
    if shell == "bash":
        return ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
    if shell == "sh":
        return ["sh", "-e"]
    raise ValueError(f"no reading of shell {shell!r}")


class LoggingInToEcrPublic(unittest.TestCase):
    """The jobs that read public.ecr.aws in bulk log in before they read, when they can.

    A client logged in to ECR Public is metered by the AWS account its token
    came from rather than by the runner's shared address. One step assumes the
    pull role over OIDC and one hands the token it mints to `docker login`.
    Which of them runs is decided by their conditions, so those are evaluated
    for every event the workflow runs on, a configured role and an unset one,
    and the login script is run against stand-ins for the aws and docker CLIs.
    """

    # Each job that logs in, and the step that reads public.ecr.aws in it.
    READERS = {"ci.yml:charts": "render-addons.py --fetch",
               "ci.yml:image-vulnerabilities": "check-image-vulnerabilities.py"}
    REPO = "owner/repo"
    OUTPUTS = {"aws-access-key-id": "key-id", "aws-secret-access-key": "secret-key",
               "aws-session-token": "session-token"}

    def setUp(self):
        self.doc = workflows()["ci.yml"]
        self.logins: dict[str, tuple[dict, list[dict], int, int]] = {}
        for name, job in jobs().items():
            steps = job.get("steps") or []
            creds = [i for i, s in enumerate(steps)
                     if str(s.get("uses", "")).startswith(CREDENTIALS_ACTION)]
            logins = [i for i, s in enumerate(steps) if "docker login" in str(s.get("run", ""))]
            if creds or logins:
                self.assertEqual((len(creds), len(logins)), (1, 1),
                                 f"{name} assumes the role and logs in once each")
                self.logins[name] = (job, steps, creds[0], logins[0])
        self.assertEqual(sorted(self.logins), sorted(self.READERS))

    def condition(self, step: dict, context: dict[str, str], passing: bool = True) -> bool:
        status = {"always": True, "success": passing, "failure": not passing,
                  "cancelled": False}
        return bool(evaluate(str(step.get("if") or "success()"), context, status))

    def test_each_job_logs_in_before_it_reads(self):
        for name, (_, steps, creds, login) in self.logins.items():
            reads = [i for i, s in enumerate(steps) if self.READERS[name] in str(s.get("run", ""))]
            with self.subTest(job=name):
                self.assertEqual(len(reads), 1, f"{name} reads public.ecr.aws once")
                self.assertLess(creds, login)
                self.assertLess(login, reads[0])
                self.assertEqual(steps[creds]["with"]["role-to-assume"],
                                 f"${{{{ {ROLE_VARIABLE} }}}}")

    def test_the_role_is_assumed_only_when_configured_and_never_for_a_fork(self):
        """GitHub issues a fork's pull request no OIDC token, and an unset variable names no role."""
        events = {"a push": ("push", ""),
                  "a pull request from this repo": ("pull_request", self.REPO),
                  "a pull request from a fork": ("pull_request", "fork/repo")}
        for name, (_, steps, creds, _) in self.logins.items():
            for role in ("", "the-role"):
                for label, (event, head) in events.items():
                    context = {ROLE_VARIABLE: role, "github.event_name": event,
                               "github.event.pull_request.head.repo.full_name": head,
                               "github.repository": self.REPO}
                    with self.subTest(job=name, role=role or "unset", event=label):
                        self.assertEqual(self.condition(steps[creds], context),
                                         bool(role) and head != "fork/repo")

    def test_the_login_runs_only_once_the_role_was_assumed(self):
        """Skipped with the role, so an unconfigured or fork run reads anonymously."""
        for name, (_, steps, creds, login) in self.logins.items():
            outcome = f"steps.{steps[creds]['id']}.outcome"
            with self.subTest(job=name):
                self.assertTrue(self.condition(steps[login], {outcome: "success"}))
                self.assertFalse(self.condition(steps[login], {outcome: "skipped"}))
                self.assertFalse(self.condition(steps[login], {outcome: "failure"},
                                                passing=False))

    def test_the_role_credentials_reach_the_login_step_alone(self):
        """As outputs of the step that assumed the role, not as environment every
        later step in the job inherits."""
        for name, (_, steps, creds, login) in self.logins.items():
            given = steps[creds]["with"]
            outputs = f"steps.{steps[creds]['id']}.outputs."
            with self.subTest(job=name):
                self.assertIs(given.get("output-env-credentials"), False)
                self.assertIs(given.get("output-credentials"), True)
                self.assertEqual(steps[login].get("env"), {
                    "AWS_ACCESS_KEY_ID": f"${{{{ {outputs}aws-access-key-id }}}}",
                    "AWS_SECRET_ACCESS_KEY": f"${{{{ {outputs}aws-secret-access-key }}}}",
                    "AWS_SESSION_TOKEN": f"${{{{ {outputs}aws-session-token }}}}",
                })
                readers = [s.get("name") for i, s in enumerate(steps)
                           if i != login and outputs in str(s)]
                self.assertEqual(readers, [], "another step reads the role's credentials")

    def run_login(self, aws: str, docker: str
                  ) -> dict[str, tuple[subprocess.CompletedProcess, dict[str, str]]]:
        """Each job's login step, run under the shell the runner gives it with
        stand-ins for aws and docker, and what the stand-ins recorded, by job.

        `aws` and `docker` are the bodies of the stand-ins; each runs with $LOG
        naming a directory it records into, and with the environment the step
        sets, its expressions rendered from the outputs in OUTPUTS.
        """
        runs = {}
        for name, (job, steps, creds, login) in self.logins.items():
            step = steps[login]
            with tempfile.TemporaryDirectory() as tmp:
                bin_dir = pathlib.Path(tmp) / "bin"
                log = pathlib.Path(tmp) / "log"
                bin_dir.mkdir()
                log.mkdir()
                for tool, body in (("aws", aws), ("docker", docker)):
                    stub = bin_dir / tool
                    stub.write_text(f"#!/bin/sh\n{body}\n")
                    stub.chmod(0o755)
                script = pathlib.Path(tmp) / "step.sh"
                script.write_text(str(step["run"]))
                context = {f"steps.{steps[creds]['id']}.outputs.{k}": v
                           for k, v in self.OUTPUTS.items()}
                env = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin", "LOG": str(log),
                       **{k: render(str(v), context) for k, v in step["env"].items()}}
                done = subprocess.run([*step_shell(self.doc, job, step), str(script)],
                                      env=env, capture_output=True, text=True, timeout=30,
                                      check=False)
                runs[name] = (done, {f.name: f.read_text() for f in log.iterdir()})
        self.assertTrue(runs, "no login step was run")
        return runs

    def test_the_minted_token_is_handed_to_docker_on_stdin(self):
        runs = self.run_login(
            aws='echo "$* $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN" '
                '> "$LOG/aws"; echo minted-token',
            docker='echo "$*" > "$LOG/docker"; cat > "$LOG/stdin"')
        for name, (done, recorded) in runs.items():
            with self.subTest(job=name):
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(recorded["aws"].split(),
                                 ["ecr-public", "get-login-password", "--region", "us-east-1",
                                  *self.OUTPUTS.values()])
                self.assertEqual(recorded["docker"].split(),
                                 ["login", "--username", "AWS", "--password-stdin",
                                  "public.ecr.aws"])
                self.assertEqual(recorded["stdin"], "minted-token\n")

    def test_a_token_that_could_not_be_fetched_fails_the_step_whatever_docker_does(self):
        """Without pipefail the pipeline's status is docker's, and a docker that
        accepted the empty input would pass a login that never happened."""
        runs = self.run_login(aws="echo 'Unable to locate credentials' >&2; exit 253",
                              docker='cat > "$LOG/stdin"')
        for name, (done, recorded) in runs.items():
            with self.subTest(job=name):
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(recorded["stdin"], "")

    def test_id_token_is_granted_only_to_the_jobs_that_log_in(self):
        """A workflow-level grant hands every job, and every job added later, the
        OIDC token the pull role is assumed with."""
        granted = []
        for name, doc in workflows().items():
            with self.subTest(workflow=name):
                self.assertEqual(doc.get("permissions"), {"contents": "read"})
            for job_name, job in (doc.get("jobs") or {}).items():
                permissions = job.get("permissions") or {}
                if permissions == "write-all" or (
                        isinstance(permissions, dict)
                        and permissions.get("id-token", "none") != "none"):
                    granted.append(f"{name}:{job_name}")
        self.assertEqual(sorted(granted), sorted(self.logins))


class TheEvaluator(unittest.TestCase):
    """The conditions above are only as well read as this reads them."""

    CONTEXT = {"steps.a.outcome": "success", "steps.b.outcome": "failure"}
    PASSING = {"always": True, "success": True, "failure": False, "cancelled": False}
    FAILING = {"always": True, "success": False, "failure": True, "cancelled": False}

    def test_and_binds_tighter_than_or(self):
        expr = "steps.a.outcome == 'failure' && steps.b.outcome == 'x' || always()"
        self.assertTrue(evaluate(expr, self.CONTEXT, self.PASSING))

    def test_a_condition_with_no_status_function_runs_only_while_passing(self):
        expr = "steps.a.outcome == 'success'"
        self.assertTrue(evaluate(expr, self.CONTEXT, self.PASSING))
        self.assertFalse(evaluate(expr, self.CONTEXT, self.FAILING))
        self.assertTrue(evaluate(f"always() && {expr}", self.CONTEXT, self.FAILING))

    def test_strings_compare_ignoring_case_and_parentheses_group(self):
        expr = "${{ always() && (steps.b.outcome == 'FAILURE' || steps.a.outcome != 'success') }}"
        self.assertTrue(evaluate(expr, self.CONTEXT, self.FAILING))

    def test_a_property_nothing_provides_is_refused(self):
        with self.assertRaises(KeyError):
            evaluate("steps.fecth.outcome == 'success'", self.CONTEXT, self.PASSING)

    def test_an_operator_it_does_not_read_is_refused(self):
        with self.assertRaises(ValueError):
            evaluate("!cancelled()", self.CONTEXT, self.PASSING)


if __name__ == "__main__":
    unittest.main()
