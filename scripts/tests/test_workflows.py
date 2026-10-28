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
"""

from __future__ import annotations

import pathlib
import re
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
    the same pins restores. So the conditions on the save steps are evaluated
    for each outcome the fetch can have, and the keys they save under rendered.
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

    def test_restore_keys_hand_a_run_the_last_set_kept_complete_or_not(self):
        primary = self.primary()
        partial = self.saved("failure", hit=False)[0]
        prefixes = str(self.restore["with"].get("restore-keys", "")).split()
        self.assertTrue(prefixes, "no restore-keys, so a pin bump starts from nothing")
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assertTrue(primary.startswith(prefix))
                self.assertTrue(partial.startswith(prefix))

    def test_every_rendering_job_restores_the_key_a_complete_set_is_kept_under(self):
        """Each restores exactly that key, so none restores an incomplete set."""
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
