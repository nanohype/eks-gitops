"""The reader that decides whether an exempted harness is actually invoked.

controls.py excuses four executables from carrying a positive control on the
grounds that each asserts its own outcome every time it runs. That excuse is
worth what its second half is worth, and the second half rests entirely on the
reader underneath: one satisfied by the path appearing anywhere in a caller's
bytes is satisfied by a comment naming the harness, which is the shape
blank_comments exists to reject one screen up in the same file.

So every case here is a planted violation against the READER. Each supplies a
caller that names the harness in prose and requires the answer to be no, or a
caller that runs it and requires yes. Passing the rule a stub proves the rule;
it is these that prove the thing the rule asks.
"""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent


def _load_controls():
    """controls.py, by path: it is an executable, not an importable module name."""
    path = HERE / "controls.py"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} does not exist — the harness this module tests was renamed "
            f"or removed and these assertions now say nothing."
        )
    spec = importlib.util.spec_from_file_location("controls_under_test", path)
    assert spec and spec.loader, f"{path} is not loadable as a module"
    module = importlib.util.module_from_spec(spec)
    sys.modules["controls_under_test"] = module
    spec.loader.exec_module(module)
    return module


controls = _load_controls()

# The path the fixtures name. Its spelling is the only thing the reader is given
# to find, so a fixture that names it and is still answered "no" is a fixture
# where the mention was not in a command.
HARNESS = "tests/harness.sh"
PATH = f"scripts/{HARNESS}"


class CallerFixture(unittest.TestCase):
    """A tree holding only the two files that decide what runs."""

    def tree(
        self,
        taskfile: str | None = None,
        workflow: str | None = None,
        extra: tuple[str, str] | None = None,
    ) -> pathlib.Path:
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".github" / "workflows").mkdir(parents=True)
        if taskfile is not None:
            (root / "Taskfile.yaml").write_text(taskfile)
        if workflow is not None:
            (root / ".github" / "workflows" / "ci.yml").write_text(workflow)
        if extra is not None:
            (root / extra[0]).write_text(extra[1])
        return root

    def invoked(self, **kw) -> bool:
        return controls.invoked_anywhere(HARNESS, self.tree(**kw))


class ProseNamingAHarnessIsNotAnInvocation(CallerFixture):
    """Every one of these names the path and none of them runs it."""

    def test_a_yaml_comment_in_the_taskfile_does_not_count(self):
        self.assertFalse(
            self.invoked(
                taskfile=(
                    "version: '3'\n"
                    "tasks:\n"
                    "  validate:\n"
                    f"    # {PATH}\n"
                    "    cmds:\n"
                    "      - echo hello\n"
                )
            )
        )

    def test_a_task_description_does_not_count(self):
        self.assertFalse(
            self.invoked(
                taskfile=(
                    "version: '3'\n"
                    "tasks:\n"
                    "  validate:\n"
                    f'    desc: "the mutation harness, {PATH}"\n'
                    "    cmds:\n"
                    "      - echo hello\n"
                )
            )
        )

    def test_a_yaml_comment_in_a_workflow_does_not_count(self):
        self.assertFalse(
            self.invoked(
                workflow=(
                    "on: push\n"
                    "jobs:\n"
                    "  t:\n"
                    "    steps:\n"
                    f"      # exempted in {PATH}\n"
                    "      - run: echo hello\n"
                )
            )
        )

    def test_a_step_name_does_not_count(self):
        self.assertFalse(
            self.invoked(
                workflow=(
                    "on: push\n"
                    "jobs:\n"
                    "  t:\n"
                    "    steps:\n"
                    f"      - name: {PATH}\n"
                    "        run: echo hello\n"
                )
            )
        )

    def test_a_shell_comment_inside_a_run_block_does_not_count(self):
        """The runner inside `run: |` is a shell, so a `#` line there is prose too."""
        self.assertFalse(
            self.invoked(
                workflow=(
                    "on: push\n"
                    "jobs:\n"
                    "  t:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    f"          # {PATH}\n"
                    "          echo hello\n"
                )
            )
        )

    def test_a_quoted_mention_inside_a_command_does_not_count(self):
        """A path inside a quoted string is a word of the string, not of the command.

        The mention sits mid-string on purpose. At the end of one, the closing
        quote stays attached to the path under any splitter that does not read
        quoting, and the case is then answered correctly by a reader that cannot
        tell a quoted word from a command word — a fixture that passes for a
        reason other than the one it was written for.
        """
        self.assertFalse(
            self.invoked(
                taskfile=(
                    "version: '3'\n"
                    "tasks:\n"
                    "  validate:\n"
                    "    cmds:\n"
                    f'      - echo "see {PATH} for the probe list"\n'
                )
            )
        )

    def test_a_command_in_a_file_that_is_not_a_caller_does_not_count(self):
        """Neither the task runner nor Actions reads it, so nothing runs it."""
        self.assertFalse(
            self.invoked(
                taskfile="version: '3'\ntasks:\n  validate:\n    cmds:\n      - echo hello\n",
                extra=("other.yaml", f"version: '3'\ntasks:\n  x:\n    cmds:\n      - ./{PATH}\n"),
            )
        )


class ACommandTheRunnerExecutesIsAnInvocation(CallerFixture):
    """The other direction, without which "no" everywhere is a passing reader."""

    def test_a_taskfile_command_counts(self):
        self.assertTrue(
            self.invoked(
                taskfile=(f"version: '3'\ntasks:\n  validate:\n    cmds:\n      - ./{PATH}\n")
            )
        )

    def test_the_path_as_an_interpreter_argument_counts(self):
        self.assertTrue(
            self.invoked(
                taskfile=(f"version: '3'\ntasks:\n  validate:\n    cmds:\n      - bash {PATH}\n")
            )
        )

    def test_a_nested_cmd_mapping_counts(self):
        self.assertTrue(
            self.invoked(
                taskfile=(f"version: '3'\ntasks:\n  validate:\n    cmds:\n      - cmd: ./{PATH}\n")
            )
        )

    def test_a_workflow_run_step_counts(self):
        self.assertTrue(
            self.invoked(workflow=(f"on: push\njobs:\n  t:\n    steps:\n      - run: ./{PATH}\n"))
        )

    def test_a_command_below_a_comment_naming_it_still_counts(self):
        """Blanking the comment must not take the command under it with it."""
        self.assertTrue(
            self.invoked(
                workflow=(
                    "on: push\n"
                    "jobs:\n"
                    "  t:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          # the mutation harness\n"
                    f"          ./{PATH}\n"
                )
            )
        )


class ACallerThatWillNotParseIsItsOwnFact(CallerFixture):
    """Distinct from a caller that runs nothing. They are one value to `any()`."""

    def test_the_unparseable_caller_is_named(self):
        root = self.tree(taskfile="tasks:\n  x:\n   - [unbalanced\n")
        _commands, unreadable = controls.caller_commands(root)
        self.assertTrue(any("Taskfile.yaml" in u for u in unreadable), unreadable)

    def test_a_parseable_caller_is_not_named(self):
        root = self.tree(taskfile="version: '3'\ntasks:\n  x:\n    cmds:\n      - echo hi\n")
        self.assertEqual([], controls.caller_commands(root)[1])


class TheRuleReachesTheReader(unittest.TestCase):
    """Supplying `invoked=` exercises the rule. Omitting it exercises this repo.

    Both directions, because either alone is satisfied by a constant: a reader
    returning False always passes the first, one returning True always passes
    the second.
    """

    def test_a_harness_this_repo_runs_is_accepted(self):
        name = "tests/controls.py"
        self.assertEqual(
            [], controls.vacuity_problems({name}, set(), {}, {name: "the control harness"})
        )

    def test_a_harness_this_repo_does_not_run_is_reported(self):
        name = "tests/nothing-invokes-this.sh"
        found = controls.vacuity_problems({name}, set(), {}, {name: "a recorded reason"})
        self.assertTrue(any("A harness nothing invokes asserts nothing" in p for p in found), found)


class TheVerdictOnTheMutatedTree(unittest.TestCase):
    """What run_control accepts as a gate's rejection: exit 1, and only exit 1.

    The gate is a stand-in that passes the clean tree and answers the mutated one
    with the status under test, naming the mutated file each time, so the only
    thing a case varies is the status. Exit 2 is the one that matters: counted as
    a rejection, it let check-workflows.sh pass its control while it reported a
    blocking zizmor finding as a run that never audited.
    """

    def verdict(self, status: int) -> tuple[bool, str]:
        def mutate(tree: pathlib.Path):
            path = tree / "planted.txt"
            path.write_text("planted MARK\n")
            return path, "", "planted MARK\n", "MARK"

        answers = iter([0, status])

        def run_gate(gate, cwd):
            code = next(answers)
            return controls.subprocess.CompletedProcess(
                [gate], code, stdout="" if code == 0 else "planted.txt: the violation", stderr=""
            )

        with (
            mock.patch.object(controls, "copy_tree", lambda dest: None),
            mock.patch.object(controls, "run_gate", run_gate),
        ):
            return controls.run_control("check-x.py", "a planted violation", mutate)

    def test_exit_1_naming_the_file_is_a_rejection(self):
        ok, why = self.verdict(1)
        self.assertTrue(ok, why)
        self.assertIn("rejected a planted violation (exit 1", why)

    def test_could_not_run_is_not_a_rejection(self):
        ok, why = self.verdict(controls.CANNOT_RUN)
        self.assertFalse(ok, why)
        self.assertIn("could-not-run is not a rejection", why)

    def test_a_status_outside_the_taxonomy_is_not_a_rejection(self):
        for status in (3, 13, 14, 127):
            with self.subTest(status=status):
                ok, why = self.verdict(status)
                self.assertFalse(ok, why)
                self.assertIn("neither a rejection (1) nor could-not-run", why)

    def test_an_acceptance_is_reported_as_one(self):
        ok, why = self.verdict(0)
        self.assertFalse(ok, why)
        self.assertIn("gate ACCEPTED a planted violation", why)


if __name__ == "__main__":
    unittest.main()
