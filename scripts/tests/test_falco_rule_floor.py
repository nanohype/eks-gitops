"""Unit tests for the Falco rule-floor gate.

The gate answers "is every rule set installed on a node one Falco actually
loads?". Its own failure mode is a FALSE NEGATIVE — reporting the fleet healthy
while a tier sits unread on disk — because that failure is silent in exactly the
way the gate exists to prevent. These concentrate on the decisions that produce
it: which paths count as read, and which priorities count as loading a rule.

Everything here is offline. The gate's registry and helm calls are exercised by
the controls sweep against a mutated tree, not from here.
"""

import unittest

from gateloader import load

gate = load("check-falco-rule-floor")


class PathIsRead(unittest.TestCase):
    """falcoctl writes to the root of the shared dir; Falco reads a listed set.

    The gap between those two is the defect the gate exists for, so the rule
    deciding it is tested directly rather than through a whole run.
    """

    FILES = {"/etc/falco/falco_rules.yaml", "/etc/falco/falco_rules.local.yaml"}
    DIRS = {"/etc/falco/rules.d"}

    def test_a_named_file_is_read(self):
        self.assertTrue(
            gate.reachable("/etc/falco/falco_rules.yaml", self.FILES, self.DIRS))

    def test_a_file_under_a_named_directory_is_read(self):
        self.assertTrue(
            gate.reachable("/etc/falco/rules.d/extra.yaml", self.FILES, self.DIRS))

    def test_an_installed_but_unnamed_file_is_not_read(self):
        """The exact shape #231 shipped against: the tier downloads and sits."""
        self.assertFalse(
            gate.reachable("/etc/falco/falco-sandbox_rules.yaml", self.FILES, self.DIRS),
            "a rule set falcoctl installs but rules_files does not name was "
            "reported as read, which is the regression this gate exists to catch",
        )

    def test_a_sibling_sharing_a_directory_prefix_is_not_read(self):
        """Anchored on a separator: `rules.d` must not cover `rules.disabled`."""
        self.assertFalse(
            gate.reachable("/etc/falco/rules.disabled", self.FILES, self.DIRS))

    def test_the_directory_itself_is_not_a_rule_file(self):
        self.assertFalse(
            gate.reachable("/etc/falco/rules.d", self.FILES, self.DIRS))


class SeverityOrder(unittest.TestCase):
    """Falco loads a rule when its priority is at least as severe as the floor.

    Getting the direction wrong inverts the gate: it would pass the strict
    configuration it exists to reject and fail the permissive one.
    """

    def test_more_severe_than_the_floor_loads(self):
        self.assertLessEqual(gate.rank("critical"), gate.rank("warning"))

    def test_less_severe_than_the_floor_does_not(self):
        self.assertGreater(gate.rank("info"), gate.rank("warning"))

    def test_informational_is_the_long_spelling_of_info(self):
        self.assertEqual(gate.rank("informational"), gate.rank("info"))

    def test_case_and_padding_are_tolerated(self):
        self.assertEqual(gate.rank("  CRITICAL "), gate.rank("critical"))

    def test_an_unknown_spelling_is_rejected_not_ordered(self):
        """-1 must not sort as "most severe" and quietly load everything."""
        self.assertEqual(gate.rank("urgent"), -1)

    def test_the_minimum_is_permissive_enough_for_info_rules(self):
        """The privileged-container rules are INFO; `notice` leaves them unloaded."""
        self.assertGreaterEqual(gate.rank(gate.MIN_PRIORITY), gate.rank("info"))
        self.assertGreater(gate.rank(gate.MIN_PRIORITY), gate.rank("notice"))


class RulesFilesSplit(unittest.TestCase):
    """rules_files mixes files and directories, and they are matched differently."""

    def setUp(self):
        self._saved = list(gate.failures)
        self.addCleanup(lambda: gate.failures.__setitem__(slice(None), self._saved))
        gate.failures.clear()

    def test_files_and_directories_are_separated(self):
        files, dirs = gate.read_paths(
            {"rules_files": ["/etc/falco/a.yaml", "/etc/falco/b.yml",
                             "/etc/falco/rules.d"]}, "development")
        self.assertEqual(files, {"/etc/falco/a.yaml", "/etc/falco/b.yml"})
        self.assertEqual(dirs, {"/etc/falco/rules.d"})
        self.assertEqual(gate.failures, [])

    def test_a_trailing_slash_does_not_make_a_second_directory(self):
        _, dirs = gate.read_paths({"rules_files": ["/etc/falco/rules.d/"]}, "staging")
        self.assertEqual(dirs, {"/etc/falco/rules.d"})

    def test_an_absent_rules_files_is_reported(self):
        files, dirs = gate.read_paths({}, "production")
        self.assertEqual((files, dirs), (set(), set()))
        self.assertTrue(any("rules_files" in f for f in gate.failures),
                        f"an empty rules_files was accepted: {gate.failures}")


class DerivedFromTheTree(unittest.TestCase):
    """Coordinates and environments come from the repo, never re-declared here."""

    def test_chart_pin_comes_from_the_applicationset(self):
        repo, chart, version = gate.chart_pin()
        self.assertEqual(chart, "falco")
        self.assertTrue(repo.startswith("http"), repo)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_environments_are_read_from_the_addon_directory(self):
        envs = gate.environments()
        self.assertIn("production", envs)
        self.assertTrue(envs, "no environment discovered — the gate would check none")


if __name__ == "__main__":
    unittest.main()
