"""The manager-default drift check, run against a Renovate package fixture.

The script's whole job is to compare a transcript against a package it does not
control, so the package is what a test has to be able to vary. Every case here
builds a tiny `node_modules/renovate` and runs the real script against it — the
script is never stubbed, because a rule exercised against a stub proves the
stub.

The failure that made this module exist was not a wrong comparison. Renovate
declares `engines.node`, its own code uses language features newer than some
runtimes ship, and a job that inherited the runner's Node ran the package below
that floor: the import threw, the script refused, and a gate that refuses on
every run gates nothing. So the floor is asserted here in both directions — a
runtime below it, and a `.node-version` below it — and the refusals are checked
for the status they exit with, because "could not run" and "the tree is wrong"
are different answers to whoever reads the build.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check-renovate-defaults.mjs"
RECORD = ROOT / "scripts" / "renovate-manager-defaults.json"
NODE = shutil.which("node") or ""

# The layout the script imports. Named once here so a test tree and the script
# cannot drift apart silently — if the script's path changes, `test_the_recorded
# _layout_is_the_one_the_script_imports` fails rather than every case passing
# against a fixture nothing reads.
REGISTRY_REL = "dist/modules/manager/index.js"

DEFAULTS = {
    "argocd": [],
    "github-actions": ["/(^|/)action\\.ya?ml$/"],
    "gomod": ["/(^|/)go\\.mod$/"],
}


def running_major() -> int:
    """The major of the node these cases run under.

    Every floor below is expressed relative to it rather than as a literal, so a
    case saying "the runtime satisfies the floor and the pin does not" keeps
    saying that on whatever node the suite runs on.
    """
    out = subprocess.run([NODE, "-p", "process.versions.node"],
                         capture_output=True, text=True, timeout=60).stdout
    return int(out.strip().split(".")[0])


@unittest.skipUnless(NODE, "node is not on PATH")
class TheDriftCheckAgainstAPackageFixture(unittest.TestCase):
    def package(self, root: pathlib.Path, *, engines: str | None,
                defaults: dict | None = None, registry: bool = True) -> None:
        pkg = root / "node_modules" / "renovate"
        (pkg / "dist" / "modules" / "manager").mkdir(parents=True)
        body: dict[str, object] = {
            "name": "renovate", "version": "0.0.1", "type": "module"}
        if engines is not None:
            body["engines"] = {"node": engines}
        (pkg / "package.json").write_text(json.dumps(body))
        if not registry:
            return
        known = json.dumps(DEFAULTS if defaults is None else defaults)
        (pkg / REGISTRY_REL).write_text(
            f"const DEFAULTS = {known};\n"
            "export const isKnownManager = (name) => name in DEFAULTS;\n"
            "export const get = (name, key) =>\n"
            "  key === 'defaultConfig' ? {managerFilePatterns: DEFAULTS[name]} : undefined;\n"
        )

    def tree(self, *, engines: str | None = None, managers=("argocd", "gomod"),
             record=None, node_version: str | None = "999.0.0",
             defaults=None, registry: bool = True) -> pathlib.Path:
        """A repo root the script can run in, with a Renovate package inside it."""
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "scripts").mkdir()
        shutil.copy(SCRIPT, root / "scripts" / SCRIPT.name)
        (root / "renovate.json").write_text(json.dumps({"enabledManagers": list(managers)}))
        recorded = {m: DEFAULTS.get(m) for m in managers} if record is None else record
        (root / "scripts" / RECORD.name).write_text(json.dumps({
            "generated": {"by": "test", "renovate": "0.0.1"},
            "managers": recorded,
        }))
        if node_version is not None:
            (root / ".node-version").write_text(node_version + "\n")
        self.package(root, engines=engines, defaults=defaults, registry=registry)
        return root

    def run_in(self, root: pathlib.Path, *args: str):
        proc = subprocess.run(
            [NODE, "scripts/" + SCRIPT.name, *args],
            cwd=root, capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout + proc.stderr

    # ── the passing direction, which every refusal below is measured against ──

    def test_a_matching_record_on_a_satisfied_floor_passes(self):
        rc, out = self.run_in(self.tree(engines=">=0.0.0", node_version="99.0.0"))
        self.assertEqual(rc, 0, out)
        self.assertIn("manager defaults OK", out)

    def test_a_package_declaring_no_engines_is_not_a_refusal(self):
        """The floor is the package's claim to make. Absent, there is nothing to
        check and nothing to refuse over."""
        rc, out = self.run_in(self.tree(engines=None))
        self.assertEqual(rc, 0, out)

    # ── could not run: exit 2 ─────────────────────────────────────────────────

    def test_a_runtime_below_the_declared_floor_cannot_run(self):
        """The shape that made a gate refuse on every run. Not exit 1: nothing
        about the tree was read, so there is no verdict on it."""
        rc, out = self.run_in(self.tree(engines="^999.0.0"))
        self.assertEqual(rc, 2, out)
        self.assertIn("engines.node ^999.0.0", out)
        self.assertIn("No default was resolved", out)

    def test_a_registry_that_moved_cannot_run(self):
        rc, out = self.run_in(self.tree(engines=">=0.0.0", registry=False))
        self.assertEqual(rc, 2, out)
        self.assertIn("is not importable", out)

    def test_a_registry_that_moved_says_the_runtime_was_not_the_reason(self):
        """Two failures that look identical from a failed import, and they have
        different repairs — raise the Node, or re-point the script."""
        _, out = self.run_in(self.tree(engines=">=0.0.0", registry=False))
        self.assertIn("the module layout moved", out)

    def test_a_manager_the_registry_does_not_know_cannot_run(self):
        """Misspelled here, or removed upstream. Either way no default was
        resolved for it, which is not a default that matches."""
        rc, out = self.run_in(self.tree(engines=">=0.0.0", managers=("argocd", "gomud"),
                                        record={"argocd": [], "gomud": []}))
        self.assertEqual(rc, 2, out)
        self.assertIn("does not know that name", out)

    def test_an_absent_package_cannot_run(self):
        root = self.tree(engines=">=0.0.0")
        shutil.rmtree(root / "node_modules")
        rc, out = self.run_in(root)
        self.assertEqual(rc, 2, out)
        self.assertIn("not resolvable", out)

    def test_an_engines_range_this_does_not_implement_cannot_run(self):
        """Guessed one way it passes a Node the package cannot run on, guessed
        the other it fails one it can."""
        rc, out = self.run_in(self.tree(engines="20 || >=24"))
        self.assertEqual(rc, 2, out)
        self.assertIn("does not implement", out)

    # ── the tree is wrong: exit 1 ─────────────────────────────────────────────

    def test_a_pinned_node_below_the_floor_is_a_tree_defect(self):
        """This run resolved everything; the next CI run would resolve nothing.
        Exit 1, because the repair is in the tree and the tree is what was read.

        The runtime is above the floor and the pin is below it, which is the only
        arrangement that reaches this verdict — below it on both, the run refuses
        before reading the tree at all.
        """
        major = running_major()
        rc, out = self.run_in(self.tree(engines=f">={major}.0.0",
                                        node_version=f"{major - 1}.0.0"))
        self.assertEqual(rc, 1, out)
        self.assertIn(f".node-version pins node {major - 1}.0.0", out)

    def test_a_caret_floor_rejects_the_next_major(self):
        """`^24.11.0` does not admit 25. A comparator reading it as a lower bound
        would pass a Node the package excludes."""
        major = running_major()
        rc, out = self.run_in(self.tree(engines=f"^{major}.0.0",
                                        node_version=f"{major + 1}.0.0"))
        self.assertEqual(rc, 1, out)
        self.assertIn(f".node-version pins node {major + 1}.0.0", out)

    def test_a_gte_floor_admits_the_next_major(self):
        major = running_major()
        rc, out = self.run_in(self.tree(engines=f">={major}.0.0",
                                        node_version=f"{major + 1}.0.0"))
        self.assertEqual(rc, 0, out)

    def test_an_absent_node_version_is_a_tree_defect(self):
        """Inherited from the runner, the floor is satisfied by luck rather than
        by a pin — which is the state this whole check exists to end."""
        rc, out = self.run_in(self.tree(engines=">=0.0.0", node_version=None))
        self.assertEqual(rc, 1, out)
        self.assertIn("satisfied by luck", out)

    def test_a_record_that_disagrees_with_the_package_is_a_tree_defect(self):
        rc, out = self.run_in(self.tree(engines=">=0.0.0",
                                        record={"argocd": [], "gomod": ["/^go\\.mod$/"]}))
        self.assertEqual(rc, 1, out)
        self.assertIn("package ships", out)

    def test_a_manager_absent_from_the_record_is_a_tree_defect(self):
        rc, out = self.run_in(self.tree(engines=">=0.0.0", record={"argocd": []}))
        self.assertEqual(rc, 1, out)
        self.assertIn("absent from the record", out)

    def test_a_record_that_outlived_its_manager_is_a_tree_defect(self):
        rc, out = self.run_in(self.tree(engines=">=0.0.0", managers=("argocd",),
                                        record={"argocd": [], "gomod": []}))
        self.assertEqual(rc, 1, out)
        self.assertIn("no longer enables it", out)


class TheFixtureDescribesTheRealScript(unittest.TestCase):
    """A fixture nothing reads passes every case above for no reason."""

    def test_the_registry_path_is_the_one_the_script_imports(self):
        self.assertIn(f'"renovate/{REGISTRY_REL}"', SCRIPT.read_text())

    def test_the_shipped_node_pin_satisfies_the_recorded_renovate(self):
        """Asserted here as well as in the script, so a `.node-version` lowered
        below the floor fails in the suite rather than only where the package is
        installed."""
        version_file = ROOT / ".node-version"
        self.assertTrue(version_file.is_file(),
                        ".node-version does not exist, so the Node the "
                        "renovate-coverage job runs is whatever the runner ships")
        major = int(version_file.read_text().strip().lstrip("v").split(".")[0])
        self.assertGreaterEqual(major, 24,
                                "the recorded Renovate declares engines.node ^24.11.0")


if __name__ == "__main__":
    unittest.main()
