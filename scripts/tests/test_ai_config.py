"""Unit tests for the AI control-plane gate, scripts/check-ai-config.py.

The gate reads the Platform, Tenant, BudgetPolicy and ModelGateway CRs under
addons/ai-platform/ and holds them to llm-policy and to each other. Each edit it
refuses breaks somewhere no other gate looks: a bare or wrongly-prefixed model id
is refused by Bedrock at the first call, a route naming a model the allowlist
omits is denied by IAM, and a dangling budget reference leaves the kill switch
with nothing to suspend. These build an overlay holding one consistent set of
CRs, break one reference at a time, and require the gate to name it.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-ai-config")

SONNET = "us.anthropic.claude-sonnet-5"
HAIKU = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def control_plane() -> list[dict]:
    """A Tenant, its Platform, the Platform's BudgetPolicy and a ModelGateway over it."""
    return [
        {"kind": "Tenant", "metadata": {"name": "platform-ops"}, "spec": {}},
        {"kind": "Platform", "metadata": {"name": "ops"},
         "spec": {"tenant": "platform-ops", "budget": {"name": "ops-budget"},
                  "identity": {"allowedModels": [SONNET, HAIKU]}}},
        {"kind": "BudgetPolicy", "metadata": {"name": "ops-budget"},
         "spec": {"platformRef": {"name": "ops"}, "killSwitchEnabled": True}},
        {"kind": "ModelGateway", "metadata": {"name": "ops"},
         "spec": {"platformRef": {"name": "ops"},
                  "routes": [{"name": "reason", "modelId": SONNET},
                             {"name": "cheap", "modelId": HAIKU}]}},
    ]


class AnOverlay(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        # The published standard resolves nowhere, so no run reads this machine's.
        self.no_standard = mock.patch.object(gate, "STANDARD_PATHS",
                                             (self.root / "no-standard.json",))
        self.no_standard.start()
        self.addCleanup(self.no_standard.stop)

    def write(self, docs: list[dict], name: str = "agent-platform/base/platform.yaml") -> None:
        path = self.root / "addons" / "ai-platform" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump_all(docs))

    def check(self, docs: list[dict] | None = None) -> tuple[int, str]:
        if docs is not None:
            self.write(docs)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch("sys.argv", ["check-ai-config.py", "--root", str(self.root)]):
            rc = gate.main()
        return rc, out.getvalue()

    def edited(self, kind: str, edit) -> list[dict]:
        docs = copy.deepcopy(control_plane())
        edit(next(d for d in docs if d["kind"] == kind))
        return docs


class AConsistentControlPlane(AnOverlay):
    def test_passes_and_says_what_it_checked(self):
        rc, said = self.check(control_plane())
        self.assertEqual(rc, 0, said)
        self.assertIn("assertion(s) over 4 AI control-plane CR(s)", said)
        self.assertIn("NOT COMPARED", said)

    def test_documents_of_other_kinds_are_not_read(self):
        rc, said = self.check([*control_plane(),
                               {"kind": "ConfigMap", "metadata": {"name": "x"}}, "a string"])
        self.assertEqual(rc, 0, said)
        self.assertIn("over 4 AI control-plane CR(s)", said)

    def test_no_platform_cannot_run(self):
        rc, said = self.check([d for d in control_plane() if d["kind"] != "Platform"])
        self.assertEqual(rc, 2, said)
        self.assertIn("found no Platform CRs", said)

    def test_no_ai_platform_directory_cannot_run(self):
        rc, said = self.check()
        self.assertEqual(rc, 2, said)
        self.assertIn("found no Platform CRs", said)


class AModelId(AnOverlay):
    def route_to(self, model: str) -> list[dict]:
        def edit(gateway):
            gateway["spec"]["routes"][0]["modelId"] = model
        docs = self.edited("ModelGateway", edit)
        platform = next(d for d in docs if d["kind"] == "Platform")
        platform["spec"]["identity"]["allowedModels"].append(model)
        return docs

    def test_a_bare_foundation_model_id_is_refused(self):
        rc, said = self.check(self.route_to("anthropic.claude-sonnet-5"))
        self.assertEqual(rc, 1, said)
        self.assertIn("'anthropic.claude-sonnet-5' is a bare foundation-model id", said)
        self.assertIn("ModelGateway/ops routes[reason].modelId", said)

    def test_a_global_profile_is_refused_for_its_prefix(self):
        rc, said = self.check(self.route_to("global.anthropic.claude-sonnet-5"))
        self.assertEqual(rc, 1, said)
        self.assertIn("does not carry the 'us.' geo prefix", said)
        self.assertNotIn("bare foundation-model id", said)

    def test_another_regions_profile_is_refused_for_its_prefix(self):
        rc, said = self.check(self.route_to("eu.anthropic.claude-sonnet-5"))
        self.assertEqual(rc, 1, said)
        self.assertIn("does not carry the 'us.' geo prefix", said)

    def test_a_profile_at_no_tier_is_refused(self):
        rc, said = self.check(self.route_to("us.anthropic.claude-3-opus"))
        self.assertEqual(rc, 1, said)
        self.assertIn("is not one of the tiers llm-policy names", said)

    def test_an_allowlisted_id_is_held_to_the_same_rules(self):
        def edit(platform):
            platform["spec"]["identity"]["allowedModels"].append("anthropic.claude-opus-5")
        rc, said = self.check(self.edited("Platform", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("Platform/ops identity.allowedModels", said)

    def test_a_route_without_a_model_id_names_none(self):
        self.assertEqual(list(gate.model_ids({"spec": {"routes": [{"name": "x"}, "y"]}})), [])


class AReference(AnOverlay):
    def test_a_route_outside_the_allowlist_is_denied_by_iam(self):
        def edit(platform):
            platform["spec"]["identity"]["allowedModels"] = [SONNET]
        rc, said = self.check(self.edited("Platform", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn(f"route 'cheap': modelId '{HAIKU}' is absent from Platform/ops's "
                      "allowedModels", said)

    def test_a_gateway_naming_no_platform_is_refused(self):
        def edit(gateway):
            gateway["spec"]["platformRef"]["name"] = "elsewhere"
        rc, said = self.check(self.edited("ModelGateway", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("ModelGateway/ops: platformRef names 'elsewhere', which no Platform", said)

    def test_a_platform_naming_no_tenant_is_refused(self):
        def edit(platform):
            platform["spec"]["tenant"] = "nobody"
        rc, said = self.check(self.edited("Platform", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("Platform/ops: tenant 'nobody' names no Tenant CR", said)

    def test_a_budget_policy_naming_no_platform_is_refused(self):
        def edit(budget):
            budget["spec"]["platformRef"]["name"] = "elsewhere"
        rc, said = self.check(self.edited("BudgetPolicy", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("BudgetPolicy/ops-budget: platformRef names 'elsewhere'", said)


class ABudget(AnOverlay):
    def test_a_platform_with_no_budget_is_refused(self):
        def edit(platform):
            del platform["spec"]["budget"]
        rc, said = self.check(self.edited("Platform", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("Platform/ops: carries no budget reference", said)

    def test_a_budget_naming_no_policy_is_refused(self):
        def edit(platform):
            platform["spec"]["budget"]["name"] = "missing"
        rc, said = self.check(self.edited("Platform", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("budget 'missing' names no BudgetPolicy", said)

    def test_a_budget_nothing_enforces_is_refused(self):
        def edit(budget):
            budget["spec"]["killSwitchEnabled"] = False
        rc, said = self.check(self.edited("BudgetPolicy", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("BudgetPolicy/ops-budget: killSwitchEnabled is not set", said)

    def test_every_problem_is_reported_in_one_run(self):
        def edit(platform):
            platform["spec"]["tenant"] = "nobody"
            del platform["spec"]["budget"]
        rc, said = self.check(self.edited("Platform", edit))
        self.assertEqual(rc, 1, said)
        self.assertIn("has 2 problem(s)", said)


class ThePolicySnapshot(AnOverlay):
    def standard(self, content) -> pathlib.Path:
        path = self.root / "llm-policy.json"
        path.write_text(json.dumps(content))
        return path

    def compare(self, path: pathlib.Path) -> tuple[list[str], str]:
        with mock.patch.object(gate, "STANDARD_PATHS", (self.root / "absent.json", path)):
            return gate.check_policy_drift()

    def test_a_standard_naming_the_same_tiers_matches(self):
        path = self.standard({"content": {"models": {v: k for k, v
                                                     in gate.POLICY_MODELS.items()}}})
        self.assertEqual(self.compare(path), ([], f"matches {path}"))

    def test_a_standard_that_moved_is_drift(self):
        models = {v: k for k, v in gate.POLICY_MODELS.items()}
        models["default"] = "us.anthropic.claude-sonnet-6"
        problems, note = self.compare(self.standard({"content": {"models": models}}))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("In the standard and not here: ['us.anthropic.claude-sonnet-6']", problems[0])
        self.assertIn(f"Here and not in the standard: ['{SONNET}']", problems[0])
        self.assertTrue(note.startswith("compared against"), note)

    def test_a_standard_without_models_is_unreadable(self):
        problems, note = self.compare(self.standard({"content": {}}))
        self.assertIn("is not a readable llm-policy standard", problems[0])
        self.assertTrue(note.startswith("unreadable:"), note)

    def test_drift_fails_the_run(self):
        models = {v: k for k, v in gate.POLICY_MODELS.items()}
        models["light"] = "us.anthropic.claude-haiku-5"
        path = self.standard({"content": {"models": models}})
        self.write(control_plane())
        with mock.patch.object(gate, "STANDARD_PATHS", (path,)):
            rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("POLICY_MODELS has drifted", said)

    def test_no_standard_anywhere_is_said_and_not_failed(self):
        problems, note = gate.check_policy_drift()
        self.assertEqual(problems, [])
        self.assertIn("NOT COMPARED", note)

    def test_the_snapshot_names_one_model_per_tier(self):
        self.assertEqual(sorted(gate.POLICY_MODELS.values()), ["default", "escalation", "light"])
        for model in gate.POLICY_MODELS:
            with self.subTest(model=model):
                self.assertTrue(model.startswith(gate.GEO_PREFIX), model)


if __name__ == "__main__":
    unittest.main()
