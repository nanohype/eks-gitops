"""Unit tests for the verify-images identity gate.

`kyverno test` verifies real signatures, so it proves the release identity
admits a release-signed fixture and refuses a branch-signed one. A policy
weakened in a way both fixtures still satisfy passes it, and this gate is what
refuses that policy. The cases below are those weakenings, each applied to the
shipped policy, and each must be refused with a message naming it.

The subject expression is held to a corpus as well as to the gate. The gate
compares it as a string, so an edit to SUBJECT_REGEXP itself is the one change
the gate cannot see; the corpus tests are what fail when the trusted identity
widens.
"""

from __future__ import annotations

import contextlib
import copy
import io
import pathlib
import re
import tempfile
import unittest

import yaml
from gateloader import load

gate = load("check-image-verification")

SHIPPED = yaml.safe_load(gate.POLICY.read_text())


def run_gate(doc) -> tuple[int, str]:
    """Run main() over `doc` written as the policy file; return (exit, output)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "verify-images.yaml"
        path.write_text(doc if isinstance(doc, str) else yaml.safe_dump(doc))
        original = gate.POLICY
        gate.POLICY = path
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                gate.main()
        except SystemExit as exc:
            return int(exc.code or 0), buf.getvalue()
        finally:
            gate.POLICY = original
    return 0, buf.getvalue()


def mutated(edit) -> tuple[int, str]:
    """The shipped policy with `edit(spec)` applied, through the gate."""
    doc = copy.deepcopy(SHIPPED)
    edit(doc["spec"])
    return run_gate(doc)


def identity(spec) -> dict:
    return spec["attestors"][0]["cosign"]["keyless"]["identities"][0]


class TheShippedPolicy(unittest.TestCase):
    def test_it_satisfies_the_contract(self):
        code, out = run_gate(copy.deepcopy(SHIPPED))
        self.assertEqual(code, 0, out)
        self.assertIn("identity contract OK", out)

    def test_its_subject_is_the_release_identity(self):
        """The constant and the policy name one expression; the gate compares them."""
        self.assertEqual(identity(SHIPPED["spec"])["subjectRegExp"], gate.SUBJECT_REGEXP)


class TheReleaseIdentity(unittest.TestCase):
    """SUBJECT_REGEXP against certificate subjects, matched the way cosign does.

    cosign searches rather than full-matches, so the anchors are part of what is
    being tested here, not an assumption the test makes.
    """

    def test_a_release_workflow_on_a_tag_in_an_org_repository_is_accepted(self):
        for subject in gate.ACCEPTED_SUBJECTS:
            with self.subTest(subject=subject):
                self.assertTrue(re.search(gate.SUBJECT_REGEXP, subject))

    def test_every_near_miss_is_refused(self):
        for subject in gate.REFUSED_SUBJECTS:
            with self.subTest(subject=subject):
                self.assertIsNone(re.search(gate.SUBJECT_REGEXP, subject))

    def test_the_branch_signed_fixture_subject_is_refused(self):
        """The identity on ghcr.io/nanohype/fab@sha256:9e415943…, the suite's
        branch-signed fixture."""
        self.assertIsNone(re.search(
            gate.SUBJECT_REGEXP,
            "https://github.com/nanohype/fab/.github/workflows/ci.yml@refs/heads/main"))


class AWidenedSubjectIsRefused(unittest.TestCase):
    """Every expression here is anchored, org-scoped, names a release workflow
    and names a tag ref, and each admits a signer the release identity refuses."""

    def assertRefused(self, subject, admits):
        def edit(spec):
            identity(spec)["subjectRegExp"] = subject
        code, out = mutated(edit)
        self.assertEqual(code, 1, out)
        self.assertIn("is not the release identity", out)
        self.assertIn(f"It admits {admits}", out)

    def test_release_anywhere_in_the_workflow_name(self):
        self.assertRefused(
            r"^https://github\.com/nanohype/.+release.+@refs/tags/.+$",
            "https://github.com/nanohype/fab/.github/workflows/prerelease-check.yml@refs/tags/v1.0.0")

    def test_an_unescaped_dot_in_the_host(self):
        self.assertRefused(
            r"^https://github.com/nanohype/[^/]+/\.github/workflows/release\.ya?ml@refs/tags/.+$",
            "https://githubxcom/nanohype/fab/.github/workflows/release.yml@refs/tags/v1.0.0")

    def test_a_missing_start_anchor(self):
        self.assertRefused(
            r"https://github\.com/nanohype/[^/]+/\.github/workflows/release\.ya?ml@refs/tags/.+$",
            "prefix-https://github.com/nanohype/fab/.github/workflows/release.yml@refs/tags/v1.0.0")

    def test_any_ref(self):
        self.assertRefused(
            r"^https://github\.com/nanohype/[^/]+/\.github/workflows/release\.ya?ml@refs/.+$",
            "https://github.com/nanohype/fab/.github/workflows/release.yml@refs/heads/main")

    def test_any_org(self):
        self.assertRefused(
            r"^https://github\.com/[^/]+/[^/]+/\.github/workflows/release\.ya?ml@refs/tags/.+$",
            "https://github.com/example/fab/.github/workflows/release.yml@refs/tags/v1.0.0")

    def test_a_wildcard(self):
        self.assertRefused(".*", gate.REFUSED_SUBJECTS[0])


class ADifferentSubjectIsRefusedWhateverItAdmits(unittest.TestCase):
    def subject(self, value):
        def edit(spec):
            identity(spec)["subjectRegExp"] = value
        return mutated(edit)

    def test_a_narrower_expression_names_the_release_it_refuses(self):
        code, out = self.subject(
            r"^https://github\.com/nanohype/fab/\.github/workflows/release\.yml@refs/tags/.+$")
        self.assertEqual(code, 1, out)
        self.assertIn("It refuses https://github.com/nanohype/eks-agent-platform/", out)

    def test_an_expression_the_corpus_cannot_tell_apart_is_still_refused(self):
        """The verdict is the comparison; the corpus only explains a failure."""
        code, out = self.subject(gate.SUBJECT_REGEXP + "|^unreachable$")
        self.assertEqual(code, 1, out)
        self.assertIn("corpus does not tell the two apart", out)

    def test_an_expression_that_does_not_compile_is_named_as_such(self):
        code, out = self.subject("^https://github\\.com/nanohype/(")
        self.assertEqual(code, 1, out)
        self.assertIn("does not compile", out)

    def test_an_absent_subject_is_refused(self):
        code, out = self.subject("")
        self.assertEqual(code, 1, out)
        self.assertIn("no subjectRegExp", out)


class TheAttestor(unittest.TestCase):
    def refused(self, edit, says):
        code, out = mutated(edit)
        self.assertEqual(code, 1, out)
        self.assertIn(says, out)

    def test_no_attestor(self):
        self.refused(lambda s: s.update(attestors=[]), "no attestors")

    def test_a_key_based_attestor(self):
        def edit(spec):
            spec["attestors"][0]["cosign"] = {"key": {"data": "PEM"}}
        self.refused(edit, "is not keyless Cosign")

    def test_a_field_beside_keyless(self):
        def edit(spec):
            spec["attestors"][0]["cosign"]["tuf"] = {"root": {}}
        self.refused(edit, "sets ['tuf']")

    def test_no_transparency_log(self):
        def edit(spec):
            del spec["attestors"][0]["cosign"]["ctlog"]
        self.refused(edit, "names no transparency log")

    def test_the_transparency_log_ignored(self):
        for flag in ("insecureIgnoreTlog", "insecureIgnoreSCT"):
            with self.subTest(flag=flag):
                def edit(spec, flag=flag):
                    spec["attestors"][0]["cosign"]["ctlog"][flag] = True
                self.refused(edit, f"sets ctlog.{flag}")

    def test_no_identity(self):
        def edit(spec):
            spec["attestors"][0]["cosign"]["keyless"]["identities"] = []
        self.refused(edit, "has no keyless identities")

    def test_a_loose_identity_field(self):
        for loose in ("issuerRegExp", "subject", "subjectExpression"):
            with self.subTest(field=loose):
                def edit(spec, loose=loose):
                    identity(spec)[loose] = ".*"
                self.refused(edit, f"identity sets {loose}")

    def test_another_issuer(self):
        def edit(spec):
            identity(spec)["issuer"] = "https://accounts.google.com"
        self.refused(edit, "keyless issuer is 'https://accounts.google.com'")

    def test_a_second_attestor_is_held_to_the_same_contract(self):
        def edit(spec):
            second = copy.deepcopy(spec["attestors"][0])
            second["name"] = "second"
            second["cosign"]["keyless"]["identities"][0]["subjectRegExp"] = ".*"
            spec["attestors"].append(second)
        self.refused(edit, "subjectRegExp '.*' is not the release identity")

    def test_a_second_attestor_meeting_the_contract_passes(self):
        def edit(spec):
            second = copy.deepcopy(spec["attestors"][0])
            second["name"] = "second"
            spec["attestors"].append(second)
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)


class TheScope(unittest.TestCase):
    def refused(self, edit, says):
        code, out = mutated(edit)
        self.assertEqual(code, 1, out)
        self.assertIn(says, out)

    def test_no_image_reference(self):
        self.refused(lambda s: s.update(matchImageReferences=[]), "selects no image")

    def test_a_reference_that_is_not_a_glob(self):
        self.refused(lambda s: s.update(matchImageReferences=[{"expression": "true"}]),
                     "is not a glob")

    def test_a_bare_wildcard(self):
        self.refused(lambda s: s.update(matchImageReferences=[{"glob": "*"}]), "bare '*'")

    def test_another_registry(self):
        self.refused(lambda s: s.update(matchImageReferences=[{"glob": "ghcr.io/*"}]),
                     "is not scoped to ghcr.io/nanohype/*")

    def test_every_reference_is_checked(self):
        refs = [{"glob": "ghcr.io/nanohype/*"}, {"glob": "docker.io/*"}]
        self.refused(lambda s: s.update(matchImageReferences=refs),
                     "'docker.io/*' is not scoped")

    def test_a_policy_that_fails_open(self):
        self.refused(lambda s: s.update(failurePolicy="Ignore"), "failurePolicy is Ignore")

    def test_a_selector_pods_can_opt_out_through(self):
        for narrowing in ("objectSelector", "excludeResourceRules"):
            with self.subTest(field=narrowing):
                def edit(spec, narrowing=narrowing):
                    spec["matchConstraints"][narrowing] = {"matchLabels": {"skip": "true"}}
                self.refused(edit, f"matchConstraints.{narrowing} is set")

    def test_a_match_condition(self):
        self.refused(lambda s: s.update(matchConditions=[{"name": "c", "expression": "false"}]),
                     "matchConditions is set")

    def test_pods_matched_on_create_only(self):
        def edit(spec):
            spec["matchConstraints"]["resourceRules"] = [
                {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"],
                 "resources": ["pods"]},
                {"apiGroups": ["apps"], "apiVersions": ["v1"], "operations": ["UPDATE"],
                 "resources": ["deployments"]},
            ]
        self.refused(edit, "match pods on ['CREATE']")

    def test_the_ephemeral_container_subresource_unmatched(self):
        """`kubectl debug` adds its container through the subresource alone, so a
        policy matching pods sees an empty images.ephemeralContainers forever."""
        def edit(spec):
            spec["matchConstraints"]["resourceRules"][0]["resources"] = ["pods"]
        self.refused(edit, "do not match pods/ephemeralcontainers on UPDATE")

    def test_the_ephemeral_container_subresource_matched_in_a_rule_of_its_own(self):
        def edit(spec):
            spec["matchConstraints"]["resourceRules"] = [
                {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                 "resources": ["pods"]},
                {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["UPDATE"],
                 "resources": ["pods/ephemeralcontainers"]},
            ]
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)

    def test_a_namespace_selector_that_does_not_name_namespaces(self):
        def edit(spec):
            spec["matchConstraints"]["namespaceSelector"]["matchExpressions"].append(
                {"key": "team", "operator": "NotIn", "values": ["x"]})
        self.refused(edit, "is not a NotIn on kubernetes.io/metadata.name")

    def test_a_workload_namespace_excluded(self):
        def edit(spec):
            spec["matchConstraints"]["namespaceSelector"]["matchExpressions"][0][
                "values"].append("workloads")
        self.refused(edit, "a workload namespace on this list runs unverified images")

    def test_rules_generated_for_pod_controllers(self):
        """A generated rule pins the digest into a template ArgoCD compares with git."""
        for autogen in ({}, {"podControllers": {}},
                        {"podControllers": {"controllers": ["deployments"]}}):
            with self.subTest(autogen=autogen):
                def edit(spec, autogen=autogen):
                    spec["autogen"] = autogen
                self.refused(edit, "autogen.podControllers.controllers is")

    def test_no_namespace_exclusion(self):
        """Excluding nothing is a different set from SYSTEM_NS, and refused."""
        def edit(spec):
            spec["matchConstraints"]["namespaceSelector"] = {}
        self.refused(edit, "namespaceSelector excludes []")


class TheValidationConfiguration(unittest.TestCase):
    def test_each_field_must_be_true(self):
        for field in ("required", "mutateDigest", "verifyDigest"):
            with self.subTest(field=field):
                def edit(spec, field=field):
                    spec["validationConfigurations"][field] = False
                code, out = mutated(edit)
                self.assertEqual(code, 1, out)
                self.assertIn(f"validationConfigurations.{field} must be true", out)


class TheAttestationAndValidations(unittest.TestCase):
    def refused(self, edit, says):
        code, out = mutated(edit)
        self.assertEqual(code, 1, out)
        self.assertIn(says, out)

    def test_no_spdx_attestation(self):
        def edit(spec):
            spec["attestations"] = [{"name": "prov",
                                     "intoto": {"type": "https://slsa.dev/provenance/v1"}}]
        self.refused(edit, "no attestation of in-toto type")

    def test_the_spdx_attestation_found_among_others(self):
        def edit(spec):
            spec["attestations"].insert(
                0, {"name": "prov", "intoto": {"type": "https://slsa.dev/provenance/v1"}})
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)

    def test_no_signature_validation(self):
        def edit(spec):
            spec["validations"] = [v for v in spec["validations"]
                                   if "verifyImageSignatures(" not in v["expression"]]
        self.refused(edit, "no validation calls verifyImageSignatures")

    def test_a_signature_validation_over_containers_only(self):
        def edit(spec):
            v = spec["validations"][0]
            v["expression"] = ("images.containers.map(image, verifyImageSignatures("
                               "image, [attestors.release])).all(e, e > 0)")
        self.refused(edit, "the signature validation does not cover")

    def test_no_attestation_validation(self):
        def edit(spec):
            spec["validations"] = [v for v in spec["validations"]
                                   if "verifyAttestationSignatures(" not in v["expression"]]
        self.refused(edit, "no validation calls verifyAttestationSignatures")

    def test_an_attestation_validation_over_containers_only(self):
        def edit(spec):
            v = spec["validations"][1]
            v["expression"] = ("images.containers.map(image, verifyAttestationSignatures("
                               "image, attestations.sbom, [attestors.release])).all(e, e > 0)")
        self.refused(edit, "the SBOM validation does not cover")


class ThePolicyFile(unittest.TestCase):
    def test_an_absent_policy_is_refused(self):
        original = gate.POLICY
        gate.POLICY = pathlib.Path(tempfile.gettempdir()) / "no-such-verify-images.yaml"
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as raised:
                gate.main()
        finally:
            gate.POLICY = original
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("policy not found", buf.getvalue())

    def test_a_clusterpolicy_is_not_the_contract(self):
        doc = copy.deepcopy(SHIPPED)
        doc["apiVersion"], doc["kind"] = "kyverno.io/v1", "ClusterPolicy"
        code, out = run_gate(doc)
        self.assertEqual(code, 1, out)
        self.assertIn("expected policies.kyverno.io/v1/ImageValidatingPolicy", out)

    def test_an_empty_file_is_not_the_contract(self):
        code, out = run_gate("")
        self.assertEqual(code, 1, out)
        self.assertIn("is None/None", out)

    def test_a_policy_with_no_spec_fails_on_scope(self):
        code, out = run_gate({"apiVersion": gate.EXPECTED_API, "kind": gate.EXPECTED_KIND})
        self.assertEqual(code, 1, out)
        self.assertIn("selects no image", out)


if __name__ == "__main__":
    unittest.main()
