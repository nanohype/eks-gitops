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

A cluster installs an overlay, not the base, so the same contract is held on
every rendered overlay. kustomize is replaced by a stub answering per overlay,
which by default renders the base with that environment's validationActions,
the way the shipped patch-only overlays do; one test renders the real tree with
the real kustomize.
"""

from __future__ import annotations

import contextlib
import copy
import io
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-image-verification")

SHIPPED = yaml.safe_load(gate.POLICY.read_text())


def tier(doc, env: str):
    """`doc` as a patch-only overlay renders it for `env`."""
    if not isinstance(doc, dict):
        return ""
    out = copy.deepcopy(doc)
    (out.setdefault("spec", {}) or {})["validationActions"] = list(gate.EXPECTED_ACTIONS[env])
    return out


class Kustomize:
    """Stands in for subprocess.run(["kustomize", "build", <overlay>]).

    Answers by the overlay directory's name: a document (or list of them) is
    rendered as YAML, a string is the render itself, a CompletedProcess is
    returned as is and an exception is raised.
    """

    def __init__(self, answers: dict) -> None:
        self.answers = answers
        self.built: list[str] = []

    def __call__(self, cmd, **_):
        env = pathlib.Path(cmd[-1]).name
        self.built.append(env)
        answer = self.answers[env]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, subprocess.CompletedProcess):
            return answer
        if isinstance(answer, dict):
            answer = [answer]
        out = answer if isinstance(answer, str) else yaml.safe_dump_all(answer)
        return subprocess.CompletedProcess(cmd, 0, out, "")


def run_gate(doc, overlays=None, envs=None, kustomize=None) -> tuple[int, str]:
    """Run main() over `doc` as the base policy, in a policy tree of its own.

    `doc` None leaves the base absent. Every environment in `envs` (by default
    the ones EXPECTED_ACTIONS names) gets an overlay, rendered as tier(doc, env)
    unless `overlays` maps it to another answer. Returns (exit, output).
    """
    envs = list(gate.EXPECTED_ACTIONS) if envs is None else envs
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        group = root / "policies" / "kyverno" / "supply-chain"
        base = group / "base" / "verify-images.yaml"
        base.parent.mkdir(parents=True)
        if doc is not None:
            base.write_text(doc if isinstance(doc, str) else yaml.safe_dump(doc))
        answers = {}
        for env in envs:
            d = group / "overlays" / env
            d.mkdir(parents=True)
            (d / "kustomization.yaml").write_text("resources: [../../base]\n")
            answers[env] = tier(doc, env) if env in gate.EXPECTED_ACTIONS else tier(doc, "production")
        answers.update(overlays or {})
        stub = kustomize or Kustomize(answers)
        buf = io.StringIO()
        with mock.patch.multiple(gate, ROOT=root, GROUP=group, POLICY=base), \
             mock.patch.object(gate.gatelib, "require"), \
             mock.patch.object(gate.subprocess, "run", stub), \
             contextlib.redirect_stdout(buf):
            try:
                gate.main()
            except SystemExit as exc:
                return int(exc.code or 0), buf.getvalue()
    return 0, buf.getvalue()


def mutated(edit) -> tuple[int, str]:
    """The shipped policy with `edit(spec)` applied, through the gate."""
    doc = copy.deepcopy(SHIPPED)
    edit(doc["spec"])
    return run_gate(doc)


def overlay(env: str, edit) -> tuple[int, str]:
    """The shipped base, with `edit(spec)` applied to the render of `env` only."""
    doc = tier(SHIPPED, env)
    edit(doc["spec"])
    return run_gate(copy.deepcopy(SHIPPED), overlays={env: doc})


def identity(spec) -> dict:
    return spec["attestors"][0]["cosign"]["keyless"]["identities"][0]


class TheShippedPolicy(unittest.TestCase):
    def test_it_satisfies_the_contract(self):
        code, out = run_gate(copy.deepcopy(SHIPPED))
        self.assertEqual(code, 0, out)
        self.assertIn("identity contract OK on the base and 3 rendered overlay(s) "
                      "(development Audit, production Deny, staging Deny)", out)

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

    def test_a_root_bundle_of_its_own(self):
        def edit(spec):
            spec["attestors"][0]["cosign"]["keyless"]["roots"] = "PEM"
        self.refused(edit, "keyless sets ['roots']")

    def test_a_log_key_or_timestamp_chain_of_its_own(self):
        for field in ("rekorPubKey", "ctLogPubKey", "tsaCertChain"):
            with self.subTest(field=field):
                def edit(spec, field=field):
                    spec["attestors"][0]["cosign"]["ctlog"][field] = "PEM"
                self.refused(edit, f"ctlog sets ['{field}']")

    def test_another_transparency_log(self):
        def edit(spec):
            spec["attestors"][0]["cosign"]["ctlog"]["url"] = "https://rekor.example.net"
        self.refused(edit, "ctlog.url is 'https://rekor.example.net', expected "
                           "'https://rekor.sigstore.dev'")

    def test_an_identity_field_outside_the_contract(self):
        """An empty loose field passes the by-name check; the allowlist still names it."""
        def edit(spec):
            identity(spec)["issuerRegExp"] = ""
        self.refused(edit, "identity sets ['issuerRegExp']")

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

    def test_a_narrower_nanohype_glob(self):
        """Both fixtures still match, so kyverno test decides as before."""
        globs = [{"glob": "ghcr.io/nanohype/eks-agent-platform*"}, {"glob": "ghcr.io/nanohype/fab*"}]
        self.refused(lambda s: s.update(matchImageReferences=globs),
                     "expected exactly ['ghcr.io/nanohype/*']")

    def test_admission_evaluation_switched_off(self):
        self.refused(lambda s: s.update(evaluation={"admission": {"enabled": False}}),
                     "evaluation.admission.enabled is false")

    def test_another_evaluation_mode(self):
        self.refused(lambda s: s.update(evaluation={"mode": "HTTP"}),
                     "evaluation.mode is 'HTTP', not Kubernetes")

    def test_kubernetes_mode_and_admission_spelled_out_pass(self):
        def edit(spec):
            spec["evaluation"] = {"mode": "Kubernetes", "admission": {"enabled": True},
                                  "background": {"enabled": False}}
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)

    def test_an_extractor_shadowing_a_container_field(self):
        """A custom extractor of the same name replaces the built-in one."""
        for field in gate.CONTAINER_FIELDS:
            with self.subTest(field=field):
                self.refused(lambda s, field=field: s.update(
                    images=[{"name": field, "expression": "[]"}]),
                    f"spec.images declares an extractor named ['{field}']")

    def test_an_extractor_of_another_name_passes(self):
        def edit(spec):
            spec["images"] = [{"name": "sidecars", "expression": "[]"}]
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)

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
        self.refused(edit, "the signature validation is not the expected expression")

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
        self.refused(edit, "the SBOM validation is not the expected expression")

    def test_a_validation_neutralised_with_or_true(self):
        """Every field and the call are still named, so a check made of parts passes it."""
        for index, what in ((0, "signature"), (1, "SBOM")):
            with self.subTest(validation=what):
                def edit(spec, index=index):
                    spec["validations"][index]["expression"] += " || true"
                self.refused(edit, f"the {what} validation is not the expected expression")

    def test_a_count_that_passes_an_unverified_image(self):
        for old, new in (("e > 0", "e >= 0"), (".all(", ".exists(")):
            with self.subTest(change=new):
                def edit(spec, old=old, new=new):
                    v = spec["validations"][0]
                    v["expression"] = v["expression"].replace(old, new)
                self.refused(edit, "the signature validation is not the expected expression")

    def test_the_same_expression_wrapped_differently_passes(self):
        def edit(spec):
            for v in spec["validations"]:
                v["expression"] = "\n  ".join(v["expression"].replace("(", "( ").split(" "))
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)

    def test_validations_against_another_attestor_meeting_the_contract_pass(self):
        def edit(spec):
            spec["attestors"][0]["name"] = "signer"
            for v in spec["validations"]:
                v["expression"] = v["expression"].replace("attestors.release", "attestors.signer")
        code, out = mutated(edit)
        self.assertEqual(code, 0, out)


class ThePolicyFile(unittest.TestCase):
    def test_an_absent_policy_is_refused(self):
        code, out = run_gate(None)
        self.assertEqual(code, 1, out)
        self.assertIn("base/verify-images.yaml: policy not found", out)

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



class TheRenderedOverlays(unittest.TestCase):
    """What a cluster installs is the overlay, and a patch there can undo the base."""

    def refused(self, env, edit, says):
        code, out = overlay(env, edit)
        self.assertEqual(code, 1, out)
        self.assertIn(f"overlays/{env}: ", out)
        self.assertIn(says, out)

    def test_an_overlay_widening_the_subject(self):
        def edit(spec):
            identity(spec)["subjectRegExp"] = r"^https://github\.com/nanohype/.+@refs/tags/.+$"
        self.refused("production", edit, "is not the release identity")

    def test_an_overlay_swapping_the_issuer(self):
        def edit(spec):
            identity(spec)["issuer"] = "https://accounts.google.com"
        self.refused("staging", edit, "keyless issuer is 'https://accounts.google.com'")

    def test_an_overlay_growing_the_namespace_exclusion(self):
        def edit(spec):
            spec["matchConstraints"]["namespaceSelector"]["matchExpressions"][0][
                "values"].append("workloads")
        self.refused("development", edit, "a workload namespace on this list runs unverified")

    def test_an_overlay_making_verification_optional(self):
        def edit(spec):
            spec["validationConfigurations"]["required"] = False
        self.refused("production", edit, "validationConfigurations.required must be true")

    def test_an_enforcing_tier_that_only_reports(self):
        for env in ("staging", "production"):
            with self.subTest(env=env):
                self.refused(env, lambda s: s.update(validationActions=["Audit"]),
                             f"validationActions is ['Audit'], expected ['Deny'] for {env}")

    def test_a_reporting_tier_that_blocks(self):
        self.refused("development", lambda s: s.update(validationActions=["Deny"]),
                     "expected ['Audit'] for development — the tier would block")

    def test_every_overlay_is_rendered(self):
        stub = Kustomize({env: tier(SHIPPED, env) for env in gate.EXPECTED_ACTIONS})
        code, out = run_gate(copy.deepcopy(SHIPPED), kustomize=stub)
        self.assertEqual(code, 0, out)
        self.assertEqual(stub.built, sorted(gate.EXPECTED_ACTIONS))

    def test_an_overlay_that_does_not_render(self):
        broken = subprocess.CompletedProcess([], 1, "", "Error: accumulating resources\nmore")
        code, out = run_gate(copy.deepcopy(SHIPPED), overlays={"staging": broken})
        self.assertEqual(code, 1, out)
        self.assertIn("overlays/staging: it does not render — Error: accumulating resources",
                      out)

    def test_an_overlay_rendering_no_verify_images(self):
        renamed = tier(SHIPPED, "production")
        renamed["metadata"]["name"] = "verify-images-off"
        for answer in ("", [{"kind": "ConfigMap", "metadata": {"name": "verify-images"}}],
                       renamed, "--- just a string\n"):
            with self.subTest(answer=str(answer)[:40]):
                code, out = run_gate(copy.deepcopy(SHIPPED), overlays={"production": answer})
                self.assertEqual(code, 1, out)
                self.assertIn("renders no ImageValidatingPolicy named verify-images", out)

    def test_a_render_that_does_not_finish_cannot_run(self):
        stuck = subprocess.TimeoutExpired(["kustomize"], gate.LOCAL_TIMEOUT)
        code, out = run_gate(copy.deepcopy(SHIPPED), overlays={"development": stuck})
        self.assertEqual(code, 2, out)
        self.assertIn("Cannot run: kustomize build", out)

    def test_an_overlay_no_expected_action_is_recorded_for(self):
        envs = [*gate.EXPECTED_ACTIONS, "hub"]
        code, out = run_gate(copy.deepcopy(SHIPPED), envs=envs)
        self.assertEqual(code, 1, out)
        self.assertIn("overlay(s) ['hub'] carry no entry in EXPECTED_ACTIONS", out)

    def test_an_environment_with_no_overlay(self):
        envs = [e for e in gate.EXPECTED_ACTIONS if e != "staging"]
        code, out = run_gate(copy.deepcopy(SHIPPED), envs=envs)
        self.assertEqual(code, 1, out)
        self.assertIn("no overlay for ['staging']", out)

    def test_a_base_violation_is_reported_before_any_render(self):
        doc = copy.deepcopy(SHIPPED)
        identity(doc["spec"])["issuer"] = "https://accounts.google.com"
        stub = Kustomize({})
        code, out = run_gate(doc, kustomize=stub)
        self.assertEqual(code, 1, out)
        self.assertIn("base/verify-images.yaml: keyless issuer", out)
        self.assertEqual(stub.built, [])


@unittest.skipIf(shutil.which("kustomize") is None, "kustomize is not on PATH")
class TheShippedTree(unittest.TestCase):
    def test_the_real_overlays_render_and_meet_the_contract(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            gate.main()
        self.assertIn("rendered overlay(s) (development Audit, production Deny, "
                      "staging Deny)", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
