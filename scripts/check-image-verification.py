#!/usr/bin/env python3
"""Supply-chain gate — the keyless-signing IDENTITY contract of verify-images.

    ┌─────────────────────────────────────────────────────────────────────┐
    │ WHAT kyverno test DOES NOT COVER — read first.                      │
    │                                                                     │
    │ The unit suite verifies real signatures, so it proves the release   │
    │ identity admits a release-signed image and refuses a branch-signed  │
    │ one. It cannot see a WEAKENED identity that still admits both       │
    │ fixtures: a subjectRegExp that also accepts another workflow, ref   │
    │ or org, an issuer swapped for an issuerRegExp, `required: false`, a │
    │ Rekor check switched off, or a namespace exclusion grown over a     │
    │ workload namespace. Each renders and schema-validates clean and     │
    │ ships silently — the policy still "verifies images", it just        │
    │ accepts more signers or checks fewer pods. This structural gate     │
    │ refuses those.                                                      │
    └─────────────────────────────────────────────────────────────────────┘

The contract is asserted on policies/kyverno/supply-chain/base/verify-images.yaml
and on each supply-chain overlay as kustomize renders it, because the overlay is
what a cluster installs and a patch there can undo anything the base says. Each
rendition must be an ImageValidatingPolicy (policies.kyverno.io/v1) in which:
  - matchImageReferences is exactly the one glob ghcr.io/nanohype/*;
  - the policy fails closed (failurePolicy is not Ignore), runs at admission in
    Kubernetes mode, matches pods on CREATE and UPDATE and
    pods/ephemeralcontainers on UPDATE, excludes exactly the system namespaces
    in SYSTEM_NS, and declares no image extractor shadowing a container field;
  - no rule is generated for pod controllers (autogen.podControllers.controllers
    is an empty list), so admission pins the pod and leaves the template git
    holds as written;
  - validationConfigurations sets required, mutateDigest and verifyDigest true;
  - every attestor is keyless Cosign with no key, root or log of its own: the
    GitHub Actions OIDC issuer exactly, SUBJECT_REGEXP exactly as the
    subjectRegExp, and the public Rekor log at REKOR_URL checked;
  - an attestation of in-toto type https://spdx.dev/Document is declared;
  - one validation is SIGNATURE_VALIDATION and one is ATTESTATION_VALIDATION,
    each compared whole against the keyless attestor and the SPDX attestation.

Each overlay also sets the validationActions EXPECTED_ACTIONS names for its
environment, so a tier that enforces cannot drop to reporting.

BLOCKING: exits 1 on the first violation, and 2 when kustomize is absent or a
render does not finish.
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

import gatelib
import yaml

ROOT = Path(__file__).resolve().parent.parent
GROUP = ROOT / "policies/kyverno/supply-chain"
POLICY = GROUP / "base/verify-images.yaml"
POLICY_NAME = "verify-images"

# Seconds one kustomize render may take. It reads only the working tree.
LOCAL_TIMEOUT = 120

# The validationActions each rendered overlay sets, by environment. An overlay
# under no name here is a tier whose enforcement nobody decided, and an
# environment here with no overlay is a tier this gate never rendered; both fail.
EXPECTED_ACTIONS = {
    "development": ["Audit"],
    "staging": ["Deny"],
    "production": ["Deny"],
}

EXPECTED_API = "policies.kyverno.io/v1"
EXPECTED_KIND = "ImageValidatingPolicy"
EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"
EXPECTED_SBOM_TYPE = "https://spdx.dev/Document"
REGISTRY_PREFIX = "ghcr.io/nanohype/"
SCOPE = REGISTRY_PREFIX + "*"
# The transparency log every release signature is recorded in.
REKOR_URL = "https://rekor.sigstore.dev"
# The namespaces the policy skips, and no others. Adding a namespace here is a
# decision to run unverified nanohype images in it.
SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease", "kyverno"}
# The image lists Kyverno extracts from a pod, which the validations read as
# images.<field>. A spec.images extractor of the same name replaces the built-in
# one, so the expression reads unchanged while verifying whatever it returns.
CONTAINER_FIELDS = ("containers", "initContainers", "ephemeralContainers")
# The only request that adds an ephemeral container.
EPHEMERAL = "pods/ephemeralcontainers"

# The one signer verify-images trusts: a release.yml or release.yaml workflow, in
# a repository of the nanohype org, running on a tag push. Compared whole, as a
# string. A regular expression is a language, and its parts say nothing about
# what it accepts: `^https://github\.com/nanohype/.+release.+@refs/tags/.+$` is
# anchored, org-scoped, names "release" and names a tag ref, and it admits
# prerelease-check.yml on any tag. Trusting another identity is an edit to this
# constant, which scripts/tests/test_image_verification.py holds to the two
# subject lists below.
SUBJECT_REGEXP = r"^https://github\.com/nanohype/[^/]+/\.github/workflows/release\.ya?ml@refs/tags/.+$"

# Certificate subjects as Fulcio writes them for a GitHub Actions run
# (<repository URL>/<workflow path>@<ref>). The release identity accepts the
# first list and refuses the second. A policy whose subjectRegExp differs from
# SUBJECT_REGEXP is reported against both, so the failure names what the
# difference admits.
ACCEPTED_SUBJECTS = (
    "https://github.com/nanohype/eks-agent-platform/.github/workflows/release.yaml@refs/tags/operator-v0.6.1",
    "https://github.com/nanohype/fab/.github/workflows/release.yml@refs/tags/v1.0.0",
)
REFUSED_SUBJECTS = (
    # Another workflow of an org repository, on a tag.
    "https://github.com/nanohype/fab/.github/workflows/ci.yml@refs/tags/v1.0.0",
    # A workflow whose name contains "release", on a tag.
    "https://github.com/nanohype/fab/.github/workflows/prerelease-check.yml@refs/tags/v1.0.0",
    # The release workflow on a branch push and on a pull-request ref.
    "https://github.com/nanohype/fab/.github/workflows/release.yml@refs/heads/main",
    "https://github.com/nanohype/fab/.github/workflows/release.yml@refs/pull/1/merge",
    # The release workflow on a ref that names no tag.
    "https://github.com/nanohype/fab/.github/workflows/release.yml@refs/tags/",
    # The same path under another organization.
    "https://github.com/nanohype-fork/fab/.github/workflows/release.yml@refs/tags/v1.0.0",
    "https://github.com/example/fab/.github/workflows/release.yml@refs/tags/v1.0.0",
    # A release workflow below .github/workflows rather than in it.
    "https://github.com/nanohype/fab/.github/workflows/nested/release.yml@refs/tags/v1.0.0",
    # A repository segment carrying a slash.
    "https://github.com/nanohype/fab/extra/.github/workflows/release.yml@refs/tags/v1.0.0",
    # Hosts an unescaped or unanchored host would let through.
    "https://githubxcom/nanohype/fab/.github/workflows/release.yml@refs/tags/v1.0.0",
    "https://github.com.example.net/nanohype/fab/.github/workflows/release.yml@refs/tags/v1.0.0",
    "prefix-https://github.com/nanohype/fab/.github/workflows/release.yml@refs/tags/v1.0.0",
)


# The two validations, as SIGNATURE_VALIDATION.format(attestor=...) and
# ATTESTATION_VALIDATION.format(attestor=..., attestation=...) spell them. Each
# is compared whole, with whitespace removed: CEL ignores whitespace between
# tokens, YAML folding decides where it falls, and the expressions carry no
# string literal it could change the meaning of. A check made of parts — the
# call is present, every field is named — passes an expression that neutralises
# itself: `... || true`, a count compared with `>= 0`, `exists` where `all`
# belongs.
_IMAGES = "(" + " + ".join(f"images.{f}" for f in CONTAINER_FIELDS) + ")"
SIGNATURE_VALIDATION = (
    _IMAGES + ".map(image, verifyImageSignatures(image, [attestors.{attestor}]))"
    ".all(e, e > 0)"
)
ATTESTATION_VALIDATION = (
    _IMAGES + ".map(image, verifyAttestationSignatures(image, attestations.{attestation}, "
    "[attestors.{attestor}])).all(e, e > 0)"
)


class Violation(Exception):
    """One way a rendition of the policy breaks the contract."""


def fail(msg: str) -> NoReturn:
    raise Violation(msg)


def check_scope(spec: dict) -> None:
    refs = spec.get("matchImageReferences") or []
    if not refs:
        fail("matchImageReferences is empty — the policy selects no image")
    globs = set()
    for ref in refs:
        glob = (ref or {}).get("glob")
        if glob is None:
            fail(f"matchImageReferences entry {ref!r} is not a glob — scope it to {SCOPE}")
        if glob.strip() == "*":
            fail("matchImageReferences contains a bare '*' — signature demanded on every image; "
                 f"scope it to {SCOPE}")
        if not glob.startswith(REGISTRY_PREFIX):
            fail(f"matchImageReferences glob {glob!r} is not scoped to {SCOPE}")
        globs.add(glob)
    if globs != {SCOPE}:
        fail(f"matchImageReferences is {sorted(globs)}, expected exactly ['{SCOPE}'] — a "
             f"narrower glob leaves every other nanohype image unverified while both "
             f"fixtures still decide as before")

    if spec.get("failurePolicy") == "Ignore":
        fail("failurePolicy is Ignore — a webhook timeout or a Kyverno outage would admit "
             "every image unverified")

    evaluation = spec.get("evaluation") or {}
    if (evaluation.get("admission") or {}).get("enabled") is False:
        fail("evaluation.admission.enabled is false — the policy never runs at admission, "
             "so no pod is verified or pinned")
    if evaluation.get("mode", "Kubernetes") != "Kubernetes":
        fail(f"evaluation.mode is {evaluation.get('mode')!r}, not Kubernetes — the policy "
             f"evaluates another kind of payload and no pod admission reaches it")

    extractors = {(e or {}).get("name") for e in spec.get("images") or []}
    shadowing = [f for f in CONTAINER_FIELDS if f in extractors]
    if shadowing:
        fail(f"spec.images declares an extractor named {shadowing} — it replaces the "
             f"built-in list the validations read, so they verify what it returns")

    mc = spec.get("matchConstraints") or {}
    for narrowing in ("objectSelector", "excludeResourceRules"):
        if mc.get(narrowing):
            fail(f"matchConstraints.{narrowing} is set — pods can opt out of verification "
                 f"through it")
    if spec.get("matchConditions"):
        fail("matchConditions is set — a pod failing one is never verified")

    rules = mc.get("resourceRules") or []
    pod_ops = {op for r in rules if "pods" in (r.get("resources") or [])
               for op in (r.get("operations") or [])}
    if not {"CREATE", "UPDATE"} <= pod_ops:
        fail(f"resourceRules match pods on {sorted(pod_ops)} — CREATE and UPDATE are both "
             f"required, or a pod admitted one way swaps its image the other")
    ephemeral_ops = {op for r in rules if EPHEMERAL in (r.get("resources") or [])
                     for op in (r.get("operations") or [])}
    if "UPDATE" not in ephemeral_ops:
        fail(f"resourceRules do not match {EPHEMERAL} on UPDATE — an ephemeral container "
             f"is added through that subresource and no other request, so its image runs "
             f"unverified whatever the validations read from images.ephemeralContainers")

    exprs = ((mc.get("namespaceSelector") or {}).get("matchExpressions")) or []
    excluded = set()
    for e in exprs:
        if e.get("key") != "kubernetes.io/metadata.name" or e.get("operator") != "NotIn":
            fail(f"namespaceSelector expression {e!r} is not a NotIn on "
                 f"kubernetes.io/metadata.name — the exclusion must name namespaces")
        excluded |= set(e.get("values") or [])
    if excluded != SYSTEM_NS:
        fail(f"namespaceSelector excludes {sorted(excluded)}, expected exactly "
             f"{sorted(SYSTEM_NS)} — a workload namespace on this list runs unverified images")

    controllers = ((spec.get("autogen") or {}).get("podControllers") or {}).get("controllers")
    if controllers != []:
        fail(f"autogen.podControllers.controllers is {controllers!r}, not [] — a rule "
             f"Kyverno generates for a pod controller pins the digest into its pod "
             f"template, which ArgoCD compares with git and reports as drift on every sync")


def check_validation_config(spec: dict) -> None:
    cfg = spec.get("validationConfigurations") or {}
    for field, why in (
        ("required", "a matched image no validation verified would be admitted"),
        ("mutateDigest", "admission would verify a tag the kubelet resolves again at pull"),
        ("verifyDigest", "a tag that was never pinned would reach validation and pass"),
    ):
        if cfg.get(field) is not True:
            fail(f"validationConfigurations.{field} must be true — {why}")


def check_attestors(spec: dict) -> set[str]:
    attestors = spec.get("attestors") or []
    if not attestors:
        fail("no attestors — nothing defines whose signature is accepted")
    names = set()
    for att in attestors:
        name = att.get("name")
        cosign = att.get("cosign") or {}
        keyless = cosign.get("keyless")
        if not keyless:
            fail(f"attestor {name!r} is not keyless Cosign — the release workflows sign "
                 f"keyless (Fulcio + Rekor), and any other attestor admits a second signer")
        if set(cosign) - {"keyless", "ctlog"}:
            fail(f"attestor {name!r} sets {sorted(set(cosign) - {'keyless', 'ctlog'})} — only "
                 f"keyless identities and the transparency log are part of the contract")
        if set(keyless) - {"identities"}:
            fail(f"attestor {name!r} keyless sets {sorted(set(keyless) - {'identities'})} — "
                 f"a root bundle of its own verifies certificates no Fulcio issued, and "
                 f"the contract is the public Sigstore roots")
        ctlog = cosign.get("ctlog") or {}
        if not ctlog.get("url"):
            fail(f"attestor {name!r} names no transparency log (ctlog.url)")
        for flag in ("insecureIgnoreTlog", "insecureIgnoreSCT"):
            if ctlog.get(flag):
                fail(f"attestor {name!r} sets ctlog.{flag} — signatures absent from the "
                     f"public log would verify")
        if set(ctlog) - {"url"}:
            fail(f"attestor {name!r} ctlog sets {sorted(set(ctlog) - {'url'})} — a log key "
                 f"or timestamp chain of its own trusts entries the public Rekor never "
                 f"recorded")
        if ctlog["url"] != REKOR_URL:
            fail(f"attestor {name!r} ctlog.url is {ctlog['url']!r}, expected {REKOR_URL!r} — "
                 f"another log holds whatever its operator writes to it")
        identities = keyless.get("identities") or []
        if not identities:
            fail(f"attestor {name!r} has no keyless identities")
        for ident in identities:
            for loose in ("issuerRegExp", "subject", "subjectExpression"):
                if ident.get(loose):
                    fail(f"attestor {name!r} identity sets {loose} — the contract is one "
                         f"exact issuer and one anchored subjectRegExp")
            if set(ident) - {"issuer", "subjectRegExp"}:
                fail(f"attestor {name!r} identity sets "
                     f"{sorted(set(ident) - {'issuer', 'subjectRegExp'})} — the contract is "
                     f"one exact issuer and one anchored subjectRegExp")
            issuer = ident.get("issuer")
            if issuer != EXPECTED_ISSUER:
                fail(f"keyless issuer is {issuer!r}, expected {EXPECTED_ISSUER!r}")
            subj = ident.get("subjectRegExp")
            if not subj:
                fail("keyless identity has no subjectRegExp — any signer from the issuer would pass")
            if subj != SUBJECT_REGEXP:
                fail(f"subjectRegExp '{subj}' is not the release identity '{SUBJECT_REGEXP}'."
                     + "".join(f"\n  {line}" for line in subject_difference(subj)))
        names.add(name)
    return names


def subject_difference(subj: str) -> list[str]:
    """What a subjectRegExp other than SUBJECT_REGEXP does to the subject corpus.

    Matched the way cosign matches a subject, an unanchored search, so a pattern
    missing an anchor shows up as the subject it admits. Python's regex dialect
    stands in for Go's here; the two agree on every construct the release
    identity uses, and the verdict is the string comparison either way.
    """
    try:
        pattern = re.compile(subj)
    except re.error as exc:
        return [f"It does not compile as a regular expression: {exc}."]
    admitted = [f"It admits {s}" for s in REFUSED_SUBJECTS if pattern.search(s)]
    refused = [f"It refuses {s}" for s in ACCEPTED_SUBJECTS if not pattern.search(s)]
    if admitted or refused:
        return admitted + refused
    return ["It decides every subject in the corpus the way the release identity does, "
            "which shows only that the corpus does not tell the two apart. Trusting "
            "another identity is a change to SUBJECT_REGEXP and the corpus together."]


def check_attestations(spec: dict) -> str:
    for att in spec.get("attestations") or []:
        if ((att.get("intoto") or {}).get("type")) == EXPECTED_SBOM_TYPE:
            return att["name"]
    fail(f"no attestation of in-toto type {EXPECTED_SBOM_TYPE!r} — the SBOM the release "
         f"workflows attest is never required")


def canonical(expr: str) -> str:
    return "".join(expr.split())


def check_validations(spec: dict, attestors: set[str], sbom: str) -> None:
    exprs = [v.get("expression") or "" for v in spec.get("validations") or []]
    present = {canonical(e) for e in exprs}

    for what, template, call, why in (
        ("signature", SIGNATURE_VALIDATION, "verifyImageSignatures(",
         "signatures are never checked"),
        ("SBOM", ATTESTATION_VALIDATION, "verifyAttestationSignatures(",
         f"the attestations.{sbom} SBOM is declared and never required"),
    ):
        expected = [template.format(attestor=n, attestation=sbom) for n in sorted(attestors)]
        if any(canonical(x) in present for x in expected):
            continue
        calling = [" ".join(e.split()) for e in exprs if call in e]
        if not calling:
            fail(f"no validation calls {call[:-1]} — {why}")
        fail(f"the {what} validation is not the expected expression, compared whole: "
             f"found {calling[0]!r}, expected {expected[0]!r}. An expression naming the "
             f"call and every container field can still pass every image")


def check_contract(doc: dict) -> None:
    if doc.get("apiVersion") != EXPECTED_API or doc.get("kind") != EXPECTED_KIND:
        fail(f"it is {doc.get('apiVersion')}/{doc.get('kind')}, expected "
             f"{EXPECTED_API}/{EXPECTED_KIND}")
    spec = doc.get("spec") or {}

    check_scope(spec)
    check_validation_config(spec)
    attestors = check_attestors(spec)
    sbom = check_attestations(spec)
    check_validations(spec, attestors, sbom)


def check_actions(env: str, doc: dict) -> None:
    actions = (doc.get("spec") or {}).get("validationActions") or []
    if sorted(actions) != sorted(EXPECTED_ACTIONS[env]):
        fail(f"validationActions is {actions}, expected {EXPECTED_ACTIONS[env]} for "
             f"{env} — the tier would {'report' if 'Deny' not in actions else 'block'} "
             f"an image failing verification")


def cannot_run(msg: str) -> NoReturn:
    print(f"Cannot run: {msg}")
    print("The overlays a cluster installs were NOT checked — that is different from")
    print("every one meeting the contract.")
    sys.exit(gatelib.CANNOT_RUN)


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def render(overlay: Path) -> dict:
    """The verify-images document `kustomize build` writes for one overlay."""
    try:
        build = subprocess.run(["kustomize", "build", str(overlay)], capture_output=True,
                               text=True, timeout=LOCAL_TIMEOUT)
    except subprocess.TimeoutExpired:
        cannot_run(f"kustomize build {rel(overlay)} ran past {LOCAL_TIMEOUT}s")
    if build.returncode != 0:
        fail(f"it does not render — {(build.stderr.strip().splitlines() or ['?'])[0]}")
    for doc in yaml.safe_load_all(build.stdout):
        if (isinstance(doc, dict) and doc.get("kind") == EXPECTED_KIND
                and (doc.get("metadata") or {}).get("name") == POLICY_NAME):
            return doc
    fail(f"it renders no {EXPECTED_KIND} named {POLICY_NAME} — that tier installs no "
         f"signature verification")


def overlay_dirs() -> list[Path]:
    """Every supply-chain overlay, held to the environments EXPECTED_ACTIONS names."""
    overlays = sorted(p for p in (GROUP / "overlays").glob("*")
                      if (p / "kustomization.yaml").is_file())
    unexpected = sorted({p.name for p in overlays} - set(EXPECTED_ACTIONS))
    if unexpected:
        fail(f"overlay(s) {unexpected} carry no entry in EXPECTED_ACTIONS — whether that "
             f"tier blocks or reports a failed verification is a decision to record there")
    absent = sorted(set(EXPECTED_ACTIONS) - {p.name for p in overlays})
    if absent:
        fail(f"no overlay for {absent} — a tier this gate does not render is a tier it "
             f"does not check")
    return overlays


def main() -> None:
    # The base first, so its violation is reported without a render; then each
    # overlay as kustomize writes it, which is what a cluster installs.
    where = rel(POLICY)
    try:
        if not POLICY.exists():
            fail("policy not found, so there is no contract to read")
        check_contract(yaml.safe_load(POLICY.read_text()) or {})
        where = rel(GROUP / "overlays")
        overlays = overlay_dirs()
        gatelib.require("kustomize")
        for overlay in overlays:
            where = rel(overlay)
            doc = render(overlay)
            check_contract(doc)
            check_actions(overlay.name, doc)
    except Violation as exc:
        print(f"::error::verify-images identity contract: {where}: {exc}")
        sys.exit(1)

    tiers = ", ".join(f"{p.name} {'+'.join(EXPECTED_ACTIONS[p.name])}" for p in overlays)
    print(f"verify-images identity contract OK on the base and {len(overlays)} rendered "
          f"overlay(s) ({tiers}): {SCOPE} scope, admission-time Kubernetes evaluation, "
          f"system-only namespace exclusion, required + pinned digest, GitHub OIDC issuer, "
          f"the release-on-tag subjectRegExp, public Rekor, both validations compared "
          f"whole, SPDX attestation required")


if __name__ == "__main__":
    main()
