#!/usr/bin/env python3
"""Supply-chain gate — the keyless-signing IDENTITY contract of verify-images.

    ┌─────────────────────────────────────────────────────────────────────┐
    │ WHAT kyverno test DOES NOT COVER — read first.                      │
    │                                                                     │
    │ The unit suite verifies real signatures, so it proves the release   │
    │ identity admits a release image and refuses a branch-signed one.    │
    │ It cannot see a WEAKENED identity that still admits both fixtures:  │
    │ a subjectRegExp broadened to `.*` or any org, an issuer swapped for │
    │ an issuerRegExp, `required: false`, a Rekor check switched off, or  │
    │ a namespace exclusion grown over a workload namespace. Each renders │
    │ and schema-validates clean and ships silently — the policy still    │
    │ "verifies images", it just accepts more signers or checks fewer     │
    │ pods. This structural gate refuses those.                           │
    └─────────────────────────────────────────────────────────────────────┘

Asserts, on policies/kyverno/supply-chain/base/verify-images.yaml (an
ImageValidatingPolicy, policies.kyverno.io/v1):
  - matchImageReferences is scoped to ghcr.io/nanohype/*, never a bare "*";
  - the policy fails closed (failurePolicy is not Ignore) and matches pods on
    CREATE and UPDATE, excluding exactly the system namespaces in SYSTEM_NS;
  - validationConfigurations sets required, mutateDigest and verifyDigest true;
  - every attestor is keyless Cosign: the GitHub Actions OIDC issuer exactly,
    a subjectRegExp anchored (^...$), org-scoped to github.com/nanohype, bound
    to a release workflow on refs/tags and not a wildcard, and the Rekor
    transparency log checked;
  - an attestation of in-toto type https://spdx.dev/Document is declared;
  - one validation verifies image signatures and one verifies that SPDX
    attestation, each against the keyless attestor and over every container
    field.

BLOCKING: exits non-zero on the first violation.
"""

import re
import sys
from pathlib import Path
from typing import NoReturn

POLICY = (
    Path(__file__).resolve().parent.parent
    / "policies/kyverno/supply-chain/base/verify-images.yaml"
)

EXPECTED_API = "policies.kyverno.io/v1"
EXPECTED_KIND = "ImageValidatingPolicy"
EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"
EXPECTED_SBOM_TYPE = "https://spdx.dev/Document"
REGISTRY_PREFIX = "ghcr.io/nanohype/"
# The namespaces the policy skips, and no others. Adding a namespace here is a
# decision to run unverified nanohype images in it.
SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease", "kyverno"}
CONTAINER_FIELDS = ("images.containers", "images.initContainers", "images.ephemeralContainers")
# A subjectRegExp is "permissive" if it would accept a signer outside the org.
WILDCARD_SUBJECTS = {".*", ".+", "^.*$", "^.+$", "*"}


def fail(msg: str) -> NoReturn:
    print(f"::error::verify-images identity contract: {msg}")
    sys.exit(1)


def check_scope(spec: dict) -> None:
    refs = spec.get("matchImageReferences") or []
    if not refs:
        fail("matchImageReferences is empty — the policy selects no image")
    for ref in refs:
        glob = (ref or {}).get("glob")
        if glob is None:
            fail(f"matchImageReferences entry {ref!r} is not a glob — scope it to {REGISTRY_PREFIX}*")
        if glob.strip() == "*":
            fail("matchImageReferences contains a bare '*' — signature demanded on every image; "
                 f"scope it to {REGISTRY_PREFIX}*")
        if not glob.startswith(REGISTRY_PREFIX):
            fail(f"matchImageReferences glob {glob!r} is not scoped to {REGISTRY_PREFIX}*")

    if spec.get("failurePolicy") == "Ignore":
        fail("failurePolicy is Ignore — a webhook timeout or a Kyverno outage would admit "
             "every image unverified")

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
        ctlog = cosign.get("ctlog") or {}
        if not ctlog.get("url"):
            fail(f"attestor {name!r} names no transparency log (ctlog.url)")
        for flag in ("insecureIgnoreTlog", "insecureIgnoreSCT"):
            if ctlog.get(flag):
                fail(f"attestor {name!r} sets ctlog.{flag} — signatures absent from the "
                     f"public log would verify")
        identities = keyless.get("identities") or []
        if not identities:
            fail(f"attestor {name!r} has no keyless identities")
        for ident in identities:
            for loose in ("issuerRegExp", "subject", "subjectExpression"):
                if ident.get(loose):
                    fail(f"attestor {name!r} identity sets {loose} — the contract is one "
                         f"exact issuer and one anchored subjectRegExp")
            issuer = ident.get("issuer")
            if issuer != EXPECTED_ISSUER:
                fail(f"keyless issuer is {issuer!r}, expected {EXPECTED_ISSUER!r}")
            subj = ident.get("subjectRegExp")
            if not subj:
                fail("keyless identity has no subjectRegExp — any signer from the issuer would pass")
            if subj.strip() in WILDCARD_SUBJECTS:
                fail(f"subjectRegExp {subj!r} is a wildcard — it accepts any signer; pin the "
                     f"org release workflow")
            if not (subj.startswith("^") and subj.endswith("$")):
                fail(f"subjectRegExp {subj!r} is not fully anchored (^...$) — a substring "
                     f"match is bypassable")
            if not subj.startswith(r"^https://github\.com/nanohype/"):
                fail(f"subjectRegExp {subj!r} is not scoped to the nanohype org")
            if "release" not in subj:
                fail(f"subjectRegExp {subj!r} does not bind to a release workflow")
            if "@refs/tags/" not in subj:
                fail(f"subjectRegExp {subj!r} does not bind to a tag push (@refs/tags/) — a "
                     f"branch build could sign")
            try:
                re.compile(subj)
            except re.error as exc:
                fail(f"subjectRegExp {subj!r} is not a valid regex: {exc}")
        names.add(name)
    return names


def check_attestations(spec: dict) -> str:
    for att in spec.get("attestations") or []:
        if ((att.get("intoto") or {}).get("type")) == EXPECTED_SBOM_TYPE:
            return att["name"]
    fail(f"no attestation of in-toto type {EXPECTED_SBOM_TYPE!r} — the SBOM the release "
         f"workflows attest is never required")


def covers_every_field(expr: str) -> bool:
    return all(f in expr for f in CONTAINER_FIELDS)


def check_validations(spec: dict, attestors: set[str], sbom: str) -> None:
    exprs = [v.get("expression") or "" for v in spec.get("validations") or []]
    refs = [f"attestors.{n}" for n in sorted(attestors)]

    sig = [e for e in exprs if "verifyImageSignatures(" in e and any(r in e for r in refs)]
    if not sig:
        fail("no validation calls verifyImageSignatures against the keyless attestor — "
             "signatures are never checked")
    if not any(covers_every_field(e) for e in sig):
        fail(f"the signature validation does not cover {', '.join(CONTAINER_FIELDS)} — a "
             f"nanohype image in an uncovered field runs unverified")

    att = [e for e in exprs if "verifyAttestationSignatures(" in e
           and f"attestations.{sbom}" in e and any(r in e for r in refs)]
    if not att:
        fail(f"no validation calls verifyAttestationSignatures for attestations.{sbom} "
             f"against the keyless attestor — the SBOM attestation is declared and never "
             f"required")
    if not any(covers_every_field(e) for e in att):
        fail(f"the SBOM validation does not cover {', '.join(CONTAINER_FIELDS)} — a "
             f"nanohype image in an uncovered field runs without an attested SBOM")


def main() -> None:
    try:
        import yaml
    except ImportError:
        fail("PyYAML is required (pip install pyyaml)")

    if not POLICY.exists():
        fail(f"policy not found at {POLICY}")

    doc = yaml.safe_load(POLICY.read_text()) or {}
    if doc.get("apiVersion") != EXPECTED_API or doc.get("kind") != EXPECTED_KIND:
        fail(f"{POLICY.name} is {doc.get('apiVersion')}/{doc.get('kind')}, expected "
             f"{EXPECTED_API}/{EXPECTED_KIND}")
    spec = doc.get("spec") or {}

    check_scope(spec)
    check_validation_config(spec)
    attestors = check_attestors(spec)
    sbom = check_attestations(spec)
    check_validations(spec, attestors, sbom)

    print("verify-images identity contract OK: ghcr.io/nanohype/* scope, system-only "
          "namespace exclusion, required + pinned digest, GitHub OIDC issuer, anchored "
          "org-scoped release-on-tag subjectRegExp, Rekor, SPDX attestation required")


if __name__ == "__main__":
    main()
