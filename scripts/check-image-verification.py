#!/usr/bin/env python3
"""Supply-chain gate — the keyless-signing IDENTITY contract of verify-images.

    ┌─────────────────────────────────────────────────────────────────────┐
    │ WHY THIS EXISTS AND kyverno test DOES NOT COVER IT — read first.     │
    │                                                                     │
    │ `kyverno test` cannot verify a Cosign signature offline: it never   │
    │ reaches Fulcio/Rekor, so a verifyImages rule reports Pass/Ok        │
    │ regardless of the attestor. The kyverno unit tests therefore only    │
    │ pin the MATCH/EXCLUDE scoping (a widened imageReferences or a        │
    │ dropped namespace exclude flips their result). They are blind to the │
    │ one regression that matters most here: a WEAKENED SIGNING IDENTITY.  │
    │                                                                     │
    │ A subjectRegExp broadened to `.*` (or any-org), a flipped           │
    │ `required: false`, or a changed issuer renders and schema-validates  │
    │ clean and ships silently — the policy still "verifies images", it    │
    │ just now accepts anyone's signature. That is theater, and it is what │
    │ this structural gate refuses to let merge.                          │
    └─────────────────────────────────────────────────────────────────────┘

Asserts, on policies/kyverno/supply-chain/base/verify-images.yaml:
  - the verifyImages rule requires a signature (required: true);
  - it is scoped to ghcr.io/nanohype/* — never a bare "*" that would demand a
    signature on every third-party image (or, widened the other way, match
    nothing meaningful);
  - the keyless attestor pins the GitHub Actions OIDC issuer exactly;
  - the subjectRegExp is anchored (^...$), org-scoped to github.com/nanohype,
    bound to a release workflow firing on a tag, and is NOT a permissive
    wildcard.

BLOCKING: exits non-zero on the first violation.
"""

import re
import sys
from pathlib import Path

POLICY = (
    Path(__file__).resolve().parent.parent
    / "policies/kyverno/supply-chain/base/verify-images.yaml"
)

EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"
# A subjectRegExp is "permissive" if it would accept a signer outside the org.
# Bare wildcards and unanchored org-agnostic patterns are the theater cases.
WILDCARD_SUBJECTS = {".*", ".+", "^.*$", "^.+$", "*"}


def fail(msg: str) -> None:
    print(f"::error::verify-images identity contract: {msg}")
    sys.exit(1)


def main() -> None:
    try:
        import yaml
    except ImportError:
        fail("PyYAML is required (pip install pyyaml)")

    if not POLICY.exists():
        fail(f"policy not found at {POLICY}")

    doc = yaml.safe_load(POLICY.read_text())
    rules = (doc.get("spec") or {}).get("rules") or []
    verify_rules = [r for r in rules if "verifyImages" in r]
    if not verify_rules:
        fail("no rule with a verifyImages block — image signing is not enforced at all")

    for rule in verify_rules:
        for vi in rule["verifyImages"]:
            refs = vi.get("imageReferences") or []
            if not refs:
                fail("verifyImages has no imageReferences")
            if "*" in refs or any(r.strip() == "*" for r in refs):
                fail("imageReferences contains a bare '*' — signature demanded on every image; scope it to ghcr.io/nanohype/*")
            if not any("nanohype" in r for r in refs):
                fail(f"imageReferences {refs} is not scoped to ghcr.io/nanohype/*")

            if vi.get("required") is not True:
                fail("verifyImages.required must be true — a false/absent value makes verification advisory")

            attestors = vi.get("attestors") or []
            keyless_seen = False
            for att in attestors:
                for entry in att.get("entries") or []:
                    keyless = entry.get("keyless")
                    if not keyless:
                        continue
                    keyless_seen = True
                    issuer = keyless.get("issuer")
                    if issuer != EXPECTED_ISSUER:
                        fail(f"keyless issuer is {issuer!r}, expected {EXPECTED_ISSUER!r}")
                    subj = keyless.get("subjectRegExp")
                    if not subj:
                        fail("keyless attestor has no subjectRegExp — any signer from the issuer would pass")
                    if subj.strip() in WILDCARD_SUBJECTS:
                        fail(f"subjectRegExp {subj!r} is a wildcard — it accepts any signer; pin the org release workflow")
                    if not (subj.startswith("^") and subj.endswith("$")):
                        fail(f"subjectRegExp {subj!r} is not fully anchored (^...$) — a substring match is bypassable")
                    if "nanohype" not in subj:
                        fail(f"subjectRegExp {subj!r} is not scoped to the nanohype org")
                    if "refs/tags" not in subj:
                        fail(f"subjectRegExp {subj!r} does not bind to a tag push (refs/tags) — an untagged workflow run could sign")
                    # The pattern must actually be a valid regex.
                    try:
                        re.compile(subj)
                    except re.error as exc:
                        fail(f"subjectRegExp {subj!r} is not a valid regex: {exc}")
            if not keyless_seen:
                fail("no keyless attestor — only keyless Cosign (Fulcio+Rekor) is accepted by the release workflows")

    print("verify-images identity contract OK: required signature, ghcr.io/nanohype/* scope, "
          "GitHub OIDC issuer, anchored org-scoped release-workflow subjectRegExp")


if __name__ == "__main__":
    main()
