"""What the tests of the two shell gates on the image-verification path share.

scripts/kyverno-test.sh reads the verifier's errors out of the Kyverno CLI, and
scripts/check-digest-rewrite.sh out of the admission controller. Both are the
same verifier, logging the same line, refusing under the same policy message,
so their tests build those from one place and a fixture cannot drift between
them.
"""

from __future__ import annotations

import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
POLICY = ROOT / "policies" / "kyverno" / "supply-chain" / "base" / "verify-images.yaml"

# The escape that opens each terminal colour code. The verifier logs through
# zerolog's console writer, which colours field names and values.
ESC = "\033"


def setting(script: pathlib.Path, name: str) -> int:
    """The number a shell script assigns to `name`, on a line of its own."""
    found = re.search(rf"^{name}=(\d+)$", script.read_text(), re.M)
    assert found, f"{script.name} sets no {name}"
    return int(found.group(1))


def verifier_line(error: str, tail: str = "") -> str:
    """A line Kyverno's cosign verifier logs for a failed verification, coloured.

    `tail` follows the attestor field: the admission controller names the image
    there, and the CLI at -v 1 ends the line at the attestor.
    """
    line = (f"2026-01-01T00:00:00Z {ESC}[31mERR{ESC}[0m github.com/kyverno/kyverno/pkg/image/"
            f"verifiers/ivpol/cosign/verifier.go:281 > image verification failed "
            f"{ESC}[36merror={ESC}[0m{ESC}[31m\"{error}\"{ESC}[0m attestor=release")
    return f"{line} {tail}" if tail else line


def identity_message() -> str:
    """The message verify-images refuses an image under when no release signature verifies.

    Read from the validation that calls verifyImageSignatures, so a fixture
    carries what the policy says rather than a copy of it.
    """
    for doc in yaml.safe_load_all(POLICY.read_text()):
        if not doc or doc.get("kind") != "ImageValidatingPolicy":
            continue
        for validation in doc["spec"].get("validations") or []:
            if "verifyImageSignatures(" in validation.get("expression", ""):
                return str(validation["message"])
    raise AssertionError(f"{POLICY.name} holds no validation calling verifyImageSignatures")
