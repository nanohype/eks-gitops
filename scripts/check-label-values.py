#!/usr/bin/env python3
"""Assert every k8s label this repo writes has a value the API server accepts.

An ApplicationSet's `spec.template.metadata.labels` is a plain string map in the
CRD schema, so nothing about it is a label as far as validation is concerned.
It only becomes one when the ApplicationSet controller renders an Application
and the API server admits it. Every gate upstream of that point sees a
well-formed manifest:

  * kubeconform validates the ApplicationSet against its CRD schema, where the
    field is `additionalProperties: {type: string}` — any string passes.
  * yamllint reads syntax.
  * kustomize/helm render the text without submitting it.
  * `kyverno apply` evaluates policy rules, not API-server field validation.

So a value like an `org/name` repository slug passes the whole pipeline and then
fails at admission, where the message names one generated Application:

  Application.argoproj.io "cert-manager" is invalid: metadata.labels:
  Invalid value: "nanohype/eks-gitops": a valid label must be an empty string or
  consist of alphanumeric characters, '-', '_' or '.'

That failure is not scoped to the one Application it names. app-of-apps syncs
the ApplicationSets, an invalid generated Application fails the sync task, and
the whole app-of-apps sync reports Failed — so a single bad label value in a
shared template block stops the entire addon catalog from installing. The
cluster comes up healthy, ArgoCD is running, and nothing is deployed.

This gate reads the label values directly and applies the API server's own rule,
so the manifest and the thing it becomes cannot disagree.

Scope: `metadata.labels` and `spec.template.metadata.labels` anywhere in the
tracked YAML. Annotations are deliberately not checked — annotation values are
unconstrained, which is where a genuine `org/name` belongs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent

# The API server's rule, from k8s.io/apimachinery validation: a label value is
# either empty, or up to 63 chars of alphanumerics/'-'/'_'/'.' that starts and
# ends alphanumeric.
LABEL_VALUE = re.compile(r"^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$")
MAX_LEN = 63

# A value that is entirely a Go template resolves at render time, so its literal
# text is not the value the API server sees and this gate cannot judge it. What
# it CAN judge is the surrounding literal text: `{{ .x }}-suffix` is checked with
# the template elided, so a slash typed next to a placeholder is still caught.
TEMPLATE = re.compile(r"\{\{[^}]*\}\}")

SKIP_DIRS = {".git", "node_modules", "rendered", "__pycache__", ".task"}

# Inside a Kyverno policy, `spec.rules[].validate.pattern.metadata.labels` is a
# MATCHER over other resources' labels, not labels being applied — `?*` there
# means "any non-empty value" and is correct. The policy's own top-level
# metadata.labels are real labels and are still checked.
KYVERNO_KINDS = {"ClusterPolicy", "Policy", "ClusterCleanupPolicy", "CleanupPolicy"}


def label_blocks(node, path="") -> list[tuple[str, dict]]:
    """Yield every (jsonpath, labels-map) pair reachable in a parsed document."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}"
            if key == "labels" and isinstance(value, dict) and path.endswith(".metadata"):
                found.append((here, value))
            found.extend(label_blocks(value, here))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found.extend(label_blocks(item, f"{path}[{i}]"))
    return found


def blocks_for(doc) -> list[tuple[str, dict]]:
    """Label blocks worth checking in one document."""
    if isinstance(doc, dict) and doc.get("kind") in KYVERNO_KINDS:
        own = doc.get("metadata", {}).get("labels")
        return [(".metadata.labels", own)] if isinstance(own, dict) else []
    return label_blocks(doc)


def check_value(raw) -> str | None:
    """Return a human-readable reason the value is invalid, or None."""
    # YAML gives back bools/ints for unquoted true/8080; the API server sees the
    # serialized form, and the serialized form of those is always valid.
    if not isinstance(raw, str):
        return None

    elided = TEMPLATE.sub("", raw)
    if elided != raw and elided == "":
        return None  # pure template — resolves at render time

    if len(elided) > MAX_LEN:
        return f"{len(elided)} chars of literal text exceeds the {MAX_LEN}-char limit"
    if not LABEL_VALUE.match(elided):
        bad = sorted({c for c in elided if not re.match(r"[-A-Za-z0-9_.]", c)})
        if bad:
            return "contains " + ", ".join(f"{c!r}" for c in bad)
        return "must start and end with an alphanumeric character"
    return None


# Floors on what was EXAMINED, not on what was found. Printing a denominator
# is not gating on it: this gate printed its count and exited 0 against a
# tree containing only the scripts — which is what a renamed directory or a
# wrong working directory looks like. Set well under the real numbers, so
# they catch "matched almost nothing", never "someone removed one".
MIN_FILES = 200
MIN_VALUES = 100


# Two floors, deliberately not collapsed into one number.
#
#   UNCONDITIONAL — at least one thing examined OUTSIDE the gate's own
#   directories. This is a law about ANY tree: a run over scripts/ and the test
#   fixtures alone has examined nothing this repo ships, whatever the count
#   says. It is what catches a gate-scripts-only checkout even if someone later
#   lowers the number below.
#
#   REPO-ONLY — the count floors below. True of THIS repo and not a law about
#   any tree, which is why they are separate: collapsing the two makes the floor
#   reject a legitimate small fixture and report it as the gate failing
#   everything.
SELF_DIRS = ("scripts", "policies/kyverno/tests", "applicationsets/rendertest")


def outside_self(paths, root) -> int:
    """How many of `paths` lie outside the gate's own directories."""
    n = 0
    for p in paths:
        try:
            rel = Path(p).resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        if not rel.startswith(SELF_DIRS):
            n += 1
    return n


def main() -> int:
    failures: list[str] = []
    scanned = 0

    files = sorted(
        p
        for p in REPO.rglob("*.y*ml")
        if not any(part in SKIP_DIRS for part in p.parts)
    )

    for path in files:
        try:
            docs = list(yaml.safe_load_all(path.read_text()))
        except yaml.YAMLError:
            # Helm templates and other non-YAML-parseable files are the concern
            # of the render gates, not this one.
            continue

        rel = path.relative_to(REPO)
        for doc in docs:
            if doc is None:
                continue
            for where, labels in blocks_for(doc):
                for key, value in labels.items():
                    scanned += 1
                    reason = check_value(value)
                    if reason:
                        failures.append(
                            f"  {rel}\n"
                            f"    at {where.lstrip('.')}\n"
                            f"    {key}: {value!r}\n"
                            f"    -> {reason}"
                        )

    print(f"Checked {scanned} label value(s) across {len(files)} YAML file(s)")
    product = outside_self(files, REPO)
    if product == 0:
        print(f"FAIL  every file examined lies inside {SELF_DIRS} — this run saw the "
              f"gate's own directories and none of the manifests this repo ships.")
        return 2
    if len(files) < MIN_FILES or scanned < MIN_VALUES:
        print(f"FAIL  examined {len(files)} file(s) and {scanned} label value(s), under "
              f"the floors ({MIN_FILES}/{MIN_VALUES}). This gate looked at almost "
              f"nothing, which is not the same as finding nothing.")
        return 2

    if failures:
        print(
            f"\n✗ {len(failures)} label value(s) the API server will reject:\n",
            file=sys.stderr,
        )
        print("\n\n".join(failures), file=sys.stderr)
        print(
            "\nA label value is [A-Za-z0-9] separated by '-', '_' or '.', max 63 chars.\n"
            "'/' is legal in a label KEY's prefix and in an AWS tag value, but never in\n"
            "a label value. Render an org/name slug as org.name here and keep the\n"
            "slashed form for the AWS tag surface, or move it to an annotation.",
            file=sys.stderr,
        )
        return 1

    print("✓ every label value satisfies the API server's grammar")
    return 0


if __name__ == "__main__":
    sys.exit(main())
