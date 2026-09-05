#!/usr/bin/env python3
"""Every input that decides a load balancer's scheme is one this catalog's policy reads.

    python3 scripts/check-lb-scheme-inputs.py             # blocking gate, offline
    python3 scripts/check-lb-scheme-inputs.py --live      # scheduled, reads the controller
    python3 scripts/check-lb-scheme-inputs.py --sync      # re-derive and rewrite the record
    python3 scripts/check-lb-scheme-inputs.py --self-test

WHY A GATE AND NOT A LONGER LIST

inject-adopt-lb-subnets injects private or public subnet ids according to the
scheme it believes a load balancer will have. Reading one annotation per object
kind made that belief a pattern rather than a derivation: a second spelling of
the same thing — `aws-load-balancer-internal`, still honoured, still ahead of the
default — read as internal and handed a private-subnet list to a load balancer
the controller puts on public subnets. Adding that second annotation to the
policy fixes the instance. It does nothing about the third.

So the population is derived from the code that actually decides it. The AWS Load
Balancer Controller answers two questions, in two functions, and this gate reads
both at the version the catalog pins:

    buildLoadBalancerScheme   (pkg/service and pkg/ingress) — which scheme
    IsServiceSupported        (pkg/service)                 — whose Service it is

Every symbol those functions and their callees consult is derived and must be
accounted for in scripts/lb-scheme-inputs.json: READ, with a string the policy
must contain; UNREAD, with the reason the policy cannot or will not consult it;
or PLUMBING, with the reason it decides nothing. A symbol that is none of those
fails --sync, so a new deciding input cannot be recorded without somebody
choosing what to do about it.

WHAT THIS DOES NOT ESTABLISH

That the derivation sees every possible input. It reads the two entry functions
and the functions they call within their own files; an input reached through a
package this walk does not open would be missed. What it does establish is that
the set is derived from the controller rather than remembered, and that the set
moving fails a build.

THE SPLIT

    default (offline, BLOCKING) — the record matches the chart pin, every symbol
        recorded READ appears in the policy, every other symbol carries its
        reason, and every literal the policy hardcodes is one the record derived.
        A function of the tree, so a chart bump makes the record stale and fails
        here rather than on a cluster.

    --live (network, SCHEDULED) — re-derive the symbols from the controller
        source, and re-render the chart with this catalog's values to confirm the
        flags the policy assumes are the flags the controller is given.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import NoReturn

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSET = ROOT / "applicationsets" / "addons-networking.yaml"
ADDON = ROOT / "addons" / "networking" / "aws-load-balancer-controller"
POLICY = ROOT / "policies" / "kyverno" / "networking" / "base" / "inject-adopt-lb-subnets.yaml"
# Beside the checker for the reason scripts/chart-provenance.json is: the
# directories it describes are read by other gates as manifests.
RECORDS = ROOT / "scripts" / "lb-scheme-inputs.json"

ADDON_NAME = "aws-load-balancer-controller"
SOURCE = "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller"

# The functions that decide, and the file each lives in. Entry points, not a list
# of inputs — what they consult is derived.
ENTRY_POINTS = (
    ("scheme", "Service", "pkg/service/model_build_load_balancer.go", "buildLoadBalancerScheme"),
    ("scheme", "Ingress", "pkg/ingress/model_build_load_balancer.go", "buildLoadBalancerScheme"),
    ("ownership", "Service", "pkg/service/service_utils.go", "IsServiceSupported"),
)
# Read for the annotation names and prefixes the entry points reference by
# identifier, and for the string values the policy has to match.
LOOKUP_FILES = (
    "pkg/annotations/constants.go",
    "pkg/service/model_builder.go",
    "controllers/service/service_controller.go",
)

STATUSES = ("read", "unread", "plumbing")
NETWORK_TIMEOUT = 120


def die(msg: str) -> NoReturn:
    print(f"lb-scheme-inputs: {msg}", file=sys.stderr)
    sys.exit(1)


# ------------------------------------------------------------------- the chart


def chart_pin() -> dict:
    """The controller's chart coordinates, from the ApplicationSet that ships it."""
    for doc in gatelib.read_yaml_all(APPSET):
        if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
            continue
        for el in gatelib.list_elements(doc):
            if el.get("appName") == ADDON_NAME:
                missing = [k for k in ("chartRepo", "chart", "chartVersion") if not el.get(k)]
                if missing:
                    die(f"{APPSET.relative_to(ROOT)} names {ADDON_NAME} without "
                        f"{', '.join(missing)} — the version this gate reads the "
                        f"controller at is not in the tree.")
                return {"chartRepo": str(el["chartRepo"]), "chart": str(el["chart"]),
                        "chartVersion": str(el["chartVersion"])}
    die(f"{APPSET.relative_to(ROOT)} carries no {ADDON_NAME} element, so this gate has "
        f"no controller version to derive against. It examined nothing, which is not "
        f"the same as finding nothing.")
    raise AssertionError("unreachable")


def app_version(pin: dict) -> str:
    """What the pinned chart says it installs — the tag the source is read at."""
    gatelib.require("helm")
    proc = subprocess.run(
        ["helm", "show", "chart", "--repo", pin["chartRepo"], pin["chart"],
         "--version", pin["chartVersion"]],
        capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
    if proc.returncode != 0:
        last = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
        die(f"{pin['chart']} {pin['chartVersion']} would not resolve — "
            f"{last[-1][:200] if last else 'no output'}")
    import yaml
    meta = yaml.safe_load(proc.stdout) or {}
    version = str(meta.get("appVersion") or "").strip()
    if not version:
        die(f"{pin['chart']} {pin['chartVersion']} publishes no appVersion, so which "
            f"controller source to read is unknown.")
    return version


def rendered_flags(pin: dict) -> dict:
    """The controller's effective configuration, as this catalog installs it."""
    gatelib.require("helm")
    values = [str(ADDON / "values.yaml")]
    proc = subprocess.run(
        ["helm", "template", ADDON_NAME, pin["chart"], "--repo", pin["chartRepo"],
         "--version", pin["chartVersion"], "-n", "kube-system",
         *sum((["-f", v] for v in values), []), "--set", "clusterName=fixture"],
        capture_output=True, text=True, timeout=NETWORK_TIMEOUT)
    if proc.returncode != 0:
        last = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
        die(f"the controller chart would not render with this catalog's values — "
            f"{last[-1][:200] if last else 'no output'}")
    import yaml
    args: list[str] = []
    mutates_services = False
    for doc in yaml.safe_load_all(proc.stdout):
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == "Deployment":
            for container in doc["spec"]["template"]["spec"]["containers"]:
                args += list(container.get("args") or [])
        if doc.get("kind") == "MutatingWebhookConfiguration":
            for hook in doc.get("webhooks") or []:
                if "service" in str(hook.get("name", "")):
                    mutates_services = True
    flags = {}
    for arg in args:
        name, _, value = str(arg).lstrip("-").partition("=")
        flags[name] = value
    return {"args": flags, "serviceMutatorWebhook": mutates_services}


# ---------------------------------------------------------- reading the source


def fetch(ref: str, path: str) -> str:
    url = f"{SOURCE}/{ref}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=NETWORK_TIMEOUT) as resp:   # noqa: S310
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as exc:
        die(f"could not read {path} at {ref} — {exc}. The controller source is what "
            f"this gate derives from; without it nothing was checked.")


def function_body(src: str, name: str) -> str | None:
    """One top-level function's body, or None when the file declares no such function.

    gofmt puts a top-level closing brace in column zero, which is what makes the
    end of a multi-line function findable without parsing Go. It also permits a
    body written on the signature line, and that shape has to be read too: an
    entry point written that way is loud (the walk finds nothing and the gate
    refuses), but a one-line HELPER would simply drop out of the walk and take
    whatever it consults with it, leaving a shorter input list and a clean run.
    """
    m = re.search(rf"^func \([^)]*\) {re.escape(name)}\(.*$", src, re.M)
    if m is None:
        return None
    line = m.group(0)
    if line.rstrip().endswith("}") and "{" in line:
        return line[line.index("{") + 1:line.rstrip().rindex("}")]
    rest = src[m.end():]
    end = rest.find("\n}\n")
    return rest[:end] if end != -1 else None


def reachable(src: str, entry: str) -> list[tuple[str, str]]:
    """`entry` and every function in the same file it calls, transitively."""
    seen: set[str] = set()
    todo = [entry]
    out: list[tuple[str, str]] = []
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        body = function_body(src, name)
        if body is None:
            continue
        out.append((name, body))
        # Receiver-agnostic: a helper on a different receiver decides just as much.
        todo += [c for c in re.findall(r"\b\w+\.(\w+)\(", body) if c not in seen]
    return out


def constants(sources: dict[str, str]) -> dict[str, str]:
    """Every `Name = "value"` the lookup files declare."""
    found: dict[str, str] = {}
    for text in sources.values():
        for name, value in re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"\s*$', text, re.M):
            found.setdefault(name, value)
    return found


def symbols(ref: str) -> dict[str, dict]:
    """Every symbol the deciding functions consult, keyed for the record."""
    lookups = {p: fetch(ref, p) for p in LOOKUP_FILES}
    consts = constants(lookups)
    prefixes = {
        "Ingress": consts.get("AnnotationPrefixIngress", ""),
        "Service": consts.get("serviceAnnotationPrefix", ""),
    }
    for kind, prefix in prefixes.items():
        if not prefix:
            die(f"the controller source at {ref} declares no annotation prefix for "
                f"{kind}, so a suffix constant cannot be turned into the annotation "
                f"a policy would read.")

    found: dict[str, dict] = {}
    for decides, kind, path, entry in ENTRY_POINTS:
        src = fetch(ref, path)
        walked = reachable(src, entry)
        if not walked:
            die(f"{path} at {ref} declares no {entry} — the function this gate derives "
                f"from has moved or been renamed, and a walk that found it missing "
                f"must not report that everything is accounted for.")
        text = "\n".join(body for _, body in walked)

        for ident in sorted(set(re.findall(r"\bannotations\.(\w+)", text))):
            suffix = consts.get(ident)
            if suffix is None:
                die(f"{entry} consults annotations.{ident}, which none of "
                    f"{', '.join(LOOKUP_FILES)} declares. The annotation it names "
                    f"cannot be resolved, so whether the policy reads it is unknown.")
            name = suffix if "/" in suffix else f"{prefixes[kind]}/{suffix}"
            found[f"{kind}.annotations.{ident}"] = {
                "decides": decides, "kind": kind, "annotation": name}
        for field in sorted(set(re.findall(r"\.Spec\.(\w+)", text))):
            found[f"{kind}.Spec.{field}"] = {
                "decides": decides, "kind": kind, "annotation": None}
        for field in sorted(set(re.findall(r"\b[a-z]\.(\w+)\b(?!\()", text))):
            found[f"{kind}.{entry}.{field}"] = {
                "decides": decides, "kind": kind, "annotation": None}
    return found


# ----------------------------------------------------------------- the records


def load_records() -> dict:
    if not RECORDS.exists():
        die(f"{RECORDS.relative_to(ROOT)} does not exist. Run --sync to create it.")
    return gatelib.read_json(RECORDS)


def mentions(policy: str, text: str) -> bool:
    """True when `policy` names `text` as a whole token rather than as a prefix.

    A containment test reads `aws-load-balancer-internal` as present inside
    `aws-load-balancer-internal-something-else`, so renaming an annotation the
    policy consults would leave this gate green. Annotation names, JMESPath paths
    and quoted literals all end at the same class of character, so both edges are
    asserted against it.
    """
    edge = r"[A-Za-z0-9._/-]"
    return re.search(rf"(?<!{edge}){re.escape(text)}(?!{edge})", policy) is not None


def policy_text() -> str:
    if not POLICY.is_file():
        print(f"Cannot run: {POLICY.relative_to(ROOT)} does not exist. This gate "
              f"examined no policy, which is not the same as finding nothing wrong "
              f"with one.")
        sys.exit(gatelib.CANNOT_RUN)
    return POLICY.read_text(encoding="utf-8")


# ---------------------------------------------------------------- offline gate


def check_offline(record: dict, pin: dict, policy: str) -> int:
    problems: list[str] = []
    controller = record.get("controller") or {}
    recorded_symbols = record.get("symbols") or {}
    literals = record.get("literals") or {}

    for field, value in pin.items():
        if controller.get(field) != value:
            problems.append(
                f"the controller is pinned at {field}={value} and "
                f"{RECORDS.relative_to(ROOT)} was derived at "
                f"{controller.get(field)!r}. Everything below was read out of a "
                f"different version of the controller. Run --sync.")
    if not controller.get("sourceRef"):
        problems.append(
            f"{RECORDS.relative_to(ROOT)} names no sourceRef, so which controller "
            f"source the symbols came from is unknown.")

    if not recorded_symbols:
        die(f"{RECORDS.relative_to(ROOT)} records no symbol at all. A run over an "
            f"empty derivation reports the same thing as a run over a complete one.")

    for decides, kind, _, _ in ENTRY_POINTS:
        if not any(s.get("decides") == decides and s.get("kind") == kind
                   for s in recorded_symbols.values()):
            problems.append(
                f"nothing is recorded for what decides {kind} {decides}, so that "
                f"question was derived from nothing.")

    for key, rec in sorted(recorded_symbols.items()):
        status = rec.get("status")
        if status not in STATUSES:
            problems.append(
                f"{key} is recorded with status {status!r}, which is not one of "
                f"{', '.join(STATUSES)} — it has not been decided about.")
            continue
        if status == "read":
            evidence = rec.get("evidence") or rec.get("annotation")
            if not evidence:
                problems.append(
                    f"{key} is recorded as read with nothing naming where the policy "
                    f"reads it, so the claim rests on the record agreeing with itself.")
            elif not mentions(policy, evidence):
                problems.append(
                    f"{key} is recorded as read, and {POLICY.relative_to(ROOT)} does "
                    f"not contain {evidence!r}. The policy stopped reading an input "
                    f"the controller still decides on.")
        elif not rec.get("note"):
            problems.append(
                f"{key} is recorded as {status} with no reason. An input nobody read "
                f"and nobody excused is the gap this gate exists to close.")

    if not literals:
        problems.append(
            f"{RECORDS.relative_to(ROOT)} records no literal, so the strings the "
            f"policy compares against are held equal to nothing.")
    for value, why in sorted(literals.items()):
        if not mentions(policy, value):
            problems.append(
                f"{POLICY.relative_to(ROOT)} does not contain {value!r} ({why}). The "
                f"policy and the controller disagree about a value one of them "
                f"decides on.")

    counts: dict[str, int] = {}
    for rec in recorded_symbols.values():
        counts[rec.get("status", "?")] = counts.get(rec.get("status", "?"), 0) + 1
    print(f"        {len(recorded_symbols)} symbol(s) derived from "
          f"{controller.get('sourceRef')}: "
          + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
    for key, rec in sorted(recorded_symbols.items()):
        if rec.get("status") != "read":
            print(f"        {rec.get('status'):9} {key}")

    if problems:
        print(f"FAIL  {len(problems)} problem(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    {len(recorded_symbols)} deciding symbol(s) and {len(literals)} "
          f"literal(s) accounted for against the pinned controller.")
    return 0


# ------------------------------------------------------------------ live check


def check_live(record: dict, pin: dict) -> int:
    controller = record.get("controller") or {}
    ref = controller.get("sourceRef") or app_version(pin)
    derived = symbols(ref)
    recorded = record.get("symbols") or {}
    problems = []

    for key in sorted(set(derived) - set(recorded)):
        problems.append(
            f"{key} decides {derived[key]['kind']} {derived[key]['decides']} and is in "
            f"no record. Run --sync and decide what the policy does about it.")
    for key in sorted(set(recorded) - set(derived)):
        problems.append(
            f"{key} is recorded and the controller at {ref} no longer consults it — "
            f"drop it, or find out what replaced it.")
    for key in sorted(set(recorded) & set(derived)):
        if recorded[key].get("annotation") != derived[key]["annotation"]:
            problems.append(
                f"{key} resolves to annotation {derived[key]['annotation']!r} and is "
                f"recorded as {recorded[key].get('annotation')!r}.")

    flags = rendered_flags(pin)
    expected = record.get("controllerConfig") or {}
    for name, want in sorted(expected.get("args", {}).items()):
        got = flags["args"].get(name, want if name not in flags["args"] else "")
        if name in flags["args"] and got != want:
            problems.append(
                f"the chart renders --{name}={got!r} and the policy is written for "
                f"{want!r}.")
    if flags["serviceMutatorWebhook"] != expected.get("serviceMutatorWebhook"):
        problems.append(
            f"the chart renders serviceMutatorWebhook="
            f"{flags['serviceMutatorWebhook']} and the record says "
            f"{expected.get('serviceMutatorWebhook')}. Which Services carry a "
            f"loadBalancerClass depends on it.")

    if problems:
        print(f"FAIL  {len(problems)} problem(s) against the controller at {ref}:")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    {len(derived)} deciding symbol(s) at {ref} match the record, and the "
          f"rendered controller matches the configuration the policy is written for.")
    return 0


# ------------------------------------------------------------------------ sync


def sync(record: dict, pin: dict) -> int:
    ref = app_version(pin)
    derived = symbols(ref)
    prior = record.get("symbols") or {}

    undecided = []
    out: dict[str, dict] = {}
    for key, rec in sorted(derived.items()):
        was = prior.get(key) or {}
        entry = dict(rec)
        entry["status"] = was.get("status", "")
        if was.get("evidence"):
            entry["evidence"] = was["evidence"]
        if was.get("note"):
            entry["note"] = was["note"]
        if entry["status"] not in STATUSES:
            undecided.append(key)
        out[key] = entry
    if undecided:
        die(f"the controller at {ref} consults {len(undecided)} symbol(s) nothing has "
            f"decided about:\n  " + "\n  ".join(undecided) +
            f"\nAdd each to {RECORDS.relative_to(ROOT)} with a status of "
            f"{'/'.join(STATUSES)} and, unless it is read, the reason. A new deciding "
            f"input is a decision, not a record to regenerate.")

    flags = rendered_flags(pin)
    config = record.get("controllerConfig") or {}
    config["args"] = {k: flags["args"].get(k, v) for k, v in (config.get("args") or {}).items()}
    config["serviceMutatorWebhook"] = flags["serviceMutatorWebhook"]

    RECORDS.write_text(json.dumps({
        "_README": README,
        "controller": {**pin, "sourceRef": ref},
        "controllerConfig": config,
        "literals": record.get("literals") or {},
        "symbols": out,
    }, indent=2) + "\n")
    print(f"wrote {RECORDS.relative_to(ROOT)} ({len(out)} symbol(s) at {ref})")
    return 0


README = (
    "Every symbol the AWS Load Balancer Controller consults when it decides a load "
    "balancer's scheme, and when it decides whether a Service is its own, derived "
    "from the controller source at the version the chart pin installs. Each is READ "
    "by policies/kyverno/networking/base/inject-adopt-lb-subnets.yaml with a string "
    "the policy must contain, UNREAD with the reason the policy does not consult it, "
    "or PLUMBING with the reason it decides nothing. A symbol that is none of those "
    "fails --sync: a new deciding input is a decision somebody makes, not a record to "
    "regenerate. Re-derive with scripts/check-lb-scheme-inputs.py --sync."
)


# ------------------------------------------------------------------- self-test


def self_test() -> int:
    """Break each input the offline verdict rests on and confirm it is rejected."""
    import contextlib
    import copy
    import io

    record = load_records()
    pin = chart_pin()
    policy = policy_text()

    def run(r, p, t):
        with contextlib.redirect_stdout(io.StringIO()):
            return check_offline(r, p, t)

    key = sorted(k for k, v in (record.get("symbols") or {}).items()
                 if v.get("status") == "read")[0]
    unread = sorted(k for k, v in (record.get("symbols") or {}).items()
                    if v.get("status") != "read")[0]

    breaks = []

    r = copy.deepcopy(record)
    r["symbols"][key]["evidence"] = "an-annotation-the-policy-does-not-read"
    breaks.append(("an input recorded as read that the policy does not read", r, pin, policy))

    r = copy.deepcopy(record)
    r["symbols"][unread].pop("note", None)
    breaks.append(("an input nobody read and nobody excused", r, pin, policy))

    r = copy.deepcopy(record)
    r["symbols"][unread]["status"] = ""
    breaks.append(("an input with no decision recorded about it", r, pin, policy))

    r = copy.deepcopy(record)
    r["controller"]["chartVersion"] = "0.0.0-not-the-pin"
    breaks.append(("a record derived from a version nothing pins", r, pin, policy))

    r = copy.deepcopy(record)
    r["controller"]["sourceRef"] = ""
    breaks.append(("a record that does not say which source it read", r, pin, policy))

    r = copy.deepcopy(record)
    r["literals"] = {}
    breaks.append(("a policy whose literals are held equal to nothing", r, pin, policy))

    literal = sorted(record.get("literals") or {})[0]
    breaks.append((f"a policy that stopped naming {literal!r}",
                   record, pin, policy.replace(literal, "something-else")))

    failures = []
    for label, r, p, t in breaks:
        if run(r, p, t) == 0:
            failures.append(label)
            print(f"  ACCEPTED  {label}   <-- not caught")
        else:
            print(f"  rejected  {label}")

    if run(record, pin, policy) != 0:
        failures.append("the shipped policy does not pass")
        print("  ACCEPTED  (control) the shipped policy is rejected")
    else:
        print(f"  passed    (control) the shipped policy, "
              f"{len(record.get('symbols') or {})} symbol(s)")

    if failures:
        print(f"\nFAIL  {len(failures)} break(s) not caught.")
        return 1
    print(f"\nOK    all {len(breaks)} breaks rejected, and the shipped policy passes.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--live", action="store_true",
                    help="re-derive from the controller source and the rendered chart")
    ap.add_argument("--sync", action="store_true",
                    help="rewrite the record from the pinned controller (network)")
    ap.add_argument("--self-test", action="store_true",
                    help="break the offline gate's inputs and confirm each is caught")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.sync:
        return sync(load_records() if RECORDS.exists() else {}, chart_pin())
    if args.live:
        return check_live(load_records(), chart_pin())
    return check_offline(load_records(), chart_pin(), policy_text())


if __name__ == "__main__":
    sys.exit(main())
