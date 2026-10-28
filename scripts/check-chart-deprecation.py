#!/usr/bin/env python3
"""Every chart this catalog pins is still the chart it was pinned for.

    python3 scripts/check-chart-deprecation.py            # blocking gate, offline
    python3 scripts/check-chart-deprecation.py --live     # scheduled, hits the registries
    python3 scripts/check-chart-deprecation.py --sync     # rewrite the records from upstream
    python3 scripts/check-chart-deprecation.py --self-test

Two different questions, and only one of them is a function of this commit.

A chart can be deprecated, handed to a different maintainer, or re-scoped to a
different product at any moment, with no change here. Asking that at merge time
would turn an unrelated pull request red because someone upstream pushed
overnight — the same reason mirror-check asks "has upstream moved?" on a
schedule rather than in the gate. So the work splits:

  default (offline, BLOCKING) — every pinned chart has a provenance record and
      every record names a chart still pinned. A function of the tree, so the
      verdict cannot change without a commit.

  --live (network, SCHEDULED) — fetch each pinned chart and compare it against
      its record: a `deprecated: true`, or a description that no longer matches.

The description comparison is the part that earns its keep. `deprecated: true`
is easy and loud. The failure that prompted this was quiet: the OSS Loki chart
moved to grafana-community, and the chart still published at the original
repository was re-scoped to Grafana Enterprise Logs. No deprecation flag was
ever set on it. The pin resolved, the chart installed, CI stayed green, and
Renovate kept offering patches — a currency signal reporting "current" for a
chart that had changed product underneath it. The description was the only
field that moved.

HOW A PIN IS READ

An HTTPS pin is read with `helm show chart`. An OCI pin is read over the OCI
distribution API directly: the manifest, then the config blob `helm push`
writes, which is the chart's Chart.yaml metadata as JSON. Public OCI registries
rate-limit anonymous clients with HTTP 429 and say when to come back in a
Retry-After header. helm reports a 429 as a line of error text with the header
dropped, so a retry wrapped around helm could only guess at the wait and would
have to parse prose to tell a rate limit from a missing chart. Reading the
registry here, a 429 is retried a bounded number of times, waiting as long as
Retry-After asks; every other status, and every network error, is reported on
the first attempt. An HTTPS repository that answers 429 is reported like any
other failure, without a retry.
"""

from __future__ import annotations

import email.utils
import hashlib
import http.client
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping

import yaml

# Shared precondition helper, loaded by path: these are hyphenated executables
# run from varying working directories.
_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)


ROOT = pathlib.Path(__file__).resolve().parent.parent
APPSETS = ROOT / "applicationsets"
# Beside the checker, not beside the pins. `applicationsets/` is scanned by
# kubeconform, which reads every file in it as a manifest and rejects one with
# no `kind` — the record would have had to be exempted from a schema gate to
# live next to what it describes, and weakening a gate to make room for a new
# file is the wrong trade.
RECORDS = ROOT / "scripts" / "chart-provenance.json"


def die(msg: str) -> None:
    print(f"chart-provenance: {msg}", file=sys.stderr)
    sys.exit(1)


def walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk(v)


def pins() -> dict[str, dict]:
    """{chart: {repo, version, source}} for every literal helm pin in the catalog.

    Two shapes carry one: an ApplicationSet source (`repoURL` + `chart` +
    `targetRevision`) and a list-generator element (`chartRepo` + `chart` +
    `chartVersion`). Templated pins are skipped — their value is not in the tree.
    """
    found: dict[str, dict] = {}
    for path in sorted(APPSETS.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            for node in walk(doc or {}):
                chart = node.get("chart")
                version = node.get("chartVersion") or node.get("targetRevision")
                repo = node.get("repoURL") or node.get("chartRepo")
                if not (isinstance(chart, str) and isinstance(version, str) and isinstance(repo, str)):
                    continue
                if "{{" in chart or "{{" in version or "{{" in repo:
                    continue
                if not repo.startswith(("http://", "https://", "oci://")):
                    continue
                prior = found.get(chart)
                if prior and (prior["repo"], prior["version"]) != (repo, version):
                    die(
                        f"{chart} is pinned twice and they disagree: "
                        f"{prior['version']} from {prior['repo']} ({prior['source']}) "
                        f"vs {version} from {repo} ({path.name})"
                    )
                found[chart] = {"repo": repo, "version": version, "source": path.name}
    if not found:
        die("read no chart pins out of applicationsets/ — the parser and the catalog disagree")
    return found


def load_records() -> dict:
    if not RECORDS.exists():
        die(f"{RECORDS.relative_to(ROOT)} does not exist. Run --sync to create it.")
    return json.loads(RECORDS.read_text()).get("charts", {})


def fetch(chart: str, repo: str, version: str) -> dict:
    """Chart.yaml as upstream currently publishes it, or {"_error": why not}."""
    if repo.startswith("oci://"):
        try:
            return oci_chart_metadata(repo, version)
        except urllib.error.HTTPError as err:
            return {"_error": f"HTTP {err.code} from {err.url}"}
        # OSError covers URLError, timeouts and a dropped connection;
        # HTTPException a response cut off mid-body; ValueError a body that is
        # not the JSON the API promises.
        except (OSError, http.client.HTTPException, RegistryError, ValueError,
                KeyError) as err:
            return {"_error": f"{type(err).__name__}: {err}"[:200]}
    cmd = ["helm", "show", "chart", "--repo", repo, chart, "--version", version]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        return {"_error": (out.stderr or out.stdout).strip().splitlines()[-1][:200]}
    return yaml.safe_load(out.stdout) or {}


# ------------------------------------------------------------ registry reads

# A 429 is the registry rate-limiting this client, not an answer about the
# chart, so it is the one status retried. RETRY_ATTEMPTS bounds the requests
# per URL. The wait before each retry is the registry's Retry-After when it
# sends one, and RETRY_BASE_SECONDS doubling per attempt when it does not. A
# Retry-After beyond RETRY_MAX_WAIT_SECONDS is reported rather than waited out,
# with the wait the registry asked for: a scheduled job sleeping past its own
# timeout reports nothing at all.
RETRY_ATTEMPTS = 4
RETRY_BASE_SECONDS = 5.0
RETRY_MAX_WAIT_SECONDS = 120.0
HTTP_TIMEOUT = 60

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"

# Docker Hub serves the distribution API from a host other than the one its
# references name.
REGISTRY_API_HOSTS = {"docker.io": "registry-1.docker.io"}

_CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')

Getter = Callable[[str, Mapping[str, str], "str | None"], bytes]


class RegistryError(Exception):
    """A registry read that did not produce chart metadata, with the reason."""


def retry_after(value: str | None, now: float) -> float | None:
    """Seconds a Retry-After header asks for, or None when it states nothing usable.

    The header is either delta-seconds or an HTTP-date. A date already past asks
    for no wait at all.
    """
    if value is None:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, when.timestamp() - now)


def http_get(url: str, headers: Mapping[str, str], authorization: str | None, *,
             urlopen=urllib.request.urlopen, sleep=time.sleep,
             clock=time.time) -> bytes:
    """GET url, retrying HTTP 429 as the module constants bound it.

    Every other HTTPError, and every URLError, propagates from the attempt that
    raised it.
    """
    host = urllib.parse.urlsplit(url).netloc
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        req = urllib.request.Request(url, headers=dict(headers))
        if authorization:
            # Unredirected: a blob read redirects to object storage, which
            # rejects a request carrying the registry's bearer token.
            req.add_unredirected_header("Authorization", authorization)
        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            if err.code != 429:
                raise
            asked = retry_after(err.headers.get("Retry-After") if err.headers else None,
                                clock())
            if attempt == RETRY_ATTEMPTS:
                raise RegistryError(
                    f"{host} answered HTTP 429 to all {RETRY_ATTEMPTS} attempts at {url}"
                ) from err
            wait = asked if asked is not None else RETRY_BASE_SECONDS * 2 ** (attempt - 1)
            if wait > RETRY_MAX_WAIT_SECONDS:
                raise RegistryError(
                    f"{host} answered HTTP 429 with Retry-After {wait:.0f}s, beyond the "
                    f"{RETRY_MAX_WAIT_SECONDS:.0f}s this check waits, at {url}"
                ) from err
            source = "Retry-After" if asked is not None else "backoff"
            print(f"  {host}: HTTP 429, retry {attempt}/{RETRY_ATTEMPTS - 1} in "
                  f"{wait:.0f}s ({source})", file=sys.stderr)
            sleep(wait)
    raise AssertionError("unreachable: the last attempt returns or raises")


def anonymous_token(challenge: str, path: str, get: Getter) -> str:
    """A pull token from the realm a registry's Bearer challenge names."""
    scheme, _, params = challenge.partition(" ")
    if scheme.lower() != "bearer":
        raise RegistryError(f"the registry asked for {scheme or 'no'} authentication, "
                            f"and only an anonymous bearer token is supported")
    fields = dict(_CHALLENGE_PARAM.findall(params))
    realm = fields.get("realm")
    if not realm:
        raise RegistryError(f"the bearer challenge names no realm: {challenge!r}")
    query = {"scope": f"repository:{path}:pull"}
    if fields.get("service"):
        query["service"] = fields["service"]
    body = json.loads(get(f"{realm}?{urllib.parse.urlencode(query)}", {}, None))
    token = body.get("token") or body.get("access_token")
    if not token:
        raise RegistryError(f"{realm} returned no token for repository:{path}:pull")
    return str(token)


def oci_chart_metadata(repo: str, version: str, get: Getter = http_get) -> dict:
    """The Chart.yaml metadata `helm push` stores as an OCI chart's config blob."""
    registry, _, path = repo[len("oci://"):].partition("/")
    base = f"https://{REGISTRY_API_HOSTS.get(registry, registry)}/v2/{path}"
    token: str | None = None

    def read(url: str, accept: str | None = None) -> bytes:
        nonlocal token
        headers = {"Accept": accept} if accept else {}
        try:
            return get(url, headers, f"Bearer {token}" if token else None)
        except urllib.error.HTTPError as err:
            if err.code != 401 or token is not None:
                raise
            challenge = err.headers.get("WWW-Authenticate", "") if err.headers else ""
            token = anonymous_token(challenge, path, get)
            return get(url, headers, f"Bearer {token}")

    manifest = json.loads(read(f"{base}/manifests/{version}", OCI_MANIFEST))
    config = manifest.get("config") or {}
    if config.get("mediaType") != HELM_CONFIG:
        raise RegistryError(f"{repo}:{version} is not a Helm chart: its config media "
                            f"type is {config.get('mediaType')!r}")
    digest = str(config.get("digest", ""))
    blob = read(f"{base}/blobs/{digest}")
    algorithm, _, expected = digest.partition(":")
    if algorithm != "sha256" or hashlib.sha256(blob).hexdigest() != expected:
        raise RegistryError(f"{repo}:{version}: the config blob does not match its "
                            f"digest {digest}")
    meta = json.loads(blob)
    if not isinstance(meta, dict):
        raise RegistryError(f"{repo}:{version}: the config blob is not a JSON object")
    return meta


# ---------------------------------------------------------------- offline gate

def check_offline(live: dict, recorded: dict) -> int:
    problems = []

    for chart, pin in sorted(live.items()):
        rec = recorded.get(chart)
        if rec is None:
            problems.append(
                f"{chart} is pinned ({pin['version']}, {pin['source']}) with no provenance record. "
                f"Nothing would notice if that chart were deprecated or re-scoped. Run --sync."
            )
            continue
        if rec.get("repo") != pin["repo"]:
            problems.append(
                f"{chart} is pinned from {pin['repo']} but recorded against {rec.get('repo')}. "
                f"A repository change is a change of maintainer — re-record it deliberately."
            )
        if not rec.get("description"):
            problems.append(f"{chart} has a provenance record with no description to compare against.")
        if rec.get("deprecated") is True:
            problems.append(
                f"{chart} is recorded as deprecated upstream and is still pinned. "
                f"Either migrate it or record why it stays."
            )

    for chart in sorted(set(recorded) - set(live)):
        problems.append(f"{chart} has a provenance record but is no longer pinned — drop the record.")

    if problems:
        print(f"FAIL  {len(problems)} problem(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    {len(live)} chart pin(s), each with a provenance record, none recorded deprecated.")
    return 0


# ------------------------------------------------------------------ live check

def check_live() -> int:
    live = pins()
    recorded = load_records()
    problems, ok = [], 0

    for chart, pin in sorted(live.items()):
        meta = fetch(chart, pin["repo"], pin["version"])
        if "_error" in meta:
            problems.append(f"{chart}: could not read upstream metadata — {meta['_error']}")
            continue
        rec = recorded.get(chart, {})
        if meta.get("deprecated") is True:
            problems.append(
                f"{chart} {pin['version']} is marked deprecated by upstream ({pin['repo']})."
            )
        desc = (meta.get("description") or "").strip()
        was = (rec.get("description") or "").strip()
        if was and desc != was:
            problems.append(
                f"{chart} changed what it says it is.\n"
                f"            recorded: {was}\n"
                f"            upstream: {desc}\n"
                f"          A chart that redescribes itself may have changed product or maintainer. "
                f"Read the upstream notes, then --sync if it is still the chart you want."
            )
        if not problems or problems[-1].split()[0] != chart:
            ok += 1

    if problems:
        print(f"FAIL  {len(problems)} problem(s) across {len(live)} pinned chart(s):")
        for p in problems:
            print(f"        {p}")
        return 1
    print(f"OK    all {len(live)} pinned chart(s) match their record and none is deprecated.")
    return 0


# ------------------------------------------------------------------------ sync

def sync() -> int:
    live = pins()
    charts = {}
    for chart, pin in sorted(live.items()):
        meta = fetch(chart, pin["repo"], pin["version"])
        if "_error" in meta:
            die(f"{chart}: {meta['_error']}")
        charts[chart] = {
            "repo": pin["repo"],
            "description": (meta.get("description") or "").strip(),
            "deprecated": bool(meta.get("deprecated", False)),
        }
        print(f"  recorded {chart:32} {pin['version']:12} deprecated={charts[chart]['deprecated']}")
    RECORDS.write_text(
        json.dumps(
            {
                "_README": (
                    "What each pinned chart says it is, recorded so that a change is visible. "
                    "check-chart-deprecation.py compares upstream against this on a schedule; the "
                    "blocking gate only checks that every pin has a record and every record a pin. "
                    "A description change means the chart redescribed itself — read the upstream "
                    "notes before running --sync, because that is the signal a chart has changed "
                    "product or maintainer without ever setting a deprecated flag."
                ),
                "charts": charts,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nwrote {RECORDS.relative_to(ROOT)} ({len(charts)} charts)")
    return 0


# ------------------------------------------------------------------- self-test

def self_test() -> int:
    """Break the offline gate's inputs and confirm each break is rejected."""
    import contextlib
    import io

    real_pins = pins()
    real_records = load_records()

    def run(p, r):
        with contextlib.redirect_stdout(io.StringIO()):
            return check_offline(p, r)

    breaks = []
    # a pinned chart with no record
    p = dict(real_pins)
    p["ghost-chart"] = {"repo": "https://example.invalid", "version": "1.0.0", "source": "x.yaml"}
    breaks.append(("a pinned chart with no provenance record", p, real_records))
    # a record for a chart nobody pins
    r = dict(real_records)
    r["retired-chart"] = {"repo": "https://example.invalid", "description": "x", "deprecated": False}
    breaks.append(("a record for a chart no longer pinned", real_pins, r))
    # the recorded repo disagrees with the pin
    name = sorted(real_pins)[0]
    r2 = json.loads(json.dumps(real_records))
    r2[name]["repo"] = "https://somewhere.else.invalid"
    breaks.append(("the recorded repository differs from the pin", real_pins, r2))
    # a record marked deprecated but still pinned
    r3 = json.loads(json.dumps(real_records))
    r3[name]["deprecated"] = True
    breaks.append(("a chart recorded deprecated but still pinned", real_pins, r3))
    # a record with no description to compare
    r4 = json.loads(json.dumps(real_records))
    r4[name]["description"] = ""
    breaks.append(("a record with no description", real_pins, r4))

    failures = []
    for label, p, r in breaks:
        if run(p, r) == 0:
            failures.append(label)
            print(f"  ACCEPTED  {label}   <-- not caught")
        else:
            print(f"  rejected  {label}")

    if run(real_pins, real_records) != 0:
        failures.append("the real catalog does not pass")
        print("  ACCEPTED  (control) the shipped catalog is rejected")
    else:
        print("  passed    (control) the shipped catalog")

    if failures:
        print(f"\nFAIL  {len(failures)} break(s) not caught.")
        return 1
    print(f"\nOK    all {len(breaks)} breaks rejected, and the shipped catalog passes.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    if "--sync" in sys.argv:
        gatelib.require("helm")     # --sync resolves every chart upstream
        return sync()
    if "--live" in sys.argv:
        gatelib.require("helm")     # --live fetches each pinned chart
        return check_live()
    return check_offline(pins(), load_records())


if __name__ == "__main__":
    sys.exit(main())
