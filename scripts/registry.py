"""The registry client every chart and OCI artifact a gate reads goes through.

Public registries rate-limit anonymous clients with HTTP 429 and say when to
come back in a Retry-After header. helm reports a 429 as a line of error text
with the header dropped, so a retry wrapped around helm could only guess at the
wait and would have to parse prose to tell a rate limit from a missing chart.
So a gate fetches each chart here and hands helm the local archive.

What http_get does with each answer:

  * HTTP 429 is retried within RETRY_ATTEMPTS requests, waiting as long as
    Retry-After asks. A Retry-After over RETRY_MAX_WAIT_SECONDS is reported
    without waiting.
  * HTTP 401, on a read that passes a challenge handler, is answered once: the
    handler turns the WWW-Authenticate header into a token and the request is
    repeated inside the same RETRY_ATTEMPTS. A second 401 is reported.
  * Every other status, and every network error, is reported on the attempt
    that produced it.

An archive is kept only once it hashes to the digest its registry publishes,
and is handed out of the cache only while it still hashes to the digest it was
kept with. A chart repository that publishes no digest for the pinned version
is refused rather than trusted.

Loaded by path, the way the gates load gatelib (see its docstring), under the
name `registry`. Each loading gate gets its own instance, so a gate catches the
exception classes of the instance it called — never another gate's. This module
loads gatelib in turn, for the exit status a chart that could not be fetched
earns.
"""

from __future__ import annotations

import datetime
import email.utils
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any, NoReturn

_gl = pathlib.Path(__file__).resolve().parent / "gatelib.py"
_gs = importlib.util.spec_from_file_location("gatelib", _gl)
assert _gs and _gs.loader, f"{_gl} is not loadable as a module"
gatelib = importlib.util.module_from_spec(_gs)
sys.modules["gatelib"] = gatelib
_gs.loader.exec_module(gatelib)

# A 429 is the registry rate-limiting this client, not an answer about what it
# holds, so it is the one status retried. RETRY_ATTEMPTS bounds the requests one
# http_get call makes to its URL, the repeat after a 401 challenge included; the
# token request that challenge leads to is a call of its own, under its own
# bound. The wait before a retry is the registry's Retry-After when it sends
# one, and RETRY_BASE_SECONDS doubling per retry when it does not, stretched by
# up to RETRY_JITTER of itself so jobs the registry throttled together do not
# come back together. A Retry-After over RETRY_MAX_WAIT_SECONDS is reported
# without waiting, naming the wait the registry asked for: a job sleeping past
# its own timeout reports nothing at all.
RETRY_ATTEMPTS = 4
RETRY_BASE_SECONDS = 5.0
RETRY_JITTER = 0.25
RETRY_MAX_WAIT_SECONDS = 120.0
HTTP_TIMEOUT = 60

# CDNs in front of chart hosts refuse urllib's default User-Agent
# (Python-urllib/<version>) with a 403, which this client reports rather than
# retries, so every request names the client instead.
USER_AGENT = "eks-gitops-gates"

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"
HELM_CHART_CONTENT = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

# Docker Hub serves the distribution API from a host other than the one its
# references name.
REGISTRY_API_HOSTS = {"docker.io": "registry-1.docker.io"}

# Where chart_archive keeps what it fetched. A published chart version is read
# as immutable — the assumption helm's own repository cache makes — so an
# archive already here is used without asking the registry again, and a CI job
# that restores this directory pulls only the charts its pins moved to.
CHART_CACHE = pathlib.Path.home() / ".cache" / "eks-gitops" / "charts"

_CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')

# What every registry read is handed: url, headers, Authorization, and an
# optional `challenge` keyword. http_get is the one implementation; tests pass a
# scripted one.
Getter = Callable[..., bytes]


class RegistryError(Exception):
    """A registry read that did not produce what was asked for, with the reason."""


class ChartUnavailable(Exception):
    """A chart pin that could not be read, and whether its source said why.

    `answered` is True only when the registry or chart repository replied and
    its reply rules the pin out: the chart or version is not there, or the index
    lists it with no archive to fetch or no digest to check one against. That is
    a finding about the pin, and asking again gets the same reply. Every other
    failure, a rate limit that outlasted the retries included, says nothing
    about this repository.
    """

    def __init__(self, message: str, *, answered: bool) -> None:
        super().__init__(message)
        self.answered = answered


def retry_after(value: str | None, now: float) -> float | None:
    """Seconds a Retry-After header asks for, or None when it states nothing usable.

    The header is either delta-seconds or an HTTP-date. Every HTTP-date is UTC,
    including the obsolete asctime form that carries no zone, so a date parsed
    without one is read as UTC. A date already past asks for no wait at all.
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
        when = when.replace(tzinfo=datetime.UTC)
    return max(0.0, when.timestamp() - now)


def http_get(url: str, headers: Mapping[str, str] | None = None,
             authorization: str | None = None, *,
             challenge: Callable[[str], str] | None = None,
             urlopen: Callable[..., Any] = urllib.request.urlopen,
             sleep: Callable[[float], None] = time.sleep,
             clock: Callable[[], float] = time.time,
             jitter: Callable[[], float] = random.random) -> bytes:
    """GET `url`, retrying HTTP 429 within RETRY_ATTEMPTS requests.

    `challenge`, when given, answers one HTTP 401: it receives the
    WWW-Authenticate header and returns the Authorization to repeat the request
    with, and the repeat counts toward the bound. A 401 on the last attempt
    leaves no request to repeat it with, and is reported. A second 401
    propagates, as do every other HTTPError and every URLError, from the
    request that raised it.
    """
    host = urllib.parse.urlsplit(url).netloc
    attempt = 0
    while True:
        attempt += 1
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   **dict(headers or {})})
        if authorization:
            # Unredirected: a blob read redirects to object storage, which
            # rejects a request carrying the registry's bearer token.
            req.add_unredirected_header("Authorization", authorization)
        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            if err.code == 401 and challenge is not None:
                answer, challenge = challenge, None
                asked_for = err.headers.get("WWW-Authenticate", "") if err.headers else ""
                err.close()
                if attempt == RETRY_ATTEMPTS:
                    raise RegistryError(
                        f"{host} asked for a token on the last of {RETRY_ATTEMPTS} "
                        f"attempts at {url}, leaving none to repeat it with"
                    ) from err
                authorization = answer(asked_for)
                continue
            if err.code != 429:
                raise
            asked = retry_after(err.headers.get("Retry-After") if err.headers else None,
                                clock())
            err.close()
            if attempt == RETRY_ATTEMPTS:
                raise RegistryError(
                    f"{host} answered HTTP 429 to all {RETRY_ATTEMPTS} attempts at {url}"
                ) from err
            if asked is not None and asked > RETRY_MAX_WAIT_SECONDS:
                raise RegistryError(
                    f"{host} answered HTTP 429 with Retry-After {asked:.0f}s, beyond the "
                    f"{RETRY_MAX_WAIT_SECONDS:.0f}s this client waits, at {url}"
                ) from err
            base = asked if asked is not None else RETRY_BASE_SECONDS * 2 ** (attempt - 1)
            wait = base * (1 + RETRY_JITTER * jitter())
            source = "Retry-After" if asked is not None else "backoff"
            print(f"  {host}: request {attempt} of {RETRY_ATTEMPTS} answered HTTP 429, "
                  f"retrying in {wait:.0f}s ({source})", file=sys.stderr)
            sleep(wait)


def anonymous_token(challenge: str, path: str, get: Getter = http_get) -> str:
    """A pull token for `path` from the realm a registry's Bearer challenge names.

    The scope and service are added to whatever query the realm already carries.
    """
    scheme, _, params = challenge.strip().partition(" ")
    if scheme.lower() != "bearer":
        raise RegistryError(f"the registry asked for {scheme or 'no'} authentication, "
                            f"and only an anonymous bearer token is supported")
    fields = dict(_CHALLENGE_PARAM.findall(params))
    realm = fields.get("realm")
    if not realm:
        raise RegistryError(f"the bearer challenge names no realm: {challenge!r}")
    parts = urllib.parse.urlsplit(realm)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append(("scope", f"repository:{path}:pull"))
    if fields.get("service"):
        query.append(("service", fields["service"]))
    url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    body = json.loads(get(url, {}, None))
    token = body.get("token") or body.get("access_token") if isinstance(body, dict) else None
    if not token:
        raise RegistryError(f"{realm} returned no token for repository:{path}:pull")
    return str(token)


class OciRepository:
    """Anonymous reads from one OCI repository, sharing one pull token.

    The first read goes out without a token; the registry's 401 challenge is
    answered once, and every later read carries the token it produced. A read
    refused while it carries that token is refused for a reason a second token
    would not change, so it is reported rather than answered again.
    """

    def __init__(self, ref: str, get: Getter = http_get) -> None:
        registry, _, self.path = ref.removeprefix("oci://").partition("/")
        self.base = f"https://{REGISTRY_API_HOSTS.get(registry, registry)}/v2/{self.path}"
        self.token: str | None = None
        self._get = get

    def read(self, suffix: str, accept: str | None = None) -> bytes:
        headers = {"Accept": accept} if accept else {}
        url = f"{self.base}/{suffix}"
        if self.token is None:
            return self._get(url, headers, None, challenge=self._authorize)
        return self._get(url, headers, f"Bearer {self.token}")

    def _authorize(self, www_authenticate: str) -> str:
        self.token = anonymous_token(www_authenticate, self.path, self._get)
        return f"Bearer {self.token}"

    def manifest(self, reference: str) -> dict:
        doc = json.loads(self.read(f"manifests/{reference}", OCI_MANIFEST))
        if not isinstance(doc, dict):
            raise RegistryError(f"{self.base}/manifests/{reference} is not a JSON object")
        return doc

    def blob(self, digest: str) -> bytes:
        """The blob at `digest`, refused unless its bytes hash to that digest.

        A digest that is not sha256 is refused before anything is read: there
        would be nothing to check the bytes against.
        """
        algorithm, _, expected = digest.partition(":")
        if algorithm != "sha256" or not expected:
            raise RegistryError(f"{self.base}: {digest!r} is not a sha256 digest, so a "
                                f"blob read by it could not be checked")
        data = self.read(f"blobs/{digest}")
        if hashlib.sha256(data).hexdigest() != expected:
            raise RegistryError(f"{self.base}: the blob does not match its digest {digest}")
        return data


def oci_chart_metadata(ref: str, version: str, get: Getter = http_get) -> dict:
    """The Chart.yaml metadata `helm push` stores as an OCI chart's config blob."""
    repo = OciRepository(ref, get)
    config = repo.manifest(version).get("config") or {}
    if config.get("mediaType") != HELM_CONFIG:
        raise RegistryError(f"{ref}:{version} is not a Helm chart: its config media "
                            f"type is {config.get('mediaType')!r}")
    meta = json.loads(repo.blob(str(config.get("digest", ""))))
    if not isinstance(meta, dict):
        raise RegistryError(f"{ref}:{version}: the config blob is not a JSON object")
    return meta


def oci_chart_content(ref: str, version: str, get: Getter = http_get) -> bytes:
    """The packaged chart `helm push` stores as an OCI chart's content layer."""
    repo = OciRepository(ref, get)
    manifest = repo.manifest(version)
    if (manifest.get("config") or {}).get("mediaType") != HELM_CONFIG:
        raise RegistryError(f"{ref}:{version} is not a Helm chart")
    for layer in manifest.get("layers") or []:
        if isinstance(layer, dict) and layer.get("mediaType") == HELM_CHART_CONTENT:
            return repo.blob(str(layer.get("digest", "")))
    raise RegistryError(f"{ref}:{version} carries no {HELM_CHART_CONTENT} layer")


# Parsed index.yaml per repository URL, so charts sharing a repository share one
# download within a run.
_INDEXES: dict[str, dict] = {}


def repo_index_entry(repo: str, chart: str, version: str,
                     get: Getter = http_get) -> dict:
    """The index.yaml entry an HTTPS chart repository publishes for chart@version.

    A 'v' prefix on either side matches its absence on the other: Helm accepts
    both spellings of a version, and the index and the pin need not agree.
    """
    import yaml

    index = _INDEXES.get(repo)
    if index is None:
        raw = get(f"{repo.rstrip('/')}/index.yaml", {}, None)
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        try:
            index = yaml.load(raw, Loader=loader) or {}
        except yaml.YAMLError as exc:
            raise RegistryError(f"{repo}/index.yaml is not YAML: {exc}") from exc
        if not isinstance(index, dict):
            raise RegistryError(f"{repo}/index.yaml is not a mapping")
        _INDEXES[repo] = index
    bare = version.removeprefix("v")
    for entry in (index.get("entries") or {}).get(chart) or []:
        listed = str((entry or {}).get("version", ""))
        if listed == version or listed.removeprefix("v") == bare:
            return entry
    raise ChartUnavailable(f"{repo.rstrip('/')}/index.yaml lists no {chart} {version}",
                           answered=True)


def _unavailable(err: BaseException) -> ChartUnavailable:
    if isinstance(err, urllib.error.HTTPError):
        return ChartUnavailable(f"HTTP {err.code} from {err.url}", answered=err.code == 404)
    return ChartUnavailable(f"{type(err).__name__}: {err}", answered=False)


# Every way a registry read fails without the registry answering about the pin.
# OSError covers URLError, HTTPError, timeouts and a dropped connection;
# HTTPException a response cut off mid-body; ValueError a body that is not the
# JSON the API promises. A gate reading through OciRepository directly catches
# this tuple, so it classifies a failure the way chart_archive does.
READ_FAILURES = (OSError, http.client.HTTPException, RegistryError, ValueError)


def chart_metadata(source: str, chart: str, version: str,
                   get: Getter = http_get) -> dict:
    """What chart@version says it is, read from the registry without a cache.

    `source` is an oci:// chart reference or an HTTPS chart repository. For the
    first that is the config blob; for the second, the index entry, which
    carries the chart's Chart.yaml fields.
    """
    try:
        if source.startswith("oci://"):
            return oci_chart_metadata(source, version, get)
        entry = repo_index_entry(source, chart, version, get)
        return {k: v for k, v in entry.items() if k not in ("urls", "digest", "created")}
    except READ_FAILURES as err:
        raise _unavailable(err) from err


def archive_path(source: str, chart: str, version: str,
                 cache: pathlib.Path | None = None) -> pathlib.Path:
    """Where chart_archive keeps chart@version from `source`."""
    parts = urllib.parse.urlsplit(source)
    where = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{parts.netloc}{parts.path}").strip("_")
    return (CHART_CACHE if cache is None else cache) / where / f"{chart}-{version}.tgz"


def digest_path(archive: pathlib.Path) -> pathlib.Path:
    """Where chart_archive records the sha256 `archive` was verified to hash to."""
    return archive.with_name(f"{archive.name}.sha256")


def prune_archives(keep: set[pathlib.Path], cache: pathlib.Path | None = None) -> int:
    """Delete every cached file but the archives in `keep` and their digest records.

    Returns how many files went. A cache carried from one pin set to the next
    would otherwise hold every version ever pinned, and the partial a fetch
    leaves when it is cut off between its write and its rename would stay
    beside them.
    """
    root = CHART_CACHE if cache is None else cache
    if not root.is_dir():
        return 0
    kept = {p.resolve() for p in keep} | {digest_path(p).resolve() for p in keep}
    dropped = 0
    for path in sorted(p for p in root.glob("*/*") if p.is_file()):
        if path.resolve() not in kept:
            path.unlink()
            dropped += 1
    for folder in sorted(root.iterdir()):
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    return dropped


def _intact(archive: pathlib.Path) -> bool:
    """True when `archive` still hashes to the digest recorded when it was kept.

    The record lives in the same cache as the archive, so this catches an
    archive that changed after it was verified — a truncated restore, a write
    cut off — and not one rewritten by whoever could rewrite the record too.
    """
    try:
        recorded = digest_path(archive).read_text().strip()
        data = archive.read_bytes()
    except OSError:
        return False
    return hashlib.sha256(data).hexdigest() == recorded


def _keep(archive: pathlib.Path, data: bytes) -> None:
    """Write `data` to `archive`, then its digest record, each by one rename.

    The record goes second, so an archive cut off before its record lands is
    one _intact refuses rather than one it vouches for.
    """
    archive.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest().encode()
    for target, content in ((archive, data), (digest_path(archive), digest)):
        partial = target.with_name(f".{target.name}.{os.getpid()}")
        partial.write_bytes(content)
        os.replace(partial, target)


def _https_archive(repo: str, chart: str, version: str, get: Getter) -> bytes:
    """chart@version's archive from an HTTPS repository, checked against its index."""
    entry = repo_index_entry(repo, chart, version, get)
    index = f"{repo.rstrip('/')}/index.yaml"
    urls = entry.get("urls") or []
    if not urls:
        raise ChartUnavailable(f"{index} names no archive for {chart} {version}",
                               answered=True)
    digest = str(entry.get("digest") or "")
    if not digest:
        raise ChartUnavailable(f"{index} publishes no digest for {chart} {version}, so "
                               f"its archive could not be checked", answered=True)
    data = get(urllib.parse.urljoin(repo.rstrip("/") + "/", str(urls[0])), {}, None)
    if hashlib.sha256(data).hexdigest() != digest:
        raise RegistryError(f"{chart} {version} from {repo} does not match the digest "
                            f"its index publishes")
    return data


def chart_archive(source: str, chart: str, version: str, *,
                  cache: pathlib.Path | None = None, get: Getter = http_get) -> pathlib.Path:
    """A local archive of chart@version, fetched once into the chart cache.

    `source` is an oci:// chart reference — ArgoCD's repoURL with the chart name
    appended when it does not already end in it — or an HTTPS chart repository.
    An archive is kept only once it hashes to the digest its registry publishes,
    and that digest is recorded beside it. A cached archive that no longer
    hashes to its record, or carries none, is fetched again. Raises
    ChartUnavailable.
    """
    path = archive_path(source, chart, version, cache)
    if _intact(path):
        return path
    if path.exists():
        print(f"  {path}: cached, and not the bytes that were verified when it was "
              f"kept; fetching it again", file=sys.stderr)
    try:
        if source.startswith("oci://"):
            data = oci_chart_content(source, version, get)
        else:
            data = _https_archive(source, chart, version, get)
    except READ_FAILURES as err:
        raise _unavailable(err) from err
    _keep(path, data)
    return path


def chart_archive_or_exit(source: str, chart: str, version: str) -> pathlib.Path:
    """chart_archive, or exit with the status the failure earns.

    1 when the registry answered and its answer rules the pin out — a pin that
    does not resolve to an archive this client can verify is a finding about
    this repository. CANNOT_RUN for every other failure, which says nothing
    about it.
    """
    try:
        return chart_archive(source, chart, version)
    except ChartUnavailable as exc:
        _refuse_chart(chart, version, source, exc)


def _refuse_chart(chart: str, version: str, source: str,
                  exc: ChartUnavailable) -> NoReturn:
    if exc.answered:
        print(f"{chart} {version}: {source} answered, and its answer rules the pin out "
              f"— {exc}")
        print("A pin that does not resolve to an archive this client can verify is a "
              "finding about this repo.")
        sys.exit(1)
    print(f"Cannot run: {chart} {version} could not be fetched from {source} — {exc}")
    print("Nothing was rendered from it, which is not the same as nothing being wrong.")
    print("An unreachable registry is a fact about the network, not about the catalogue.")
    sys.exit(gatelib.CANNOT_RUN)
