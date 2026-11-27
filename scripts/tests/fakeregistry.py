"""A registry served at the urlopen level, for tests of scripts/registry.py and
of the gates that read charts through it.

What a registry serves is stated here rather than read from the client under
test: the media types are the ones the OCI and Helm specifications name, so a
client that drifted from them fails against this fake instead of agreeing with
itself. A 200 is the http.client.HTTPResponse urlopen hands back, parsed from
the bytes a server would send, so the client reads a body, Content-Length or
chunked, through the same code it reads one through in CI.

A gate is run whole against these with serve(): the real client, its real
cache under a test's own directory, and every request routed to a fake by URL.
The charts they serve are real archives (chart_archive()), so the gate renders
them with the real helm.
"""

from __future__ import annotations

import email.message
import functools
import gzip
import hashlib
import http.client
import io
import json
import pathlib
import tarfile
import unittest
import urllib.error
from collections.abc import Callable
from types import ModuleType
from unittest import mock

import yaml

NOW = 1_800_000_000.0

HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"
HELM_CHART_CONTENT = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"


def http_error(
    url: str, code: int, headers: dict[str, str] | None = None, body: bytes = b""
) -> urllib.error.HTTPError:
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(url, code, f"status {code}", msg, io.BytesIO(body))


def auth(req) -> str | None:
    return req.unredirected_hdrs.get("Authorization")


class Wire(io.RawIOBase):
    """What a server sends on one connection, one segment per read of the socket.

    A read takes at most the next segment and charges `charge` the seconds that
    segment was scripted to take. A server that keeps sending inside every
    socket timeout is a run of segments each charged just under it.
    """

    def __init__(
        self, segments: list[tuple[bytes, float]], charge: Callable[[float], None] | None = None
    ) -> None:
        super().__init__()
        self.segments = list(segments)
        self.charge = charge

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        if not self.segments:
            return 0
        data, seconds = self.segments.pop(0)
        n = min(len(buffer), len(data))
        buffer[:n] = data[:n]
        if n < len(data):
            self.segments.insert(0, (data[n:], 0.0))
        if self.charge:
            self.charge(seconds)
        return n

    def unsent(self) -> int:
        """Bytes the server had still to send."""
        return sum(len(data) for data, _ in self.segments)


class _Socket:
    """The one call http.client.HTTPResponse makes on its socket."""

    def __init__(self, wire: Wire) -> None:
        self.wire = wire

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(self.wire)


class Served(http.client.HTTPResponse):
    """A 200 as urlopen returns it, with the wire it is read from."""

    wire: Wire


def served(
    body: bytes,
    *,
    piece: int | None = None,
    seconds: float = 0.0,
    chunked: bool = False,
    length: int | None = None,
    charge: Callable[[float], None] | None = None,
) -> Served:
    """A 200 carrying `body`, its status line and headers already read.

    The status line and headers arrive on one read of the socket, and what
    follows them `piece` bytes per read, each read charged `seconds`. `chunked`
    sends the body in chunks of `piece`, framing and all; otherwise a
    Content-Length of `length`, the body's own by default, says how much is
    coming.
    """
    piece = piece or max(len(body), 1)
    if chunked:
        framing = "Transfer-Encoding: chunked"
        chunks = [body[i : i + piece] for i in range(0, len(body), piece)]
        payload = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in chunks) + b"0\r\n\r\n"
    else:
        framing = f"Content-Length: {len(body) if length is None else length}"
        payload = body
    head = f"HTTP/1.1 200 OK\r\n{framing}\r\n\r\n".encode()
    wire = Wire(
        [(head, 0.0)] + [(payload[i : i + piece], seconds) for i in range(0, len(payload), piece)],
        charge,
    )
    resp = Served(_Socket(wire), method="GET")  # type: ignore[arg-type]
    resp.wire = wire
    resp.begin()
    return resp


class Transport:
    """An urlopen stand-in that answers each request with the next scripted step.

    A step is bytes (a 200 carrying them), a response (returned as it is), an
    exception (raised), or a callable taking the request and returning any of
    those — which is how a registry whose answer depends on the Authorization
    header is written.

    `elapsed` is the time the client has spent on this transport, on the timer
    http_get's deadline reads. Every request is charged the whole timeout the
    client gave it, as one that never answers is, every wait the time it asked
    to sleep, and every read of a trickled body the seconds it was scripted to
    take, so a deadline the client keeps is one it keeps in the worst case.
    A `latency` charges each request that many seconds instead, which is how a
    registry answering faster than the spacing it holds a client to is written.

    `sent_at` is the `elapsed` reading each request went out at, and `sent` is
    the record of the last request to each host that http_get spaces requests
    by, one per transport so no test inherits another's.
    """

    def __init__(self, *steps):
        self.steps = list(steps)
        self.requests: list = []
        self.timeouts: list[float] = []
        self.waits: list[float] = []
        self.responses: list[Served] = []
        self.elapsed = 0.0
        self.latency: float | None = None
        self.sent_at: list[float] = []
        self.sent: dict[str, float] = {}
        self.on_sleep = None

    def urlopen(self, req, timeout=None):
        self.requests.append(req)
        self.timeouts.append(timeout)
        self.sent_at.append(self.elapsed)
        self.elapsed += (timeout or 0.0) if self.latency is None else self.latency
        step = self.steps.pop(0)
        if callable(step) and not isinstance(step, BaseException):
            step = step(req)
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, bytes):
            step = served(step)
        self.responses.append(step)
        return step

    def sleep(self, seconds: float) -> None:
        if self.on_sleep:
            self.on_sleep()
        self.waits.append(seconds)
        self.elapsed += seconds

    def charge(self, seconds: float) -> None:
        self.elapsed += seconds

    def trickle(self, body: bytes, *, piece: int, seconds: float, chunked: bool = False):
        """A step serving `body` `piece` bytes per read of the socket, each read
        charged `seconds` on this transport's timer."""
        return lambda _req: served(
            body, piece=piece, seconds=seconds, chunked=chunked, charge=self.charge
        )

    def bind(self, http_get, jitter: float = 0.0):
        """`http_get` over this transport, with a fixed wall clock, the transport's
        own timer, its own record of the last request to each host and a fixed
        jitter draw."""
        return functools.partial(
            http_get,
            urlopen=self.urlopen,
            sleep=self.sleep,
            clock=lambda: NOW,
            timer=lambda: self.elapsed,
            jitter=lambda: jitter,
            last_sent=self.sent,
        )

    def urls(self) -> list[str]:
        return [r.full_url for r in self.requests]


class OciRegistry:
    """One chart in one OCI repository, served only to a bearer token it issued.

    The token realm is on a host of its own unless `realm` names another, as
    ECR Public's is on the registry's own host.
    """

    TOKEN = "t0k"
    REALM = "https://auth.example/token"
    CHALLENGE = f'Bearer realm="{REALM}",service="registry.example",scope="aws"'
    transport_class = Transport

    def __init__(
        self,
        host,
        path,
        version,
        config,
        *,
        content=b"chart-tgz",
        media_type=None,
        digest=None,
        realm=None,
    ):
        self.base = f"https://{host}/v2/{path}"
        self.version = version
        self.blob = json.dumps(config).encode()
        self.digest = digest or "sha256:" + hashlib.sha256(self.blob).hexdigest()
        self.content = content
        self.content_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.media_type = media_type or HELM_CONFIG
        self.realm = realm or self.REALM
        self.challenge = self.CHALLENGE.replace(self.REALM, self.realm)

    def __call__(self, req):
        url = req.full_url
        if url.startswith(f"{self.realm}?"):
            return json.dumps({"token": self.TOKEN}).encode()
        if auth(req) != f"Bearer {self.TOKEN}":
            return http_error(url, 401, {"WWW-Authenticate": self.challenge})
        if url == f"{self.base}/manifests/{self.version}":
            return json.dumps(
                {
                    "config": {"mediaType": self.media_type, "digest": self.digest},
                    "layers": [{"mediaType": HELM_CHART_CONTENT, "digest": self.content_digest}],
                }
            ).encode()
        if url == f"{self.base}/blobs/{self.digest}":
            return self.blob
        if url == f"{self.base}/blobs/{self.content_digest}":
            return self.content
        return http_error(url, 404)

    def transport(self, *overrides):
        """A transport answering from this registry, with scripted steps first."""
        return self.transport_class(*overrides, *([self] * 20))


def chart_archive(
    name: str,
    version: str,
    templates: dict[str, str],
    *,
    values: str = "",
    crds: dict[str, str] | None = None,
) -> bytes:
    """An archive `helm template` renders, laid out as `helm package` writes one.

    `name/` holds Chart.yaml, values.yaml, each of `templates` under templates/
    and each of `crds` under crds/. Modes and times are fixed, so the same files
    give the same bytes, and so the digest an index publishes for them.
    """
    files = {
        "Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: {version}\n",
        "values.yaml": values,
        **{f"templates/{path}": text for path, text in templates.items()},
        **{f"crds/{path}": text for path, text in (crds or {}).items()},
    }
    raw = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):
        for path, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"{name}/{path}")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


class ChartRepository:
    """An HTTPS chart repository: an index.yaml listing each archive with the
    digest Helm's index carries for it, and each archive at the URL it names.

    `answer`, when set, answers every request in its place, which is how a
    repository that is down or refusing is written.
    """

    def __init__(self, base: str, charts: dict[tuple[str, str], bytes]) -> None:
        self.base = base.rstrip("/")
        self.charts = dict(charts)
        self.answer: Callable | None = None

    def index(self) -> bytes:
        entries: dict[str, list[dict]] = {}
        for (name, version), data in sorted(self.charts.items()):
            entries.setdefault(name, []).append(
                {
                    "version": version,
                    "urls": [f"{name}-{version}.tgz"],
                    "digest": hashlib.sha256(data).hexdigest(),
                }
            )
        return yaml.safe_dump({"apiVersion": "v1", "entries": entries}).encode()

    def __call__(self, req):
        url = req.full_url
        if self.answer is not None:
            return self.answer(req)
        if url == f"{self.base}/index.yaml":
            return self.index()
        for (name, version), data in self.charts.items():
            if url == f"{self.base}/{name}-{version}.tgz":
                return data
        return http_error(url, 404)


class Hosts:
    """urlopen for registry.http_get over several fakes, each serving the URLs
    under its prefix, with every URL asked for and every wait recorded.

    A URL no fake serves raises AssertionError, which no registry read handles,
    so a request the test did not expect fails it rather than reading as a
    registry's answer.
    """

    def __init__(self, routes: dict[str, Callable]) -> None:
        self.routes = routes
        self.urls: list[str] = []
        self.waits: list[float] = []

    def urlopen(self, req, timeout=None):
        url = req.full_url
        self.urls.append(url)
        server = next((s for prefix, s in self.routes.items() if url.startswith(prefix)), None)
        if server is None:
            raise AssertionError(f"no fake serves {url}")
        answer = server(req)
        if isinstance(answer, BaseException):
            raise answer
        return served(answer) if isinstance(answer, bytes) else answer

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)


def serve(
    case: unittest.TestCase, client: ModuleType, routes: dict[str, Callable], cache: pathlib.Path
) -> Hosts:
    """Point `client`, the registry module the gates import, at `routes` for the
    length of `case`, keeping its charts in `cache` and its indexes fresh."""
    hosts = Hosts(routes)
    for patch in (
        mock.patch.object(client, "CHART_CACHE", cache),
        mock.patch.dict(client._INDEXES, clear=True),
        mock.patch.dict(
            client.http_get.__kwdefaults__, {"urlopen": hosts.urlopen, "sleep": hosts.sleep}
        ),
    ):
        patch.start()
        case.addCleanup(patch.stop)
    return hosts
