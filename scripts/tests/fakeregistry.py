"""A registry served at the urlopen level, for tests of scripts/registry.py.

What a registry serves is stated here rather than read from the client under
test: the media types are the ones the OCI and Helm specifications name, so a
client that drifted from them fails against this fake instead of agreeing with
itself.
"""

from __future__ import annotations

import email.message
import functools
import hashlib
import io
import json
import urllib.error

NOW = 1_800_000_000.0

HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"
HELM_CHART_CONTENT = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"


def http_error(url: str, code: int, headers: dict[str, str] | None = None,
               body: bytes = b"") -> urllib.error.HTTPError:
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(url, code, f"status {code}", msg, io.BytesIO(body))


def auth(req) -> str | None:
    return req.unredirected_hdrs.get("Authorization")


class Transport:
    """An urlopen stand-in that answers each request with the next scripted step.

    A step is bytes (a 200), an exception (raised), or a callable taking the
    request and returning either — which is how a registry whose answer depends
    on the Authorization header is written.

    `elapsed` is the time the client has spent on this transport, on the timer
    http_get's deadline reads. Every request is charged the whole timeout the
    client gave it, as one that never answers is, and every wait the time it
    asked to sleep, so a deadline the client keeps is one it keeps in the worst
    case.
    """

    def __init__(self, *steps):
        self.steps = list(steps)
        self.requests: list = []
        self.timeouts: list[float] = []
        self.waits: list[float] = []
        self.elapsed = 0.0
        self.on_sleep = None

    def urlopen(self, req, timeout=None):
        self.requests.append(req)
        self.timeouts.append(timeout)
        self.elapsed += timeout or 0.0
        step = self.steps.pop(0)
        if callable(step) and not isinstance(step, BaseException):
            step = step(req)
        if isinstance(step, BaseException):
            raise step
        return io.BytesIO(step)

    def sleep(self, seconds: float) -> None:
        if self.on_sleep:
            self.on_sleep()
        self.waits.append(seconds)
        self.elapsed += seconds

    def bind(self, http_get, jitter: float = 0.0):
        """`http_get` over this transport, with a fixed wall clock, the transport's
        own timer and a fixed jitter draw."""
        return functools.partial(http_get, urlopen=self.urlopen, sleep=self.sleep,
                                 clock=lambda: NOW, timer=lambda: self.elapsed,
                                 jitter=lambda: jitter)

    def urls(self) -> list[str]:
        return [r.full_url for r in self.requests]


class OciRegistry:
    """One chart in one OCI repository, served only to a bearer token it issued."""

    TOKEN = "t0k"
    CHALLENGE = ('Bearer realm="https://auth.example/token",service="registry.example",'
                 'scope="aws"')
    transport_class = Transport

    def __init__(self, host, path, version, config, *, content=b"chart-tgz",
                 media_type=None, digest=None):
        self.base = f"https://{host}/v2/{path}"
        self.version = version
        self.blob = json.dumps(config).encode()
        self.digest = digest or "sha256:" + hashlib.sha256(self.blob).hexdigest()
        self.content = content
        self.content_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.media_type = media_type or HELM_CONFIG

    def __call__(self, req):
        url = req.full_url
        if url.startswith("https://auth.example/token?"):
            return json.dumps({"token": self.TOKEN}).encode()
        if auth(req) != f"Bearer {self.TOKEN}":
            return http_error(url, 401, {"WWW-Authenticate": self.CHALLENGE})
        if url == f"{self.base}/manifests/{self.version}":
            return json.dumps({
                "config": {"mediaType": self.media_type, "digest": self.digest},
                "layers": [{"mediaType": HELM_CHART_CONTENT,
                            "digest": self.content_digest}],
            }).encode()
        if url == f"{self.base}/blobs/{self.digest}":
            return self.blob
        if url == f"{self.base}/blobs/{self.content_digest}":
            return self.content
        return http_error(url, 404)

    def transport(self, *overrides):
        """A transport answering from this registry, with scripted steps first."""
        return self.transport_class(*overrides, *([self] * 20))
