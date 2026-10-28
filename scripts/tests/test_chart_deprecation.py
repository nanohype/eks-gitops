"""Unit tests for the chart provenance gate.

Two halves decide what this gate says. The offline verdict decides whether every
pin has a record and every record a pin; the registry read decides what `--live`
and `--sync` see upstream.

The read is where these concentrate, because both of its failure modes are
quiet. A retry that fires on the wrong status turns a missing chart or a server
fault into a slow run that still ends in the same line of text, so the status
that would have explained it is spent on waiting. A retry with no bound turns a
registry that keeps answering 429 into a scheduled job that hits its own timeout
and reports nothing at all.
"""

from __future__ import annotations

import contextlib
import datetime
import email.message
import email.utils
import hashlib
import http.client
import io
import json
import unittest
import urllib.error
import urllib.parse
from unittest import mock

from gateloader import load

ccd = load("check-chart-deprecation")

NOW = 1_800_000_000.0


def http_error(url: str, code: int, headers: dict[str, str] | None = None):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(url, code, f"status {code}", msg, None)


class ScriptedTransport:
    """An urlopen stand-in that answers each request with the next scripted step."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.requests = []
        self.waits: list[float] = []

    def urlopen(self, req, timeout=None):
        self.requests.append(req)
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return io.BytesIO(step)

    def get(self, url="https://registry.example/v2/x/manifests/1.0.0", authorization=None):
        return ccd.http_get(url, {}, authorization, urlopen=self.urlopen,
                            sleep=self.waits.append, clock=lambda: NOW)


class ReadingRetryAfter(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(ccd.retry_after("7", NOW), 7.0)

    def test_http_date_is_measured_from_now(self):
        when = datetime.datetime.fromtimestamp(NOW + 30, tz=datetime.UTC)
        self.assertAlmostEqual(
            ccd.retry_after(email.utils.format_datetime(when, usegmt=True), NOW), 30.0)

    def test_a_date_already_past_asks_for_no_wait(self):
        when = datetime.datetime.fromtimestamp(NOW - 30, tz=datetime.UTC)
        self.assertEqual(
            ccd.retry_after(email.utils.format_datetime(when, usegmt=True), NOW), 0.0)

    def test_an_absent_or_unreadable_header_states_nothing(self):
        self.assertIsNone(ccd.retry_after(None, NOW))
        self.assertIsNone(ccd.retry_after("soon", NOW))
        self.assertIsNone(ccd.retry_after("-5", NOW))


class RetryingOnlyARateLimit(unittest.TestCase):
    URL = "https://registry.example/v2/x/manifests/1.0.0"

    def test_retry_after_seconds_is_the_wait(self):
        t = ScriptedTransport(http_error(self.URL, 429, {"Retry-After": "3"}), b"ok")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(t.get(), b"ok")
        self.assertEqual(t.waits, [3.0])
        self.assertEqual(len(t.requests), 2)

    def test_retry_after_date_is_the_wait(self):
        when = datetime.datetime.fromtimestamp(NOW + 12, tz=datetime.UTC)
        header = email.utils.format_datetime(when, usegmt=True)
        t = ScriptedTransport(http_error(self.URL, 429, {"Retry-After": header}), b"ok")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(t.get(), b"ok")
        self.assertEqual(len(t.waits), 1)
        self.assertAlmostEqual(t.waits[0], 12.0)

    def test_no_header_backs_off_exponentially(self):
        t = ScriptedTransport(http_error(self.URL, 429), http_error(self.URL, 429), b"ok")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(t.get(), b"ok")
        base = ccd.RETRY_BASE_SECONDS
        self.assertEqual(t.waits, [base, base * 2])

    def test_a_registry_that_never_relents_is_reported_after_the_bound(self):
        t = ScriptedTransport(*[http_error(self.URL, 429, {"Retry-After": "1"})]
                              * ccd.RETRY_ATTEMPTS)
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(ccd.RegistryError) as caught:
            t.get()
        self.assertEqual(len(t.requests), ccd.RETRY_ATTEMPTS)
        self.assertEqual(len(t.waits), ccd.RETRY_ATTEMPTS - 1)
        self.assertIn("429", str(caught.exception))
        self.assertIn(self.URL, str(caught.exception))

    def test_a_wait_beyond_the_cap_is_reported_not_slept(self):
        asked = int(ccd.RETRY_MAX_WAIT_SECONDS) + 1
        t = ScriptedTransport(http_error(self.URL, 429, {"Retry-After": str(asked)}))
        with self.assertRaises(ccd.RegistryError) as caught:
            t.get()
        self.assertEqual(t.waits, [])
        self.assertEqual(len(t.requests), 1)
        self.assertIn(f"Retry-After {asked}s", str(caught.exception))

    def test_other_statuses_are_reported_on_the_first_attempt(self):
        for code in (400, 401, 403, 404, 500, 502, 503):
            with self.subTest(code=code):
                t = ScriptedTransport(http_error(self.URL, code, {"Retry-After": "1"}), b"ok")
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    t.get()
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(len(t.requests), 1)
                self.assertEqual(t.waits, [])

    def test_a_network_error_is_reported_on_the_first_attempt(self):
        t = ScriptedTransport(urllib.error.URLError("connection refused"), b"ok")
        with self.assertRaises(urllib.error.URLError):
            t.get()
        self.assertEqual(len(t.requests), 1)
        self.assertEqual(t.waits, [])

    def test_the_token_does_not_follow_a_redirect(self):
        t = ScriptedTransport(b"ok")
        t.get(authorization="Bearer abc")
        req = t.requests[0]
        self.assertEqual(req.unredirected_hdrs.get("Authorization"), "Bearer abc")
        self.assertNotIn("Authorization", req.headers)


class FakeRegistry:
    """A registry that wants an anonymous bearer token before it serves anything."""

    TOKEN = "t0k"

    def __init__(self, host, path, version, config, *, media_type=None, digest=None,
                 challenge=None, reject_token=False):
        self.base = f"https://{host}/v2/{path}"
        self.version = version
        self.blob = json.dumps(config).encode()
        self.digest = digest or "sha256:" + hashlib.sha256(self.blob).hexdigest()
        self.media_type = media_type or ccd.HELM_CONFIG
        self.challenge = challenge or ('Bearer realm="https://auth.example/token",'
                                       'service="registry.example",scope="aws"')
        self.reject_token = reject_token
        self.calls: list[tuple[str, str | None]] = []

    def get(self, url, headers, authorization):
        self.calls.append((url, authorization))
        if url.startswith("https://auth.example/token?"):
            return json.dumps({"token": self.TOKEN}).encode()
        if authorization != f"Bearer {self.TOKEN}" or self.reject_token:
            raise http_error(url, 401, {"WWW-Authenticate": self.challenge})
        if url == f"{self.base}/manifests/{self.version}":
            return json.dumps({"config": {"mediaType": self.media_type,
                                          "digest": self.digest}}).encode()
        if url == f"{self.base}/blobs/{self.digest}":
            return self.blob
        raise http_error(url, 404)


class ReadingAnOciChart(unittest.TestCase):
    META = {"name": "karpenter", "version": "1.2.3", "description": "nodes"}

    def test_the_config_blob_is_the_metadata(self):
        reg = FakeRegistry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        meta = ccd.oci_chart_metadata("oci://public.ecr.aws/karpenter/karpenter", "1.2.3",
                                      reg.get)
        self.assertEqual(meta, self.META)

    def test_the_token_is_scoped_to_pulling_this_repository(self):
        reg = FakeRegistry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        ccd.oci_chart_metadata("oci://public.ecr.aws/karpenter/karpenter", "1.2.3", reg.get)
        token_urls = [u for u, _ in reg.calls if u.startswith("https://auth.example/")]
        self.assertEqual(len(token_urls), 1, "the token is fetched once and reused")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(token_urls[0]).query)
        self.assertEqual(query["scope"], ["repository:karpenter/karpenter:pull"])
        self.assertEqual(query["service"], ["registry.example"])

    def test_docker_hub_is_read_from_its_api_host(self):
        reg = FakeRegistry("registry-1.docker.io", "envoyproxy/gateway-helm", "1.0.0",
                           self.META)
        meta = ccd.oci_chart_metadata("oci://docker.io/envoyproxy/gateway-helm", "1.0.0",
                                      reg.get)
        self.assertEqual(meta, self.META)

    def test_a_blob_that_does_not_match_its_digest_is_refused(self):
        reg = FakeRegistry("r.example", "c", "1.0.0", self.META, digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(ccd.RegistryError, "does not match its digest"):
            ccd.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.get)

    def test_an_artifact_that_is_not_a_chart_is_refused(self):
        reg = FakeRegistry("r.example", "c", "1.0.0", self.META,
                           media_type="application/vnd.oci.image.config.v1+json")
        with self.assertRaisesRegex(ccd.RegistryError, "is not a Helm chart"):
            ccd.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.get)

    def test_a_challenge_other_than_bearer_is_refused(self):
        reg = FakeRegistry("r.example", "c", "1.0.0", self.META,
                           challenge='Basic realm="r.example"')
        with self.assertRaisesRegex(ccd.RegistryError, "Basic"):
            ccd.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.get)

    def test_a_401_after_the_token_is_reported_not_retried(self):
        reg = FakeRegistry("r.example", "c", "1.0.0", self.META, reject_token=True)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            ccd.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.get)
        self.assertEqual(caught.exception.code, 401)
        manifest_reads = [u for u, _ in reg.calls if "/manifests/" in u]
        self.assertEqual(len(manifest_reads), 2)


class FetchReportsWhyNot(unittest.TestCase):
    """fetch() returns an `_error` the live check prints, never an exception."""

    def fetch_failing_with(self, exc):
        with mock.patch.object(ccd, "oci_chart_metadata", side_effect=exc):
            return ccd.fetch("c", "oci://r.example/c", "1.0.0")

    def test_an_http_status_names_the_status_and_the_url(self):
        meta = self.fetch_failing_with(http_error("https://r.example/v2/c/manifests/1.0.0",
                                                  404))
        self.assertEqual(meta, {"_error": "HTTP 404 from https://r.example/v2/c/manifests/1.0.0"})

    def test_an_exhausted_rate_limit_is_reported_in_its_own_words(self):
        meta = self.fetch_failing_with(ccd.RegistryError("r.example answered HTTP 429"))
        self.assertEqual(meta, {"_error": "RegistryError: r.example answered HTTP 429"})

    def test_a_network_error_is_reported(self):
        meta = self.fetch_failing_with(urllib.error.URLError("no route"))
        self.assertIn("URLError", meta["_error"])

    def test_a_dropped_or_truncated_response_is_reported(self):
        for exc in (ConnectionResetError("reset by peer"),
                    http.client.IncompleteRead(b"partial", 10)):
            with self.subTest(exc=type(exc).__name__):
                meta = self.fetch_failing_with(exc)
                self.assertIn(type(exc).__name__, meta["_error"])


class TheLiveVerdict(unittest.TestCase):
    PINS = {"c": {"repo": "oci://r.example/c", "version": "1.0.0", "source": "x.yaml"}}
    RECORDS = {"c": {"repo": "oci://r.example/c", "description": "a chart",
                     "deprecated": False}}

    def live(self, meta):
        out = io.StringIO()
        with mock.patch.object(ccd, "pins", return_value=self.PINS), \
                mock.patch.object(ccd, "load_records", return_value=self.RECORDS), \
                mock.patch.object(ccd, "fetch", return_value=meta), \
                contextlib.redirect_stdout(out):
            return ccd.check_live(), out.getvalue()

    def test_a_matching_chart_passes(self):
        rc, _ = self.live({"description": "a chart"})
        self.assertEqual(rc, 0)

    def test_an_unreadable_chart_fails_with_the_reason(self):
        rc, out = self.live({"_error": "RegistryError: r.example answered HTTP 429"})
        self.assertEqual(rc, 1)
        self.assertIn("answered HTTP 429", out)

    def test_a_redescribed_chart_fails(self):
        rc, out = self.live({"description": "an enterprise product"})
        self.assertEqual(rc, 1)
        self.assertIn("changed what it says it is", out)

    def test_a_deprecated_chart_fails(self):
        rc, out = self.live({"description": "a chart", "deprecated": True})
        self.assertEqual(rc, 1)
        self.assertIn("marked deprecated", out)


class TheOfflineVerdict(unittest.TestCase):
    def offline(self, pins, records):
        with contextlib.redirect_stdout(io.StringIO()):
            return ccd.check_offline(pins, records)

    def test_the_shipped_catalog_passes(self):
        self.assertEqual(self.offline(ccd.pins(), ccd.load_records()), 0)

    def test_a_pin_with_no_record_fails(self):
        pins = dict(ccd.pins())
        pins["ghost"] = {"repo": "https://example.invalid", "version": "1.0.0",
                         "source": "x.yaml"}
        self.assertEqual(self.offline(pins, ccd.load_records()), 1)

    def test_a_record_with_no_pin_fails(self):
        records = dict(ccd.load_records())
        records["retired"] = {"repo": "https://example.invalid", "description": "x"}
        self.assertEqual(self.offline(ccd.pins(), records), 1)


if __name__ == "__main__":
    unittest.main()
