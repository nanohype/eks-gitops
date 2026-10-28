"""Unit tests for the registry client every chart and OCI read goes through.

The client checks every archive against a digest and handles a pull token, so
run.py holds it at a per-file floor of 100% rather than at a ratchet: a branch
here that no test reaches is a branch nothing proves.

Its failure modes are quiet. A retry that fires on the wrong status turns a
missing chart or a server fault into a slow run that still ends in the same line
of text, so the status that would have explained it is spent on waiting. A retry
with no bound turns a registry that keeps answering 429 into a job that hits its
own timeout and reports nothing at all. A digest check that passes over a
missing digest, or a cache that hands out whatever bytes it holds, renders a
chart nobody verified and reports it as the pinned one.
"""

import contextlib
import datetime
import email.utils
import hashlib
import http.client
import io
import json
import os
import pathlib
import shutil
import tempfile
import time
import unittest
import urllib.error
import urllib.parse

import fakeregistry as fake
from fakeregistry import NOW, auth, http_error
from gateloader import load

registry = load("registry")


class Transport(fake.Transport):
    def get(self, jitter: float = 0.0):
        """http_get bound to this transport, a fixed clock and a fixed jitter draw."""
        return self.bind(registry.http_get, jitter)


class Registry(fake.OciRegistry):
    transport_class = Transport


class ReadingRetryAfter(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(registry.retry_after("7", NOW), 7.0)

    def test_http_date_is_measured_from_now(self):
        when = datetime.datetime.fromtimestamp(NOW + 30, tz=datetime.UTC)
        self.assertAlmostEqual(
            registry.retry_after(email.utils.format_datetime(when, usegmt=True), NOW), 30.0)

    def test_a_naive_http_date_is_read_as_utc(self):
        """The asctime form carries no zone, and every HTTP-date is UTC.

        Read in the runner's local zone the wait would move by the zone's offset —
        hours either way — and refusing it would discard a wait the registry did
        state. The local zone is pinned ten hours from UTC, so a reading in it
        cannot agree by the runner happening to keep UTC.
        """
        saved = os.environ.get("TZ")
        os.environ["TZ"] = "Pacific/Honolulu"
        time.tzset()

        def restore():
            if saved is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = saved
            time.tzset()

        self.addCleanup(restore)
        when = datetime.datetime.fromtimestamp(NOW + 45, tz=datetime.UTC)
        asctime = when.strftime("%a %b %d %H:%M:%S %Y")
        self.assertIsNone(email.utils.parsedate_to_datetime(asctime).tzinfo,
                          "the fixture must be a date with no zone")
        self.assertAlmostEqual(registry.retry_after(asctime, NOW), 45.0)

    def test_a_date_already_past_asks_for_no_wait(self):
        when = datetime.datetime.fromtimestamp(NOW - 30, tz=datetime.UTC)
        self.assertEqual(
            registry.retry_after(email.utils.format_datetime(when, usegmt=True), NOW), 0.0)

    def test_an_absent_or_unreadable_header_states_nothing(self):
        self.assertIsNone(registry.retry_after(None, NOW))
        self.assertIsNone(registry.retry_after("soon", NOW))
        self.assertIsNone(registry.retry_after("-5", NOW))


class RetryingOnlyARateLimit(unittest.TestCase):
    URL = "https://registry.example/v2/x/manifests/1.0.0"

    def get(self, t: Transport, jitter: float = 0.0, **kw):
        with contextlib.redirect_stderr(io.StringIO()):
            return t.get(jitter)(self.URL, {}, None, **kw)

    def test_retry_after_seconds_is_the_wait(self):
        t = Transport(http_error(self.URL, 429, {"Retry-After": "3"}), b"ok")
        self.assertEqual(self.get(t), b"ok")
        self.assertEqual(t.waits, [3.0])
        self.assertEqual(len(t.requests), 2)

    def test_retry_after_date_is_the_wait(self):
        when = datetime.datetime.fromtimestamp(NOW + 12, tz=datetime.UTC)
        header = email.utils.format_datetime(when, usegmt=True)
        t = Transport(http_error(self.URL, 429, {"Retry-After": header}), b"ok")
        self.assertEqual(self.get(t), b"ok")
        self.assertEqual(len(t.waits), 1)
        self.assertAlmostEqual(t.waits[0], 12.0)

    def test_no_header_backs_off_exponentially(self):
        t = Transport(http_error(self.URL, 429), http_error(self.URL, 429), b"ok")
        self.assertEqual(self.get(t), b"ok")
        base = registry.RETRY_BASE_SECONDS
        self.assertEqual(t.waits, [base, base * 2])

    def test_jitter_stretches_a_wait_and_never_shortens_one(self):
        """Jobs throttled together must not come back together, and a registry's
        Retry-After is a minimum: the draw only ever adds to it."""
        t = Transport(http_error(self.URL, 429, {"Retry-After": "8"}),
                      http_error(self.URL, 429), b"ok")
        self.assertEqual(self.get(t, jitter=1.0), b"ok")
        stretch = 1 + registry.RETRY_JITTER
        self.assertEqual(t.waits, [8.0 * stretch,
                                   registry.RETRY_BASE_SECONDS * 2 * stretch])

    def test_the_refused_response_is_closed_before_the_wait(self):
        """A rate-limited client holding the refused connection open while it
        sleeps is still holding a connection the registry counted."""
        refused = http_error(self.URL, 429, {"Retry-After": "1"}, body=b"slow down")
        t = Transport(refused, b"ok")
        closed_at_sleep = []
        t.on_sleep = lambda: closed_at_sleep.append(refused.fp.closed)
        self.assertEqual(self.get(t), b"ok")
        self.assertEqual(closed_at_sleep, [True])

    def test_a_registry_that_never_relents_is_reported_after_the_bound(self):
        t = Transport(*[http_error(self.URL, 429, {"Retry-After": "1"})]
                      * registry.RETRY_ATTEMPTS)
        with self.assertRaises(registry.RegistryError) as caught:
            self.get(t)
        self.assertEqual(len(t.requests), registry.RETRY_ATTEMPTS)
        self.assertEqual(len(t.waits), registry.RETRY_ATTEMPTS - 1)
        self.assertIn("429", str(caught.exception))
        self.assertIn(self.URL, str(caught.exception))

    def test_a_wait_beyond_the_cap_is_reported_not_slept(self):
        asked = int(registry.RETRY_MAX_WAIT_SECONDS) + 1
        t = Transport(http_error(self.URL, 429, {"Retry-After": str(asked)}))
        with self.assertRaises(registry.RegistryError) as caught:
            self.get(t)
        self.assertEqual(t.waits, [])
        self.assertEqual(len(t.requests), 1)
        self.assertIn(f"Retry-After {asked}s", str(caught.exception))

    def test_other_statuses_are_reported_on_the_first_attempt(self):
        for code in (400, 401, 403, 404, 500, 502, 503):
            with self.subTest(code=code):
                t = Transport(http_error(self.URL, code, {"Retry-After": "1"}), b"ok")
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.get(t)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(len(t.requests), 1)
                self.assertEqual(t.waits, [])

    def test_a_network_error_is_reported_on_the_first_attempt(self):
        t = Transport(urllib.error.URLError("connection refused"), b"ok")
        with self.assertRaises(urllib.error.URLError):
            self.get(t)
        self.assertEqual(len(t.requests), 1)
        self.assertEqual(t.waits, [])

    def test_every_request_names_this_client(self):
        """urllib's default User-Agent is refused outright by some chart CDNs."""
        t = Transport(b"ok")
        t.get()("https://r.example/index.yaml", {"Accept": "text/yaml"}, None)
        self.assertEqual(t.requests[0].get_header("User-agent"), registry.USER_AGENT)
        self.assertEqual(t.requests[0].get_header("Accept"), "text/yaml")

    def test_the_token_does_not_follow_a_redirect(self):
        t = Transport(b"ok")
        t.get()(self.URL, {}, "Bearer abc")
        req = t.requests[0]
        self.assertEqual(req.unredirected_hdrs.get("Authorization"), "Bearer abc")
        self.assertNotIn("Authorization", req.headers)

    def test_a_challenge_is_answered_once_and_the_repeat_carries_its_answer(self):
        t = Transport(http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}), b"ok")
        seen = []

        def answer(www):
            seen.append(www)
            return "Bearer fresh"

        self.assertEqual(self.get(t, challenge=answer), b"ok")
        self.assertEqual(seen, ["Bearer x"])
        self.assertEqual([auth(r) for r in t.requests], [None, "Bearer fresh"])

    def test_a_second_401_is_reported_not_answered_again(self):
        t = Transport(http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}),
                      http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}), b"ok")
        answers = []
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get(t, challenge=lambda www: answers.append(www) or "Bearer t")
        self.assertEqual(caught.exception.code, 401)
        self.assertEqual(len(answers), 1)
        self.assertEqual(len(t.requests), 2)

    def test_a_challenge_on_the_last_attempt_is_reported_not_answered(self):
        """The repeat would be one request past the bound, so there is none to
        make: the token is not fetched, and the reason names the bound."""
        limited = [http_error(self.URL, 429)] * (registry.RETRY_ATTEMPTS - 1)
        t = Transport(*limited, http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}),
                      b"ok")
        answers = []
        with self.assertRaises(registry.RegistryError) as caught:
            self.get(t, challenge=lambda www: answers.append(www) or "Bearer t")
        self.assertIn(f"asked for a token on the last of {registry.RETRY_ATTEMPTS}",
                      str(caught.exception))
        self.assertEqual(answers, [])
        self.assertEqual(len(t.requests), registry.RETRY_ATTEMPTS)


class RequestingAToken(unittest.TestCase):
    def token_url(self, challenge: str, body=None) -> str:
        asked = []

        def get(url, headers, authorization, **_):
            asked.append(url)
            return json.dumps(body or {"token": "t"}).encode()

        self.assertEqual(registry.anonymous_token(challenge, "org/chart", get), "t")
        return asked[0]

    def test_the_scope_and_service_are_added_to_the_realm(self):
        url = self.token_url('Bearer realm="https://auth.example/token",service="reg"')
        parts = urllib.parse.urlsplit(url)
        self.assertEqual(f"{parts.scheme}://{parts.netloc}{parts.path}",
                         "https://auth.example/token")
        self.assertEqual(urllib.parse.parse_qs(parts.query),
                         {"scope": ["repository:org/chart:pull"], "service": ["reg"]})

    def test_a_realm_that_already_carries_a_query_keeps_it(self):
        """Appending `?scope=` to a realm with its own query makes a URL whose
        path ends in the realm's query string — a token endpoint that answers
        404, or a token for the wrong scope."""
        url = self.token_url('Bearer realm="https://auth.example/token?account=ci",'
                             'service="reg"')
        parts = urllib.parse.urlsplit(url)
        self.assertEqual(parts.path, "/token")
        self.assertEqual(urllib.parse.parse_qs(parts.query),
                         {"account": ["ci"], "scope": ["repository:org/chart:pull"],
                          "service": ["reg"]})

    def test_an_access_token_field_is_a_token_too(self):
        """The token spec names both fields, and some realms answer with only the
        OAuth2 one."""
        self.token_url('Bearer realm="https://auth.example/token"', {"access_token": "t"})

    def test_a_challenge_other_than_bearer_is_refused(self):
        with self.assertRaisesRegex(registry.RegistryError, "Basic"):
            registry.anonymous_token('Basic realm="r"', "c", lambda *a, **k: b"{}")

    def test_a_challenge_with_no_realm_is_refused(self):
        with self.assertRaisesRegex(registry.RegistryError, "no realm"):
            registry.anonymous_token('Bearer service="r"', "c", lambda *a, **k: b"{}")

    def test_a_realm_that_returns_no_token_is_refused(self):
        for body in (b"{}", b'["t"]'):
            with self.subTest(body=body), \
                    self.assertRaisesRegex(registry.RegistryError, "no token"):
                registry.anonymous_token('Bearer realm="https://a/t"', "c",
                                         lambda *a, _b=body, **k: _b)

    def test_a_realm_that_answers_something_other_than_json_raises_a_read_failure(self):
        with self.assertRaises(registry.READ_FAILURES):
            registry.anonymous_token('Bearer realm="https://a/t"', "c",
                                     lambda *a, **k: b"<html>sign in</html>")


class ReadingAnOciChart(unittest.TestCase):
    META = {"name": "karpenter", "version": "1.2.3", "description": "nodes"}
    REF = "oci://public.ecr.aws/karpenter/karpenter"

    def test_the_config_blob_is_the_metadata(self):
        reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        t = reg.transport()
        self.assertEqual(registry.oci_chart_metadata(self.REF, "1.2.3", t.get()), self.META)

    def test_the_token_is_scoped_to_pulling_this_repository_and_fetched_once(self):
        reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        t = reg.transport()
        registry.oci_chart_metadata(self.REF, "1.2.3", t.get())
        token_urls = [u for u in t.urls() if u.startswith("https://auth.example/")]
        self.assertEqual(len(token_urls), 1, "the token is fetched once and reused")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(token_urls[0]).query)
        self.assertEqual(query["scope"], ["repository:karpenter/karpenter:pull"])
        self.assertEqual(query["service"], ["registry.example"])

    def test_the_401_then_429_path_stays_inside_one_bound(self):
        """The challenge's repeat and the rate-limit retries share one budget.

        The manifest read is refused anonymously, answered with a token, then
        rate-limited twice before it is served: four requests to the manifest —
        RETRY_ATTEMPTS — one to the realm, and the blob read after it reuses the
        token without a challenge.
        """
        reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        manifest = f"{reg.base}/manifests/1.2.3"
        limited = http_error(manifest, 429, {"Retry-After": "2"})
        t = Transport(reg, reg, http_error(manifest, 429), limited, reg, reg)
        with contextlib.redirect_stderr(io.StringIO()):
            meta = registry.oci_chart_metadata(self.REF, "1.2.3", t.get())
        self.assertEqual(meta, self.META)
        urls = t.urls()
        self.assertEqual(urls.count(manifest), registry.RETRY_ATTEMPTS)
        self.assertEqual(sum(u.startswith("https://auth.example/") for u in urls), 1)
        self.assertEqual(len(urls), registry.RETRY_ATTEMPTS + 2)
        self.assertEqual(t.waits, [registry.RETRY_BASE_SECONDS * 2, 2.0])
        self.assertEqual([auth(r) for r in t.requests if r.full_url == manifest],
                         [None] + [f"Bearer {reg.TOKEN}"] * 3)

    def test_a_rate_limit_after_the_challenge_is_reported_at_the_bound(self):
        """The challenge's repeat is one of the RETRY_ATTEMPTS, not extra."""
        reg = Registry("r.example", "c", "1.0.0", self.META)
        manifest = f"{reg.base}/manifests/1.0.0"
        t = Transport(reg, reg, *[http_error(manifest, 429)] * registry.RETRY_ATTEMPTS)
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(registry.RegistryError):
            registry.oci_chart_metadata("oci://r.example/c", "1.0.0", t.get())
        self.assertEqual(t.urls().count(manifest), registry.RETRY_ATTEMPTS)
        self.assertEqual(len(t.requests), registry.RETRY_ATTEMPTS + 1)

    def test_a_401_on_the_blob_read_is_reported_not_answered_again(self):
        """The second-401 guard. The blob read carries the token the manifest
        read earned; a registry refusing it is refusing for a reason a second
        token would not change, so the client neither asks for one nor loops."""
        reg = Registry("r.example", "c", "1.0.0", self.META)
        blob = f"{reg.base}/blobs/{reg.digest}"
        t = Transport(reg, reg, reg,
                      http_error(blob, 401, {"WWW-Authenticate": Registry.CHALLENGE}),
                      reg, reg)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            registry.oci_chart_metadata("oci://r.example/c", "1.0.0", t.get())
        self.assertEqual(caught.exception.code, 401)
        urls = t.urls()
        self.assertEqual(urls.count(blob), 1)
        self.assertEqual(sum(u.startswith("https://auth.example/") for u in urls), 1)
        self.assertEqual(len(t.requests), 4)

    def test_docker_hub_is_read_from_its_api_host(self):
        reg = Registry("registry-1.docker.io", "envoyproxy/gateway-helm", "1.0.0", self.META)
        meta = registry.oci_chart_metadata("oci://docker.io/envoyproxy/gateway-helm",
                                           "1.0.0", reg.transport().get())
        self.assertEqual(meta, self.META)

    def test_a_blob_that_does_not_match_its_digest_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", self.META, digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(registry.RegistryError, "does not match its digest"):
            registry.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.transport().get())

    def test_a_digest_that_is_not_sha256_is_refused_before_anything_is_read(self):
        for digest in ("", "sha256:", "md5:" + "0" * 32):
            with self.subTest(digest=digest):
                t = Transport()
                repo = registry.OciRepository("oci://r.example/c", t.get())
                with self.assertRaisesRegex(registry.RegistryError, "not a sha256 digest"):
                    repo.blob(digest)
                self.assertEqual(t.requests, [])

    def test_an_artifact_that_is_not_a_chart_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", self.META,
                       media_type="application/vnd.oci.image.config.v1+json")
        with self.assertRaisesRegex(registry.RegistryError, "is not a Helm chart"):
            registry.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.transport().get())
        with self.assertRaisesRegex(registry.RegistryError, "is not a Helm chart"):
            registry.oci_chart_content("oci://r.example/c", "1.0.0", reg.transport().get())

    def test_a_manifest_that_is_not_a_json_object_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", self.META)
        t = reg.transport(reg, reg, b'["not", "a", "manifest"]')
        with self.assertRaisesRegex(registry.RegistryError, "is not a JSON object"):
            registry.oci_chart_metadata("oci://r.example/c", "1.0.0", t.get())

    def test_a_config_blob_that_is_not_a_json_object_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", ["a", "list"])
        with self.assertRaisesRegex(registry.RegistryError, "config blob is not a JSON"):
            registry.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.transport().get())

    def test_the_chart_content_layer_is_the_archive(self):
        reg = Registry("r.example", "c", "1.0.0", self.META, content=b"packaged")
        self.assertEqual(registry.oci_chart_content("oci://r.example/c", "1.0.0",
                                                    reg.transport().get()), b"packaged")

    def test_the_content_layer_is_found_among_the_others(self):
        """A provenance layer, or a malformed entry, ahead of the chart is passed over."""
        reg = Registry("r.example", "c", "1.0.0", self.META, content=b"packaged")
        manifest = json.dumps({
            "config": {"mediaType": fake.HELM_CONFIG, "digest": reg.digest},
            "layers": ["not-a-layer",
                       {"mediaType": "application/vnd.cncf.helm.chart.provenance.v1.prov",
                        "digest": "sha256:" + "1" * 64},
                       {"mediaType": fake.HELM_CHART_CONTENT, "digest": reg.content_digest}],
        }).encode()
        t = reg.transport(reg, reg, manifest)
        self.assertEqual(registry.oci_chart_content("oci://r.example/c", "1.0.0", t.get()),
                         b"packaged")

    def test_a_chart_with_no_content_layer_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", self.META)
        manifest = json.dumps({"config": {"mediaType": fake.HELM_CONFIG}}).encode()
        t = reg.transport(reg, reg, manifest)
        with self.assertRaisesRegex(registry.RegistryError, "carries no"):
            registry.oci_chart_content("oci://r.example/c", "1.0.0", t.get())


class ReadingAnHttpsRepository(unittest.TestCase):
    REPO = "https://charts.example/stable"

    def setUp(self):
        registry._INDEXES.clear()
        self.addCleanup(registry._INDEXES.clear)
        self.cache = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.cache, True)
        self.archive = b"loki-archive"
        self.index = {"entries": {"loki": [
            {"name": "loki", "version": "6.1.0", "description": "logs",
             "urls": ["loki-6.1.0.tgz"],
             "digest": hashlib.sha256(self.archive).hexdigest()},
            {"name": "loki", "version": "v7.0.0", "description": "logs",
             "urls": ["loki-7.0.0.tgz"]},
            {"name": "loki", "version": "8.0.0", "description": "logs", "urls": [],
             "digest": hashlib.sha256(self.archive).hexdigest()},
        ]}}

    def transport(self, *steps):
        index = json.dumps(self.index).encode()   # JSON is YAML
        return Transport(*(steps or (index, self.archive)))

    def archive_of(self, version, t):
        with contextlib.redirect_stderr(io.StringIO()):
            return registry.chart_archive(self.REPO, "loki", version, cache=self.cache,
                                          get=t.get())

    def test_the_index_entry_is_the_metadata(self):
        t = self.transport()
        meta = registry.chart_metadata(self.REPO, "loki", "6.1.0", t.get())
        self.assertEqual(meta, {"name": "loki", "version": "6.1.0", "description": "logs"})
        self.assertEqual(t.urls(), [f"{self.REPO}/index.yaml"])

    def test_a_bare_pin_matches_a_v_prefixed_index_entry(self):
        t = self.transport()
        self.assertEqual(registry.repo_index_entry(self.REPO, "loki", "7.0.0",
                                                   t.get())["version"], "v7.0.0")

    def test_a_v_prefixed_pin_matches_a_bare_index_entry(self):
        t = self.transport()
        self.assertEqual(registry.repo_index_entry(self.REPO, "loki", "v6.1.0",
                                                   t.get())["version"], "6.1.0")

    def test_the_index_is_read_once_per_repository(self):
        t = self.transport(json.dumps(self.index).encode())
        registry.repo_index_entry(self.REPO, "loki", "6.1.0", t.get())
        registry.repo_index_entry(self.REPO, "loki", "7.0.0", t.get())
        self.assertEqual(t.urls(), [f"{self.REPO}/index.yaml"])

    def test_an_index_that_is_not_yaml_or_not_a_mapping_is_refused(self):
        for body, why in ((b"entries: [unclosed", "is not YAML"),
                          (b"- a\n- list\n", "is not a mapping")):
            with self.subTest(why=why):
                registry._INDEXES.clear()
                with self.assertRaisesRegex(registry.RegistryError, why):
                    registry.repo_index_entry(self.REPO, "loki", "6.1.0",
                                              Transport(body).get())

    def test_a_version_the_index_does_not_list_was_answered(self):
        t = self.transport()
        with self.assertRaises(registry.ChartUnavailable) as caught:
            registry.chart_metadata(self.REPO, "loki", "9.9.9", t.get())
        self.assertTrue(caught.exception.answered)
        self.assertIn("lists no loki 9.9.9", str(caught.exception))

    def test_the_archive_is_fetched_relative_to_the_repository_and_kept(self):
        t = self.transport()
        path = self.archive_of("6.1.0", t)
        self.assertEqual(path.read_bytes(), self.archive)
        self.assertEqual(t.urls(), [f"{self.REPO}/index.yaml", f"{self.REPO}/loki-6.1.0.tgz"])
        self.assertEqual(registry.digest_path(path).read_text(),
                         hashlib.sha256(self.archive).hexdigest())
        again = self.archive_of("6.1.0", Transport())
        self.assertEqual(again, path, "a kept archive is used without a request")

    def test_an_archive_that_does_not_match_the_index_digest_is_not_kept(self):
        t = self.transport(json.dumps(self.index).encode(), b"tampered")
        with self.assertRaises(registry.ChartUnavailable) as caught:
            self.archive_of("6.1.0", t)
        self.assertFalse(caught.exception.answered)
        self.assertEqual(list(self.cache.rglob("*")), [])

    def test_an_entry_that_publishes_no_digest_is_refused_unfetched(self):
        """Nothing could be checked, so nothing is read: the index has said all
        it will, and asking again gets the same entry."""
        t = self.transport(json.dumps(self.index).encode())
        with self.assertRaises(registry.ChartUnavailable) as caught:
            self.archive_of("7.0.0", t)
        self.assertTrue(caught.exception.answered)
        self.assertIn("publishes no digest", str(caught.exception))
        self.assertEqual(t.urls(), [f"{self.REPO}/index.yaml"])
        self.assertEqual(list(self.cache.rglob("*")), [])

    def test_an_entry_that_names_no_archive_is_refused(self):
        t = self.transport(json.dumps(self.index).encode())
        with self.assertRaises(registry.ChartUnavailable) as caught:
            self.archive_of("8.0.0", t)
        self.assertTrue(caught.exception.answered)
        self.assertIn("names no archive", str(caught.exception))

    def test_an_oci_archive_is_kept_under_its_reference(self):
        reg = Registry("r.example", "org/c", "1.0.0", {"name": "c"}, content=b"oci-tgz")
        path = registry.chart_archive("oci://r.example/org/c", "c", "1.0.0",
                                      cache=self.cache, get=reg.transport().get())
        self.assertEqual(path.read_bytes(), b"oci-tgz")
        self.assertEqual(path.relative_to(self.cache).as_posix(),
                         "r.example_org_c/c-1.0.0.tgz")
        self.assertEqual(registry.digest_path(path).read_text(),
                         hashlib.sha256(b"oci-tgz").hexdigest())


class ReusingACachedArchive(unittest.TestCase):
    """The cache is restored from somewhere else, so what it holds is re-checked.

    An archive is handed out only while it hashes to the digest recorded when it
    was verified. Anything else — bytes changed after the fact, or an archive
    kept with no record — is fetched again rather than rendered.
    """

    REPO = "https://charts.example"

    def setUp(self):
        registry._INDEXES.clear()
        self.addCleanup(registry._INDEXES.clear)
        self.cache = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.cache, True)
        self.archive = b"verified-archive"
        self.index = json.dumps({"entries": {"c": [
            {"version": "1.0.0", "urls": ["c-1.0.0.tgz"],
             "digest": hashlib.sha256(self.archive).hexdigest()}]}}).encode()

    def fetch(self, t):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            path = registry.chart_archive(self.REPO, "c", "1.0.0", cache=self.cache,
                                          get=t.get())
        return path, err.getvalue()

    def kept(self) -> pathlib.Path:
        path, _ = self.fetch(Transport(self.index, self.archive))
        registry._INDEXES.clear()
        return path

    def test_an_intact_archive_is_handed_out_without_a_request(self):
        path = self.kept()
        t = Transport()
        again, err = self.fetch(t)
        self.assertEqual((again, t.requests, err), (path, [], ""))

    def test_an_archive_whose_bytes_changed_is_fetched_again(self):
        path = self.kept()
        path.write_bytes(b"truncated")
        t = Transport(self.index, self.archive)
        again, err = self.fetch(t)
        self.assertEqual(again.read_bytes(), self.archive)
        self.assertEqual(len(t.requests), 2)
        self.assertIn("not the bytes that were verified", err)

    def test_an_archive_kept_with_no_record_is_fetched_again(self):
        path = self.kept()
        registry.digest_path(path).unlink()
        t = Transport(self.index, self.archive)
        self.fetch(t)
        self.assertEqual(len(t.requests), 2)
        self.assertTrue(registry.digest_path(path).is_file())

    def test_a_record_that_is_not_the_archives_digest_is_not_trusted(self):
        path = self.kept()
        registry.digest_path(path).write_text("0" * 64)
        t = Transport(self.index, self.archive)
        self.fetch(t)
        self.assertEqual(len(t.requests), 2)

    def test_an_archive_that_cannot_be_fetched_again_is_not_handed_out(self):
        path = self.kept()
        path.write_bytes(b"truncated")
        with self.assertRaises(registry.ChartUnavailable):
            self.fetch(Transport(urllib.error.URLError("no route to host")))


class PruningTheChartCache(unittest.TestCase):
    """A cache carried across pin sets keeps the current set and nothing older."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def archive(self, source, chart, version):
        path = registry.archive_path(source, chart, version, self.root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"tgz")
        registry.digest_path(path).write_text(hashlib.sha256(b"tgz").hexdigest())
        return path

    def test_archives_no_pin_names_are_dropped_and_pinned_ones_kept(self):
        current = self.archive("https://charts.example", "a", "2.0.0")
        older = self.archive("https://charts.example", "a", "1.0.0")
        retired = self.archive("oci://r.example/b", "b", "1.0.0")
        dropped = registry.prune_archives({current}, self.root)
        self.assertEqual(dropped, 4, "two archives, and the digest record of each")
        self.assertTrue(current.is_file())
        self.assertTrue(registry.digest_path(current).is_file())
        self.assertFalse(older.exists())
        self.assertFalse(registry.digest_path(older).exists())
        self.assertFalse(retired.exists())

    def test_a_partial_left_by_an_interrupted_fetch_is_dropped(self):
        keep = self.archive("https://charts.example", "a", "1.0.0")
        partials = [keep.with_name(f".{keep.name}.4242"),
                    keep.with_name(f".{registry.digest_path(keep).name}.4242")]
        for p in partials:
            p.write_bytes(b"half")
        registry.prune_archives({keep}, self.root)
        self.assertEqual([p for p in partials if p.exists()], [])
        self.assertTrue(keep.is_file())

    def test_a_folder_left_empty_goes_with_its_archives(self):
        keep = self.archive("https://charts.example", "a", "1.0.0")
        gone = self.archive("oci://r.example/b", "b", "1.0.0")
        registry.prune_archives({keep}, self.root)
        self.assertFalse(gone.parent.exists())
        self.assertTrue(keep.parent.is_dir())

    def test_an_absent_cache_drops_nothing(self):
        self.assertEqual(registry.prune_archives(set(), self.root / "absent"), 0)


class WhatAnUnavailableChartMeans(unittest.TestCase):
    """Exit 1 is a finding about a pin; exit 2 is a fact about the network.

    Collapsing them makes an outage read as a defect in the catalogue, and trains
    readers to re-run a red gate rather than read it.
    """

    REPO = "https://charts.example"
    OCI = "oci://r.example/c"

    def setUp(self):
        registry._INDEXES.clear()
        self.addCleanup(registry._INDEXES.clear)

    def unavailable(self, *steps, source=REPO):
        t = Transport(*steps)
        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(registry.ChartUnavailable) as caught:
            registry.chart_archive(source, "c", "1.0.0", cache=pathlib.Path(tmp),
                                   get=t.get())
        return caught.exception

    def test_a_404_was_answered(self):
        exc = self.unavailable(http_error(f"{self.REPO}/index.yaml", 404))
        self.assertTrue(exc.answered)
        self.assertEqual(str(exc), f"HTTP 404 from {self.REPO}/index.yaml")

    def test_a_rate_limit_that_outlasts_the_retries_was_not_answered(self):
        exc = self.unavailable(*[http_error(f"{self.REPO}/index.yaml", 429)]
                               * registry.RETRY_ATTEMPTS)
        self.assertFalse(exc.answered)
        self.assertIn("429", str(exc))

    def test_a_server_fault_or_network_error_was_not_answered(self):
        for step in (http_error(f"{self.REPO}/index.yaml", 500),
                     http_error(f"{self.REPO}/index.yaml", 403),
                     urllib.error.URLError("no route to host"),
                     ConnectionResetError("reset by peer"),
                     http.client.IncompleteRead(b"partial", 10)):
            with self.subTest(step=type(step).__name__):
                self.assertFalse(self.unavailable(step).answered)

    def test_a_body_that_is_not_the_json_the_api_promises_was_not_answered(self):
        """A captive portal or an error page served with a 200 says nothing
        about the pin, and must not escape as a traceback that exits 1."""
        reg = Registry("r.example", "c", "1.0.0", {"name": "c"})
        for steps in ((reg, b"<html>sign in</html>"),
                      (reg, reg, b"<html>maintenance</html>")):
            with self.subTest(read="token" if len(steps) == 2 else "manifest"):
                exc = self.unavailable(*steps, source=self.OCI)
                self.assertFalse(exc.answered)
                self.assertIn("JSONDecodeError", str(exc))

    def test_the_exit_status_follows_the_answer(self):
        for answered, status in ((True, 1), (False, registry.gatelib.CANNOT_RUN)):
            with self.subTest(answered=answered):
                exc = registry.ChartUnavailable("why", answered=answered)
                original = registry.chart_archive

                def refuse(*_a, _exc=exc, **_k):
                    raise _exc

                registry.chart_archive = refuse
                try:
                    with contextlib.redirect_stdout(io.StringIO()) as out, \
                            self.assertRaises(SystemExit) as caught:
                        registry.chart_archive_or_exit(self.REPO, "c", "1.0.0")
                finally:
                    registry.chart_archive = original
                self.assertEqual(caught.exception.code, status)
                self.assertIn("why", out.getvalue())

    def test_an_archive_that_is_fetched_is_returned(self):
        original = registry.chart_archive
        registry.chart_archive = lambda *_a, **_k: pathlib.Path("/cache/c-1.0.0.tgz")
        try:
            got = registry.chart_archive_or_exit(self.REPO, "c", "1.0.0")
        finally:
            registry.chart_archive = original
        self.assertEqual(got, pathlib.Path("/cache/c-1.0.0.tgz"))


if __name__ == "__main__":
    unittest.main()
