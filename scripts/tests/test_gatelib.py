"""Unit tests for the shared gate helpers.

gatelib is loaded by every gate, so a defect here narrows several corpora at
once and each of them reports the same success it always did. Two halves:

The generator walk, which had exactly that failure in two gates simultaneously:
it returned on the first list generator, and the count each gate printed was
derived from the same truncated list, so neither could expose its own omission.

The registry client every chart and OCI read goes through. Both of its failure
modes are quiet. A retry that fires on the wrong status turns a missing chart or
a server fault into a slow run that still ends in the same line of text, so the
status that would have explained it is spent on waiting. A retry with no bound
turns a registry that keeps answering 429 into a job that hits its own timeout
and reports nothing at all.
"""

import contextlib
import datetime
import email.message
import email.utils
import functools
import hashlib
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

from gateloader import load

gatelib = load("gatelib")


def appset(*generators):
    return {"kind": "ApplicationSet", "spec": {"generators": list(generators)}}


def matrix(*inner):
    return {"matrix": {"generators": list(inner)}}


def listgen(*names):
    return {"list": {"elements": [{"appName": n} for n in names]}}


class EveryListGeneratorIsWalked(unittest.TestCase):
    """The defect this helper exists to prevent, stated as a test.

    An ApplicationSet may declare more than one list generator; each contributes
    its own Applications. Returning on the first drops the rest silently.
    """

    def names(self, doc):
        return [e["appName"] for e in gatelib.list_elements(doc)]

    def test_a_single_list_generator(self):
        doc = appset(matrix({"clusters": {}}, listgen("a", "b")))
        self.assertEqual(self.names(doc), ["a", "b"])

    def test_two_matrix_generators_each_with_a_list(self):
        """The shape this catalog already ships."""
        doc = appset(
            matrix({"clusters": {}}, listgen("first")),
            matrix({"clusters": {}}, listgen("second")),
        )
        self.assertEqual(
            self.names(doc), ["first", "second"],
            "an element past the first list generator was dropped — the walk "
            "that did this reported a full run over a truncated corpus",
        )

    def test_two_lists_inside_one_matrix(self):
        doc = appset(matrix(listgen("x"), listgen("y")))
        self.assertEqual(self.names(doc), ["x", "y"])

    def test_a_bare_list_generator_outside_a_matrix(self):
        self.assertEqual(self.names(appset(listgen("solo"))), ["solo"])

    def test_generators_without_a_list_contribute_nothing(self):
        doc = appset(matrix({"clusters": {}}, {"git": {}}))
        self.assertEqual(self.names(doc), [])

    def test_a_non_mapping_generator_is_skipped_not_crashed(self):
        """A manifest that parses but nests something odd must not traceback.

        Exit 1 is what these gates use for "the tree is wrong"; an uncaught
        AttributeError is indistinguishable from it by status alone.
        """
        doc = {"spec": {"generators": ["not-a-mapping", matrix(listgen("ok"))]}}
        self.assertEqual(self.names(doc), ["ok"])

    def test_a_non_mapping_element_is_skipped(self):
        doc = {"spec": {"generators": [{"list": {"elements": ["str", {"appName": "ok"}]}}]}}
        self.assertEqual(self.names(doc), ["ok"])

    def test_an_empty_document_yields_nothing(self):
        for empty in ({}, {"spec": {}}, {"spec": {"generators": []}}):
            self.assertEqual(gatelib.list_elements(empty), [])


class MatrixGeneratorsFlattens(unittest.TestCase):
    """A matrix contributes its inner generators; a bare generator itself."""

    def test_matrix_members_are_yielded_not_the_matrix(self):
        got = list(gatelib.matrix_generators(appset(matrix({"clusters": {}}, listgen("a")))))
        self.assertEqual(len(got), 2)
        self.assertIn("clusters", got[0])
        self.assertIn("list", got[1])

    def test_a_bare_generator_is_yielded_as_itself(self):
        got = list(gatelib.matrix_generators(appset({"clusters": {"selector": {}}})))
        self.assertEqual(len(got), 1)
        self.assertIn("clusters", got[0])

    def test_both_shapes_in_one_document(self):
        doc = appset({"clusters": {}}, matrix(listgen("a"), {"git": {}}))
        self.assertEqual(len(list(gatelib.matrix_generators(doc))), 3)


class TheRealCatalogIsWalkedWhole(unittest.TestCase):
    """Read against the shipped tree, so the corpus cannot shrink unnoticed.

    A count asserted only against a fixture says nothing about the repo. This
    keys on the property instead: every list generator in every ApplicationSet
    contributes, so the total is the sum and not the first.
    """

    def test_every_list_generator_in_the_catalog_contributes(self):
        import pathlib

        import yaml

        root = pathlib.Path(gatelib.__file__).resolve().parent.parent
        appsets = sorted((root / "applicationsets").glob("*.yaml"))
        self.assertTrue(appsets, "no ApplicationSets found — this asserts nothing")

        multi = 0
        for path in appsets:
            doc = yaml.safe_load(path.read_text())
            if not isinstance(doc, dict) or doc.get("kind") != "ApplicationSet":
                continue
            lists = [g for g in gatelib.matrix_generators(doc)
                     if (g.get("list") or {}).get("elements")]
            if len(lists) > 1:
                multi += 1
            expected = sum(len(g["list"]["elements"]) for g in lists)
            self.assertEqual(
                len(gatelib.list_elements(doc)), expected,
                f"{path.name}: the walk returned fewer elements than its "
                f"generators declare",
            )
        self.assertGreater(
            multi, 0,
            "no ApplicationSet declares more than one list generator, so this "
            "suite no longer exercises the case the walk exists for — either the "
            "catalog changed shape or the fixture-only tests above are all that "
            "remain",
        )



# ── The registry client ──────────────────────────────────────────────────────

NOW = 1_800_000_000.0


def http_error(url: str, code: int, headers: dict[str, str] | None = None,
               body: bytes = b"") -> urllib.error.HTTPError:
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(url, code, f"status {code}", msg, io.BytesIO(body))


class Transport:
    """An urlopen stand-in that answers each request with the next scripted step.

    A step is bytes (a 200), an exception (raised), or a callable taking the
    request and returning either — which is how a registry whose answer depends
    on the Authorization header is written.
    """

    def __init__(self, *steps):
        self.steps = list(steps)
        self.requests: list = []
        self.waits: list[float] = []
        self.on_sleep = None

    def urlopen(self, req, timeout=None):
        self.requests.append(req)
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

    def get(self, jitter: float = 0.0):
        """http_get bound to this transport, a fixed clock and a fixed jitter draw."""
        return functools.partial(gatelib.http_get, urlopen=self.urlopen, sleep=self.sleep,
                                 clock=lambda: NOW, jitter=lambda: jitter)

    def urls(self) -> list[str]:
        return [r.full_url for r in self.requests]


def auth(req) -> str | None:
    return req.unredirected_hdrs.get("Authorization")


class ReadingRetryAfter(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(gatelib.retry_after("7", NOW), 7.0)

    def test_http_date_is_measured_from_now(self):
        when = datetime.datetime.fromtimestamp(NOW + 30, tz=datetime.UTC)
        self.assertAlmostEqual(
            gatelib.retry_after(email.utils.format_datetime(when, usegmt=True), NOW), 30.0)

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
        self.assertAlmostEqual(gatelib.retry_after(asctime, NOW), 45.0)

    def test_a_date_already_past_asks_for_no_wait(self):
        when = datetime.datetime.fromtimestamp(NOW - 30, tz=datetime.UTC)
        self.assertEqual(
            gatelib.retry_after(email.utils.format_datetime(when, usegmt=True), NOW), 0.0)

    def test_an_absent_or_unreadable_header_states_nothing(self):
        self.assertIsNone(gatelib.retry_after(None, NOW))
        self.assertIsNone(gatelib.retry_after("soon", NOW))
        self.assertIsNone(gatelib.retry_after("-5", NOW))


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
        base = gatelib.RETRY_BASE_SECONDS
        self.assertEqual(t.waits, [base, base * 2])

    def test_jitter_stretches_a_wait_and_never_shortens_one(self):
        """Jobs throttled together must not come back together, and a registry's
        Retry-After is a minimum: the draw only ever adds to it."""
        t = Transport(http_error(self.URL, 429, {"Retry-After": "8"}),
                      http_error(self.URL, 429), b"ok")
        self.assertEqual(self.get(t, jitter=1.0), b"ok")
        stretch = 1 + gatelib.RETRY_JITTER
        self.assertEqual(t.waits, [8.0 * stretch,
                                   gatelib.RETRY_BASE_SECONDS * 2 * stretch])

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
                      * gatelib.RETRY_ATTEMPTS)
        with self.assertRaises(gatelib.RegistryError) as caught:
            self.get(t)
        self.assertEqual(len(t.requests), gatelib.RETRY_ATTEMPTS)
        self.assertEqual(len(t.waits), gatelib.RETRY_ATTEMPTS - 1)
        self.assertIn("429", str(caught.exception))
        self.assertIn(self.URL, str(caught.exception))

    def test_a_wait_beyond_the_cap_is_reported_not_slept(self):
        asked = int(gatelib.RETRY_MAX_WAIT_SECONDS) + 1
        t = Transport(http_error(self.URL, 429, {"Retry-After": str(asked)}))
        with self.assertRaises(gatelib.RegistryError) as caught:
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
        self.assertEqual(t.requests[0].get_header("User-agent"), gatelib.USER_AGENT)
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


class RequestingAToken(unittest.TestCase):
    def token_url(self, challenge: str) -> str:
        asked = []

        def get(url, headers, authorization, **_):
            asked.append(url)
            return json.dumps({"token": "t"}).encode()

        self.assertEqual(gatelib.anonymous_token(challenge, "org/chart", get), "t")
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

    def test_a_challenge_other_than_bearer_is_refused(self):
        with self.assertRaisesRegex(gatelib.RegistryError, "Basic"):
            gatelib.anonymous_token('Basic realm="r"', "c", lambda *a, **k: b"{}")

    def test_a_challenge_with_no_realm_is_refused(self):
        with self.assertRaisesRegex(gatelib.RegistryError, "no realm"):
            gatelib.anonymous_token('Bearer service="r"', "c", lambda *a, **k: b"{}")

    def test_a_realm_that_returns_no_token_is_refused(self):
        with self.assertRaisesRegex(gatelib.RegistryError, "no token"):
            gatelib.anonymous_token('Bearer realm="https://a/t"', "c",
                                    lambda *a, **k: b"{}")


class Registry:
    """A registry served at the urlopen level, wanting a bearer token first."""

    TOKEN = "t0k"
    CHALLENGE = ('Bearer realm="https://auth.example/token",service="registry.example",'
                 'scope="aws"')

    def __init__(self, host, path, version, config, *, content=b"chart-tgz",
                 media_type=None, digest=None):
        self.base = f"https://{host}/v2/{path}"
        self.version = version
        self.blob = json.dumps(config).encode()
        self.digest = digest or "sha256:" + hashlib.sha256(self.blob).hexdigest()
        self.content = content
        self.content_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.media_type = media_type or gatelib.HELM_CONFIG

    def __call__(self, req):
        url = req.full_url
        if url.startswith("https://auth.example/token?"):
            return json.dumps({"token": self.TOKEN}).encode()
        if auth(req) != f"Bearer {self.TOKEN}":
            return http_error(url, 401, {"WWW-Authenticate": self.CHALLENGE})
        if url == f"{self.base}/manifests/{self.version}":
            return json.dumps({
                "config": {"mediaType": self.media_type, "digest": self.digest},
                "layers": [{"mediaType": gatelib.HELM_CHART_CONTENT,
                            "digest": self.content_digest}],
            }).encode()
        if url == f"{self.base}/blobs/{self.digest}":
            return self.blob
        if url == f"{self.base}/blobs/{self.content_digest}":
            return self.content
        return http_error(url, 404)

    def transport(self, *overrides):
        """A transport answering from this registry, with scripted steps first."""
        return Transport(*overrides, *([self] * 20))


class ReadingAnOciChart(unittest.TestCase):
    META = {"name": "karpenter", "version": "1.2.3", "description": "nodes"}
    REF = "oci://public.ecr.aws/karpenter/karpenter"

    def test_the_config_blob_is_the_metadata(self):
        reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        t = reg.transport()
        self.assertEqual(gatelib.oci_chart_metadata(self.REF, "1.2.3", t.get()), self.META)

    def test_the_token_is_scoped_to_pulling_this_repository_and_fetched_once(self):
        reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        t = reg.transport()
        gatelib.oci_chart_metadata(self.REF, "1.2.3", t.get())
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
            meta = gatelib.oci_chart_metadata(self.REF, "1.2.3", t.get())
        self.assertEqual(meta, self.META)
        urls = t.urls()
        self.assertEqual(urls.count(manifest), gatelib.RETRY_ATTEMPTS)
        self.assertEqual(sum(u.startswith("https://auth.example/") for u in urls), 1)
        self.assertEqual(len(urls), gatelib.RETRY_ATTEMPTS + 2)
        self.assertEqual(t.waits, [gatelib.RETRY_BASE_SECONDS * 2, 2.0])
        self.assertEqual([auth(r) for r in t.requests if r.full_url == manifest],
                         [None] + [f"Bearer {reg.TOKEN}"] * 3)

    def test_a_rate_limit_after_the_challenge_is_reported_at_the_bound(self):
        """The challenge's repeat is one of the RETRY_ATTEMPTS, not extra."""
        reg = Registry("r.example", "c", "1.0.0", self.META)
        manifest = f"{reg.base}/manifests/1.0.0"
        t = Transport(reg, reg, *[http_error(manifest, 429)] * gatelib.RETRY_ATTEMPTS)
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(gatelib.RegistryError):
            gatelib.oci_chart_metadata("oci://r.example/c", "1.0.0", t.get())
        self.assertEqual(t.urls().count(manifest), gatelib.RETRY_ATTEMPTS)
        self.assertEqual(len(t.requests), gatelib.RETRY_ATTEMPTS + 1)

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
            gatelib.oci_chart_metadata("oci://r.example/c", "1.0.0", t.get())
        self.assertEqual(caught.exception.code, 401)
        urls = t.urls()
        self.assertEqual(urls.count(blob), 1)
        self.assertEqual(sum(u.startswith("https://auth.example/") for u in urls), 1)
        self.assertEqual(len(t.requests), 4)

    def test_docker_hub_is_read_from_its_api_host(self):
        reg = Registry("registry-1.docker.io", "envoyproxy/gateway-helm", "1.0.0", self.META)
        meta = gatelib.oci_chart_metadata("oci://docker.io/envoyproxy/gateway-helm",
                                          "1.0.0", reg.transport().get())
        self.assertEqual(meta, self.META)

    def test_a_blob_that_does_not_match_its_digest_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", self.META, digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(gatelib.RegistryError, "does not match its digest"):
            gatelib.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.transport().get())

    def test_an_artifact_that_is_not_a_chart_is_refused(self):
        reg = Registry("r.example", "c", "1.0.0", self.META,
                       media_type="application/vnd.oci.image.config.v1+json")
        with self.assertRaisesRegex(gatelib.RegistryError, "is not a Helm chart"):
            gatelib.oci_chart_metadata("oci://r.example/c", "1.0.0", reg.transport().get())

    def test_the_chart_content_layer_is_the_archive(self):
        reg = Registry("r.example", "c", "1.0.0", self.META, content=b"packaged")
        self.assertEqual(gatelib.oci_chart_content("oci://r.example/c", "1.0.0",
                                                   reg.transport().get()), b"packaged")


class ReadingAnHttpsRepository(unittest.TestCase):
    REPO = "https://charts.example/stable"

    def setUp(self):
        gatelib._INDEXES.clear()
        self.addCleanup(gatelib._INDEXES.clear)
        self.archive = b"loki-archive"
        self.index = {"entries": {"loki": [
            {"name": "loki", "version": "6.1.0", "description": "logs",
             "urls": ["loki-6.1.0.tgz"],
             "digest": hashlib.sha256(self.archive).hexdigest()},
            {"name": "loki", "version": "v7.0.0", "description": "logs", "urls": []},
        ]}}

    def transport(self, *steps):
        index = json.dumps(self.index).encode()   # JSON is YAML
        return Transport(*(steps or (index, self.archive)))

    def test_the_index_entry_is_the_metadata(self):
        t = self.transport()
        meta = gatelib.chart_metadata(self.REPO, "loki", "6.1.0", t.get())
        self.assertEqual(meta, {"name": "loki", "version": "6.1.0", "description": "logs"})
        self.assertEqual(t.urls(), [f"{self.REPO}/index.yaml"])

    def test_a_v_prefix_on_either_side_matches(self):
        t = self.transport()
        self.assertEqual(gatelib.repo_index_entry(self.REPO, "loki", "7.0.0",
                                                  t.get())["version"], "v7.0.0")

    def test_a_version_the_index_does_not_list_was_answered(self):
        t = self.transport()
        with self.assertRaises(gatelib.ChartUnavailable) as caught:
            gatelib.chart_metadata(self.REPO, "loki", "9.9.9", t.get())
        self.assertTrue(caught.exception.answered)
        self.assertIn("lists no loki 9.9.9", str(caught.exception))

    def test_the_archive_is_fetched_relative_to_the_repository_and_kept(self):
        t = self.transport()
        with tempfile.TemporaryDirectory() as tmp:
            cache = pathlib.Path(tmp)
            path = gatelib.chart_archive(self.REPO, "loki", "6.1.0", cache=cache, get=t.get())
            self.assertEqual(path.read_bytes(), self.archive)
            self.assertEqual(t.urls(), [f"{self.REPO}/index.yaml",
                                        f"{self.REPO}/loki-6.1.0.tgz"])
            again = gatelib.chart_archive(self.REPO, "loki", "6.1.0", cache=cache,
                                          get=Transport().get())
            self.assertEqual(again, path, "a kept archive is used without a request")

    def test_an_archive_that_does_not_match_the_index_digest_is_not_kept(self):
        t = self.transport(json.dumps(self.index).encode(), b"tampered")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(gatelib.ChartUnavailable) as caught:
                gatelib.chart_archive(self.REPO, "loki", "6.1.0", cache=pathlib.Path(tmp),
                                      get=t.get())
            self.assertFalse(caught.exception.answered)
            self.assertEqual(list(pathlib.Path(tmp).rglob("*.tgz")), [])

    def test_an_oci_archive_is_kept_under_its_reference(self):
        reg = Registry("r.example", "org/c", "1.0.0", {"name": "c"}, content=b"oci-tgz")
        with tempfile.TemporaryDirectory() as tmp:
            path = gatelib.chart_archive("oci://r.example/org/c", "c", "1.0.0",
                                         cache=pathlib.Path(tmp), get=reg.transport().get())
            self.assertEqual(path.read_bytes(), b"oci-tgz")
            self.assertEqual(path.relative_to(tmp).as_posix(), "r.example_org_c/c-1.0.0.tgz")


class PruningTheChartCache(unittest.TestCase):
    """A cache carried across pin sets keeps the current set and nothing older."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def archive(self, source, chart, version):
        path = gatelib.archive_path(source, chart, version, self.root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"tgz")
        return path

    def test_archives_no_pin_names_are_dropped_and_pinned_ones_kept(self):
        current = self.archive("https://charts.example", "a", "2.0.0")
        older = self.archive("https://charts.example", "a", "1.0.0")
        retired = self.archive("oci://r.example/b", "b", "1.0.0")
        dropped = gatelib.prune_archives({current}, self.root)
        self.assertEqual(dropped, 2)
        self.assertTrue(current.is_file())
        self.assertFalse(older.exists())
        self.assertFalse(retired.exists())

    def test_a_folder_left_empty_goes_with_its_archives(self):
        keep = self.archive("https://charts.example", "a", "1.0.0")
        gone = self.archive("oci://r.example/b", "b", "1.0.0")
        gatelib.prune_archives({keep}, self.root)
        self.assertFalse(gone.parent.exists())
        self.assertTrue(keep.parent.is_dir())

    def test_an_absent_cache_drops_nothing(self):
        self.assertEqual(gatelib.prune_archives(set(), self.root / "absent"), 0)


class WhatAnUnavailableChartMeans(unittest.TestCase):
    """Exit 1 is a finding about a pin; exit 2 is a fact about the network.

    Collapsing them makes an outage read as a defect in the catalogue, and trains
    readers to re-run a red gate rather than read it.
    """

    REPO = "https://charts.example"

    def setUp(self):
        gatelib._INDEXES.clear()
        self.addCleanup(gatelib._INDEXES.clear)

    def unavailable(self, *steps) -> BaseException:
        t = Transport(*steps)
        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(gatelib.ChartUnavailable) as caught:
            gatelib.chart_archive(self.REPO, "c", "1.0.0", cache=pathlib.Path(tmp),
                                  get=t.get())
        return caught.exception

    def test_a_404_was_answered(self):
        exc = self.unavailable(http_error(f"{self.REPO}/index.yaml", 404))
        self.assertTrue(exc.answered)
        self.assertEqual(str(exc), f"HTTP 404 from {self.REPO}/index.yaml")

    def test_a_rate_limit_that_outlasts_the_retries_was_not_answered(self):
        exc = self.unavailable(*[http_error(f"{self.REPO}/index.yaml", 429)]
                               * gatelib.RETRY_ATTEMPTS)
        self.assertFalse(exc.answered)
        self.assertIn("429", str(exc))

    def test_a_server_fault_or_network_error_was_not_answered(self):
        for step in (http_error(f"{self.REPO}/index.yaml", 500),
                     http_error(f"{self.REPO}/index.yaml", 403),
                     urllib.error.URLError("no route to host"),
                     ConnectionResetError("reset by peer")):
            with self.subTest(step=type(step).__name__):
                self.assertFalse(self.unavailable(step).answered)

    def test_the_exit_status_follows_the_answer(self):
        for answered, status in ((True, 1), (False, gatelib.CANNOT_RUN)):
            with self.subTest(answered=answered):
                exc = gatelib.ChartUnavailable("why", answered=answered)
                original = gatelib.chart_archive

                def refuse(*_a, _exc=exc, **_k):
                    raise _exc

                gatelib.chart_archive = refuse
                try:
                    with contextlib.redirect_stdout(io.StringIO()), \
                            self.assertRaises(SystemExit) as caught:
                        gatelib.chart_archive_or_exit(self.REPO, "c", "1.0.0")
                finally:
                    gatelib.chart_archive = original
                self.assertEqual(caught.exception.code, status)


if __name__ == "__main__":
    unittest.main()
