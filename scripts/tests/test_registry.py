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

Time is read off the fake transport, which charges every request the whole
timeout the client gave it, every wait the time it slept and every read of a
trickled body the time the server took over it. A deadline held there is one
the client keeps when nothing answers in time.
"""

import contextlib
import datetime
import email.utils
import functools
import hashlib
import http.client
import io
import itertools
import json
import os
import pathlib
import re
import shutil
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
from unittest import mock

import fakeregistry as fake
import gateloader
import yaml
from fakeregistry import NOW, auth, http_error
from gateloader import load

registry = load("registry")


def own_process_records(test: unittest.TestCase) -> None:
    """Give `test` its own record of the lines said and the logins refused.

    Both are the process's, so a refusal one test plants would otherwise leave
    every later test in the run asking that host anonymously.
    """
    for name in ("_SAID", "_REFUSED_LOGINS"):
        patch = mock.patch.object(registry, name, set[str]())
        patch.start()
        test.addCleanup(patch.stop)


class TheSuiteReadsNoStoredLogin(unittest.TestCase):
    def test_docker_config_is_an_empty_directory_the_harness_made(self):
        """gateloader points the process at it before any gate is loaded, so no
        suite reads the logins of whoever runs it, and a token request in a test
        carries no credentials the test did not write."""
        config = os.environ.get("DOCKER_CONFIG")
        self.assertEqual(config, gateloader.DOCKER_CONFIG)
        self.assertEqual(list(pathlib.Path(config).iterdir()), [])
        self.assertEqual(registry.docker_credentials(), {})


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


class RetryingOnlyWhatMayClear(unittest.TestCase):
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

    def test_the_backoff_doubles_to_the_longest_wait_by_the_last_retry(self):
        """A registry that names no wait is waited on as long as one naming the
        longest this client takes, which is the wait the deadline holds room for
        before every retry. One stopping short spends every attempt while the
        throttling it is waiting out still holds."""
        t = Transport(*[http_error(self.URL, 429)] * registry.RETRY_ATTEMPTS)
        with self.assertRaises(registry.RegistryError):
            self.get(t)
        base = registry.RETRY_BASE_SECONDS
        self.assertEqual(t.waits, [base * 2 ** i for i in range(registry.RETRY_ATTEMPTS - 1)])
        self.assertEqual(t.waits[-1], registry.RETRY_MAX_WAIT_SECONDS)

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

    def test_a_call_throttled_at_every_retry_ends_inside_the_bound(self):
        """Every attempt is made, and the call still ends inside its deadline.

        The deadline is derived to fit RETRY_ATTEMPTS requests and the longest
        wait before each retry. One left short of that spends the attempts the
        client promises on a deadline instead, and reports a deadline rather
        than the status the registry kept answering with.
        """
        longest = str(int(registry.RETRY_MAX_WAIT_SECONDS))
        cases = {"the longest Retry-After": {"Retry-After": longest}, "backoff": {}}
        for label, headers in cases.items():
            with self.subTest(label):
                t = Transport(*[http_error(self.URL, 429, headers)] * registry.RETRY_ATTEMPTS)
                with self.assertRaises(registry.RegistryError) as caught:
                    self.get(t, jitter=1.0)
                self.assertEqual(len(t.requests), registry.RETRY_ATTEMPTS)
                self.assertIn(f"HTTP 429 to the last of {registry.RETRY_ATTEMPTS}",
                              str(caught.exception))
                self.assertLessEqual(t.elapsed, registry.CALL_DEADLINE_SECONDS)

    def test_no_request_is_given_longer_than_the_call_has_left(self):
        t = Transport(urllib.error.URLError("timed out"))
        with self.assertRaises(urllib.error.URLError):
            self.get(t, deadline=t.elapsed + 7)
        self.assertEqual(t.timeouts, [7])

    def test_a_wait_that_would_end_past_the_deadline_is_reported_not_slept(self):
        t = Transport(http_error(self.URL, 503, {"Retry-After": "30"}), b"ok")
        with self.assertRaises(registry.RegistryError) as caught:
            self.get(t, deadline=registry.HTTP_TIMEOUT + 20)
        self.assertEqual(t.waits, [])
        self.assertEqual(len(t.requests), 1)
        self.assertIn("would end past", str(caught.exception))

    def test_a_call_whose_deadline_has_passed_makes_no_request(self):
        t = Transport(b"ok")
        with self.assertRaisesRegex(registry.RegistryError, "ran out before request 1"):
            self.get(t, deadline=t.elapsed)
        self.assertEqual(t.requests, [])

    def test_a_retry_after_at_the_cap_is_slept(self):
        """The cap is the longest wait taken, not the shortest refused."""
        cap = str(int(registry.RETRY_MAX_WAIT_SECONDS))
        t = Transport(http_error(self.URL, 429, {"Retry-After": cap}), b"ok")
        self.assertEqual(self.get(t), b"ok")
        self.assertEqual(t.waits, [registry.RETRY_MAX_WAIT_SECONDS])

    def test_a_wait_beyond_the_cap_is_reported_not_slept(self):
        asked = int(registry.RETRY_MAX_WAIT_SECONDS) + 1
        t = Transport(http_error(self.URL, 429, {"Retry-After": str(asked)}))
        with self.assertRaises(registry.RegistryError) as caught:
            self.get(t)
        self.assertEqual(t.waits, [])
        self.assertEqual(len(t.requests), 1)
        self.assertIn(f"Retry-After {asked}s", str(caught.exception))

    def test_a_gateway_or_an_unavailable_server_is_retried(self):
        """A 502, 503 or 504 is a proxy or server that could not answer this time."""
        for code in (502, 503, 504):
            with self.subTest(code=code):
                t = Transport(http_error(self.URL, code), b"ok")
                self.assertEqual(self.get(t), b"ok")
                self.assertEqual(len(t.requests), 2)
                self.assertEqual(t.waits, [registry.RETRY_BASE_SECONDS])

    def test_a_503_waits_as_long_as_its_retry_after_asks(self):
        t = Transport(http_error(self.URL, 503, {"Retry-After": "9"}), b"ok")
        self.assertEqual(self.get(t), b"ok")
        self.assertEqual(t.waits, [9.0])

    def test_other_statuses_are_reported_on_the_first_attempt(self):
        for code in (400, 401, 403, 404, 500):
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

        def answer(www, _deadline):
            seen.append(www)
            return "Bearer fresh"

        self.assertEqual(self.get(t, challenge=answer), b"ok")
        self.assertEqual(seen, ["Bearer x"])
        self.assertEqual([auth(r) for r in t.requests], [None, "Bearer fresh"])

    def test_the_challenge_is_handed_the_calls_own_deadline(self):
        t = Transport(http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}), b"ok")
        handed = []
        self.get(t, deadline=500.0,
                 challenge=lambda _www, deadline: handed.append(deadline) or "Bearer t")
        self.assertEqual(handed, [500.0])

    def test_a_second_401_is_reported_not_answered_again(self):
        t = Transport(http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}),
                      http_error(self.URL, 401, {"WWW-Authenticate": "Bearer x"}), b"ok")
        answers = []
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get(t, challenge=lambda www, _d: answers.append(www) or "Bearer t")
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
            self.get(t, challenge=lambda www, _d: answers.append(www) or "Bearer t")
        self.assertIn(f"asked for a token on the last of {registry.RETRY_ATTEMPTS}",
                      str(caught.exception))
        self.assertEqual(answers, [])
        self.assertEqual(len(t.requests), registry.RETRY_ATTEMPTS)


class SpacingRequestsToAHost(unittest.TestCase):
    """A host that serves an anonymous client a request a second is sent no more.

    ECR Public refuses a client over its quota with a 429 and no Retry-After. A
    chart read is four requests to it, and sent back to back they draw that 429
    on their own, which the retries then have to wait out. The transport answers
    each request in LATENCY seconds, inside the spacing, so a client that did not
    space its requests sends them closer together than the host allows.
    """

    HOST = "public.ecr.aws"
    OTHER = "registry.example"
    LATENCY = 0.2
    META = {"name": "karpenter", "version": "1.2.3"}

    def setUp(self):
        self.spacing = registry.REQUEST_SPACING_SECONDS[self.HOST]

    def transport(self, *steps) -> Transport:
        t = Transport(*steps)
        t.latency = self.LATENCY
        return t

    def assertSpaced(self, times: list[float]):
        self.assertGreater(len(times), 1, "no two requests to compare")
        for earlier, later in itertools.pairwise(times):
            self.assertGreaterEqual(later - earlier, self.spacing)

    def test_the_spacing_sits_above_the_quota_ecr_public_allows(self):
        """One unauthenticated pull a second, a quota AWS does not adjust."""
        self.assertGreater(registry.REQUEST_SPACING_SECONDS["public.ecr.aws"], 1.0)

    def test_successive_reads_of_a_spaced_host_are_spaced(self):
        t = self.transport(b"ok", b"ok", b"ok")
        get = t.get()
        for blob in ("a", "b", "c"):
            get(f"https://{self.HOST}/v2/x/blobs/{blob}", {}, None)
        self.assertSpaced(t.sent_at)
        self.assertEqual(len(t.waits), 2)
        for wait in t.waits:
            self.assertAlmostEqual(wait, self.spacing - self.LATENCY)

    def test_a_chart_read_spaces_its_challenge_token_and_repeat(self):
        """ECR Public's token realm is on the registry's own host, so the token
        request a challenge leads to is held to the same spacing."""
        reg = Registry(self.HOST, "karpenter/karpenter", "1.2.3", self.META,
                       realm=f"https://{self.HOST}/token/")
        t = self.transport(*[reg] * 4)
        registry.oci_chart_content(f"oci://{self.HOST}/karpenter/karpenter", "1.2.3", t.get())
        self.assertEqual({urllib.parse.urlsplit(u).netloc for u in t.urls()}, {self.HOST})
        self.assertEqual(len(t.requests), 4)
        self.assertSpaced(t.sent_at)

    def test_a_host_with_no_spacing_is_not_spaced(self):
        t = self.transport(b"ok", b"ok", b"ok")
        get = t.get()
        for blob in ("a", "b", "c"):
            get(f"https://{self.OTHER}/v2/x/blobs/{blob}", {}, None)
        self.assertEqual(t.waits, [])

    def test_each_host_is_spaced_from_its_own_last_request(self):
        """A request to another host in between neither resets nor extends the spacing."""
        t = self.transport(b"ok", b"ok", b"ok")
        get = t.get()
        get(f"https://{self.HOST}/v2/x/blobs/a", {}, None)
        get(f"https://{self.OTHER}/v2/x/blobs/b", {}, None)
        get(f"https://{self.HOST}/v2/x/blobs/c", {}, None)
        self.assertEqual(len(t.waits), 1)
        self.assertAlmostEqual(t.waits[0], self.spacing - 2 * self.LATENCY)

    def test_calls_given_no_record_share_the_processes(self):
        """Every gate's calls in one process read the one record, so a chart read
        is spaced from the chart read before it."""
        t = self.transport(b"ok", b"ok")
        get = functools.partial(registry.http_get, urlopen=t.urlopen, sleep=t.sleep,
                                clock=lambda: NOW, timer=lambda: t.elapsed)
        with mock.patch.dict(registry._LAST_SENT, clear=True):
            get(f"https://{self.HOST}/v2/x/blobs/a", {}, None)
            get(f"https://{self.HOST}/v2/x/blobs/b", {}, None)
            self.assertIn(self.HOST, registry._LAST_SENT)
        self.assertSpaced(t.sent_at)

    def test_a_retry_waits_its_backoff_and_no_spacing_on_top(self):
        """The shortest backoff outlasts every spacing, so a retry after a backoff
        waits nothing more, and the room the deadline holds for a retry's wait
        covers the spacing whichever of the two is longer."""
        url = f"https://{self.HOST}/v2/x/manifests/1.2.3"
        t = self.transport(http_error(url, 429), b"ok")
        with contextlib.redirect_stderr(io.StringIO()):
            t.get()(url, {}, None)
        self.assertEqual(t.waits, [registry.RETRY_BASE_SECONDS])
        self.assertGreater(registry.RETRY_BASE_SECONDS,
                           max(registry.REQUEST_SPACING_SECONDS.values()))

    def test_a_retry_after_inside_the_spacing_is_followed_by_what_it_left(self):
        """A registry naming no wait at all is still asked again no sooner than
        the spacing after the request it refused, and no later."""
        url = f"https://{self.HOST}/v2/x/manifests/1.2.3"
        t = self.transport(http_error(url, 429, {"Retry-After": "0"}), b"ok")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(t.get()(url, {}, None), b"ok")
        self.assertEqual(len(t.waits), 2)
        self.assertEqual(t.waits[0], 0.0)
        self.assertAlmostEqual(t.waits[1], self.spacing - self.LATENCY)
        self.assertSpaced(t.sent_at)

    def test_a_retry_after_that_outlasts_the_spacing_has_no_spacing_on_top(self):
        """The spacing runs from the refused request, so the wait before the retry
        counts toward it, and nothing is added to a wait that outlasts it."""
        url = f"https://{self.HOST}/v2/x/manifests/1.2.3"
        asked = 1.0
        self.assertGreater(self.LATENCY + asked, self.spacing,
                           "the fixture must outlast the spacing")
        t = self.transport(http_error(url, 429, {"Retry-After": f"{asked:.0f}"}), b"ok")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(t.get()(url, {}, None), b"ok")
        self.assertEqual(t.waits, [asked])
        self.assertSpaced(t.sent_at)

    def test_a_spacing_wait_that_would_end_past_the_deadline_is_reported_not_slept(self):
        t = self.transport(b"ok", b"ok")
        get = t.get()
        get(f"https://{self.HOST}/v2/x/blobs/a", {}, None)
        with self.assertRaises(registry.RegistryError) as caught:
            get(f"https://{self.HOST}/v2/x/blobs/b", {}, None, deadline=t.elapsed + 0.5)
        self.assertEqual(t.waits, [])
        self.assertEqual(len(t.requests), 1)
        said = str(caught.exception)
        self.assertIn("ran out before request 1", said)
        self.assertIn(f"inside the {self.spacing:g}s kept between requests to it", said)

    def test_a_spacing_wait_that_overran_the_deadline_sends_nothing(self):
        """A sleep can end later than it was asked to, and the request after it is
        then one the call has no time left for."""
        t = self.transport(b"ok", b"ok")
        get = t.get()
        get(f"https://{self.HOST}/v2/x/blobs/a", {}, None)
        t.on_sleep = lambda: setattr(t, "elapsed", t.elapsed + 5)
        with self.assertRaisesRegex(registry.RegistryError, "ran out before request 1"):
            get(f"https://{self.HOST}/v2/x/blobs/b", {}, None, deadline=t.elapsed + 2)
        self.assertEqual(len(t.requests), 1)

    def test_a_paced_call_throttled_at_every_retry_makes_every_attempt(self):
        """The spacing has no room of its own in the deadline. It falls before a
        call's first request, which still leaves every attempt inside it."""
        url = f"https://{self.HOST}/v2/x/manifests/1.2.3"
        longest = {"Retry-After": str(int(registry.RETRY_MAX_WAIT_SECONDS))}
        t = Transport(b"ok", *[http_error(url, 429, longest)] * registry.RETRY_ATTEMPTS)
        t.latency = self.LATENCY
        get = t.get(jitter=1.0)
        get(f"https://{self.HOST}/v2/x/blobs/a", {}, None)
        t.latency = None
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(registry.RegistryError) as caught:
            get(url, {}, None)
        self.assertIn(f"HTTP 429 to the last of {registry.RETRY_ATTEMPTS}",
                      str(caught.exception))
        self.assertEqual(t.urls().count(url), registry.RETRY_ATTEMPTS)
        self.assertLessEqual(t.elapsed - self.LATENCY, registry.CALL_DEADLINE_SECONDS)


class ReadingABody(unittest.TestCase):
    """A body is read a socket read at a time, each only while the call has time left.

    urlopen's timeout bounds each wait on the socket, not the body, so a server
    that keeps sending inside it keeps one read of the whole body going for as
    long as it likes. Read that way, a call outlives its deadline and every job
    timeout above it, and the job is cancelled with nothing said about the host.
    """

    URL = "https://registry.example/v2/x/blobs/sha256:abc"
    BODY = bytes(range(256)) * 64

    def get(self, t: Transport) -> bytes:
        with contextlib.redirect_stderr(io.StringIO()):
            return t.get()(self.URL, {}, None)

    def test_a_body_that_trickles_past_the_deadline_is_cut_off_and_reported(self):
        """Each read is charged just under HTTP_TIMEOUT, so no socket wait times out.

        The call is reported once its deadline has passed, with the rest of the
        body unread, and it ends within CALL_BOUND_SECONDS: the deadline plus the
        one socket read already under way when it passed. Chunked, the size line
        ahead of each chunk arrives a read at a time too, and is held to the
        same deadline.
        """
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                t = Transport()
                t.steps.append(t.trickle(self.BODY, piece=256, chunked=chunked,
                                         seconds=registry.HTTP_TIMEOUT - 1))
                with self.assertRaises(registry.RegistryError) as caught:
                    self.get(t)
                said = str(caught.exception)
                self.assertIn(f"registry.example: the {registry.CALL_DEADLINE_SECONDS:.0f}s "
                              f"one call is allowed ran out while the body of {self.URL}",
                              said)
                wire = t.responses[0].wire
                self.assertGreater(wire.unsent(), 0, "the body was read to its end")
                self.assertTrue(wire.closed, "the connection was left open")
                self.assertGreater(t.elapsed, registry.CALL_DEADLINE_SECONDS)
                self.assertLessEqual(t.elapsed, registry.CALL_BOUND_SECONDS)

    def test_a_body_arriving_over_many_reads_is_read_whole(self):
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                t = Transport()
                t.steps.append(t.trickle(self.BODY, piece=1000, seconds=1.0,
                                         chunked=chunked))
                self.assertEqual(self.get(t), self.BODY)
                self.assertEqual(t.responses[0].wire.unsent(), 0)

    def test_a_body_cut_off_before_its_content_length_is_an_incomplete_read(self):
        """Short of what Content-Length promised is a read that failed, which
        READ_FAILURES classifies, not a smaller body handed to the caller."""
        t = Transport(lambda _req: fake.served(b"short", length=10))
        with self.assertRaises(http.client.IncompleteRead):
            self.get(t)


class TheJobsReadingThroughTheClient(unittest.TestCase):
    """Every workflow job that reads through the client outlasts one client call.

    A job cancelled while a call waits out a 429 reports nothing about which
    registry refused it, and a job with no timeout waits on a registry that
    throttles call after call until the runner's own ceiling. A job reads
    through the client when it keeps or restores the chart cache, or when it
    runs a gate that reads through it — importing registry, or reading a chart
    with gatelib.chart_archive_or_exit — with --live or --fetch, the flags a
    gate reads upstream under. Each job restoring the cache also reads it under
    the key the charts job keeps it under, or it finds nothing and fetches
    every chart from its own address.
    """

    ROOT = pathlib.Path(__file__).resolve().parents[2]
    NETWORK_FLAGS = {"--live", "--fetch"}
    SCRIPT = re.compile(r"(?:\./)?scripts/([\w.-]+\.py)")

    def client_scripts(self) -> set[str]:
        """Gate scripts that read through the registry client."""
        reads = r"^import registry$|^from registry import |\bgatelib\.chart_archive_or_exit\("
        return {p.name for p in (self.ROOT / "scripts").glob("*.py")
                if re.search(reads, p.read_text(), re.M)}

    def cache_key(self, step) -> str | None:
        uses = str(step.get("uses", ""))
        path = str((step.get("with") or {}).get("path", ""))
        if uses.startswith("actions/cache") and path.endswith("/eks-gitops/charts"):
            return str(step["with"]["key"])
        return None

    def reads_upstream(self, step, clients: set[str]) -> bool:
        for line in str(step.get("run", "")).splitlines():
            words = line.split()
            for i, word in enumerate(words):
                found = self.SCRIPT.fullmatch(word)
                if found and found.group(1) in clients and self.NETWORK_FLAGS & set(words[i + 1:]):
                    return True
        return False

    def client_jobs(self) -> dict[str, tuple[dict, str | None, bool]]:
        """{workflow:job: (job, chart cache key or None, runs a gate reading upstream)}."""
        clients = self.client_scripts()
        found = {}
        for workflow in sorted((self.ROOT / ".github/workflows").glob("*.yml")):
            for name, job in (yaml.safe_load(workflow.read_text())["jobs"] or {}).items():
                steps = job.get("steps") or []
                key = next((k for k in map(self.cache_key, steps) if k), None)
                upstream = any(self.reads_upstream(step, clients) for step in steps)
                if key or upstream:
                    found[f"{workflow.name}:{name}"] = (job, key, upstream)
        return found

    def test_the_charts_job_and_its_readers_are_found(self):
        jobs = self.client_jobs()
        self.assertIn("ci.yml:charts", jobs)
        readers = [n for n, (_, key, _) in jobs.items() if key and n != "ci.yml:charts"]
        self.assertTrue(readers, "no job restores what the charts job keeps")

    def test_the_scheduled_reads_of_upstream_are_found(self):
        """The --live gates read the registry without the cache, on a schedule."""
        live = [n for n, (_, key, upstream) in self.client_jobs().items()
                if upstream and not key]
        self.assertTrue(live, "no job runs a gate that reads upstream through the client")

    def test_each_allows_longer_than_one_call(self):
        for name, (job, _, _) in self.client_jobs().items():
            with self.subTest(job=name):
                minutes = job.get("timeout-minutes")
                self.assertIsInstance(minutes, int, f"{name} sets no timeout-minutes")
                self.assertGreater(minutes * 60, registry.CALL_BOUND_SECONDS)

    def test_each_reads_the_key_the_charts_job_keeps(self):
        jobs = {n: key for n, (_, key, _) in self.client_jobs().items() if key}
        kept = jobs["ci.yml:charts"]
        self.assertIn("scripts/registry.py", kept,
                      "a client change would hand every job the archives the last one kept")
        for name, key in jobs.items():
            with self.subTest(job=name):
                self.assertEqual(key, kept)


class RequestingAToken(unittest.TestCase):
    def token_url(self, challenge: str, body=None) -> str:
        asked = []

        def get(url, headers, authorization, **_):
            asked.append(url)
            return json.dumps(body or {"token": "t"}).encode()

        self.assertEqual(registry.pull_token(challenge, "org/chart", get),
                         registry.PullToken("t", logged_in=False))
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
            registry.pull_token('Basic realm="r"', "c", lambda *a, **k: b"{}")

    def test_a_challenge_with_no_realm_is_refused(self):
        with self.assertRaisesRegex(registry.RegistryError, "no realm"):
            registry.pull_token('Bearer service="r"', "c", lambda *a, **k: b"{}")

    def test_a_realm_that_returns_no_token_is_refused(self):
        for body in (b"{}", b'["t"]'):
            with self.subTest(body=body), \
                    self.assertRaisesRegex(registry.RegistryError, "no token"):
                registry.pull_token('Bearer realm="https://a/t"', "c",
                                         lambda *a, _b=body, **k: _b)

    def test_a_realm_that_answers_something_other_than_json_raises_a_read_failure(self):
        with self.assertRaises(registry.READ_FAILURES):
            registry.pull_token('Bearer realm="https://a/t"', "c",
                                     lambda *a, **k: b"<html>sign in</html>")


class RequestingATokenAsALoggedInClient(unittest.TestCase):
    """A token asked for with the credentials `docker login` stored.

    ECR Public meters an anonymous client by its address, which a CI runner
    shares, and a logged-in one by its account. The credentials reach a realm
    only when the registry being read and the realm are both the host they
    were stored for, port included, and the realm is HTTPS. A challenge is the
    registry's to write, so a registry naming another host's realm would
    otherwise have the client spend that host's credentials on a token, and be
    sent the token on every read.
    """

    CREDENTIALS = {"public.ecr.aws": "QVdTOnNlY3JldA=="}
    LOGGED_IN = "Basic QVdTOnNlY3JldA=="

    def setUp(self):
        own_process_records(self)

    def authorization(self, realm: str, registry_host: str | None = "public.ecr.aws",
                      credentials=CREDENTIALS) -> str | None:
        """What the token request carried, held to what the token says bought it."""
        sent = []

        def get(url, headers, authorization, **_):
            sent.append(authorization)
            return b'{"token": "t"}'

        bought = registry.pull_token(f'Bearer realm="{realm}"', "org/chart", get,
                                     registry=registry_host, credentials=credentials)
        self.assertEqual(bought, registry.PullToken("t", logged_in=sent[0] is not None))
        return sent[0]

    def test_the_realm_on_the_registry_the_credentials_were_stored_for_receives_them(self):
        self.assertEqual(self.authorization("https://public.ecr.aws/token/"), self.LOGGED_IN)

    def test_a_host_that_refused_its_login_is_asked_anonymously(self):
        registry._REFUSED_LOGINS.add("public.ecr.aws")
        self.assertIsNone(self.authorization("https://public.ecr.aws/token/"))

    def test_a_registry_on_a_port_is_matched_with_its_port(self):
        """`docker login host:port` stores the port in the key, and the realm names it."""
        self.assertEqual(self.authorization("https://registry.example:5000/token",
                                            "registry.example:5000",
                                            {"registry.example:5000": "cG9ydA=="}),
                         "Basic cG9ydA==")

    def test_a_realm_on_another_host_is_asked_anonymously(self):
        self.assertIsNone(self.authorization("https://auth.example/token"))

    def test_a_registry_naming_the_realm_of_the_host_the_credentials_are_for_is_anonymous(self):
        """The realm is the credentials' host, and the registry being read is not."""
        self.assertIsNone(self.authorization("https://public.ecr.aws/token/",
                                             "registry.example"))

    def test_a_realm_on_another_port_of_the_host_is_asked_anonymously(self):
        self.assertIsNone(self.authorization("https://public.ecr.aws:8443/token/"))

    def test_a_realm_over_plain_http_is_asked_anonymously(self):
        self.assertIsNone(self.authorization("http://public.ecr.aws/token/"))

    def test_no_credentials_ask_anonymously(self):
        self.assertIsNone(self.authorization("https://public.ecr.aws/token/", credentials=None))

    def test_a_request_naming_no_registry_is_anonymous(self):
        self.assertIsNone(self.authorization("https://public.ecr.aws/token/", None))

    def test_the_repository_hands_its_credentials_to_the_token_request(self):
        sent = []

        def get(url, headers, authorization, *, challenge=None, deadline=None):
            if "/token/" in url:
                sent.append(authorization)
                return b'{"token": "t"}'
            if challenge is not None:
                return challenge('Bearer realm="https://public.ecr.aws/token/",'
                                 'service="public.ecr.aws"', 0.0) and b"{}"
            return b"{}"

        repo = registry.OciRepository("oci://public.ecr.aws/karpenter/karpenter", get,
                                      self.CREDENTIALS)
        repo.read("manifests/1.2.3")
        self.assertEqual(sent, [self.LOGGED_IN])
        self.assertEqual((repo.token, repo.logged_in), ("t", True))

    def test_a_registry_naming_another_hosts_realm_is_sent_no_token_the_credentials_bought(self):
        """End to end through http_get: the registry is answered with the token
        the realm issues an anonymous client, on the repeat and every read after."""
        realm = "https://public.ecr.aws/token/"

        def serve(req):
            if req.full_url.startswith(realm):
                token = "account" if auth(req) == self.LOGGED_IN else "anonymous"
                return json.dumps({"token": token}).encode()
            if auth(req) is None:
                return http_error(req.full_url, 401,
                                  {"WWW-Authenticate": f'Bearer realm="{realm}"'})
            return b"{}"

        t = Transport(*[serve] * 4)
        repo = registry.OciRepository("oci://registry.example/org/chart", t.get(),
                                      self.CREDENTIALS)
        repo.read("manifests/1.2.3")
        repo.read("manifests/1.2.3")
        sent = [(urllib.parse.urlsplit(r.full_url).netloc, auth(r)) for r in t.requests]
        self.assertEqual(sent, [("registry.example", None),
                                ("public.ecr.aws", None),
                                ("registry.example", "Bearer anonymous"),
                                ("registry.example", "Bearer anonymous")])


class AskingAgainWhenTheLoginIsRefused(unittest.TestCase):
    """A stored login can be refused where an anonymous client is served, as one
    that has expired is, so a refusal of the login is asked again anonymously.

    The realm can refuse the login outright, or issue it a token the registry
    then refuses on the read carrying it, which is how ECR Public answers a
    stale one. Either way the host is read anonymously from then on, stderr
    says so once, and a request refused anonymously as well is reported naming
    the login: the status alone reads as a refusal nothing on this side could
    change, when logging in again would.
    """

    CREDENTIALS = {"public.ecr.aws": "c3RhbGU="}
    LOGGED_IN = "Basic c3RhbGU="
    REALM = "https://public.ecr.aws/token/"
    CHALLENGE = f'Bearer realm="{REALM}",service="public.ecr.aws"'
    REF = "oci://public.ecr.aws/karpenter/karpenter"
    MANIFEST = "https://public.ecr.aws/v2/karpenter/karpenter/manifests/1.2.3"

    def setUp(self):
        own_process_records(self)
        self.sent: list[str | None] = []

    def said(self, why: str) -> str:
        """The line stderr carries once the host refused its login for `why`."""
        return (f"  public.ecr.aws refused the login `docker login` stored for it "
                f"({why}), so it is read anonymously\n")

    def token(self, *answers, credentials=CREDENTIALS):
        """pull_token over one scripted answer per request, each request's
        Authorization recorded in self.sent."""
        self.sent = []
        steps = list(answers)

        def get(url, headers, authorization, **_):
            self.sent.append(authorization)
            step = steps.pop(0)
            if isinstance(step, BaseException):
                raise step
            return step

        return registry.pull_token(self.CHALLENGE, "karpenter/karpenter", get,
                                   registry="public.ecr.aws", credentials=credentials)

    def serve(self, to_login, to_anonymous):
        """A registry whose realm issues the token "login" to the stored login and
        "anon" to everyone else, answering a read carrying either one with what
        the matching callable returns for its URL."""
        def answer(req):
            url = req.full_url
            if url.startswith(self.REALM):
                token = "login" if auth(req) == self.LOGGED_IN else "anon"
                return json.dumps({"token": token}).encode()
            if auth(req) is None:
                return http_error(url, 401, {"WWW-Authenticate": self.CHALLENGE})
            return (to_login if auth(req) == "Bearer login" else to_anonymous)(url)
        return Transport(*[answer] * 12)

    def test_a_realm_refusing_the_login_is_asked_again_anonymously(self):
        for code in sorted(registry.LOGIN_REFUSED):
            with self.subTest(code=code):
                registry._REFUSED_LOGINS.clear()
                registry._SAID.clear()
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    bought = self.token(http_error(self.REALM, code), b'{"token": "anon"}')
                self.assertEqual(bought, registry.PullToken("anon", logged_in=False))
                self.assertEqual(self.sent, [self.LOGGED_IN, None])
                self.assertEqual(registry._REFUSED_LOGINS, {"public.ecr.aws"})
                self.assertEqual(err.getvalue(), self.said(f"HTTP {code} from {self.REALM}"))

    def test_a_realm_refusing_the_anonymous_request_too_names_the_login(self):
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(registry.RegistryError) as caught:
            self.token(http_error(self.REALM, 401), http_error(self.REALM, 403))
        self.assertEqual(str(caught.exception),
                         f"{self.REALM} answered HTTP 401 to a token request for "
                         f"repository:karpenter/karpenter:pull carrying the login `docker "
                         f"login` stored for public.ecr.aws, and HTTP 403 to the same "
                         f"request made anonymously")

    def test_another_status_from_the_realm_is_no_refusal_of_the_login(self):
        """A realm that does not know the scope, or fails, answers an anonymous
        client the same way, so asking again spends a request on the same answer."""
        for code in (400, 404, 500):
            with self.subTest(code=code), \
                    self.assertRaisesRegex(registry.RegistryError,
                                           f"answered HTTP {code} to a token request for "
                                           f"repository:karpenter/karpenter:pull$"):
                self.token(http_error(self.REALM, code))
            self.assertEqual(self.sent, [self.LOGGED_IN])
            self.assertEqual(registry._REFUSED_LOGINS, set())

    def test_a_refused_anonymous_request_is_not_asked_again(self):
        with self.assertRaisesRegex(registry.RegistryError,
                                    "answered HTTP 401 to a token request for "
                                    "repository:karpenter/karpenter:pull$"):
            self.token(http_error(self.REALM, 401), credentials={})
        self.assertEqual(self.sent, [None])
        self.assertEqual(registry._REFUSED_LOGINS, set())

    def test_a_login_refused_once_is_not_offered_again_in_the_process(self):
        """Every OciRepository asks for a token of its own, so a gate reading
        several charts from the host would otherwise spend a refusal on each."""
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.token(http_error(self.REALM, 401), b'{"token": "anon"}')
            bought = self.token(b'{"token": "anon"}')
        self.assertEqual(bought, registry.PullToken("anon", logged_in=False))
        self.assertEqual(self.sent, [None])
        self.assertEqual(err.getvalue(), self.said(f"HTTP 401 from {self.REALM}"))

    def test_a_read_refused_the_logins_token_is_made_again_anonymously(self):
        """The realm issues the stale login a token and the registry refuses the
        read carrying it. The read is made again with an anonymous token, which
        every later read carries."""
        for code in sorted(registry.LOGIN_REFUSED):
            with self.subTest(code=code):
                registry._REFUSED_LOGINS.clear()
                registry._SAID.clear()
                t = self.serve(lambda url, c=code: http_error(url, c), lambda url: b"{}")
                repo = registry.OciRepository(self.REF, t.get(), self.CREDENTIALS)
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(repo.read("manifests/1.2.3"), b"{}")
                    self.assertEqual(repo.read("manifests/1.2.3"), b"{}")
                token = t.urls()[1]
                self.assertTrue(token.startswith(self.REALM), token)
                self.assertEqual([(r.full_url, auth(r)) for r in t.requests],
                                 [(self.MANIFEST, None), (token, self.LOGGED_IN),
                                  (self.MANIFEST, "Bearer login"),
                                  (self.MANIFEST, None), (token, None),
                                  (self.MANIFEST, "Bearer anon"),
                                  (self.MANIFEST, "Bearer anon")])
                self.assertEqual((repo.token, repo.logged_in), ("anon", False))
                self.assertEqual(err.getvalue(), self.said(
                    f"HTTP {code} from {self.MANIFEST} with the token it bought"))

    def test_a_later_read_refused_the_logins_token_is_made_again_anonymously(self):
        """The manifest is served to the login's token and the config blob is not,
        so the refusal arrives on a read carrying a token and no challenge."""
        meta = {"name": "karpenter", "version": "1.2.3"}
        blob = json.dumps(meta).encode()
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        manifest = json.dumps({"config": {"mediaType": fake.HELM_CONFIG,
                                          "digest": digest}}).encode()

        def under_login(url):
            return manifest if "/manifests/" in url else http_error(url, 403)

        t = self.serve(under_login, lambda url: manifest if "/manifests/" in url else blob)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(registry.oci_chart_metadata(self.REF, "1.2.3", t.get(),
                                                         credentials=self.CREDENTIALS), meta)
        blob_url = f"https://public.ecr.aws/v2/karpenter/karpenter/blobs/{digest}"
        self.assertEqual([auth(r) for r in t.requests if r.full_url == blob_url],
                         ["Bearer login", None, "Bearer anon"])

    def test_a_repository_made_after_the_refusal_asks_anonymously_from_the_start(self):
        t = self.serve(lambda url: http_error(url, 403), lambda url: b"{}")
        with contextlib.redirect_stderr(io.StringIO()):
            registry.OciRepository(self.REF, t.get(), self.CREDENTIALS).read("manifests/1.2.3")
            first = len(t.requests)
            registry.OciRepository(self.REF, t.get(), self.CREDENTIALS).read("manifests/1.2.3")
        self.assertEqual([auth(r) for r in t.requests[first:]], [None, None, "Bearer anon"])

    def test_a_read_refused_anonymously_too_names_the_login(self):
        cache = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, cache)
        t = self.serve(lambda url: http_error(url, 403), lambda url: http_error(url, 401))
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(registry.ChartUnavailable) as caught:
            registry.chart_archive(self.REF, "karpenter", "1.2.3", cache=cache, get=t.get(),
                                   credentials=self.CREDENTIALS)
        self.assertFalse(caught.exception.answered)
        self.assertEqual(str(caught.exception),
                         f"RegistryError: public.ecr.aws answered HTTP 403 to {self.MANIFEST} "
                         f"with the token the login `docker login` stored for it bought, and "
                         f"HTTP 401 to the same read made anonymously")

    def test_any_other_failure_of_the_anonymous_read_is_left_as_it_is(self):
        """A 404 to the anonymous read is the registry answering for the pin."""
        cache = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, cache)
        t = self.serve(lambda url: http_error(url, 403), lambda url: http_error(url, 404))
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(registry.ChartUnavailable) as caught:
            registry.chart_archive(self.REF, "karpenter", "1.2.3", cache=cache, get=t.get(),
                                   credentials=self.CREDENTIALS)
        self.assertTrue(caught.exception.answered)
        self.assertEqual(str(caught.exception), f"HTTP 404 from {self.MANIFEST}")

    def test_another_failure_under_the_logins_token_is_not_made_again(self):
        t = self.serve(lambda url: http_error(url, 404), lambda url: b"{}")
        repo = registry.OciRepository(self.REF, t.get(), self.CREDENTIALS)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            repo.read("manifests/1.2.3")
        self.assertEqual(caught.exception.code, 404)
        self.assertEqual(len(t.requests), 3)
        self.assertEqual(registry._REFUSED_LOGINS, set())

    def test_a_read_refused_an_anonymous_token_is_not_made_again(self):
        """With no login sent, a second anonymous token is refused for the same reason."""
        for code in sorted(registry.LOGIN_REFUSED):
            with self.subTest(code=code):
                t = self.serve(lambda url: b"{}", lambda url, c=code: http_error(url, c))
                repo = registry.OciRepository(self.REF, t.get(), {})
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    repo.read("manifests/1.2.3")
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(len(t.requests), 3)
                self.assertEqual(registry._REFUSED_LOGINS, set())


class ReadingDockerCredentials(unittest.TestCase):
    """What `docker login` left in a config directory, by registry host."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        own_process_records(self)

    def write(self, doc) -> None:
        (self.dir / "config.json").write_text(doc if isinstance(doc, str) else json.dumps(doc))

    def read(self) -> tuple[dict[str, str], str]:
        """The credentials read from this test's directory, and what was printed."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            found = registry.docker_credentials(self.dir)
        return found, err.getvalue()

    def test_a_bare_host_and_a_url_key_each_name_their_host(self):
        """`docker login` writes a bare host; Docker Hub's key and an insecure
        registry's are URLs, over HTTPS and plain HTTP."""
        self.write({"auths": {"public.ecr.aws": {"auth": "a"},
                              "https://index.docker.io/v1/": {"auth": "b"},
                              "http://insecure.example/": {"auth": "c"}}})
        self.assertEqual(self.read(), ({"public.ecr.aws": "a", "index.docker.io": "b",
                                        "insecure.example": "c"}, ""))

    def test_a_key_keeps_the_port_it_names(self):
        """A registry on another port of a host is another registry."""
        self.write({"auths": {"registry.example:5000": {"auth": "a"},
                              "https://mirror.example:8443/v2/": {"auth": "b"}}})
        self.assertEqual(registry.docker_credentials(self.dir),
                         {"registry.example:5000": "a", "mirror.example:8443": "b"})

    def test_an_entry_a_credential_helper_holds_is_left_out_and_said(self):
        """The secret is in the helper, not the file, so there is nothing to send,
        and the hosts it leaves anonymous are named once."""
        self.write({"auths": {"public.ecr.aws": {}, "ghcr.io": "x", "r.example": {"auth": ""},
                              "": {"auth": "c"}, "[::1": {"auth": "d"}},
                    "credsStore": "desktop"})
        found, said = self.read()
        self.assertEqual(found, {})
        self.assertEqual(said, f"  {self.dir / 'config.json'}: stores no `auth` for ghcr.io, "
                               f"public.ecr.aws, r.example, as when a credential helper "
                               f"holds it, so each is read anonymously\n")

    def test_a_config_with_no_logins_is_no_credentials_and_says_nothing(self):
        for doc in ({}, {"credsStore": "desktop"}, {"auths": {}}):
            with self.subTest(doc=doc):
                self.write(doc)
                self.assertEqual(self.read(), ({}, ""))

    def test_no_file_is_no_credentials_and_says_nothing(self):
        self.assertEqual(self.read(), ({}, ""))

    def test_a_file_that_is_no_docker_config_is_no_credentials_and_is_said(self):
        path = self.dir / "config.json"
        cases = {"not json": "not readable as a docker config",
                 '["auths"]': "holds no `auths` object",
                 '{"auths": ["public.ecr.aws"]}': "holds no `auths` object"}
        for doc, reason in cases.items():
            with self.subTest(doc=doc):
                registry._SAID.clear()
                self.write(doc)
                found, said = self.read()
                self.assertEqual(found, {})
                self.assertTrue(said.startswith(f"  {path}: {reason}"), said)
                self.assertTrue(said.endswith("so every registry is read anonymously\n"), said)

    def test_a_config_that_cannot_be_read_is_said(self):
        (self.dir / "config.json").mkdir()
        found, said = self.read()
        self.assertEqual(found, {})
        self.assertIn("not readable as a docker config", said)

    def test_a_config_is_said_once_however_many_reads_meet_it(self):
        """A gate builds an OciRepository per chart, each reading the config again."""
        self.write({"auths": {"public.ecr.aws": {}}})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for _ in range(3):
                registry.docker_credentials(self.dir)
        self.assertEqual(err.getvalue().count("\n"), 1, err.getvalue())

    def test_docker_config_names_the_directory_and_home_is_the_fallback(self):
        self.write({"auths": {"public.ecr.aws": {"auth": "a"}}})
        with mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(self.dir)}):
            self.assertEqual(registry.docker_credentials(), {"public.ecr.aws": "a"})
        home = self.dir / "home"
        (home / ".docker").mkdir(parents=True)
        (home / ".docker" / "config.json").write_text(
            json.dumps({"auths": {"ghcr.io": {"auth": "g"}}}))
        with mock.patch.dict(os.environ, {"DOCKER_CONFIG": ""}), \
                mock.patch.object(pathlib.Path, "home", return_value=home):
            self.assertEqual(registry.docker_credentials(), {"ghcr.io": "g"})

    def test_a_repository_given_no_credentials_asks_with_the_ones_docker_stored(self):
        self.write({"auths": {"public.ecr.aws": {"auth": "a"}}})
        sent = []

        def get(url, headers, authorization, *, challenge=None, deadline=None):
            if "/token/" in url:
                sent.append(authorization)
                return b'{"token": "t"}'
            if challenge is not None:
                return challenge('Bearer realm="https://public.ecr.aws/token/"', 0.0) and b"{}"
            return b"{}"

        with mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(self.dir)}):
            registry.OciRepository("oci://public.ecr.aws/x/y", get).read("manifests/1")
        self.assertEqual(sent, ["Basic a"])


class ReadingAnOciChart(unittest.TestCase):
    META = {"name": "karpenter", "version": "1.2.3", "description": "nodes"}
    REF = "oci://public.ecr.aws/karpenter/karpenter"

    def test_the_config_blob_is_the_metadata(self):
        reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META)
        t = reg.transport()
        self.assertEqual(registry.oci_chart_metadata(self.REF, "1.2.3", t.get()), self.META)

    def test_each_reader_asks_for_its_token_with_the_credentials_it_is_given(self):
        realm = "https://public.ecr.aws/token/"
        for read in (registry.oci_chart_metadata, registry.oci_chart_content):
            with self.subTest(read=read.__name__):
                reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META,
                               realm=realm)
                t = reg.transport()
                read(self.REF, "1.2.3", t.get(), credentials={"public.ecr.aws": "Y3JlZA=="})
                self.assertEqual([auth(r) for r in t.requests if r.full_url.startswith(realm)],
                                 ["Basic Y3JlZA=="])

    def test_an_archive_is_read_with_the_credentials_it_is_given(self):
        """None is what docker stored, {} is anonymous whatever it stored, and
        anything else is used as given."""
        own_process_records(self)
        config = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, config)
        (config / "config.json").write_text(
            json.dumps({"auths": {"public.ecr.aws": {"auth": "c3RvcmVk"}}}))
        realm = "https://public.ecr.aws/token/"
        cases = {"none given": (None, ["Basic c3RvcmVk"]), "empty": ({}, [None]),
                 "given": ({"public.ecr.aws": "Z2l2ZW4="}, ["Basic Z2l2ZW4="])}
        for label, (credentials, expected) in cases.items():
            with self.subTest(label):
                cache = pathlib.Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, cache)
                reg = Registry("public.ecr.aws", "karpenter/karpenter", "1.2.3", self.META,
                               realm=realm)
                t = reg.transport()
                with mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(config)}):
                    registry.chart_archive(self.REF, "karpenter", "1.2.3", cache=cache,
                                           get=t.get(), credentials=credentials)
                self.assertEqual([auth(r) for r in t.requests if r.full_url.startswith(realm)],
                                 expected)

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

    def test_a_challenged_call_throttled_everywhere_ends_inside_the_bound(self):
        """The token request a 401 leads to spends the deadline of the call it answers.

        Given one of its own, a realm that throttles to the longest wait it can
        ask for runs a whole deadline inside the call that asked for the token,
        and the call runs past its own deadline and the bound the CI jobs are
        held above.
        """
        longest = {"Retry-After": str(int(registry.RETRY_MAX_WAIT_SECONDS))}
        manifest = "https://r.example/v2/c/manifests/1.0.0"
        realm = 'Bearer realm="https://auth.example/token",service="registry.example"'

        def throttled(realm_relents_after):
            asked = []

            def answer(req):
                if req.full_url.startswith("https://auth.example/token?"):
                    asked.append(req.full_url)
                    if len(asked) > realm_relents_after:
                        return json.dumps({"token": "t"}).encode()
                    return http_error(req.full_url, 429, longest)
                if auth(req) is None:
                    return http_error(manifest, 401, {"WWW-Authenticate": realm})
                return http_error(manifest, 429, longest)
            return answer

        cases = {"the realm refuses every request": registry.RETRY_ATTEMPTS,
                 "the realm relents, the registry does not": 2}
        for label, relents_after in cases.items():
            with self.subTest(label):
                t = Transport(*[throttled(relents_after)] * (2 * registry.RETRY_ATTEMPTS))
                repo = registry.OciRepository("oci://r.example/c", t.get(jitter=1.0))
                with contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaises(registry.RegistryError):
                    repo.manifest("1.0.0")
                self.assertTrue(any(u.startswith("https://auth.example/") for u in t.urls()))
                self.assertLessEqual(t.elapsed, registry.CALL_DEADLINE_SECONDS)

    def test_a_rate_limit_after_the_challenge_is_reported_at_the_bound(self):
        """The challenge's repeat is one of the RETRY_ATTEMPTS, not extra.

        Each 429 names a short Retry-After, so the waits stay far inside the
        call's deadline and the request bound is what ends the call: a client
        allowing one request more makes it rather than running out first."""
        reg = Registry("r.example", "c", "1.0.0", self.META)
        manifest = f"{reg.base}/manifests/1.0.0"
        t = Transport(reg, reg, *[http_error(manifest, 429, {"Retry-After": "1"})]
                      * registry.RETRY_ATTEMPTS)
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

    def test_an_archive_cut_off_before_its_rename_leaves_no_record(self):
        """The archive is renamed into place first, so a write that stops there
        leaves no record for _intact to vouch for it by."""
        archive = self.cache / "c-1.0.0.tgz"
        real = os.replace

        def replace(src, dst):
            if pathlib.Path(dst) == archive:
                raise OSError("no space left on device")
            return real(src, dst)

        with mock.patch.object(registry.os, "replace", replace), \
                self.assertRaises(OSError):
            registry._keep(archive, self.archive)
        self.assertFalse(registry.digest_path(archive).exists())

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
    """`answered` is a finding about a pin; anything else is a fact about the network.

    Collapsing them makes an outage read as a defect in the catalogue, and trains
    readers to re-run a red gate rather than read it. The exit status each earns
    is gatelib.refuse_chart's, held in test_gatelib.
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

    def test_a_404_from_the_token_realm_was_not_answered(self):
        """The realm issues tokens and holds no charts: its 404 says nothing about the pin."""
        reg = Registry("r.example", "c", "1.0.0", {"name": "c"})

        def realm_404(req):
            if req.full_url.startswith("https://auth.example/token?"):
                return http_error(req.full_url, 404)
            return reg(req)

        exc = self.unavailable(realm_404, realm_404, source=self.OCI)
        self.assertFalse(exc.answered)
        self.assertIn("https://auth.example/token answered HTTP 404 to a token request",
                      str(exc))

    def test_a_gateway_that_never_recovers_was_not_answered(self):
        exc = self.unavailable(*[http_error(f"{self.REPO}/index.yaml", 503)]
                               * registry.RETRY_ATTEMPTS)
        self.assertFalse(exc.answered)
        self.assertIn("HTTP 503", str(exc))

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



if __name__ == "__main__":
    unittest.main()
