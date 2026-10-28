"""Unit tests for the Falco rule-floor gate.

The gate answers "is every rule set installed on a node one Falco actually
loads?". Its own failure mode is a FALSE NEGATIVE — reporting the fleet healthy
while a tier sits unread on disk — because that failure is silent in exactly the
way the gate exists to prevent. These concentrate on the decisions that produce
it: which paths count as read, and which priorities count as loading a rule.

Everything here is offline. The rule-set reader is exercised against a scripted
registry (scripts/tests/fakeregistry.py) through registry.py's client, the same
path a run against ghcr.io takes.
"""

import contextlib
import hashlib
import http.client
import io
import json
import tarfile
import unittest

import fakeregistry as fake
from gateloader import load

gate = load("check-falco-rule-floor")


class PathIsRead(unittest.TestCase):
    """falcoctl writes to the root of the shared dir; Falco reads a listed set.

    The gap between those two is the defect the gate exists for, so the rule
    deciding it is tested directly rather than through a whole run.
    """

    FILES = {"/etc/falco/falco_rules.yaml", "/etc/falco/falco_rules.local.yaml"}
    DIRS = {"/etc/falco/rules.d"}

    def test_a_named_file_is_read(self):
        self.assertTrue(
            gate.reachable("/etc/falco/falco_rules.yaml", self.FILES, self.DIRS))

    def test_a_file_under_a_named_directory_is_read(self):
        self.assertTrue(
            gate.reachable("/etc/falco/rules.d/extra.yaml", self.FILES, self.DIRS))

    def test_an_installed_but_unnamed_file_is_not_read(self):
        """The exact shape #231 shipped against: the tier downloads and sits."""
        self.assertFalse(
            gate.reachable("/etc/falco/falco-sandbox_rules.yaml", self.FILES, self.DIRS),
            "a rule set falcoctl installs but rules_files does not name was "
            "reported as read, which is the regression this gate exists to catch",
        )

    def test_a_sibling_sharing_a_directory_prefix_is_not_read(self):
        """Anchored on a separator: `rules.d` must not cover `rules.disabled`."""
        self.assertFalse(
            gate.reachable("/etc/falco/rules.disabled", self.FILES, self.DIRS))

    def test_the_directory_itself_is_not_a_rule_file(self):
        self.assertFalse(
            gate.reachable("/etc/falco/rules.d", self.FILES, self.DIRS))


class SeverityOrder(unittest.TestCase):
    """Falco loads a rule when its priority is at least as severe as the floor.

    Getting the direction wrong inverts the gate: it would pass the strict
    configuration it exists to reject and fail the permissive one.
    """

    def test_more_severe_than_the_floor_loads(self):
        self.assertLessEqual(gate.rank("critical"), gate.rank("warning"))

    def test_less_severe_than_the_floor_does_not(self):
        self.assertGreater(gate.rank("info"), gate.rank("warning"))

    def test_informational_is_the_long_spelling_of_info(self):
        self.assertEqual(gate.rank("informational"), gate.rank("info"))

    def test_case_and_padding_are_tolerated(self):
        self.assertEqual(gate.rank("  CRITICAL "), gate.rank("critical"))

    def test_an_unknown_spelling_is_rejected_not_ordered(self):
        """-1 must not sort as "most severe" and quietly load everything."""
        self.assertEqual(gate.rank("urgent"), -1)

    def test_the_minimum_is_permissive_enough_for_info_rules(self):
        """The privileged-container rules are INFO; `notice` leaves them unloaded."""
        self.assertGreaterEqual(gate.rank(gate.MIN_PRIORITY), gate.rank("info"))
        self.assertGreater(gate.rank(gate.MIN_PRIORITY), gate.rank("notice"))


class RulesFilesSplit(unittest.TestCase):
    """rules_files mixes files and directories, and they are matched differently."""

    def setUp(self):
        self._saved = list(gate.failures)
        self.addCleanup(lambda: gate.failures.__setitem__(slice(None), self._saved))
        gate.failures.clear()

    def test_files_and_directories_are_separated(self):
        files, dirs = gate.read_paths(
            {"rules_files": ["/etc/falco/a.yaml", "/etc/falco/b.yml",
                             "/etc/falco/rules.d"]}, "development")
        self.assertEqual(files, {"/etc/falco/a.yaml", "/etc/falco/b.yml"})
        self.assertEqual(dirs, {"/etc/falco/rules.d"})
        self.assertEqual(gate.failures, [])

    def test_a_trailing_slash_does_not_make_a_second_directory(self):
        _, dirs = gate.read_paths({"rules_files": ["/etc/falco/rules.d/"]}, "staging")
        self.assertEqual(dirs, {"/etc/falco/rules.d"})

    def test_an_absent_rules_files_is_reported(self):
        files, dirs = gate.read_paths({}, "production")
        self.assertEqual((files, dirs), (set(), set()))
        self.assertTrue(any("rules_files" in f for f in gate.failures),
                        f"an empty rules_files was accepted: {gate.failures}")


class DerivedFromTheTree(unittest.TestCase):
    """Coordinates and environments come from the repo, never re-declared here."""

    def test_chart_pin_comes_from_the_applicationset(self):
        repo, chart, version = gate.chart_pin()
        self.assertEqual(chart, "falco")
        self.assertTrue(repo.startswith("http"), repo)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_environments_are_read_from_the_addon_directory(self):
        envs = gate.environments()
        self.assertIn("production", envs)
        self.assertTrue(envs, "no environment discovered — the gate would check none")



def _rules_layer(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class ReadingARuleSetThroughTheSharedClient(unittest.TestCase):
    """rulesfile() reads ghcr.io through the shared registry client, not a reader of its own.

    So the anonymous token comes from the challenge, a 429 waits as long as the
    registry asks, the layer is checked against its digest, and a read that
    fails is classified the way every other registry read is — each of which a
    second reader would have to get right separately.
    """

    REPO = "falcosecurity/rules/falco-rules"
    BASE = f"https://ghcr.io/v2/{REPO}"
    MANIFEST = f"{BASE}/manifests/4"
    CHALLENGE = (f'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
                 f'scope="repository:{REPO}:pull"')

    def setUp(self):
        gate.failures.clear()
        self.addCleanup(gate.failures.clear)
        self.layer = _rules_layer({"falco_rules.yaml": "- rule: one\n  priority: INFO\n"})
        self.digest = "sha256:" + hashlib.sha256(self.layer).hexdigest()
        self.config = gate.RULESFILE_CONFIG

    def registry(self, req):
        url = req.full_url
        if url.startswith("https://ghcr.io/token?"):
            return json.dumps({"token": "t"}).encode()
        if fake.auth(req) != "Bearer t":
            return fake.http_error(url, 401, {"WWW-Authenticate": self.CHALLENGE})
        if url == self.MANIFEST:
            return json.dumps({"config": {"mediaType": self.config},
                               "layers": [{"digest": self.digest}]}).encode()
        if url == f"{self.BASE}/blobs/{self.digest}":
            return self.layer
        return fake.http_error(url, 404)

    def authorised(self, answer):
        """A step answering `answer` to a request that carries the token, as ghcr.io would."""
        def step(req):
            if fake.auth(req) != "Bearer t":
                return self.registry(req)
            return answer
        return step

    def read(self, *steps, ref="falco-rules:4"):
        self.transport = fake.Transport(*steps, *([self.registry] * 20))
        with contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            return gate.rulesfile(ref, self.transport.bind(gate.registry.http_get))

    def cannot_run(self, *steps):
        with self.assertRaises(SystemExit) as caught:
            self.read(*steps)
        self.assertEqual(caught.exception.code, gate.gatelib.CANNOT_RUN)
        self.assertEqual(gate.failures, [], "a read that failed was reported as a finding")

    def test_a_rule_set_is_read_with_a_token_the_challenge_named(self):
        files = self.read()
        self.assertEqual(files, {"falco_rules.yaml": "- rule: one\n  priority: INFO\n"})
        urls = self.transport.urls()
        token = [u for u in urls if u.startswith("https://ghcr.io/token?")]
        self.assertEqual(len(token), 1)
        self.assertIn(f"scope=repository%3A{self.REPO.replace('/', '%2F')}%3Apull",
                      token[0])
        self.assertEqual(urls.count(self.MANIFEST), 2)
        self.assertEqual(gate.failures, [])

    def test_a_rate_limit_waits_as_long_as_the_registry_asks(self):
        files = self.read(self.registry, self.registry,
                          fake.http_error(self.MANIFEST, 429, {"Retry-After": "7"}))
        self.assertIn("falco_rules.yaml", files)
        self.assertEqual(self.transport.waits, [7.0])

    def test_a_rate_limit_that_never_relents_cannot_run(self):
        self.cannot_run(self.registry, self.registry,
                        *[fake.http_error(self.MANIFEST, 429)] * 3)

    def test_a_ref_the_registry_does_not_have_is_a_finding(self):
        files = self.read(ref="falco-rules:99")
        self.assertIsNone(files)
        self.assertEqual(len(gate.failures), 1)
        self.assertIn("does not resolve", gate.failures[0])

    def test_a_manifest_status_other_than_404_cannot_run(self):
        """Only a 404 says the ref is not there. A 403 or a 500 says nothing about it."""
        for code in (403, 500):
            with self.subTest(code=code):
                self.cannot_run(self.registry, self.registry,
                                self.authorised(fake.http_error(self.MANIFEST, code)))

    def test_a_manifest_cut_off_mid_body_cannot_run(self):
        """http.client.IncompleteRead is no OSError; READ_FAILURES is what catches it."""
        self.cannot_run(self.registry, self.registry,
                        self.authorised(http.client.IncompleteRead(b"{")))

    def test_a_manifest_that_is_not_json_cannot_run(self):
        self.cannot_run(self.registry, self.registry, self.authorised(b"<html>"))

    def test_a_layer_the_registry_refuses_cannot_run(self):
        blob = f"{self.BASE}/blobs/{self.digest}"
        self.cannot_run(self.registry, self.registry, self.registry,
                        self.authorised(fake.http_error(blob, 403)))

    def test_a_layer_cut_off_mid_body_cannot_run(self):
        self.cannot_run(self.registry, self.registry, self.registry,
                        self.authorised(http.client.IncompleteRead(b"")))

    def test_a_layer_that_does_not_match_its_digest_cannot_run(self):
        self.layer, good = b"tampered", self.layer
        self.digest = "sha256:" + hashlib.sha256(good).hexdigest()
        self.cannot_run()

    def test_an_artifact_that_is_not_a_rulesfile_installs_no_rules(self):
        """A plugin's config names another media type, and no layer of it is read."""
        self.config = "application/vnd.cncf.falco.plugin.config.v1+json"
        self.assertIsNone(self.read())
        self.assertEqual(gate.failures, [])
        self.assertNotIn(f"{self.BASE}/blobs/{self.digest}", self.transport.urls())


if __name__ == "__main__":
    unittest.main()
