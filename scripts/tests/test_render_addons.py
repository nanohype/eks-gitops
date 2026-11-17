"""Unit tests for the render gate's discovery and failure classification.

render-addons is the corpus every other render-based gate reads: the image-pin
gate and the policy-admission gate both import its `discover()` rather than
re-deriving which chart a path belongs to. A unit it does not find is a unit
three gates never examine, and all three print a count derived from the same
short list — so the omission reports itself as a complete run.

It fetches every chart from a registry, so the positive-control sweep exempts
it. These exercise what decides the result without a network: which units exist,
where each is fetched from, and what a render is handed. What an unavailable
chart means is registry.py's, and is held in test_registry.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import fakeregistry as fake
import yaml
from gateloader import load

gate = load("render-addons")


def appset(sources, generators=None, destination=None):
    doc = {"kind": "ApplicationSet",
           "spec": {"template": {"spec": {"sources": sources}}}}
    if generators is not None:
        doc["spec"]["generators"] = generators
    if destination is not None:
        doc["spec"]["template"]["spec"]["destination"] = destination
    return doc


class OciReferences(unittest.TestCase):
    """ArgoCD resolves the OCI digest from repoURL, so the shape of it decides.

    Appending the chart name to a repoURL that already ends in it produces
    `.../karpenter/karpenter`, which is not a package.
    """

    def unit(self, repo, chart):
        return gate.Unit(appset="a.yaml", chart=chart, version="1.0.0",
                         repo=repo, path="addons/x/y")

    def test_a_repo_url_ending_in_the_chart_name_is_used_as_is(self):
        u = self.unit("oci://public.ecr.aws/karpenter/karpenter", "karpenter")
        self.assertEqual(u.oci_ref(), "oci://public.ecr.aws/karpenter/karpenter")

    def test_a_repo_url_naming_the_enclosing_namespace_gets_the_chart_appended(self):
        u = self.unit("oci://ghcr.io/nanohype/charts", "operator")
        self.assertEqual(u.oci_ref(), "oci://ghcr.io/nanohype/charts/operator")

    def test_an_https_repo_is_not_an_oci_one(self):
        self.assertFalse(self.unit("https://kyverno.github.io/kyverno", "kyverno").is_oci)
        self.assertTrue(self.unit("oci://ghcr.io/x/y", "y").is_oci)

    def test_an_oci_chart_is_fetched_from_its_reference(self):
        u = self.unit("oci://ghcr.io/nanohype/charts", "operator")
        self.assertEqual(u.source, "oci://ghcr.io/nanohype/charts/operator")

    def test_an_https_chart_is_fetched_from_its_repository(self):
        u = self.unit("https://kyverno.github.io/kyverno", "kyverno")
        self.assertEqual(u.source, "https://kyverno.github.io/kyverno")


class RecognisingATemplatedField(unittest.TestCase):
    """A templated `chart` is what says an appset renders many units, not one."""

    def test_a_go_template_is_a_template(self):
        self.assertTrue(gate._is_template("{{ .chart }}"))
        self.assertTrue(gate._is_template('{{ index .metadata.labels "environment" }}'))

    def test_a_literal_is_not(self):
        self.assertFalse(gate._is_template("kyverno"))
        self.assertFalse(gate._is_template("3.8.2"))

    def test_a_non_string_is_not(self):
        for value in (None, 3.82, ["{{ .x }}"], {"a": "{{ .x }}"}):
            with self.subTest(value=value):
                self.assertFalse(gate._is_template(value))


class FindingTheChartSource(unittest.TestCase):
    """Multi-source appsets carry a `$values` ref alongside the chart."""

    def test_the_source_carrying_a_chart_key_is_returned(self):
        values_ref = {"repoURL": "{{ .repo }}", "ref": "values"}
        chart = {"repoURL": "https://x", "chart": "loki", "targetRevision": "1"}
        self.assertIs(gate._chart_source([values_ref, chart]), chart)

    def test_an_appset_with_no_chart_source_is_not_ours(self):
        """Kustomize, git-sourced and local-chart appsets render elsewhere."""
        self.assertIsNone(gate._chart_source([{"repoURL": "https://x", "path": "p"}]))

    def test_a_non_mapping_source_is_skipped_rather_than_read(self):
        chart = {"repoURL": "https://x", "chart": "loki"}
        self.assertIs(gate._chart_source(["not-a-mapping", chart]), chart)


class SynthesisingChartParameters(unittest.TestCase):
    """ArgoCD injects the real per-cluster value; the render needs a valid one."""

    def test_a_templated_parameter_takes_its_synthetic_value(self):
        params = gate._synth_params(
            {"parameters": [{"name": "clusterName", "value": "{{ .name }}"}]})
        self.assertEqual(params, [("clusterName", "ci-cluster")])

    def test_a_templated_parameter_with_no_synthetic_value_takes_a_placeholder(self):
        params = gate._synth_params(
            {"parameters": [{"name": "someOther", "value": "{{ .x }}"}]})
        self.assertEqual(params, [("someOther", "ci")])

    def test_a_literal_parameter_is_passed_through(self):
        params = gate._synth_params(
            {"parameters": [{"name": "replicaCount", "value": 3}]})
        self.assertEqual(params, [("replicaCount", "3")])

    def test_a_valueless_parameter_takes_a_synthetic_value(self):
        params = gate._synth_params({"parameters": [{"name": "vpcId"}]})
        self.assertEqual(params, [("vpcId", "vpc-00000000000000000")])

    def test_a_nameless_parameter_is_dropped(self):
        self.assertEqual(gate._synth_params({"parameters": [{"value": "x"}]}), [])

    def test_no_parameters_block_yields_none(self):
        self.assertEqual(gate._synth_params({}), [])
        self.assertEqual(gate._synth_params({"parameters": None}), [])


class TheAddonPathFromValueFiles(unittest.TestCase):
    """A single-source appset states its addon directory only in `valueFiles`."""

    def test_the_base_values_path_is_extracted(self):
        helm = {"valueFiles": [
            "$values/addons/observability/loki/values.yaml",
            "$values/addons/observability/loki/values-production.yaml"]}
        self.assertEqual(gate._path_from_valuefiles(helm),
                         "addons/observability/loki")

    def test_a_per_environment_file_alone_does_not_supply_the_path(self):
        """Matching it would yield a directory that ends in the environment name."""
        helm = {"valueFiles": ["$values/addons/x/y/values-production.yaml"]}
        self.assertIsNone(gate._path_from_valuefiles(helm))

    def test_no_value_files_yields_nothing(self):
        self.assertIsNone(gate._path_from_valuefiles({}))
        self.assertIsNone(gate._path_from_valuefiles({"valueFiles": None}))


class WhatARenderIsHanded(unittest.TestCase):
    """helm renders the fetched archive, never a registry reference.

    A reference would put helm back on the network, where a 429 arrives as a
    line of text with the wait the registry asked for dropped.
    """

    def render(self, env_files=("values.yaml", "values-staging.yaml"), env="staging",
               path="addons/x/y", returncode=0, stderr=""):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        unit_dir = root / "addons" / "x" / "y"
        unit_dir.mkdir(parents=True)
        for name in env_files:
            (unit_dir / name).write_text("{}\n")
        unit = gate.Unit(appset="a.yaml", chart="karpenter", version="1.15.1",
                         repo="oci://public.ecr.aws/karpenter/karpenter",
                         path=path, params=[("clusterName", "ci-cluster")],
                         namespace="kube-system")
        archive = root / "karpenter-1.15.1.tgz"
        ran = mock.Mock(return_value=mock.Mock(returncode=returncode, stdout="",
                                               stderr=stderr))
        fetch = mock.Mock(return_value=archive)
        with mock.patch.object(gate, "REPO_ROOT", root), \
                mock.patch.object(gate.gatelib, "chart_archive_or_exit", fetch), \
                mock.patch.object(gate.subprocess, "run", ran):
            result = gate.render(unit, env)
        return result, fetch, ran, archive, unit_dir

    def test_the_archive_is_fetched_from_the_unit_source_and_rendered(self):
        result, fetch, ran, archive, unit_dir = self.render()
        self.assertEqual(result, (True, "rendered"))
        fetch.assert_called_once_with("oci://public.ecr.aws/karpenter/karpenter",
                                      "karpenter", "1.15.1")
        cmd = ran.call_args.args[0]
        self.assertEqual(cmd[:4], ["helm", "template", "karpenter", str(archive)])
        self.assertNotIn("--version", cmd)
        self.assertFalse(any(str(a).startswith("oci://") for a in cmd))
        self.assertEqual(cmd[4:], ["--namespace", "kube-system",
                                   "--set", "clusterName=ci-cluster",
                                   "-f", str(unit_dir / "values.yaml"),
                                   "-f", str(unit_dir / "values-staging.yaml")])

    def test_an_environment_with_no_delta_fetches_nothing(self):
        result, fetch, ran, _, _ = self.render(env_files=("values.yaml",))
        self.assertEqual(result, (True, "no env delta"))
        fetch.assert_not_called()
        ran.assert_not_called()

    def test_a_path_that_is_not_there_fails_rather_than_skipping(self):
        """An element pointing at nothing would otherwise leave the fleet one
        unit short with every render green."""
        result, fetch, ran, _, _ = self.render(path="addons/x/typo")
        self.assertFalse(result[0])
        self.assertIn("path 'addons/x/typo' does not exist", result[1])
        fetch.assert_not_called()
        ran.assert_not_called()

    def test_a_render_helm_refuses_fails_with_what_helm_said(self):
        result, _, _, _, _ = self.render(returncode=1,
                                         stderr="Error: values don't meet the schema\n")
        self.assertEqual(result, (False, "Error: values don't meet the schema"))


class FetchingTheChartCache(unittest.TestCase):
    """--fetch fills the cache every rendering job reads, and only with pins."""

    def unit(self, chart, repo):
        return gate.Unit(appset="a.yaml", chart=chart, version="1.0.0",
                         repo=repo, path=f"addons/x/{chart}")

    def fetch(self, units, skip=None):
        fetched, pruned = [], []

        def archive(source, chart, version):
            fetched.append((source, chart, version))
            return pathlib.Path(f"/cache/{chart}-{version}.tgz")

        def prune(keep):
            pruned.append(set(keep))
            return 3

        with mock.patch.object(gate.gatelib, "chart_archive_or_exit", archive), \
                mock.patch.object(gate.registry, "prune_archives", prune), \
                mock.patch.dict(gate.SKIP_CHARTS, skip or {}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = gate.fetch_all(units)
        return rc, fetched, pruned, out.getvalue()

    def test_every_pinned_chart_is_fetched_from_its_source(self):
        rc, fetched, pruned, out = self.fetch([
            self.unit("operator", "oci://ghcr.io/nanohype/charts"),
            self.unit("kyverno", "https://kyverno.github.io/kyverno"),
        ])
        self.assertEqual(rc, 0)
        self.assertEqual(fetched, [
            ("oci://ghcr.io/nanohype/charts/operator", "operator", "1.0.0"),
            ("https://kyverno.github.io/kyverno", "kyverno", "1.0.0"),
        ])
        self.assertEqual(pruned, [{pathlib.Path("/cache/operator-1.0.0.tgz"),
                                   pathlib.Path("/cache/kyverno-1.0.0.tgz")}])
        self.assertIn("removed 3 cached file(s) no pin names", out)

    def test_a_skipped_chart_is_neither_fetched_nor_kept(self):
        rc, fetched, pruned, _ = self.fetch(
            [self.unit("kyverno", "https://kyverno.github.io/kyverno"),
             self.unit("private", "https://charts.private.example")],
            skip={"private": "needs credentials"})
        self.assertEqual(rc, 0)
        self.assertEqual([c for _, c, _ in fetched], ["kyverno"])
        self.assertEqual(pruned, [{pathlib.Path("/cache/kyverno-1.0.0.tgz")}])

    def test_nothing_to_fetch_cannot_run_and_prunes_nothing(self):
        rc, fetched, pruned, out = self.fetch([])
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN)
        self.assertEqual((fetched, pruned), ([], []))
        self.assertIn("Cannot run", out)


class FetchingOverTheRegistryClient(unittest.TestCase):
    """--fetch over registry.py itself, with only the transport and the cache scripted.

    FetchingTheChartCache holds what fetch_all asks for. This holds what lands
    on disk when the real client answers it: each pinned archive and its digest
    record under archive_path's naming, nothing a pin does not name, and a
    second run that reads every archive back from the cache.
    """

    REPO = "https://charts.example/stable"
    OCI = ("ghcr.example", "org/charts/operator")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = pathlib.Path(tmp.name)
        self.archive = b"kyverno-archive"
        self.oci = fake.OciRegistry(*self.OCI, "1.0.0",
                                    {"name": "operator", "version": "1.0.0"},
                                    content=b"operator-archive")
        self.urls: list[str] = []
        for patch in (mock.patch.object(gate.registry, "CHART_CACHE", self.cache),
                      mock.patch.dict(gate.registry._INDEXES, clear=True),
                      mock.patch.dict(gate.registry.http_get.__kwdefaults__,
                                      {"urlopen": self.urlopen, "sleep": self.fail_on_wait}),
                      mock.patch.dict(gate.SKIP_CHARTS, clear=True)):
            patch.start()
            self.addCleanup(patch.stop)

    def fail_on_wait(self, seconds):
        self.fail(f"the client waited {seconds}s on a registry that never rate-limits")

    def index(self) -> bytes:
        return yaml.safe_dump({"apiVersion": "v1", "entries": {"kyverno": [{
            "version": "1.0.0", "urls": ["kyverno-1.0.0.tgz"],
            "digest": hashlib.sha256(self.archive).hexdigest()}]}}).encode()

    def urlopen(self, req, timeout=None):
        url = req.full_url
        self.urls.append(url)
        if url == f"{self.REPO}/index.yaml":
            answer = self.index()
        elif url == f"{self.REPO}/kyverno-1.0.0.tgz":
            answer = self.archive
        else:
            answer = self.oci(req)
        if isinstance(answer, BaseException):
            raise answer
        return fake.served(answer)

    def units(self):
        return [gate.Unit(appset="a.yaml", chart="kyverno", version="1.0.0",
                          repo=self.REPO, path="addons/x/kyverno"),
                gate.Unit(appset="b.yaml", chart="operator", version="1.0.0",
                          repo=f"oci://{self.OCI[0]}/org/charts", path="addons/x/operator")]

    def fetch(self):
        """One --fetch run. Each is its own process, so no index outlives it."""
        gate.registry._INDEXES.clear()
        self.urls.clear()
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            rc = gate.fetch_all(self.units())
        return rc, out.getvalue()

    def on_disk(self):
        return sorted(str(p.relative_to(self.cache)) for p in self.cache.rglob("*")
                      if p.is_file())

    def test_the_pinned_archives_and_their_records_are_what_the_cache_holds(self):
        stale = gate.registry.archive_path(self.REPO, "kyverno", "0.9.0")
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"old")
        gate.registry.digest_path(stale).write_text(hashlib.sha256(b"old").hexdigest())
        (stale.parent / ".kyverno-1.0.0.tgz.4242").write_bytes(b"cut off")

        rc, out = self.fetch()

        self.assertEqual(rc, 0, out)
        kept = [gate.registry.archive_path(u.source, u.chart, u.version)
                for u in self.units()]
        self.assertEqual(self.on_disk(), sorted(
            str(p.relative_to(self.cache)) for k in kept
            for p in (k, gate.registry.digest_path(k))))
        self.assertEqual(kept[0].read_bytes(), self.archive)
        self.assertEqual(kept[1].read_bytes(), b"operator-archive")
        for k in kept:
            self.assertEqual(gate.registry.digest_path(k).read_text(),
                             hashlib.sha256(k.read_bytes()).hexdigest())
        self.assertIn("Fetched 2 pinned chart archive(s)", out)
        self.assertIn("removed 3 cached file(s) no pin names", out)

    def test_a_second_run_reads_every_archive_from_the_cache(self):
        self.assertEqual(self.fetch()[0], 0)
        rc, out = self.fetch()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.urls, [])
        self.assertIn("removed 0 cached file(s)", out)

    def test_an_archive_changed_in_the_cache_is_fetched_again(self):
        self.assertEqual(self.fetch()[0], 0)
        kyverno = gate.registry.archive_path(self.REPO, "kyverno", "1.0.0")
        kyverno.write_bytes(b"truncated")
        rc, out = self.fetch()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.urls, [f"{self.REPO}/index.yaml",
                                     f"{self.REPO}/kyverno-1.0.0.tgz"])
        self.assertEqual(kyverno.read_bytes(), self.archive)


class ExpiredSkips(unittest.TestCase):
    """A skip whose chart an anonymous fetch reaches is reported; one it cannot reach stays."""

    def unit(self, chart):
        return gate.Unit(appset="a.yaml", chart=chart, version="1.0.0",
                         repo="https://charts.example", path=f"addons/x/{chart}")

    def stale(self, units, skip, unreachable=()):
        asked = []
        self.handed: list[tuple[pathlib.Path, dict, bool]] = []

        def archive(source, chart, version, *, cache, credentials):
            asked.append(chart)
            self.handed.append((cache, credentials, cache.is_dir()))
            if chart in unreachable:
                raise gate.registry.ChartUnavailable("HTTP 401", answered=False)
            return cache / f"{chart}-{version}.tgz"

        with mock.patch.object(gate.registry, "chart_archive", archive), \
                mock.patch.dict(gate.SKIP_CHARTS, skip, clear=True):
            return gate.stale_skips(units), asked

    def test_the_fetch_is_handed_no_login_and_an_empty_cache_of_its_own(self):
        """Deleted once it returns, so an archive it fetched is not one the next
        fetch, of this chart or any other, finds waiting."""
        self.stale([self.unit("a"), self.unit("b")], {"a": "x", "b": "y"}, unreachable={"b"})
        self.assertEqual([credentials for _, credentials, _ in self.handed], [{}, {}])
        caches = [cache for cache, _, _ in self.handed]
        self.assertEqual([existed for _, _, existed in self.handed], [True, True])
        self.assertNotIn(gate.registry.CHART_CACHE, caches)
        self.assertEqual([cache.exists() for cache in caches], [False, False])

    def test_a_skipped_chart_that_fetches_is_stale(self):
        stale, asked = self.stale([self.unit("private")], {"private": "needs credentials"})
        self.assertEqual(stale, [("private", "needs credentials")])
        self.assertEqual(asked, ["private"])

    def test_a_skipped_chart_that_still_cannot_be_fetched_stays(self):
        stale, _ = self.stale([self.unit("private")], {"private": "needs credentials"},
                              unreachable={"private"})
        self.assertEqual(stale, [])

    def test_a_chart_nothing_skips_is_not_asked_about(self):
        stale, asked = self.stale([self.unit("kyverno"), self.unit("private")],
                                  {"private": "needs credentials"},
                                  unreachable={"private"})
        self.assertEqual((stale, asked), ([], ["private"]))


class AnExpiredSkipIsAskedOfTheRegistryAnonymously(unittest.TestCase):
    """End to end through the client. A chart only a login can fetch is not
    called fetchable for a login stored where the gate runs, nor for an archive
    an earlier fetch left in the chart cache: a run for a fork's pull request
    has neither."""

    HOST = "registry.example"
    LOGIN = "bG9naW4="

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        config = self.root / "docker"
        config.mkdir()
        (config / "config.json").write_text(
            json.dumps({"auths": {self.HOST: {"auth": self.LOGIN}}}))
        self.oci = fake.OciRegistry(self.HOST, "org/charts/private", "1.0.0",
                                    {"name": "private"}, content=b"private-archive",
                                    realm=f"https://{self.HOST}/token")
        self.anonymous_served = False
        self.unit = gate.Unit(appset="a.yaml", chart="private", version="1.0.0",
                              repo=f"oci://{self.HOST}/org/charts", path="addons/x/private")
        for patch in (mock.patch.object(gate.registry, "CHART_CACHE", self.root / "cache"),
                      mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(config)}),
                      mock.patch.object(gate.registry, "_REFUSED_LOGINS", set()),
                      mock.patch.object(gate.registry, "_SAID", set()),
                      mock.patch.dict(gate.registry.http_get.__kwdefaults__,
                                      {"urlopen": self.urlopen}),
                      mock.patch.dict(gate.SKIP_CHARTS, {"private": "needs a login"},
                                      clear=True)):
            patch.start()
            self.addCleanup(patch.stop)

    def urlopen(self, req, timeout=None):
        """The fake registry, its realm issuing a token to the stored login alone
        unless anonymous_served says otherwise."""
        asked_anonymously = fake.auth(req) != f"Basic {self.LOGIN}"
        if (req.full_url.startswith(f"https://{self.HOST}/token?") and asked_anonymously
                and not self.anonymous_served):
            raise fake.http_error(req.full_url, 401)
        answer = self.oci(req)
        if isinstance(answer, BaseException):
            raise answer
        return fake.served(answer)

    def fetch_with_the_stored_login(self, cache=None):
        """What the client fetches holding the login, to show it does fetch."""
        with contextlib.redirect_stderr(io.StringIO()):
            return gate.registry.chart_archive(self.unit.source, "private", "1.0.0",
                                               cache=cache)

    def test_a_chart_only_the_stored_login_fetches_is_no_stale_skip(self):
        fetched = self.fetch_with_the_stored_login(self.root / "elsewhere")
        self.assertEqual(fetched.read_bytes(), b"private-archive")
        self.assertEqual(gate.stale_skips([self.unit]), [])

    def test_an_archive_left_in_the_chart_cache_is_no_stale_skip(self):
        kept = self.fetch_with_the_stored_login()
        self.assertTrue(kept.is_relative_to(self.root / "cache"), kept)
        self.assertEqual(gate.stale_skips([self.unit]), [])

    def test_a_chart_an_anonymous_client_fetches_is_a_stale_skip(self):
        self.anonymous_served = True
        self.assertEqual(gate.stale_skips([self.unit]), [("private", "needs a login")])


class TheDiscoveredCorpus(unittest.TestCase):
    """Every unit three gates share comes from here."""

    @classmethod
    def setUpClass(cls):
        cls.units = gate.discover()

    def test_every_appset_declaring_a_chart_contributes_a_unit(self):
        """Non-emptiness is not a floor: one unit satisfies it, and the omission
        this walk can produce is partial rather than total.

        Derived per file rather than counted, so the assertion holds as the
        catalog grows and fails on the appset that stops being seen.
        """
        contributing = {u.appset for u in self.units}
        missed = []
        for path in sorted(gate.APPSET_DIR.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text())
            if not doc or doc.get("kind") != "ApplicationSet":
                continue
            spec = doc.get("spec") or {}
            sources = ((spec.get("template") or {}).get("spec") or {}).get("sources") or []
            if gate._chart_source(sources) is None:
                continue  # kustomize / git-sourced — not this gate's corpus
            if path.name not in contributing:
                missed.append(path.name)
        self.assertEqual(missed, [],
                         "these ApplicationSets pin a Helm chart and produced no "
                         "render unit, so this gate and the two importing its "
                         "discover() never examine them")

    def test_every_matrix_element_pinning_a_chart_becomes_a_unit(self):
        """A matrix appset contributes one unit per list element, and dropping
        one is the shape that leaves the other gates' counts looking whole."""
        for path in sorted(gate.APPSET_DIR.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text())
            if not doc or doc.get("kind") != "ApplicationSet":
                continue
            spec = doc.get("spec") or {}
            sources = ((spec.get("template") or {}).get("spec") or {}).get("sources") or []
            src = gate._chart_source(sources)
            if src is None or not gate._is_template(src.get("chart")):
                continue
            elements = [e for e in gate._list_elements(spec) if "chart" in e]
            got = [u for u in self.units if u.appset == path.name]
            with self.subTest(appset=path.name):
                self.assertEqual(
                    sorted(u.chart for u in got),
                    sorted(str(e["chart"]) for e in elements),
                    "the units discovered for this appset are not its list "
                    "elements — an element was dropped from the corpus three "
                    "gates share")

    def test_every_unit_names_a_directory_that_exists(self):
        """A typo in an element's `path` removes the addon from three gates."""
        for u in self.units:
            with self.subTest(unit=f"{u.appset}:{u.chart}"):
                self.assertTrue((gate.REPO_ROOT / u.path).is_dir(),
                                f"{u.appset} points {u.chart} at '{u.path}', "
                                f"which is not a directory")

    def test_no_unit_carries_an_unrendered_template(self):
        for u in self.units:
            with self.subTest(unit=f"{u.appset}:{u.chart}"):
                for field in (u.chart, u.version, u.repo, u.path):
                    self.assertNotIn("{{", field)

    def test_every_unit_carries_a_version(self):
        for u in self.units:
            with self.subTest(unit=f"{u.appset}:{u.chart}"):
                self.assertTrue(u.version.strip())

    def test_units_are_unique_per_appset_and_chart(self):
        """Two units for one chart double-count the corpus the floor is read against."""
        seen = [(u.appset, u.chart, u.path) for u in self.units]
        self.assertEqual(len(seen), len(set(seen)))

    def test_every_skipped_chart_is_one_the_corpus_contains(self):
        """A skip naming a chart no appset pins excuses nothing and reads as care."""
        charts = {u.chart for u in self.units}
        for chart in gate.SKIP_CHARTS:
            with self.subTest(chart=chart):
                self.assertIn(chart, charts)


if __name__ == "__main__":
    unittest.main()
