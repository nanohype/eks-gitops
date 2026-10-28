"""Unit tests for the policy-admission gate's verdict.

This gate answers the question the fleet cannot answer anywhere else: would any
addon be DENIED at admission on a cluster running the Enforce-tier policies? It
reaches a chart registry, so the positive-control sweep exempts it — which left
the whole verdict resting on nobody having read it.

The verdict is where it matters. Every branch below is one where a wrong answer
prints the sentence a healthy fleet prints: a canary the run never evaluated, a
runtime pod nothing matched, a namespace receiving workloads that no exclusion
list covers. Each of those produces an empty result set, and an empty result set
is what "no addon was denied" looks like from the outside.

Everything here is offline. helm, kustomize and kyverno are replaced by a stub
that answers the way each one does, so the render walk, the policy build and the
run that ties them together are exercised against the outputs those tools give,
and the report kyverno produces is supplied directly, in the shapes it emits.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-policy-admission")


def quietly(fn, *args, **kwargs):
    """Run a gate function that narrates to stdout, returning its verdict."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


def result(policy="best-practices", rule="require-probes", verdict="fail",
           namespace="workloads", name="app", kind="Deployment"):
    """One entry as kyverno writes it into a policy report."""
    return {
        "policy": policy,
        "rule": rule,
        "result": verdict,
        "resources": [{"kind": kind, "namespace": namespace, "name": name}],
    }


def canary(rule="require-probes", verdict="fail"):
    return result(rule=rule, verdict=verdict,
                  namespace=gate.CANARY_NAMESPACE, name=gate.CANARY_NAME)


def runtime_pod(verdict="pass", rule="require-probes"):
    return result(rule=rule, verdict=verdict, kind="Pod",
                  namespace=gate.RUNTIME_POD_NAMESPACE, name=gate.RUNTIME_POD_NAME)


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["kyverno"], returncode, stdout, stderr)


class NormalisingARender(unittest.TestCase):
    """`_prepare` decides which manifests reach kyverno and in which namespace.

    Both halves change the verdict silently. A workload left unqualified misses
    the namespace exclusion and is reported as a denial that would not happen; a
    manifest dropped here is one the run cannot deny at all.
    """

    def prepare(self, docs, namespace="monitoring"):
        landed: set[str] = set()
        rendered = "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)
        out = list(yaml.safe_load_all(gate._prepare(rendered, namespace, landed)))
        return [d for d in out if d], landed

    def test_a_workload_without_a_namespace_is_qualified_with_the_release_one(self):
        docs, landed = self.prepare([{"apiVersion": "apps/v1", "kind": "Deployment",
                                      "metadata": {"name": "loki"}}])
        self.assertEqual(docs[0]["metadata"]["namespace"], "monitoring")
        self.assertEqual(landed, {"monitoring"})

    def test_a_namespace_the_chart_sets_is_left_alone_and_is_what_lands(self):
        """The coverage claim is about where pods END UP, not where helm aimed."""
        docs, landed = self.prepare([{"apiVersion": "apps/v1", "kind": "DaemonSet",
                                      "metadata": {"name": "agent",
                                                   "namespace": "kube-system"}}])
        self.assertEqual(docs[0]["metadata"]["namespace"], "kube-system")
        self.assertEqual(landed, {"kube-system"},
                         "a chart placing a workload outside the release namespace "
                         "must be recorded where it lands, or the exclusion "
                         "coverage check compares against the wrong namespace")

    def test_a_non_workload_kind_is_neither_qualified_nor_recorded(self):
        docs, landed = self.prepare([{"apiVersion": "v1", "kind": "ConfigMap",
                                      "metadata": {"name": "cfg"}}])
        self.assertNotIn("namespace", docs[0]["metadata"])
        self.assertEqual(landed, set())

    def test_a_helm_test_hook_is_dropped(self):
        """ArgoCD skips test hooks, so a chart's test Pod never hits admission."""
        docs, landed = self.prepare([
            {"apiVersion": "v1", "kind": "Pod",
             "metadata": {"name": "probe",
                          "annotations": {"helm.sh/hook": "test"}}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "real"}},
        ])
        self.assertEqual([d["metadata"]["name"] for d in docs], ["real"])
        self.assertEqual(landed, {"monitoring"})

    def test_a_kindless_document_is_dropped(self):
        """helm v4 prints OCI pull progress ahead of the manifests on a fresh pull.

        Those parse as kind-less mappings. Written back, kyverno rejects the whole
        resource file with "Object 'Kind' is missing" and the run evaluates
        nothing — which reports as no addon being denied.
        """
        docs, _ = self.prepare([{"Pulled": "ghcr.io/x/y:1.0"},
                                {"apiVersion": "v1", "kind": "Pod",
                                 "metadata": {"name": "real"}}])
        self.assertEqual([d["metadata"]["name"] for d in docs], ["real"])

    def test_every_workload_kind_is_qualified(self):
        for kind in sorted(gate.WORKLOAD_KINDS):
            with self.subTest(kind=kind):
                docs, landed = self.prepare(
                    [{"apiVersion": "v1", "kind": kind, "metadata": {"name": "w"}}])
                self.assertEqual(docs[0]["metadata"]["namespace"], "monitoring")
                self.assertEqual(landed, {"monitoring"})


class RuleNamesFromAReport(unittest.TestCase):
    """Kyverno never names a rule the way the policy file does.

    The canary is checked against the rule set read off the policy YAML, so a
    prefix left on turns every autogen variant into an unexercised rule and the
    run fails for a reason that is not true.
    """

    def test_a_plain_rule_is_unchanged(self):
        self.assertEqual(gate._rule_key(result(rule="require-probes")),
                         "best-practices/require-probes")

    def test_the_pod_controller_prefix_is_stripped(self):
        self.assertEqual(gate._rule_key(result(rule="autogen-require-probes")),
                         "best-practices/require-probes")

    def test_the_cronjob_prefix_is_stripped_whole(self):
        """`autogen-cronjob-` must be tried before `autogen-`.

        Stripping the shorter prefix first leaves `cronjob-require-probes`, which
        matches no rule in any policy file.
        """
        self.assertEqual(gate._rule_key(result(rule="autogen-cronjob-require-probes")),
                         "best-practices/require-probes")

    def test_a_rule_whose_name_begins_with_autogen_text_is_not_truncated(self):
        self.assertEqual(gate._rule_key(result(rule="autogenerate-labels")),
                         "best-practices/autogenerate-labels")


class IdentifyingTheProbes(unittest.TestCase):
    """Namespace AND name. Either alone matches an addon that happens to share it."""

    def test_the_canary_is_matched_on_both_coordinates(self):
        self.assertTrue(gate._is_canary(canary()))
        self.assertFalse(gate._is_canary(
            result(namespace="workloads", name=gate.CANARY_NAME)))
        self.assertFalse(gate._is_canary(
            result(namespace=gate.CANARY_NAMESPACE, name="something-else")))

    def test_the_runtime_pod_is_matched_on_both_coordinates(self):
        self.assertTrue(gate._is_runtime_pod(runtime_pod()))
        self.assertFalse(gate._is_runtime_pod(
            result(namespace="workloads", name=gate.RUNTIME_POD_NAME)))

    def test_a_result_carrying_no_resources_matches_neither(self):
        bare = {"policy": "p", "rule": "r", "result": "fail"}
        self.assertFalse(gate._is_canary(bare))
        self.assertFalse(gate._is_runtime_pod(bare))


class TheRuntimePodVerdictIsTwoSided(unittest.TestCase):
    """An Argo workflow step pod carries no probes and cannot.

    "No rule denied it" and "no rule ever saw it" are the same empty result set,
    and the second is the failure being guarded against.
    """

    def test_a_pod_no_rule_evaluated_is_not_admitted(self):
        verdict, out = quietly(gate.judge_runtime_pod, [result(verdict="pass")])
        self.assertFalse(verdict)
        self.assertIn("evaluated by NO rule", out)

    def test_a_pod_at_least_one_rule_passed_and_none_denied_is_admitted(self):
        verdict, _ = quietly(gate.judge_runtime_pod,
                             [runtime_pod("pass"), runtime_pod("pass", "require-labels")])
        self.assertTrue(verdict)

    def test_a_denial_alongside_a_pass_still_fails(self):
        for denial in ("fail", "warn", "error"):
            with self.subTest(denial=denial):
                verdict, out = quietly(
                    gate.judge_runtime_pod,
                    [runtime_pod("pass"), runtime_pod(denial, "require-non-root")])
                self.assertFalse(verdict)
                self.assertIn("denied by 1 rule", out)

    def test_a_skip_is_neither_a_pass_nor_a_denial(self):
        """A skipped rule proves nothing was evaluated, so the pass is missing."""
        verdict, out = quietly(gate.judge_runtime_pod, [runtime_pod("skip")])
        self.assertFalse(verdict)
        self.assertIn("evaluated by NO rule", out)


class TheRunVerdict(unittest.TestCase):
    """`judge` fails on both sides: what was denied, and what was never evaluated."""

    RULES = {"best-practices/require-probes", "best-practices/require-labels"}

    def clean_report(self, canary_result="fail"):
        return {
            "summary": {"pass": 1, "fail": 2},
            "results": [canary("require-probes", canary_result),
                        canary("require-labels", canary_result),
                        runtime_pod("pass")],
        }

    def judge(self, report, proc=None, canary_result="fail"):
        return quietly(gate.judge, "test", report, proc or completed(),
                       self.RULES, canary_result)

    def test_a_run_that_exercised_every_rule_and_flagged_nothing_passes(self):
        verdict, out = self.judge(self.clean_report())
        self.assertTrue(verdict)
        self.assertIn("canary failed by all 2 rules", out)
        self.assertIn("no addon flagged", out)

    def test_an_empty_report_at_exit_zero_is_named_as_matching_nothing(self):
        """Kyverno emits nothing and exits 0 when its rules matched no resource.

        That is indistinguishable from success to an exit-code check, which is
        why the verdict is read out of the report instead.
        """
        verdict, out = self.judge(None, completed(returncode=0, stdout=""))
        self.assertFalse(verdict)
        self.assertIn("matched NO resource", out)

    def test_an_unparseable_report_reports_the_child_failure(self):
        verdict, out = self.judge(None, completed(returncode=2, stderr="panic: boom"))
        self.assertFalse(verdict)
        self.assertIn("panic: boom", out)

    def test_a_rule_that_never_reported_the_canary_fails_the_run(self):
        report = self.clean_report()
        report["results"] = [r for r in report["results"]
                             if r["rule"] != "require-labels"]
        verdict, out = self.judge(report)
        self.assertFalse(verdict)
        self.assertIn("require-labels", out)
        self.assertIn("did not evaluate", out)

    def test_a_canary_reported_at_the_wrong_result_does_not_count_as_exercised(self):
        """An Enforce run that only warns has not enforced anything."""
        verdict, out = self.judge(self.clean_report(canary_result="warn"),
                                  canary_result="fail")
        self.assertFalse(verdict)
        self.assertIn("did not evaluate", out)

    def test_a_flagged_addon_fails_the_run(self):
        report = self.clean_report()
        report["results"].append(result(namespace="monitoring", name="loki",
                                        verdict="fail"))
        verdict, out = self.judge(report)
        self.assertFalse(verdict)
        self.assertIn("monitoring/loki", out)

    def test_the_runtime_pod_is_not_counted_among_flagged_addons(self):
        """Its verdict is judged separately and names what actually broke."""
        report = self.clean_report()
        report["results"].append(runtime_pod("fail", "require-non-root"))
        verdict, out = self.judge(report)
        self.assertFalse(verdict)
        self.assertIn("no addon flagged", out)
        self.assertIn("runtime pod was denied", out)

    def test_a_long_list_of_flagged_addons_is_cut_at_twenty_and_counted(self):
        report = self.clean_report()
        report["results"] += [result(namespace="monitoring", name=f"w{i}")
                              for i in range(23)]
        verdict, out = self.judge(report)
        self.assertFalse(verdict)
        self.assertIn("23 non-canary result(s)", out)
        self.assertIn("monitoring/w19", out)
        self.assertNotIn("monitoring/w20", out)
        self.assertIn("… and 3 more", out)

    def test_a_clean_canary_cannot_carry_a_missing_runtime_pod(self):
        report = self.clean_report()
        report["results"] = [r for r in report["results"]
                             if not gate._is_runtime_pod(r)]
        verdict, out = self.judge(report)
        self.assertFalse(verdict)
        self.assertIn("evaluated by NO rule", out)


class ExclusionCoverage(unittest.TestCase):
    """"Uncovered" and "compliant" must stop being the same signal.

    A new addon in a new namespace is a workload the policies WILL evaluate on a
    vended cluster. The canary run alone reports it only if it also happens to
    violate a rule.
    """

    def test_a_namespace_on_no_exclusion_list_fails(self):
        verdict, out = quietly(gate.check_namespace_coverage,
                               {"monitoring", "brand-new"}, {"monitoring"})
        self.assertFalse(verdict)
        self.assertIn("brand-new", out)

    def test_every_landed_namespace_excluded_passes(self):
        verdict, _ = quietly(gate.check_namespace_coverage,
                             {"monitoring"}, {"monitoring", "kube-system"})
        self.assertTrue(verdict)

    def test_an_exclusion_list_wider_than_the_fleet_is_not_this_check(self):
        """Breadth is not a failure here: a namespace excluded before its addon
        arrives is normal. Whether the four lists agree with each other is
        check_exclusion_parity's question, planted against in ExclusionListParity."""
        verdict, _ = quietly(gate.check_namespace_coverage, set(), {"monitoring"})
        self.assertTrue(verdict)


class ExclusionListParity(unittest.TestCase):
    """The four lists must agree, against a policy tree carrying a divergence.

    The exclusion list is what makes the fleet admissible at all, and it is
    hand-maintained across four files. A divergence is invisible to every other
    gate: each policy is individually valid, renders, and passes kyverno's own
    unit tests. It surfaces on a vended Enforce cluster, as one workload denied
    where its three siblings were admitted.

    So the divergence is planted rather than the agreement asserted. `ok` is a
    bool, and a function that returns True unconditionally satisfies every
    assertion a healthy tree can make about it.
    """

    def policies(self, lists):
        """A POLICY_DIR holding the four exclusion-bearing policies.

        `lists` maps each (group, filename) pair to the namespaces its single
        rule excludes, so a caller states the divergence directly.
        """
        root = pathlib.Path(tempfile.mkdtemp())
        for (group, fname), namespaces in lists.items():
            base = root / group / "base"
            base.mkdir(parents=True, exist_ok=True)
            (base / fname).write_text(yaml.safe_dump({
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {"name": fname.removesuffix(".yaml")},
                "spec": {"rules": [{
                    "name": "rule",
                    "exclude": {"any": [
                        {"resources": {"namespaces": list(namespaces)}}]},
                }]},
            }))
        return root

    def parity(self, lists):
        original = gate.POLICY_DIR
        gate.POLICY_DIR = self.policies(lists)
        try:
            return quietly(gate.check_exclusion_parity)
        finally:
            gate.POLICY_DIR = original

    def agreeing(self, namespaces=("monitoring", "kyverno")):
        return dict.fromkeys(gate.EXCLUSION_POLICIES, namespaces)

    def test_four_identical_lists_agree(self):
        (ok, excluded, keys), _ = self.parity(self.agreeing())
        self.assertTrue(ok)
        self.assertEqual(excluded, {"monitoring", "kyverno"})
        self.assertEqual(len(keys), len(gate.EXCLUSION_POLICIES))

    def test_one_list_missing_a_namespace_is_a_mismatch(self):
        """The shape that admits three workloads and denies the fourth."""
        lists = dict(self.agreeing())
        lists[gate.EXCLUSION_POLICIES[2]] = ("monitoring",)
        (ok, _, _), out = self.parity(lists)
        self.assertFalse(ok)
        self.assertIn("MISMATCH", out)
        self.assertIn("missing: ['kyverno']", out)
        self.assertIn("exclusion lists diverge", out)

    def test_one_list_carrying_an_extra_namespace_is_a_mismatch(self):
        lists = dict(self.agreeing())
        lists[gate.EXCLUSION_POLICIES[1]] = ("monitoring", "kyverno", "falco")
        (ok, _, _), out = self.parity(lists)
        self.assertFalse(ok)
        self.assertIn("extra:   ['falco']", out)

    def test_order_alone_is_not_a_divergence(self):
        """Kyverno ORs the entries; the lists are sets, not sequences."""
        lists = dict(self.agreeing())
        lists[gate.EXCLUSION_POLICIES[3]] = ("kyverno", "monitoring")
        (ok, _, _), _ = self.parity(lists)
        self.assertTrue(ok)

    def test_the_namespaces_returned_are_the_shared_baseline(self):
        """The functional half checks its coverage against this set, so a wrong
        one reports namespaces as excluded that no policy excludes."""
        (_, excluded, _), _ = self.parity(self.agreeing(("a", "b", "c")))
        self.assertEqual(excluded, {"a", "b", "c"})

    def test_a_rule_key_is_returned_per_rule(self):
        """The canary must trip every key, read off the policies rather than
        restated — so a rule added without extending the canary fails."""
        (_, _, keys), _ = self.parity(self.agreeing())
        self.assertIn("require-probes/rule", keys)


class ASecondExcludeEntryIsPartOfTheList(unittest.TestCase):
    """Kyverno ORs every `exclude.any` entry, so reading any[0] drops the rest."""

    def policy_with_two_entries(self, first, second):
        root = pathlib.Path(tempfile.mkdtemp())
        for group, fname in gate.EXCLUSION_POLICIES:
            base = root / group / "base"
            base.mkdir(parents=True, exist_ok=True)
            entries = [{"resources": {"namespaces": list(first)}}]
            if fname == gate.EXCLUSION_POLICIES[0][1]:
                entries.append({"resources": {"namespaces": list(second)}})
            (base / fname).write_text(yaml.safe_dump({
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {"name": fname.removesuffix(".yaml")},
                "spec": {"rules": [{"name": "rule",
                                    "exclude": {"any": entries}}]},
            }))
        return root

    def test_the_union_of_both_entries_is_the_list(self):
        original = gate.POLICY_DIR
        gate.POLICY_DIR = self.policy_with_two_entries(("monitoring",), ("falco",))
        try:
            (ok, _, _), out = quietly(gate.check_exclusion_parity)
        finally:
            gate.POLICY_DIR = original
        # The first policy excludes {monitoring, falco}; the other three exclude
        # {monitoring}. Reading only any[0] would make all four agree.
        self.assertFalse(ok, "a second exclude.any entry was dropped from the "
                             "parity comparison, so four lists that differ were "
                             "reported as identical")
        self.assertIn("falco", out)


class TheExclusionCorpusIsReal(unittest.TestCase):
    """The four policies the parity check compares must exist to be compared."""

    def test_each_named_exclusion_policy_is_a_file_in_the_tree(self):
        for group, name in gate.EXCLUSION_POLICIES:
            path = gate.POLICY_DIR / group / "base" / name
            with self.subTest(policy=f"{group}/{name}"):
                self.assertTrue(path.exists(),
                                f"{path} is named as an exclusion-bearing policy "
                                f"but does not exist, so the parity check compares "
                                f"three lists and reports agreement")

    def test_the_shipped_policies_agree(self):
        (ok, excluded, keys), _ = quietly(gate.check_exclusion_parity)
        self.assertTrue(ok)
        self.assertTrue(excluded)
        self.assertTrue(keys)


def deployment(name="app", namespace="workloads", replicas=1):
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"replicas": replicas}}


class WhatReachesKyverno(unittest.TestCase):
    """The resource set the CLI loads into its in-memory API server.

    That server refuses a whole run over one object it would not hold, so what
    reaches it is decided here: only the kinds the policies evaluate, and one
    object per identity — without losing an environment's own variant.
    """

    def test_only_workload_kinds_are_handed_over(self):
        prepared = "\n---\n".join(yaml.safe_dump(d) for d in (
            deployment(),
            {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
             "metadata": {"name": "things.example.io"}},
            {"apiVersion": "v1", "kind": "List", "items": []},
        ))
        self.assertEqual([d["kind"] for d in gate.workloads(prepared)], ["Deployment"])

    def test_an_exact_repeat_is_dropped(self):
        out = gate.distinct_identities([deployment(), deployment()])
        self.assertEqual(len(out), 1)

    def test_a_differing_repeat_is_kept_under_its_own_name(self):
        out = gate.distinct_identities([deployment(replicas=1), deployment(replicas=3)])
        self.assertEqual([d["metadata"]["name"] for d in out], ["app", "app--2"])
        self.assertEqual(out[1]["spec"]["replicas"], 3,
                         "the environment's variant is the object kept, renamed")
        self.assertEqual(out[1]["metadata"]["namespace"], "workloads",
                         "the namespace decides the exclusion, so it never moves")

    def test_the_same_name_in_another_namespace_is_not_a_repeat(self):
        out = gate.distinct_identities([deployment(), deployment(namespace="other")])
        self.assertEqual([d["metadata"]["name"] for d in out], ["app", "app"])


class TheReportOnStdout(unittest.TestCase):
    """`kyverno apply` prints deprecation lines on stdout ahead of the report."""

    def test_the_report_after_warning_lines_is_read(self):
        out = ("Warning: a.yaml: kyverno.io/v1 ClusterPolicy is deprecated\n"
               '{"results": [], "summary": {"pass": 1}}\n')
        self.assertEqual(gate.report_json(out), {"results": [], "summary": {"pass": 1}})

    def test_no_object_is_no_report(self):
        self.assertIsNone(gate.report_json("Warning: only a warning\n"))
        self.assertIsNone(gate.report_json(""))

    def test_an_object_that_does_not_decode_is_no_report(self):
        self.assertIsNone(gate.report_json('{"results": [\n'))


def unit(chart="loki", repo="https://grafana.github.io/helm-charts", path="addons/x/loki",
         namespace="monitoring", params=()):
    return gate.render_addons.Unit(appset="addons-x", chart=chart, version="1.0.0",
                                   repo=repo, path=path, params=list(params),
                                   namespace=namespace)


DEPLOYMENT = yaml.safe_dump(deployment(name="w", namespace="monitoring"))


class Tools:
    """Stands in for `_run`: records each command and answers by its first word.

    `answers` maps helm/kustomize/kyverno to a CompletedProcess, or to a function
    of the command for a reply that depends on what was asked.
    """

    def __init__(self, **answers) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **_):
        self.calls.append(cmd)
        answer = self.answers.get(cmd[0], completed())
        return answer(cmd) if callable(answer) else answer


class RenderingTheFleet(unittest.TestCase):
    """`render_fleet` turns the discovered units into the resource set kyverno sees.

    Each early return is a render it could not complete, and returning a count
    from one would hand the policies a fleet missing whatever came after it.
    """

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.out = self.root / "rendered"
        self.out.mkdir()

    def addon(self, path="addons/x/loki", envs=("staging", "production"), base=True):
        d = self.root / path
        d.mkdir(parents=True, exist_ok=True)
        if base:
            (d / "values.yaml").write_text("{}\n")
        for env in envs:
            (d / f"values-{env}.yaml").write_text("{}\n")

    def render(self, units, tools, skip=(), kustomize=()):
        aliases = {u.repo: "alias" for u in units}
        with mock.patch.object(gate, "REPO_ROOT", self.root), \
             mock.patch.object(gate, "discover", return_value=units), \
             mock.patch.object(gate, "add_repos", return_value=aliases), \
             mock.patch.object(gate, "SKIP_CHARTS", dict.fromkeys(skip, "reason")), \
             mock.patch.object(gate, "KUSTOMIZE_WORKLOADS", list(kustomize)), \
             mock.patch.object(gate, "_run", tools):
            return quietly(gate.render_fleet, self.out)

    def test_each_env_with_a_values_file_renders_into_the_destination_namespace(self):
        self.addon()
        tools = Tools(helm=completed(stdout=DEPLOYMENT))
        (count, landed), _ = self.render([unit(params=[("a.b", "1")])], tools)
        self.assertEqual(count, 2)
        self.assertEqual(landed, {"monitoring"})
        helm = tools.calls[0]
        self.assertEqual(helm[:3], ["helm", "template", "loki"])
        self.assertIn("alias/loki", helm)
        self.assertEqual(helm[helm.index("-n") + 1], "monitoring")
        self.assertIn("a.b=1", helm)
        self.assertTrue(helm[-1].endswith("values-staging.yaml"))
        self.assertTrue(helm[-3].endswith("values.yaml"))

    def test_the_fleet_is_written_once_per_identity_beside_both_probes(self):
        self.addon()
        self.render([unit()], Tools(helm=completed(stdout=DEPLOYMENT)))
        fleet = [d for d in yaml.safe_load_all((self.out / "fleet.yaml").read_text()) if d]
        self.assertEqual(len(fleet), 1, "two envs rendering one object is one identity")
        self.assertEqual((self.out / "zz-policy-gate-canary.yaml").read_text(),
                         gate.CANARY_MANIFEST)
        self.assertEqual((self.out / "zz-policy-gate-runtime-pod.yaml").read_text(),
                         gate.RUNTIME_POD_MANIFEST)

    def test_an_oci_chart_is_rendered_by_its_reference(self):
        self.addon(envs=("production",), base=False)
        tools = Tools(helm=completed(stdout=DEPLOYMENT))
        u = unit(chart="operator", repo="oci://ghcr.io/example/charts/operator")
        (count, _), _ = self.render([u], tools)
        self.assertEqual(count, 1)
        helm = tools.calls[0]
        self.assertIn("oci://ghcr.io/example/charts/operator", helm)
        self.assertEqual(sum(1 for a in helm if a == "-f"), 1,
                         "with no base values file, only the env file is passed")

    def test_a_skipped_chart_and_a_unit_with_no_destination_render_nothing(self):
        tools = Tools()
        (count, landed), _ = self.render(
            [unit(chart="skipped"), unit(chart="crds", namespace="")], tools, skip=["skipped"])
        self.assertEqual((count, landed), (0, set()))
        self.assertEqual(tools.calls, [])

    def test_an_element_pointing_at_no_directory_stops_the_render(self):
        (count, _), out = self.render([unit(path="addons/x/gone")], Tools())
        self.assertEqual(count, -1)
        self.assertIn("points at nothing", out)

    def test_a_failed_helm_render_stops_the_render(self):
        self.addon()
        (count, _), out = self.render([unit()], Tools(helm=completed(1, stderr="no chart")))
        self.assertEqual(count, -1)
        self.assertIn("helm render FAILED loki@1.0.0 (staging)", out)
        self.assertIn("no chart", out)

    def test_kustomize_workloads_render_per_env_or_once(self):
        tools = Tools(kustomize=completed(stdout=DEPLOYMENT))
        (count, landed), _ = self.render(
            [], tools, kustomize=[("dashboards/base", "grafana-operator", False),
                                  ("tenants", "tenants", True)])
        self.assertEqual(count, 1 + len(gate.ENFORCE_ENVS))
        roots = [c[-1] for c in tools.calls]
        self.assertTrue(roots[0].endswith("dashboards/base"))
        self.assertTrue(roots[1].endswith("tenants/overlays/staging"))
        self.assertTrue(roots[2].endswith("tenants/overlays/production"))
        self.assertEqual(landed, {"monitoring"},
                         "the namespace a workload names is where it lands")

    def test_a_failed_kustomize_build_stops_the_render(self):
        tools = Tools(kustomize=completed(1, stderr="bad root"))
        (count, _), out = self.render([], tools,
                                      kustomize=[("dashboards/base", "grafana-operator", False)])
        self.assertEqual(count, -1)
        self.assertIn("kustomize build FAILED dashboards/base", out)


class BuildingAndApplyingThePolicies(unittest.TestCase):
    def test_each_group_overlay_is_built_into_its_own_file(self):
        out = pathlib.Path(tempfile.mkdtemp())
        tools = Tools(kustomize=lambda cmd: completed(stdout=f"# {cmd[-1]}\n"))
        with mock.patch.object(gate, "_run", tools):
            files = gate.build_policies("production", out)
        self.assertEqual([pathlib.Path(f).name for f in files],
                         [f"{g}-production.yaml" for g in gate.POLICY_GROUPS])
        self.assertTrue(pathlib.Path(files[0]).read_text().rstrip().endswith(
            "best-practices/overlays/production"))

    def test_an_overlay_that_does_not_build_cannot_be_evaluated(self):
        tools = Tools(kustomize=completed(1, stderr="missing base"))
        with mock.patch.object(gate, "_run", tools), self.assertRaises(SystemExit) as raised:
            quietly(gate.build_policies, "production", pathlib.Path(tempfile.mkdtemp()))
        self.assertEqual(raised.exception.code, 2)

    def test_apply_asks_for_a_json_report_and_warns_only_in_audit(self):
        report = '{"results": [], "summary": {}}'
        for audit_warn in (False, True):
            with self.subTest(audit_warn=audit_warn):
                tools = Tools(kyverno=completed(stdout=report))
                with mock.patch.object(gate, "_run", tools):
                    parsed, proc = gate.kyverno_apply(["p.yaml"], pathlib.Path("r"), audit_warn)
                self.assertEqual(parsed, {"results": [], "summary": {}})
                self.assertEqual(proc.stdout, report)
                cmd = tools.calls[0]
                self.assertEqual(cmd[:3], ["kyverno", "apply", "p.yaml"])
                self.assertIn("--policy-report", cmd)
                self.assertEqual("--audit-warn" in cmd, audit_warn)

    def test_a_child_process_runs_under_a_deadline(self):
        proc = gate._run([sys.executable, "-c", "print('ran')"])
        self.assertEqual((proc.returncode, proc.stdout), (0, "ran\n"))
        with mock.patch.object(gate.subprocess, "run") as run:
            gate._run(["true"])
        self.assertEqual(run.call_args.kwargs["timeout"], gate.NETWORK_TIMEOUT)


class TheWholeRun(unittest.TestCase):
    """`main` passes only when parity, coverage and both kyverno runs all hold."""

    RULES = {"best-practices/require-probes"}

    def run_main(self, count=gate.MIN_RENDERED, parity=True, coverage=True,
                 verdicts=(True, True)):
        judged = iter(verdicts)
        with mock.patch.object(gate.gatelib, "require"), \
             mock.patch.object(gate, "check_exclusion_parity",
                               return_value=(parity, {"monitoring"}, self.RULES)), \
             mock.patch.object(gate, "render_fleet", return_value=(count, {"monitoring"})), \
             mock.patch.object(gate, "check_namespace_coverage", return_value=coverage), \
             mock.patch.object(gate, "build_policies", return_value=["p.yaml"]), \
             mock.patch.object(gate, "kyverno_apply",
                               return_value=({"results": []}, completed())) as apply, \
             mock.patch.object(gate, "judge", side_effect=lambda *a, **k: next(judged)):
            code, out = quietly(gate.main)
        return code, out, apply

    def test_everything_holding_passes(self):
        code, out, apply = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("Policy-admission gate PASSED", out)
        self.assertEqual([c.kwargs["audit_warn"] for c in apply.call_args_list],
                         [False, True], "Enforce first, then Audit with --audit-warn")

    def test_any_one_failing_fails_the_run(self):
        for case in ({"parity": False}, {"coverage": False},
                     {"verdicts": (False, True)}, {"verdicts": (True, False)}):
            with self.subTest(**{k: str(v) for k, v in case.items()}):
                code, out, _ = self.run_main(**case)
                self.assertEqual(code, 1)
                self.assertIn("Policy-admission gate FAILED", out)

    def test_a_render_failure_fails_before_kyverno_runs(self):
        code, _, apply = self.run_main(count=-1)
        self.assertEqual(code, 1)
        apply.assert_not_called()

    def test_a_fleet_under_the_floor_cannot_be_judged(self):
        """The canary and runtime pod keep every rule assertion green over any
        fleet, so a render of almost nothing would otherwise read as clean."""
        code, out, apply = self.run_main(count=gate.MIN_RENDERED - 1)
        self.assertEqual(code, gate.gatelib.CANNOT_RUN)
        self.assertIn("below the floor", out)
        apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
