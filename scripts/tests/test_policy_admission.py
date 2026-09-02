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

Everything here is offline. Rendering and the kyverno invocation are not
exercised from here; the report they produce is supplied directly, in the shapes
kyverno emits.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import unittest

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
        """Parity between the four lists is asserted elsewhere; breadth is not a
        failure here — a namespace excluded before its addon arrives is normal."""
        verdict, _ = quietly(gate.check_namespace_coverage, set(), {"monitoring"})
        self.assertTrue(verdict)


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


if __name__ == "__main__":
    unittest.main()
