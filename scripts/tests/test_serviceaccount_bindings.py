"""Unit tests for the ServiceAccount binding gate, scripts/check-serviceaccount-bindings.py.

Kubernetes and an EKS Pod Identity association both bind a pod to its
ServiceAccount by name, and neither fails when the name is wrong. The gate
renders each in-repo chart and requires the names its pods run as and the names
it creates to be one set, in both directions, with an exemption that has to say
what consumes a ServiceAccount no pod uses. These hold where it finds a PodSpec
in each workload kind, what it renders with, and the verdict over rendered
charts. helm is replaced by a stub that returns the documents a test hands it,
so no case depends on the chart tree on disk.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml
from gateloader import load

gate = load("check-serviceaccount-bindings")


def pod(sa: str | None) -> dict:
    return {"serviceAccountName": sa} if sa else {"containers": []}


def account(name: str) -> dict:
    return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}}


def deployment(sa: str | None) -> dict:
    return {"kind": "Deployment", "metadata": {"name": "d"},
            "spec": {"template": {"spec": pod(sa)}}}


class PodSpecs(unittest.TestCase):
    def names(self, doc: dict) -> set[str]:
        return {ps.get("serviceAccountName") for ps in gate.pod_specs(doc)} - {None}

    def test_a_pod_carries_its_own(self):
        self.assertEqual(self.names({"kind": "Pod", "spec": pod("a")}), {"a"})
        self.assertEqual(list(gate.pod_specs({"kind": "Pod", "spec": pod(None)})), [pod(None)])

    def test_every_controller_carries_its_template(self):
        for kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            with self.subTest(kind=kind):
                self.assertEqual(self.names({"kind": kind,
                                             "spec": {"template": {"spec": pod("a")}}}), {"a"})

    def test_a_cronjob_carries_its_job_templates(self):
        doc = {"kind": "CronJob",
               "spec": {"jobTemplate": {"spec": {"template": {"spec": pod("a")}}}}}
        self.assertEqual(self.names(doc), {"a"})

    def test_a_bare_podspec_alike_is_read(self):
        self.assertEqual(self.names({"kind": "WorkflowTemplate", "spec": pod("a")}), {"a"})

    def test_a_document_carrying_no_podspec_yields_nothing(self):
        self.assertEqual(list(gate.pod_specs({"kind": "ConfigMap", "data": {}})), [])
        self.assertEqual(list(gate.pod_specs({"kind": "CronJob"})), [{}])


class Charts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name).resolve()
        (self.root / "scripts").mkdir()
        self.rendered: dict[str, list[dict] | None] = {}
        self.commands: list[list[str]] = []
        # The gate finds charts relative to its own file, so it is pointed at the tree.
        patches = [mock.patch.object(gate, "__file__", str(self.root / "scripts" / "gate.py")),
                   mock.patch.object(gate.gatelib, "require", lambda *tools: None),
                   mock.patch.object(gate.subprocess, "run", self.helm)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def helm(self, cmd, **kwargs):
        self.commands.append(cmd)
        docs = self.rendered[cmd[2]]
        if docs is None:
            return subprocess.CompletedProcess(cmd, 1, "", "Error: values don't meet the schema")
        return subprocess.CompletedProcess(cmd, 0, yaml.safe_dump_all([*docs, None]), "")

    def chart(self, name: str, *docs: dict, values: bool = True) -> None:
        chart = self.root / "catalog" / name / "chart"
        chart.mkdir(parents=True)
        if values:
            (chart.parent / "values.yaml").write_text("{}\n")
        self.rendered[name] = list(docs)

    def check(self) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = gate.main()
        return rc, out.getvalue()

    def test_pods_running_as_what_the_chart_creates_pass(self):
        self.chart("app", account("app"), deployment("app"), deployment(None))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)
        self.assertIn("app: 1 ServiceAccount(s), 1 used by pods", said)
        self.assertIn("every ServiceAccount has a consumer", said)

    def test_a_pod_naming_an_account_the_chart_does_not_create_fails(self):
        self.chart("app", account("app"), deployment("app"), deployment("ap"))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("a pod runs as ServiceAccount 'ap', which this chart does not create", said)

    def test_an_account_no_pod_runs_as_fails(self):
        self.chart("app", account("app"), account("spare"), deployment("app"))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("ServiceAccount 'spare' is created and no pod in this chart runs as it", said)
        self.assertIn("1 ServiceAccount binding problem(s).", said)

    def test_an_account_with_a_named_external_consumer_passes(self):
        (chart, sa), = gate.EXTERNAL_CONSUMERS
        self.chart(chart, account(sa), account("app"), deployment("app"))
        rc, said = self.check()
        self.assertEqual(rc, 0, said)

    def test_the_exemption_is_keyed_on_the_chart(self):
        (_, sa), = gate.EXTERNAL_CONSUMERS
        self.chart("other", account(sa), account("app"), deployment("app"))
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn(f"ServiceAccount {sa!r} is created and no pod", said)

    def test_a_chart_that_renders_nothing_fails(self):
        self.chart("app", account("app"), deployment("app"))
        self.chart("broken")
        self.rendered["broken"] = None
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn("::error file=", said)
        self.assertIn("helm template failed\nError: values don't meet the schema", said)
        self.assertIn("broken/chart::rendered no documents", said)

    def test_each_chart_renders_with_its_values_and_its_required_inputs(self):
        self.chart("druid", account("druid-msk-client"))
        self.chart("plain", account("app"), deployment("app"), values=False)
        self.check()
        druid, plain = self.commands
        self.assertEqual(druid[:3], ["helm", "template", "druid"])
        self.assertEqual(druid[4:], ["-f", str(self.root / "catalog" / "druid" / "values.yaml"),
                                     *gate.RENDER_VALUES["druid"]])
        self.assertEqual(plain[3:], [str(self.root / "catalog" / "plain" / "chart")])

    def test_no_chart_is_a_gate_that_verified_nothing(self):
        rc, said = self.check()
        self.assertEqual(rc, 1, said)
        self.assertIn(f"no charts matched {gate.CHART_GLOB}", said)


class TheExemptions(unittest.TestCase):
    def test_every_exemption_names_its_consumer(self):
        for key, consumer in gate.EXTERNAL_CONSUMERS.items():
            with self.subTest(key=key):
                self.assertEqual(len(key), 2)
                self.assertTrue(consumer.strip())


if __name__ == "__main__":
    unittest.main()
