"""The digest-rewrite gate run whole, as CI runs it, against stand-ins for the cluster.

scripts/tests/test_digest_rewrite.py sources scripts/check-digest-rewrite.sh and
drives each of its steps. These run the script itself, over a checkout of their
own, with scripts/tests/digeststubs.py's stubs for every cluster tool on a PATH
that holds nothing else. They hold what only a whole run reaches:
- the tree read before any cluster exists, and each shape of it the script
  refuses before kind is asked for one;
- the loop over every overlay, and a cluster taken down however the run ends;
- the exit status the run's outcome earns.

Their own module, so the reversion harness's many probes on the steps do not
pay for a whole run each.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest

from digeststubs import (
    CHART_VERSION,
    DENIED,
    FOREIGN,
    MISMATCH,
    PINNED,
    SCRIPT,
    TAGGED,
    TOOL,
    StubbedCluster,
)

# A checkout holding only what the script reads, each file written in the shape
# the tree writes it, so a whole run can be changed one file at a time.
CHECKOUT_POD = f"""apiVersion: v1
kind: Pod
metadata:
  name: signed
  namespace: workloads
spec:
  initContainers:
    - name: init
      image: {TAGGED}
  containers:
    - name: manager
      image: {TAGGED}
"""
CHECKOUT_DEPLOYMENT = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: signed-deployment
  namespace: workloads
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: signed-deployment
  template:
    metadata:
      labels:
        app.kubernetes.io/name: signed-deployment
    spec:
      containers:
        - name: manager
          image: {TAGGED}
"""
CHECKOUT_BRANCH_SIGNED = f"""apiVersion: v1
kind: Pod
metadata:
  name: branch-signed
  namespace: workloads
spec:
  containers:
    - name: manager
      image: {FOREIGN}
"""
CHECKOUT_APPSET = f"""apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: addons-security
spec:
  generators:
    - matrix:
        generators:
          - list:
              elements:
                - appName: kyverno
                  chartRepo: https://kyverno.github.io/kyverno
                  chart: kyverno
                  chartVersion: {CHART_VERSION}
                  path: addons/security/kyverno
"""
NODE_IMAGE = f"kindest/node:v0.0.0@sha256:{'b' * 64}"
CHECKOUT_CI = f"env:\n  KIND_NODE_IMAGE: {NODE_IMAGE}\n"
CHECKOUT = {
    "policies/kyverno/tests/supply-chain-digest/pod.yaml": CHECKOUT_POD,
    "policies/kyverno/tests/supply-chain-digest/deployment.yaml": CHECKOUT_DEPLOYMENT,
    "policies/kyverno/tests/supply-chain-digest/branch-signed.yaml": CHECKOUT_BRANCH_SIGNED,
    "policies/kyverno/supply-chain/overlays/production/kustomization.yaml": "resources: []\n",
    "policies/kyverno/supply-chain/overlays/staging/kustomization.yaml": "resources: []\n",
    "applicationsets/addons-security.yaml": CHECKOUT_APPSET,
    ".github/workflows/ci.yml": CHECKOUT_CI,
    "addons/security/kyverno/values.yaml": "{}\n",
    "addons/security/kyverno/values-production.yaml": "{}\n",
}
# The script and the modules it runs, copied from the tree as they are.
CHECKOUT_SCRIPTS = ("check-digest-rewrite.sh", "verdicts.py", "gatelib.py")
OVERLAYS = "policies/kyverno/supply-chain/overlays"

# What kustomize renders for each overlay: the policy, at Deny.
RENDERED_POLICY = """apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: verify-images
spec:
  validationActions: [Deny]
"""

# kustomize, answering `kustomize build <overlay>` from answers/kustomize-<overlay
# name> where a case wrote one, and from answers/kustomize otherwise.
KUSTOMIZE = r"""#!BASH
overlay="${!#}"
overlay="${overlay%/}"
for answer in "WORK/answers/kustomize-${overlay##*/}" "WORK/answers/kustomize"; do
  [ -f "$answer.out" ] || [ -f "$answer.rc" ] || continue
  [ -f "$answer.out" ] && printf '%s\n' "$(<"$answer.out")"
  [ -f "$answer.err" ] && printf '%s\n' "$(<"$answer.err")" >&2
  [ -f "$answer.rc" ] && exit "$(<"$answer.rc")"
  exit 0
done
exit 0
"""

# The programs the script runs beside the stubs, taken from the host. The run's
# PATH holds these and the stubs and nothing else, so no cluster tool installed
# on the host can answer for a stub.
UTILITIES = ("basename", "cut", "dirname", "grep", "head", "mktemp", "rm", "sed", "tail")


class AWholeRun(StubbedCluster):
    """The script run whole, as CI runs it, against the stubs and a checkout of its own.

    test_digest_rewrite holds each step to its decision. These hold the main
    body to its own: the tree read before any cluster exists, each refused
    shape stopping the run before kind is asked for one, the loop over every
    overlay, and the exit status the run's outcome earns.
    """

    def setUp(self):
        super().setUp()
        self.checkout = self.work / "checkout"
        for rel, text in CHECKOUT.items():
            self.write(rel, text)
        (self.checkout / "scripts").mkdir()
        for name in CHECKOUT_SCRIPTS:
            shutil.copy2(SCRIPT.parent / name, self.checkout / "scripts" / name)
        for name, body in (
            ("kustomize", KUSTOMIZE),
            ("docker", TOOL),
            ("python3", f"#!BASH\nexec '{sys.executable}' \"$@\"\n"),
        ):
            stub = self.bin / name
            stub.write_text(body.replace("BASH", self.bash, 1).replace("WORK", str(self.work)))
            stub.chmod(0o755)
        self.utilities = self.work / "utilities"
        self.utilities.mkdir()
        for name in UTILITIES:
            found = shutil.which(name)
            if found is None:
                self.skipTest(f"{name} is not on PATH")
            (self.utilities / name).symlink_to(found)
        self.answer("kustomize", out=RENDERED_POLICY)
        self.answer("create-pod", out=f"{PINNED} {PINNED}")
        self.answer("patch-pinned", out=PINNED)
        self.answer("patch-foreign", err=DENIED, rc=1)
        self.answer("create-deployment", out=TAGGED)
        self.answer("get-pod", out=PINNED)
        self.answer("create-branch-signed", err=DENIED, rc=1)
        self.answer("logs", out=MISMATCH)

    def write(self, rel: str, text: str) -> None:
        path = self.checkout / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run_whole(self, **env: str) -> tuple[int, str]:
        """The checkout's copy of the script, run as CI runs it."""
        proc = subprocess.run(
            [self.bash, str(self.checkout / "scripts" / "check-digest-rewrite.sh")],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.bin}{os.pathsep}{self.utilities}",
                "HOME": str(self.work),
                "TMPDIR": str(self.work),
                **env,
            },
            timeout=120,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def clusters(self) -> list[list[str]]:
        """Each kind command the run made, under its bound."""
        return [command for _, command in self.bounded() if command[0] == "kind"]

    def assert_cluster_created_and_deleted(self) -> None:
        """The run brought one cluster up and, however it ended, took it down."""
        self.assertEqual(
            [command[:2] for command in self.clusters()], [["kind", "create"], ["kind", "delete"]]
        )


class AWholeRunsOutcome(AWholeRun):
    def test_every_overlay_holding_passes(self):
        rc, said = self.run_whole()
        self.assertEqual(rc, 0, said)
        self.assertIn(f"── kind {NODE_IMAGE}, kyverno chart {CHART_VERSION}", said)
        for overlay in ("production", "staging"):
            self.assertIn(f"── {OVERLAYS}/{overlay} (validationActions: Deny)", said)
        self.assertIn(
            "✓ 2 overlay(s) of verify-images pin a tagged image to the digest admission", said
        )
        self.assertNotIn("FAIL", said)
        self.assertEqual(len(self.calls_to("create-pod")), 2, self.calls())
        self.assert_cluster_created_and_deleted()

    def test_a_finding_fails_the_run(self):
        """A finding in the first overlay fails the run, and the next is still checked."""
        self.answer("create-deployment", out=PINNED)
        rc, said = self.run_whole()
        self.assertEqual(rc, 1, said)
        self.assertIn(
            f"FAIL  stored the Deployment's pod template as '{PINNED}', not as written.", said
        )
        self.assertIn(f"── {OVERLAYS}/staging (validationActions: Deny)", said)
        self.assertEqual(len(self.calls_to("create-deployment")), 2, self.calls())
        self.assertIn("Under real admission, that did not hold.", said)
        self.assertNotIn("✓", said)
        self.assert_cluster_created_and_deleted()


class AWholeRunInTheCluster(AWholeRun):
    """What the main body reads once the cluster exists, failing, ends the run undecided."""

    def assert_undecided(self, rc: int, said: str, cannot: str) -> None:
        self.assertEqual(rc, 2, said)
        self.assertIn(f"Cannot run: {cannot}", said)
        self.assertNotIn("✓", said)
        self.assertNotIn("did not hold", said)
        self.assert_cluster_created_and_deleted()

    def test_a_namespace_that_could_not_be_created_cannot_run(self):
        self.answer("apply--", rc=1, err="Error from server (Forbidden): namespaces is forbidden")
        rc, said = self.run_whole()
        self.assert_undecided(
            rc,
            said,
            "the namespace workloads could not be created — "
            "Error from server (Forbidden): namespaces is forbidden",
        )

    def test_an_overlay_that_does_not_render_cannot_run(self):
        self.answer("kustomize-production", err="Error: accumulating resources", rc=1)
        rc, said = self.run_whole()
        self.assert_undecided(
            rc, said, f"{OVERLAYS}/production does not render — Error: accumulating resources"
        )
        self.assertEqual(self.calls_to("create-pod"), [], self.calls())

    def test_an_overlay_rendering_no_verify_images_cannot_run(self):
        self.answer(
            "kustomize-staging", out="apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
        )
        rc, said = self.run_whole()
        self.assert_undecided(
            rc, said, f"{OVERLAYS}/staging renders no ImageValidatingPolicy named verify-images."
        )


class AWholeRunReadsTheTreeFirst(AWholeRun):
    """Every shape of the tree the run cannot use refuses before kind is asked for a cluster."""

    def assert_refused(self, cannot: str, **env: str) -> None:
        rc, said = self.run_whole(**env)
        self.assertEqual(rc, 2, said)
        self.assertIn(f"Cannot run: {cannot}", said)
        self.assertEqual(self.clusters(), [], said)
        self.assertEqual(self.calls(), [], said)

    def rewrite(self, rel: str, old: str, new: str) -> None:
        path = self.checkout / rel
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def test_the_tree_as_written_is_read(self):
        rc, said = self.run_whole()
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.clusters()[0][:3], ["kind", "create", "cluster"])

    def test_no_overlay_with_a_kustomization_refuses(self):
        for overlay in ("production", "staging"):
            (self.checkout / OVERLAYS / overlay / "kustomization.yaml").unlink()
        self.assert_refused(f"no overlay under {OVERLAYS}, so there is no rendition")

    def test_a_missing_fixture_refuses(self):
        for name in ("pod.yaml", "deployment.yaml", "branch-signed.yaml"):
            with self.subTest(fixture=name):
                rel = f"policies/kyverno/tests/supply-chain-digest/{name}"
                text = (self.checkout / rel).read_text()
                (self.checkout / rel).unlink()
                self.assert_refused(f"{self.checkout / rel} does not exist, so there is no pod")
                self.write(rel, text)

    def test_a_signed_fixture_with_no_tagged_nanohype_image_refuses(self):
        pod = "policies/kyverno/tests/supply-chain-digest/pod.yaml"
        for name, image in (
            ("no tag", "ghcr.io/nanohype/x"),
            ("another registry", "docker.io/library/x:1.0.0"),
        ):
            with self.subTest(name=name):
                self.write(pod, CHECKOUT_POD.replace(TAGGED, image))
                self.assert_refused(
                    f"{self.checkout / pod} carries no tagged ghcr.io/nanohype image"
                )

    def test_a_signed_fixture_pinned_by_digest_refuses(self):
        pod = "policies/kyverno/tests/supply-chain-digest/pod.yaml"
        self.write(pod, CHECKOUT_POD.replace(TAGGED, PINNED))
        self.assert_refused(f"{self.checkout / pod} is pinned by digest already")

    def test_another_image_beside_the_tag_refuses(self):
        for name in ("pod.yaml", "deployment.yaml"):
            with self.subTest(fixture=name):
                rel = f"policies/kyverno/tests/supply-chain-digest/{name}"
                original = (self.checkout / rel).read_text()
                self.write(rel, original + "        - name: sidecar\n          image: busybox:1\n")
                self.assert_refused(f"{self.checkout / rel} names busybox:1 beside {TAGGED}")
                self.write(rel, original)

    def test_a_tag_not_in_exactly_one_init_container_and_one_container_refuses(self):
        pod = "policies/kyverno/tests/supply-chain-digest/pod.yaml"
        self.rewrite(pod, f"  initContainers:\n    - name: init\n      image: {TAGGED}\n", "")
        self.assert_refused(f"{self.checkout / pod} does not carry the tag in exactly one init")

    def test_a_signed_pod_with_no_name_or_namespace_refuses(self):
        pod = "policies/kyverno/tests/supply-chain-digest/pod.yaml"
        for line in ("  name: signed\n", "  namespace: workloads\n"):
            with self.subTest(line=line):
                self.write(pod, CHECKOUT_POD.replace(line, "", 1))
                self.assert_refused(f"{self.checkout / pod} names no pod and namespace")

    def test_a_branch_signed_fixture_not_pinned_by_digest_refuses(self):
        rel = "policies/kyverno/tests/supply-chain-digest/branch-signed.yaml"
        self.rewrite(rel, FOREIGN, TAGGED)
        self.assert_refused(
            f"{self.checkout / rel} carries no digest-pinned ghcr.io/nanohype image"
        )

    def test_a_deployment_with_no_name_or_namespace_refuses(self):
        rel = "policies/kyverno/tests/supply-chain-digest/deployment.yaml"
        for line in ("  name: signed-deployment\n", "  namespace: workloads\n"):
            with self.subTest(line=line):
                self.write(rel, CHECKOUT_DEPLOYMENT.replace(line, "", 1))
                self.assert_refused(f"{self.checkout / rel} names no Deployment and namespace")

    def test_a_missing_appset_refuses(self):
        rel = "applicationsets/addons-security.yaml"
        (self.checkout / rel).unlink()
        self.assert_refused(f"{self.checkout / rel} does not exist, so the Kyverno chart pin")

    def test_a_missing_ci_workflow_refuses(self):
        rel = ".github/workflows/ci.yml"
        (self.checkout / rel).unlink()
        self.assert_refused(f"{self.checkout / rel} does not exist, so the pinned kind node image")

    def test_a_missing_tool_refuses(self):
        for tool in ("kind", "kubectl", "helm", "kustomize", "docker", "python3"):
            with self.subTest(tool=tool):
                stub = self.bin / tool
                body = stub.read_text()
                stub.unlink()
                self.assert_refused(f"{tool} is not on PATH. No pod was admitted")
                stub.write_text(body)
                stub.chmod(0o755)

    def test_no_gnu_timeout_refuses(self):
        (self.bin / "timeout").unlink()
        self.assert_refused("neither timeout nor gtimeout is on PATH")

    def test_gtimeout_stands_in_for_timeout(self):
        (self.bin / "timeout").rename(self.bin / "gtimeout")
        rc, said = self.run_whole()
        self.assertEqual(rc, 0, said)
        self.assertEqual(self.clusters()[0][:3], ["kind", "create", "cluster"])

    def test_an_appset_with_no_kyverno_element_refuses(self):
        self.rewrite("applicationsets/addons-security.yaml", "chart: kyverno", "chart: other")
        self.assert_refused(
            f"{self.checkout / 'applicationsets/addons-security.yaml'} names no kyverno chart"
        )

    def test_a_missing_values_file_refuses(self):
        for name in ("values.yaml", "values-production.yaml"):
            with self.subTest(values=name):
                rel = f"addons/security/kyverno/{name}"
                (self.checkout / rel).unlink()
                self.assert_refused(
                    f"{self.checkout / rel} does not exist, so Kyverno would install"
                )
                self.write(rel, "{}\n")

    def test_a_node_image_not_pinned_by_digest_refuses(self):
        self.write(".github/workflows/ci.yml", "env:\n  KIND_NODE_IMAGE: kindest/node:v0.0.0\n")
        self.assert_refused("KIND_NODE_IMAGE is 'kindest/node:v0.0.0', not a digest-pinned image")

    def test_the_node_image_the_environment_names_is_held_to_the_same_pin(self):
        self.assert_refused(
            "KIND_NODE_IMAGE is 'kindest/node:v1', not a digest-pinned image",
            KIND_NODE_IMAGE="kindest/node:v1",
        )


if __name__ == "__main__":
    unittest.main()
