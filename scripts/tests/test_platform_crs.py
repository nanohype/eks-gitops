"""Unit tests for the platform-CR admissibility walk.

The gate fetches the operator chart to read the CRD schemas the catalog's own
custom resources are checked against, so the positive-control sweep exempts it.
That leaves the walk — which is the whole gate — resting on nobody having read it.

Each rule below is one the API server enforces and no other gate here does.
kubeconform skips these kinds entirely; kustomize builds them happily; ArgoCD
applies them and the Application simply never reaches Healthy. A rule that
under-matches produces the same output as a compliant manifest, and there is no
second signal anywhere to contradict it.

The schemas here are written inline rather than fetched, so the assertions are
about the walk rather than about whatever the pinned chart currently ships.
TheGateRunWhole runs the gate end to end the same way: a fixture tree and a
fixture operator chart, served by fakeregistry through registry.py's own client.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

import fakeregistry as fake
import registry
import yaml
from gateloader import load

gate = load("check-platform-crs")

KIND = "Platform"
SOURCE = "addons/ai-platform/agent-platform/base/platform.yaml"


def problems_for(value, schema):
    found: list[str] = []
    gate.walk(value, schema, "", KIND, SOURCE, found)
    return found


class RequiredProperties(unittest.TestCase):
    """`required` is a rejection of the whole object, but not always."""

    SCHEMA = {
        "type": "object",
        "required": ["tenant", "persona"],
        "properties": {
            "tenant": {"type": "string"},
            "persona": {"type": "string", "default": "generic"},
        },
    }

    def test_a_missing_required_property_with_no_default_is_a_rejection(self):
        found = problems_for({"persona": "ops"}, self.SCHEMA)
        self.assertEqual(len(found), 1)
        self.assertIn("tenant: Required value", found[0])

    def test_a_missing_required_property_that_declares_a_default_is_admitted(self):
        """Structural-schema defaulting runs BEFORE validation.

        Reading `required` alone reports a manifest as refused over a property
        the API server fills in itself.
        """
        self.assertEqual(problems_for({"tenant": "platform-ops"}, self.SCHEMA), [])

    def test_a_complete_object_has_no_problems(self):
        self.assertEqual(problems_for({"tenant": "t", "persona": "ops"}, self.SCHEMA), [])


class ExcessProperties(unittest.TestCase):
    """A property the CRD does not carry is pruned — it never reaches a cluster."""

    SCHEMA = {"type": "object", "properties": {"tenant": {"type": "string"}}}

    def test_an_unknown_property_is_reported_as_pruned(self):
        found = problems_for({"tenant": "t", "budgetUsd": "50"}, self.SCHEMA)
        self.assertEqual(len(found), 1)
        self.assertIn("is pruned at admission", found[0])

    def test_a_schema_preserving_unknown_fields_prunes_nothing(self):
        schema = dict(self.SCHEMA, **{"x-kubernetes-preserve-unknown-fields": True})
        self.assertEqual(problems_for({"anything": 1}, schema), [])

    def test_a_schema_declaring_no_properties_is_not_walked(self):
        """The API server does not prune where the schema declines to describe."""
        self.assertEqual(problems_for({"anything": 1}, {"type": "object"}), [])


class DeclaredTypes(unittest.TestCase):
    """YAML decides the type for you, and the CRD does not negotiate."""

    def test_a_fractional_quantity_left_unquoted_is_rejected(self):
        """Kubernetes serialises fractional quantities as strings.

        `minACU: 0.5` reads as a YAML float, every property is present, none is
        excess, and the API server refuses the whole object.
        """
        found = problems_for(
            {"minACU": 0.5}, {"type": "object", "properties": {"minACU": {"type": "string"}}}
        )
        self.assertEqual(len(found), 1)
        self.assertIn("must be of type string", found[0])
        self.assertIn("quote it", found[0])

    def test_a_quoted_quantity_is_accepted(self):
        self.assertEqual(
            problems_for(
                {"minACU": "0.5"}, {"type": "object", "properties": {"minACU": {"type": "string"}}}
            ),
            [],
        )

    def test_a_bool_does_not_satisfy_integer(self):
        """In Python a bool IS an int, so a naive check passes an unquoted `true`."""
        found = problems_for(
            {"replicas": True}, {"type": "object", "properties": {"replicas": {"type": "integer"}}}
        )
        self.assertEqual(len(found), 1)
        self.assertIn("is a boolean and the CRD declares integer", found[0])

    def test_an_integer_satisfies_number(self):
        self.assertEqual(
            problems_for(
                {"ratio": 3}, {"type": "object", "properties": {"ratio": {"type": "number"}}}
            ),
            [],
        )

    def test_a_float_does_not_satisfy_integer(self):
        found = problems_for(
            {"replicas": 1.5}, {"type": "object", "properties": {"replicas": {"type": "integer"}}}
        )
        self.assertEqual(len(found), 1)
        self.assertIn("must be of type integer", found[0])

    def test_an_unset_value_is_not_a_type_error(self):
        self.assertEqual(
            problems_for(
                {"tenant": None}, {"type": "object", "properties": {"tenant": {"type": "string"}}}
            ),
            [],
        )

    def test_a_schema_declaring_no_type_checks_nothing(self):
        self.assertEqual(problems_for({"x": 1}, {"type": "object", "properties": {"x": {}}}), [])

    def test_the_reported_type_name_is_the_one_the_api_server_prints(self):
        for value, name in (
            (True, "boolean"),
            ("s", "string"),
            (1, "integer"),
            (1.5, "number"),
            ({}, "object"),
            ([], "array"),
        ):
            with self.subTest(value=value):
                self.assertEqual(gate._json_type_name(value), name)


class ListIdentity(unittest.TestCase):
    """x-kubernetes-list-type is a validation rule, not documentation.

    A duplicate is a hard rejection of the whole object — not a warning, not a
    merge of the two entries.
    """

    MAP_SCHEMA = {
        "type": "object",
        "properties": {
            "datastores": {
                "type": "array",
                "x-kubernetes-list-type": "map",
                "x-kubernetes-list-map-keys": ["name"],
                "items": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "kind": {"type": "string"}},
                },
            }
        },
    }

    def test_two_entries_sharing_the_map_key_are_rejected(self):
        found = problems_for(
            {"datastores": [{"name": "main"}, {"name": "main", "kind": "cache"}]}, self.MAP_SCHEMA
        )
        self.assertEqual(len(found), 1)
        self.assertIn("Duplicate value", found[0])
        self.assertIn("repeats name=main", found[0])

    def test_distinct_map_keys_are_accepted(self):
        self.assertEqual(
            problems_for({"datastores": [{"name": "main"}, {"name": "cache"}]}, self.MAP_SCHEMA), []
        )

    def test_an_absent_key_participates_in_the_identity(self):
        """Reading only the fields that happen to be set misses this pair."""
        found = problems_for({"datastores": [{"kind": "a"}, {"kind": "b"}]}, self.MAP_SCHEMA)
        self.assertEqual(len(found), 1)
        self.assertIn("<unset>", found[0])

    def test_a_set_list_identifies_a_scalar_by_itself(self):
        schema = {
            "type": "object",
            "properties": {
                "zones": {
                    "type": "array",
                    "x-kubernetes-list-type": "set",
                    "items": {"type": "string"},
                }
            },
        }
        found = problems_for({"zones": ["us-east-1a", "us-east-1a"]}, schema)
        self.assertEqual(len(found), 1)
        self.assertIn("repeats value=us-east-1a", found[0])

    def test_an_atomic_list_imposes_no_uniqueness(self):
        schema = {
            "type": "object",
            "properties": {
                "args": {
                    "type": "array",
                    "x-kubernetes-list-type": "atomic",
                    "items": {"type": "string"},
                }
            },
        }
        self.assertEqual(problems_for({"args": ["-v", "-v"]}, schema), [])

    def test_a_list_with_no_declared_type_imposes_no_uniqueness(self):
        schema = {
            "type": "object",
            "properties": {"args": {"type": "array", "items": {"type": "string"}}},
        }
        self.assertEqual(problems_for({"args": ["-v", "-v"]}, schema), [])

    def test_a_map_list_declaring_no_keys_imposes_no_uniqueness(self):
        schema = {
            "type": "object",
            "properties": {
                "x": {"type": "array", "x-kubernetes-list-type": "map", "items": {"type": "object"}}
            },
        }
        self.assertEqual(problems_for({"x": [{"a": 1}, {"a": 1}]}, schema), [])

    def test_three_entries_sharing_an_identity_report_each_repeat(self):
        found = problems_for(
            {"datastores": [{"name": "m"}, {"name": "m"}, {"name": "m"}]}, self.MAP_SCHEMA
        )
        self.assertEqual(len(found), 2)


class TheWalkDescends(unittest.TestCase):
    """A rule that fires only at the top level checks the least interesting layer."""

    SCHEMA = {
        "type": "object",
        "properties": {
            "identity": {
                "type": "object",
                "required": ["allowedModels"],
                "properties": {
                    "allowedModels": {
                        "type": "array",
                        "x-kubernetes-list-type": "set",
                        "items": {"type": "string"},
                    }
                },
            }
        },
    }

    def test_a_nested_required_property_is_reached(self):
        found = problems_for({"identity": {}}, self.SCHEMA)
        self.assertIn("`identity.allowedModels: Required value`", found[0])

    def test_a_duplicate_inside_a_nested_list_is_reached(self):
        found = problems_for(
            {
                "identity": {
                    "allowedModels": [
                        "us.anthropic.claude-sonnet-5",
                        "us.anthropic.claude-sonnet-5",
                    ]
                }
            },
            self.SCHEMA,
        )
        self.assertEqual(len(found), 1)
        self.assertIn(".identity.allowedModels", found[0])

    def test_a_type_error_inside_an_array_item_names_its_index(self):
        schema = {
            "type": "object",
            "properties": {
                "routes": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"rateLimit": {"type": "integer"}}},
                }
            },
        }
        found = problems_for({"routes": [{"rateLimit": 60}, {"rateLimit": "60"}]}, schema)
        self.assertEqual(len(found), 1)
        self.assertIn(".routes[1].rateLimit", found[0])

    def test_a_mistyped_container_is_reported_before_it_is_descended_into(self):
        schema = {
            "type": "object",
            "properties": {
                "identity": {"type": "object", "properties": {"allowedModels": {"type": "array"}}}
            },
        }
        found = problems_for({"identity": ["a", "b"]}, schema)
        self.assertEqual(len(found), 1)
        self.assertIn("must be of type object", found[0])

    def test_a_non_mapping_schema_is_not_walked(self):
        self.assertEqual(problems_for({"a": 1}, "not-a-schema"), [])


class TheManifestCorpus(unittest.TestCase):
    """A walk over no manifests reports the same as a walk over compliant ones."""

    def test_the_corpus_is_not_empty(self):
        self.assertTrue(list(gate.manifests()))

    def test_no_skipped_directory_swallows_the_catalog_crs(self):
        found = [
            f
            for f in gate.manifests()
            if "kind: Platform" in f.read_text(encoding="utf-8", errors="replace")
        ]
        self.assertTrue(
            found,
            "no manifest in the walk declares a Platform, so this gate "
            "examined none of the CRs it exists to check",
        )


class TheVersionThePinResolves(unittest.TestCase):
    """The CRD schemas are resolved from the version the catalog pins, so what
    the pin reads is upstream of every assertion in this file.

    Both refusals rather than one: a pin that cannot be READ and a pin that
    cannot be FOUND are different repairs, and neither is the same answer as a
    catalog with no CRs in it. The first is the one an emptied corpus produces,
    which is why the gate stops rather than resolving nothing and walking it.
    """

    def with_appset(self, body):
        """The gate reading `body` as the operator ApplicationSet, or no file."""
        root = pathlib.Path(tempfile.mkdtemp())
        path = root / "addons-agent-operator.yaml"
        if body is not None:
            path.write_text(body)
        original = gate.OPERATOR_APPSET
        original_root = gate.ROOT
        gate.OPERATOR_APPSET, gate.ROOT = path, root
        self.addCleanup(setattr, gate, "OPERATOR_APPSET", original)
        self.addCleanup(setattr, gate, "ROOT", original_root)
        return path

    # The catalog's own git source FIRST, because that ordering is what the
    # assertion is about: a pattern reading the first `targetRevision:` in the
    # file resolves `main` here and finds a chart version that does not exist.
    PINNED = """
      sources:
        - repoURL: https://github.com/nanohype/eks-gitops
          targetRevision: main
        - repoURL: oci://ghcr.io/nanohype/eks-agent-platform/charts/operator
          chart: operator
          targetRevision: 0.6.7
"""

    def test_the_operator_source_is_the_one_read(self):
        """Its sibling pins the catalog's own git revision; reading that would
        resolve CRDs from a chart version nothing installs."""
        self.with_appset(self.PINNED)
        self.assertEqual(gate.pinned_chart_version(), "0.6.7")

    def test_an_absent_appset_cannot_run(self):
        """Exit 2. The corpus this gate walks is the catalog's CRs; the pin is a
        derivation input, and losing it makes the answer unknown rather than
        empty."""
        self.with_appset(None)
        with (
            self.assertRaises(SystemExit) as caught,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            gate.pinned_chart_version()
        self.assertEqual(caught.exception.code, gate.gatelib.CANNOT_RUN)
        self.assertIn("is not the same as a catalog with no CRs in it", out.getvalue())

    def test_an_appset_with_no_operator_source_stops(self):
        self.with_appset("sources:\n  - repoURL: https://example.com\n    targetRevision: main\n")
        with self.assertRaises(SystemExit) as caught:
            gate.pinned_chart_version()
        self.assertIn(
            "could not find the operator chart's targetRevision", str(caught.exception.code)
        )

    def test_a_quoted_revision_is_unquoted(self):
        self.with_appset(self.PINNED.replace("targetRevision: 0.6.7", 'targetRevision: "0.6.7"'))
        self.assertEqual(gate.pinned_chart_version(), "0.6.7")


GROUP = "agents.nanohype.dev"


def crd(kind: str, spec: dict) -> str:
    """A CustomResourceDefinition for `kind` whose v1alpha1 spec schema is `spec`."""
    plural = f"{kind.lower()}s"
    return yaml.safe_dump(
        {
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": f"{plural}.{GROUP}"},
            "spec": {
                "group": GROUP,
                "names": {"kind": kind, "plural": plural},
                "scope": "Namespaced",
                "versions": [
                    {
                        "name": gate.CRD_VERSION,
                        "served": True,
                        "storage": True,
                        "schema": {
                            "openAPIV3Schema": {"type": "object", "properties": {"spec": spec}}
                        },
                    }
                ],
            },
        }
    )


class TheGateRunWhole(unittest.TestCase):
    """main() over a fixture tree, its CRDs read from a fixture chart by the real client.

    The walk is held above rule by rule. These hold the run: the version read
    off the ApplicationSet is the chart fetched, its CRDs are the schemas every
    CR in the tree is walked against, the corpus is complete, and each way the
    chart can fail to arrive ends the run with the status that failure earns.
    """

    VERSION = "0.7.5"
    PATH = "nanohype/eks-agent-platform/charts/operator"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name) / "tree"
        self.appset = self.root / "applicationsets" / "addons-agent-operator.yaml"
        self.appset.parent.mkdir(parents=True)
        self.pin(self.VERSION)
        self.cr("platform.yaml", "Platform", {"datastores": [{"relational": {"minACU": "0.5"}}]})
        self.cr("gateway.yaml", "ModelGateway", {"model": "claude"})
        self.schemas = {
            "Platform": {
                "type": "object",
                "properties": {
                    "datastores": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "relational": {
                                    "type": "object",
                                    "properties": {"minACU": {"type": "string"}},
                                }
                            },
                        },
                    }
                },
            },
            "ModelGateway": {
                "type": "object",
                "required": ["model"],
                "properties": {"model": {"type": "string"}},
            },
        }
        self.operator = self.chart(self.VERSION)
        self.hosts = fake.serve(
            self,
            registry,
            {
                f"https://ghcr.io/v2/{self.PATH}/": self.route,
                fake.OciRegistry.REALM: self.route,
            },
            pathlib.Path(tmp.name) / "cache",
        )
        for patch in (
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(gate, "OPERATOR_APPSET", self.appset),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def route(self, req):
        return self.operator(req)

    def chart(self, version):
        archive = fake.chart_archive(
            "operator",
            version,
            {},
            crds={f"{kind.lower()}s.yaml": crd(kind, spec) for kind, spec in self.schemas.items()},
        )
        return fake.OciRegistry(
            "ghcr.io", self.PATH, version, {"name": "operator", "version": version}, content=archive
        )

    def pin(self, version):
        self.appset.write_text(
            yaml.safe_dump(
                {
                    "kind": "ApplicationSet",
                    "spec": {
                        "template": {
                            "spec": {
                                "sources": [
                                    {
                                        "repoURL": "ghcr.io/nanohype/eks-agent-platform/charts",
                                        "chart": "operator",
                                        "targetRevision": version,
                                    },
                                    {
                                        "repoURL": "https://git.example/eks-gitops",
                                        "targetRevision": "main",
                                    },
                                ]
                            }
                        }
                    },
                }
            )
        )

    def cr(self, name, kind, spec):
        path = self.root / "addons" / "ai-platform" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": f"{GROUP}/{gate.CRD_VERSION}",
                    "kind": kind,
                    "metadata": {"name": "main"},
                    "spec": spec,
                }
            )
        )

    def run_gate(self, *argv):
        out = io.StringIO()
        with (
            mock.patch.object(gate.sys, "argv", ["check-platform-crs.py", *argv]),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(out),
        ):
            try:
                rc = gate.main()
            except SystemExit as exc:
                rc = exc.code
        return rc, out.getvalue()

    def test_a_catalog_whose_crs_the_pinned_crds_admit_passes(self):
        rc, out = self.run_gate("--list")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"operator chart {self.VERSION} → ModelGateway, Platform", out)
        self.assertIn("addons/ai-platform/gateway.yaml: ModelGateway/main", out)
        self.assertIn(f"ok: 2 platform CR(s) admissible against operator chart {self.VERSION}", out)
        self.assertIn(f"https://ghcr.io/v2/{self.PATH}/manifests/{self.VERSION}", self.hosts.urls)

    def test_a_field_the_crd_types_as_a_string_written_as_a_number_fails(self):
        self.cr("platform.yaml", "Platform", {"datastores": [{"relational": {"minACU": 0.5}}]})
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "addons/ai-platform/platform.yaml (main): Platform spec.datastores[0].relational.minACU "
            "is a number and the CRD declares string — quote it",
            out,
        )

    def test_a_required_field_left_out_fails(self):
        self.cr("gateway.yaml", "ModelGateway", {})
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("ModelGateway spec.model is REQUIRED by the CRD", out)

    def test_a_cr_of_a_kind_the_chart_ships_no_schema_for_fails(self):
        self.cr("tenant.yaml", "Tenant", {"name": "acme"})
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("1 custom resource(s) carry an operator API group and were not walked", out)
        self.assertIn("addons/ai-platform/tenant.yaml: Tenant/main", out)

    def test_a_corpus_under_the_floor_cannot_run(self):
        (self.root / "addons" / "ai-platform" / "gateway.yaml").unlink()
        rc, out = self.run_gate()
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn(f"below the floor of {gate.MIN_CRS}", out)

    def test_a_version_the_registry_does_not_have_is_a_finding(self):
        self.pin("0.9.9")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "operator 0.9.9: oci://ghcr.io/nanohype/eks-agent-platform/charts/operator answered",
            out,
        )

    def test_a_registry_that_stays_down_cannot_run(self):
        self.operator = lambda req: fake.http_error(req.full_url, 503)
        rc, out = self.run_gate()
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn(
            f"Cannot run: operator {self.VERSION} from {gate.CHART} could not be read", out
        )

    def test_chart_source_and_other_documents_in_the_tree_are_passed_over(self):
        templates = self.root / "catalog" / "x" / "chart" / "templates"
        templates.mkdir(parents=True)
        (templates.parent / "Chart.yaml").write_text("apiVersion: v2\nname: x\nversion: 0.1.0\n")
        (templates / "cm.yaml").write_text(
            "kind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"
        )
        (self.root / "addons" / "list.yaml").write_text("- one\n- two\n")
        path = self.root / "addons" / "ai-platform" / "older.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": f"{GROUP}/v1beta1",
                    "kind": "Platform",
                    "metadata": {"name": "old"},
                    "spec": {"x": 1},
                }
            )
        )
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok: 2 platform CR(s) admissible", out)

    def test_a_manifest_that_does_not_parse_cannot_run(self):
        (self.root / "addons" / "broken.yaml").write_text("kind: Platform\nspec: [unclosed\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, gate.gatelib.CANNOT_RUN, out)
        self.assertIn("addons/broken.yaml is not parseable YAML", out)

    def test_offline_skips_without_reading_the_registry(self):
        rc, out = self.run_gate("--offline")
        self.assertEqual(rc, 0, out)
        self.assertIn(
            f"--offline: skipped (would validate against operator chart {self.VERSION})", out
        )
        self.assertEqual(self.hosts.urls, [])

    def test_the_self_test_holds_the_walker(self):
        rc, out = self.run_gate("--self-test")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.hosts.urls, [])


if __name__ == "__main__":
    unittest.main()
