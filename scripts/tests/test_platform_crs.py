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
"""

from __future__ import annotations

import unittest

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
        "properties": {"tenant": {"type": "string"},
                       "persona": {"type": "string", "default": "generic"}},
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
        self.assertEqual(
            problems_for({"tenant": "t", "persona": "ops"}, self.SCHEMA), [])


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
        found = problems_for({"minACU": 0.5},
                             {"type": "object",
                              "properties": {"minACU": {"type": "string"}}})
        self.assertEqual(len(found), 1)
        self.assertIn("must be of type string", found[0])
        self.assertIn("quote it", found[0])

    def test_a_quoted_quantity_is_accepted(self):
        self.assertEqual(
            problems_for({"minACU": "0.5"},
                         {"type": "object",
                          "properties": {"minACU": {"type": "string"}}}), [])

    def test_a_bool_does_not_satisfy_integer(self):
        """In Python a bool IS an int, so a naive check passes an unquoted `true`."""
        found = problems_for({"replicas": True},
                             {"type": "object",
                              "properties": {"replicas": {"type": "integer"}}})
        self.assertEqual(len(found), 1)
        self.assertIn("is a boolean and the CRD declares integer", found[0])

    def test_an_integer_satisfies_number(self):
        self.assertEqual(
            problems_for({"ratio": 3},
                         {"type": "object",
                          "properties": {"ratio": {"type": "number"}}}), [])

    def test_a_float_does_not_satisfy_integer(self):
        found = problems_for({"replicas": 1.5},
                             {"type": "object",
                              "properties": {"replicas": {"type": "integer"}}})
        self.assertEqual(len(found), 1)
        self.assertIn("must be of type integer", found[0])

    def test_an_unset_value_is_not_a_type_error(self):
        self.assertEqual(
            problems_for({"tenant": None},
                         {"type": "object",
                          "properties": {"tenant": {"type": "string"}}}), [])

    def test_a_schema_declaring_no_type_checks_nothing(self):
        self.assertEqual(
            problems_for({"x": 1}, {"type": "object", "properties": {"x": {}}}), [])

    def test_the_reported_type_name_is_the_one_the_api_server_prints(self):
        for value, name in ((True, "boolean"), ("s", "string"), (1, "integer"),
                            (1.5, "number"), ({}, "object"), ([], "array")):
            with self.subTest(value=value):
                self.assertEqual(gate._json_type_name(value), name)


class ListIdentity(unittest.TestCase):
    """x-kubernetes-list-type is a validation rule, not documentation.

    A duplicate is a hard rejection of the whole object — not a warning, not a
    merge of the two entries.
    """

    MAP_SCHEMA = {
        "type": "object",
        "properties": {"datastores": {
            "type": "array",
            "x-kubernetes-list-type": "map",
            "x-kubernetes-list-map-keys": ["name"],
            "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "kind": {"type": "string"}}},
        }},
    }

    def test_two_entries_sharing_the_map_key_are_rejected(self):
        found = problems_for(
            {"datastores": [{"name": "main"}, {"name": "main", "kind": "cache"}]},
            self.MAP_SCHEMA)
        self.assertEqual(len(found), 1)
        self.assertIn("Duplicate value", found[0])
        self.assertIn("repeats name=main", found[0])

    def test_distinct_map_keys_are_accepted(self):
        self.assertEqual(problems_for(
            {"datastores": [{"name": "main"}, {"name": "cache"}]},
            self.MAP_SCHEMA), [])

    def test_an_absent_key_participates_in_the_identity(self):
        """Reading only the fields that happen to be set misses this pair."""
        found = problems_for(
            {"datastores": [{"kind": "a"}, {"kind": "b"}]}, self.MAP_SCHEMA)
        self.assertEqual(len(found), 1)
        self.assertIn("<unset>", found[0])

    def test_a_set_list_identifies_a_scalar_by_itself(self):
        schema = {"type": "object", "properties": {"zones": {
            "type": "array", "x-kubernetes-list-type": "set",
            "items": {"type": "string"}}}}
        found = problems_for({"zones": ["us-east-1a", "us-east-1a"]}, schema)
        self.assertEqual(len(found), 1)
        self.assertIn("repeats value=us-east-1a", found[0])

    def test_an_atomic_list_imposes_no_uniqueness(self):
        schema = {"type": "object", "properties": {"args": {
            "type": "array", "x-kubernetes-list-type": "atomic",
            "items": {"type": "string"}}}}
        self.assertEqual(problems_for({"args": ["-v", "-v"]}, schema), [])

    def test_a_list_with_no_declared_type_imposes_no_uniqueness(self):
        schema = {"type": "object", "properties": {"args": {
            "type": "array", "items": {"type": "string"}}}}
        self.assertEqual(problems_for({"args": ["-v", "-v"]}, schema), [])

    def test_a_map_list_declaring_no_keys_imposes_no_uniqueness(self):
        schema = {"type": "object", "properties": {"x": {
            "type": "array", "x-kubernetes-list-type": "map",
            "items": {"type": "object"}}}}
        self.assertEqual(problems_for({"x": [{"a": 1}, {"a": 1}]}, schema), [])

    def test_three_entries_sharing_an_identity_report_each_repeat(self):
        found = problems_for(
            {"datastores": [{"name": "m"}, {"name": "m"}, {"name": "m"}]},
            self.MAP_SCHEMA)
        self.assertEqual(len(found), 2)


class TheWalkDescends(unittest.TestCase):
    """A rule that fires only at the top level checks the least interesting layer."""

    SCHEMA = {
        "type": "object",
        "properties": {"identity": {
            "type": "object",
            "required": ["allowedModels"],
            "properties": {"allowedModels": {
                "type": "array",
                "x-kubernetes-list-type": "set",
                "items": {"type": "string"}}},
        }},
    }

    def test_a_nested_required_property_is_reached(self):
        found = problems_for({"identity": {}}, self.SCHEMA)
        self.assertIn("`identity.allowedModels: Required value`", found[0])

    def test_a_duplicate_inside_a_nested_list_is_reached(self):
        found = problems_for(
            {"identity": {"allowedModels": ["us.anthropic.claude-sonnet-5",
                                            "us.anthropic.claude-sonnet-5"]}},
            self.SCHEMA)
        self.assertEqual(len(found), 1)
        self.assertIn(".identity.allowedModels", found[0])

    def test_a_type_error_inside_an_array_item_names_its_index(self):
        schema = {"type": "object", "properties": {"routes": {
            "type": "array",
            "items": {"type": "object",
                      "properties": {"rateLimit": {"type": "integer"}}}}}}
        found = problems_for({"routes": [{"rateLimit": 60}, {"rateLimit": "60"}]},
                             schema)
        self.assertEqual(len(found), 1)
        self.assertIn(".routes[1].rateLimit", found[0])

    def test_a_mistyped_container_is_reported_before_it_is_descended_into(self):
        schema = {"type": "object", "properties": {"identity": {
            "type": "object", "properties": {"allowedModels": {"type": "array"}}}}}
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
        found = [f for f in gate.manifests()
                 if "kind: Platform" in f.read_text(encoding="utf-8", errors="replace")]
        self.assertTrue(found,
                        "no manifest in the walk declares a Platform, so this gate "
                        "examined none of the CRs it exists to check")


if __name__ == "__main__":
    unittest.main()
