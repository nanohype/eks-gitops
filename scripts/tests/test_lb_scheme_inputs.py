"""Unit tests for the load-balancer scheme-input gate.

The gate's whole value is that the set of inputs is DERIVED from the controller
rather than remembered, so the tests concentrate on the derivation and on the two
verdicts that make a new input visible: a symbol the controller consults and the
record does not carry, and a symbol the record carries that the policy has
stopped reading.

The Go reading is deliberately small — find a function, follow the calls it makes
within its own file, collect what those bodies name — and small is only safe if
each clause is pinned. A walk that silently stops one call short produces a
shorter input list and a clean run, which is the failure this gate exists to
prevent rather than to demonstrate.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest import mock

import fakeregistry as fake
from gateloader import load

gate = load("check-lb-scheme-inputs")

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

PIN = {"chartRepo": "https://example.invalid/charts", "chart": "lbc", "chartVersion": "1.2.3"}


def record(symbols=None, literals=None, **kw):
    doc = {
        "controller": {**PIN, "sourceRef": "v1.2.3"},
        "controllerConfig": {"args": {"default-load-balancer-scheme": "internal"},
                             "serviceMutatorWebhook": False},
        "literals": literals if literals is not None else {"'internal'": "the default"},
        "symbols": symbols if symbols is not None else {
            "Service.annotations.SvcLBSuffixScheme": {
                "decides": "scheme", "kind": "Service",
                "annotation": "service.beta.kubernetes.io/aws-load-balancer-scheme",
                "status": "read"},
            "Ingress.annotations.IngressSuffixScheme": {
                "decides": "scheme", "kind": "Ingress",
                "annotation": "alb.ingress.kubernetes.io/scheme", "status": "read"},
            "Service.Spec.LoadBalancerClass": {
                "decides": "ownership", "kind": "Service", "annotation": None,
                "status": "read", "evidence": "request.object.spec.loadBalancerClass"},
            "Service.buildLoadBalancerScheme.existingLoadBalancer": {
                "decides": "scheme", "kind": "Service", "annotation": None,
                "status": "unread", "note": "not visible from an admission request"},
        },
    }
    doc.update(kw)
    return doc


POLICY = (
    "service.beta.kubernetes.io/aws-load-balancer-scheme\n"
    "alb.ingress.kubernetes.io/scheme\n"
    "request.object.spec.loadBalancerClass\n"
    "|| 'internal' }}\n"
)


def verdict(rec=None, pin=None, policy=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = gate.check_offline(rec or record(), pin or PIN, policy or POLICY)
    return rc, buf.getvalue()


GO = '''package service

func (t *task) buildLoadBalancerScheme(ctx context.Context) (Scheme, error) {
	scheme, ok, err := t.viaAnnotation(ctx)
	if ok {
		return scheme, nil
	}
	return t.defaultLoadBalancerScheme, nil
}

func (t *task) viaAnnotation(ctx context.Context) (Scheme, bool, error) {
	if exists := t.annotationParser.ParseStringAnnotation(annotations.SvcLBSuffixScheme, &raw, t.service.Annotations); exists {
		return raw, true, nil
	}
	return t.legacy(ctx)
}

func (t *task) legacy(_ context.Context) (Scheme, bool, error) {
	_, err := t.annotationParser.ParseBoolAnnotation(annotations.SvcLBSuffixInternal, &internal, t.service.Annotations)
	return SchemeInternal, false, err
}

func (t *task) unrelated(ctx context.Context) error {
	return t.annotationParser.Parse(annotations.SvcLBSuffixNotConsulted)
}
'''


class ReadingGoSource(unittest.TestCase):
    def test_a_function_body_ends_at_the_closing_brace_in_column_zero(self):
        body = gate.function_body(GO, "legacy")
        self.assertIn("SvcLBSuffixInternal", body)
        self.assertNotIn("unrelated", body)

    def test_a_function_that_is_not_there_is_not_an_empty_one(self):
        # None, never "": a caller cannot tell an empty body from an absent
        # function if both are falsy, and the absent one means the derivation
        # lost its entry point.
        self.assertIsNone(gate.function_body(GO, "noSuchFunction"))

    def test_the_walk_follows_calls_transitively(self):
        names = [n for n, _ in gate.reachable(GO, "buildLoadBalancerScheme")]
        self.assertEqual(sorted(names), ["buildLoadBalancerScheme", "legacy", "viaAnnotation"])

    def test_the_walk_does_not_reach_what_the_entry_point_never_calls(self):
        text = "\n".join(b for _, b in gate.reachable(GO, "buildLoadBalancerScheme"))
        self.assertNotIn("SvcLBSuffixNotConsulted", text)

    def test_the_walk_terminates_on_a_cycle(self):
        cyclic = GO + '''
func (t *task) a(ctx context.Context) error {
	return t.b(ctx)
}

func (t *task) b(ctx context.Context) error {
	return t.a(ctx)
}
'''
        names = [n for n, _ in gate.reachable(cyclic, "a")]
        self.assertEqual(sorted(names), ["a", "b"])

    def test_a_body_written_on_the_signature_line_is_read(self):
        # gofmt allows it, and a one-line helper dropping out of the walk takes
        # whatever it consults with it — a shorter input list and a clean run.
        oneline = '''package service

func (t *task) entry(ctx context.Context) error {
	return t.helper(ctx)
}

func (t *task) helper(ctx context.Context) error { return t.parser.Parse(annotations.SvcLBSuffixOneLine) }
'''
        text = "\n".join(b for _, b in gate.reachable(oneline, "entry"))
        self.assertIn("SvcLBSuffixOneLine", text)

    def test_a_helper_on_another_receiver_is_followed_too(self):
        # IsServiceSupported reaches its type check through a different receiver
        # name; a walk keyed on one receiver drops half the ownership decision.
        other = '''package service

func (u *utils) IsServiceSupported(s *Service) bool {
	return u.checkTypeAnnotation(s)
}

func (u *utils) checkTypeAnnotation(s *Service) bool {
	return u.annotationParser.Parse(annotations.SvcLBSuffixLoadBalancerType)
}
'''
        text = "\n".join(b for _, b in gate.reachable(other, "IsServiceSupported"))
        self.assertIn("SvcLBSuffixLoadBalancerType", text)

    def test_constants_are_read_as_name_to_value(self):
        consts = gate.constants({"c.go": '''package annotations
const (
	AnnotationPrefixIngress = "alb.ingress.kubernetes.io"
	IngressSuffixScheme     = "scheme"
	IngressClass            = "kubernetes.io/ingress.class"
	NotAString              = 7
)
'''})
        self.assertEqual(consts["IngressSuffixScheme"], "scheme")
        self.assertEqual(consts["AnnotationPrefixIngress"], "alb.ingress.kubernetes.io")
        self.assertNotIn("NotAString", consts)


class DerivingTheSymbols(unittest.TestCase):
    CONSTS = '''package annotations
const (
	AnnotationPrefixIngress = "alb.ingress.kubernetes.io"
	IngressSuffixScheme     = "scheme"
	IngressClass            = "kubernetes.io/ingress.class"
	SvcLBSuffixScheme       = "aws-load-balancer-scheme"
	SvcLBSuffixInternal     = "aws-load-balancer-internal"
	serviceAnnotationPrefix = "service.beta.kubernetes.io"
)
'''
    INGRESS = '''package ingress

func (t *task) buildLoadBalancerScheme(_ context.Context) (Scheme, error) {
	if member.IngClassConfig.IngClassParams.Spec.Scheme != nil {
		return *member.IngClassConfig.IngClassParams.Spec.Scheme, nil
	}
	t.annotationParser.ParseStringAnnotation(annotations.IngressSuffixScheme, &raw, member.Ing.Annotations)
	return t.defaultScheme, nil
}
'''
    OWNERSHIP = '''package service

func (u *utils) IsServiceSupported(service *Service) bool {
	if service.Spec.LoadBalancerClass != nil {
		return *service.Spec.LoadBalancerClass == u.loadBalancerClass
	}
	return false
}
'''

    def derive(self):
        files = {"pkg/annotations/constants.go": self.CONSTS,
                 "pkg/service/model_builder.go": "package service\n",
                 "controllers/service/service_controller.go": self.CONSTS,
                 "pkg/service/model_build_load_balancer.go": GO,
                 "pkg/ingress/model_build_load_balancer.go": self.INGRESS,
                 "pkg/service/service_utils.go": self.OWNERSHIP}
        real = gate.fetch
        gate.fetch = lambda ref, path: files[path]
        try:
            return gate.symbols("vtest")
        finally:
            gate.fetch = real

    def test_a_suffix_becomes_the_annotation_a_policy_would_read(self):
        got = self.derive()
        self.assertEqual(got["Service.annotations.SvcLBSuffixScheme"]["annotation"],
                         "service.beta.kubernetes.io/aws-load-balancer-scheme")
        self.assertEqual(got["Ingress.annotations.IngressSuffixScheme"]["annotation"],
                         "alb.ingress.kubernetes.io/scheme")

    def test_the_legacy_spelling_is_derived_rather_than_listed(self):
        # The defect that prompted the gate: a second annotation the controller
        # honours, reached only because the walk follows the fallback call.
        got = self.derive()
        self.assertEqual(got["Service.annotations.SvcLBSuffixInternal"]["annotation"],
                         "service.beta.kubernetes.io/aws-load-balancer-internal")

    def test_a_source_that_is_not_an_annotation_is_derived_too(self):
        got = self.derive()
        self.assertIn("Ingress.Spec.Scheme", got)
        self.assertIsNone(got["Ingress.Spec.Scheme"]["annotation"])
        self.assertIn("Service.Spec.LoadBalancerClass", got)

    def test_each_symbol_carries_the_question_it_answers(self):
        got = self.derive()
        self.assertEqual(got["Service.Spec.LoadBalancerClass"]["decides"], "ownership")
        self.assertEqual(got["Ingress.Spec.Scheme"]["decides"], "scheme")

    def test_an_entry_point_that_has_moved_cannot_run(self):
        files = {"pkg/annotations/constants.go": self.CONSTS,
                 "pkg/service/model_builder.go": "package service\n",
                 "controllers/service/service_controller.go": self.CONSTS,
                 "pkg/service/model_build_load_balancer.go": "package service\n",
                 "pkg/ingress/model_build_load_balancer.go": self.INGRESS,
                 "pkg/service/service_utils.go": self.OWNERSHIP}
        real = gate.fetch
        gate.fetch = lambda ref, path: files[path]
        try:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                gate.symbols("vtest")
        finally:
            gate.fetch = real

    def test_an_annotation_constant_that_resolves_to_nothing_cannot_run(self):
        files = {"pkg/annotations/constants.go": 'package annotations\nconst (\n\tAnnotationPrefixIngress = "alb.ingress.kubernetes.io"\n\tserviceAnnotationPrefix = "service.beta.kubernetes.io"\n)\n',
                 "pkg/service/model_builder.go": "package service\n",
                 "controllers/service/service_controller.go": "package service\n",
                 "pkg/service/model_build_load_balancer.go": GO,
                 "pkg/ingress/model_build_load_balancer.go": self.INGRESS,
                 "pkg/service/service_utils.go": self.OWNERSHIP}
        real = gate.fetch
        gate.fetch = lambda ref, path: files[path]
        try:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                gate.symbols("vtest")
        finally:
            gate.fetch = real


class NamingSomethingIsNotContainingIt(unittest.TestCase):
    """A prefix is not a mention, and reading it as one hides a rename."""

    def test_a_whole_token_counts(self):
        self.assertTrue(gate.mentions(POLICY,
                                      "service.beta.kubernetes.io/aws-load-balancer-scheme"))

    def test_a_longer_annotation_does_not_count_as_the_shorter_one(self):
        renamed = "service.beta.kubernetes.io/aws-load-balancer-internal-renamed"
        self.assertFalse(gate.mentions(renamed,
                                       "service.beta.kubernetes.io/aws-load-balancer-internal"))

    def test_a_literal_inside_a_longer_word_does_not_count(self):
        self.assertFalse(gate.mentions("value: not-internal-either", "internal"))
        self.assertTrue(gate.mentions("value: 'internal' }}", "'internal'"))


class TheOfflineVerdict(unittest.TestCase):
    def test_the_shape_it_is_written_for_passes(self):
        rc, said = verdict()
        self.assertEqual(rc, 0, said)

    def test_an_input_the_policy_stopped_reading_is_rejected(self):
        rc, said = verdict(policy=POLICY.replace("alb.ingress.kubernetes.io/scheme", ""))
        self.assertEqual(rc, 1)
        self.assertIn("IngressSuffixScheme", said)

    def test_an_input_read_by_something_other_than_its_annotation_name(self):
        rc, said = verdict(policy=POLICY.replace("request.object.spec.loadBalancerClass", ""))
        self.assertEqual(rc, 1)
        self.assertIn("LoadBalancerClass", said)

    def test_an_input_recorded_read_with_nothing_naming_where(self):
        rec = record()
        rec["symbols"]["Service.Spec.LoadBalancerClass"].pop("evidence")
        rc, said = verdict(rec)
        self.assertEqual(rc, 1)
        self.assertIn("agreeing with itself", said)

    def test_an_input_that_is_neither_read_nor_excused(self):
        rec = record()
        rec["symbols"]["Service.buildLoadBalancerScheme.existingLoadBalancer"].pop("note")
        rc, said = verdict(rec)
        self.assertEqual(rc, 1)
        self.assertIn("nobody excused", said)

    def test_an_input_with_no_decision_recorded(self):
        rec = record()
        rec["symbols"]["Service.buildLoadBalancerScheme.existingLoadBalancer"]["status"] = "maybe"
        rc, said = verdict(rec)
        self.assertEqual(rc, 1)
        self.assertIn("not been decided about", said)

    def test_a_record_derived_from_a_version_nothing_pins(self):
        rec = record()
        rec["controller"]["chartVersion"] = "9.9.9"
        rc, said = verdict(rec)
        self.assertEqual(rc, 1)
        self.assertIn("different version", said)

    def test_a_record_that_does_not_say_which_source_it_read(self):
        rec = record()
        rec["controller"]["sourceRef"] = ""
        rc, said = verdict(rec)
        self.assertEqual(rc, 1)

    def test_a_derivation_with_no_symbols_at_all_is_not_a_pass(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            verdict(record(symbols={}))

    def test_a_question_nothing_was_derived_for_is_rejected(self):
        rec = record(symbols={k: v for k, v in record()["symbols"].items()
                              if v["decides"] != "ownership"})
        rc, said = verdict(rec)
        self.assertEqual(rc, 1)
        self.assertIn("ownership", said)

    def test_a_literal_the_policy_no_longer_names(self):
        rc, said = verdict(policy=POLICY.replace("|| 'internal' }}", ""))
        self.assertEqual(rc, 1)
        self.assertIn("'internal'", said)

    def test_literals_held_equal_to_nothing(self):
        rc, said = verdict(record(literals={}))
        self.assertEqual(rc, 1)
        self.assertIn("held equal to nothing", said)


class TheLiveVerdict(unittest.TestCase):
    """The half that finds the spelling nobody added."""

    def live(self, derived, rec=None, flags=None):
        real_sym, real_flags = gate.symbols, gate.rendered_flags
        gate.symbols = lambda ref: derived
        gate.rendered_flags = lambda pin: flags or {
            "args": {"default-load-balancer-scheme": "internal"},
            "serviceMutatorWebhook": False}
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = gate.check_live(rec or record(), PIN)
            return rc, buf.getvalue()
        finally:
            gate.symbols, gate.rendered_flags = real_sym, real_flags

    def derived_from(self, rec):
        return {k: {"decides": v["decides"], "kind": v["kind"],
                    "annotation": v.get("annotation")}
                for k, v in rec["symbols"].items()}

    def test_a_derivation_matching_the_record_passes(self):
        rec = record()
        rc, said = self.live(self.derived_from(rec), rec)
        self.assertEqual(rc, 0, said)

    def test_a_deciding_input_the_record_does_not_carry_is_rejected(self):
        # A third spelling appearing upstream: derived, unrecorded, and therefore
        # unread by a policy nobody has thought about it for.
        rec = record()
        derived = self.derived_from(rec)
        derived["Service.annotations.SvcLBSuffixSomethingNew"] = {
            "decides": "scheme", "kind": "Service",
            "annotation": "service.beta.kubernetes.io/aws-load-balancer-something-new"}
        rc, said = self.live(derived, rec)
        self.assertEqual(rc, 1)
        self.assertIn("SomethingNew", said)
        self.assertIn("--sync", said)

    def test_a_recorded_input_upstream_no_longer_consults(self):
        rec = record()
        derived = self.derived_from(rec)
        derived.pop("Service.buildLoadBalancerScheme.existingLoadBalancer")
        rc, said = self.live(derived, rec)
        self.assertEqual(rc, 1)
        self.assertIn("no longer consults", said)

    def test_an_annotation_that_was_renamed_upstream(self):
        rec = record()
        derived = self.derived_from(rec)
        derived["Service.annotations.SvcLBSuffixScheme"]["annotation"] = \
            "service.beta.kubernetes.io/aws-lb-scheme"
        rc, said = self.live(derived, rec)
        self.assertEqual(rc, 1)
        self.assertIn("aws-lb-scheme", said)

    def test_a_controller_flag_the_policy_is_not_written_for(self):
        rec = record()
        rc, said = self.live(self.derived_from(rec), rec,
                             flags={"args": {"default-load-balancer-scheme": "internet-facing"},
                                    "serviceMutatorWebhook": False})
        self.assertEqual(rc, 1)
        self.assertIn("internet-facing", said)

    def test_the_service_mutator_webhook_coming_back(self):
        # It stamps loadBalancerClass onto every LoadBalancer Service, which moves
        # the whole plain shape into the controller's population.
        rec = record()
        rc, said = self.live(self.derived_from(rec), rec,
                             flags={"args": {"default-load-balancer-scheme": "internal"},
                                    "serviceMutatorWebhook": True})
        self.assertEqual(rc, 1)
        self.assertIn("loadBalancerClass", said)


class WritingTheRecord(unittest.TestCase):
    """--sync regenerates what was derived and refuses to invent a decision."""

    def sync(self, derived, prior, flags=None):
        # Inside the repo root: the gate names its record relative to it, and a
        # path outside cannot be named that way.
        real = (gate.symbols, gate.rendered_flags, gate.app_version, gate.RECORDS)
        gate.symbols = lambda ref: derived
        gate.app_version = lambda pin: "v1.2.3"
        gate.rendered_flags = lambda pin: flags or {
            "args": {"default-load-balancer-scheme": "internal"},
            "serviceMutatorWebhook": False}
        try:
            with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                out = pathlib.Path(tmp) / "record.json"
                out.write_text(json.dumps(prior))
                gate.RECORDS = out
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = gate.sync(prior, PIN)
                return rc, json.loads(out.read_text()), buf.getvalue()
        finally:
            gate.symbols, gate.rendered_flags, gate.app_version, gate.RECORDS = real

    def derived_from(self, rec):
        return {k: {"decides": v["decides"], "kind": v["kind"],
                    "annotation": v.get("annotation")}
                for k, v in rec["symbols"].items()}

    def test_a_symbol_nobody_decided_about_stops_the_sync(self):
        # The property the gate exists for. A new deciding input is a decision
        # somebody makes; regenerating the record past it would record silence.
        prior = record()
        derived = self.derived_from(prior)
        derived["Service.annotations.SvcLBSuffixSomethingNew"] = {
            "decides": "scheme", "kind": "Service", "annotation": "x/y"}
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            self.sync(derived, prior)
        self.assertIn("SomethingNew", err.getvalue())

    def test_a_decision_already_made_is_carried_forward(self):
        prior = record()
        rc, written, _ = self.sync(self.derived_from(prior), prior)
        self.assertEqual(rc, 0)
        was = prior["symbols"]["Service.buildLoadBalancerScheme.existingLoadBalancer"]
        now = written["symbols"]["Service.buildLoadBalancerScheme.existingLoadBalancer"]
        self.assertEqual(now["status"], was["status"])
        self.assertEqual(now["note"], was["note"])

    def test_what_sync_writes_is_what_the_gate_compares_against(self):
        # A generator and a comparison that disagree leave a record nothing can
        # be regenerated to.
        prior = record()
        _, written, _ = self.sync(self.derived_from(prior), prior)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = gate.check_offline(written, PIN, POLICY)
        self.assertEqual(rc, 0, buf.getvalue())

    def test_the_source_it_read_is_recorded(self):
        prior = record()
        _, written, _ = self.sync(self.derived_from(prior), prior)
        self.assertEqual(written["controller"]["sourceRef"], "v1.2.3")
        self.assertEqual(written["controller"]["chartVersion"], PIN["chartVersion"])

    def test_the_rendered_configuration_is_recorded_not_assumed(self):
        prior = record()
        _, written, _ = self.sync(
            self.derived_from(prior), prior,
            flags={"args": {"default-load-balancer-scheme": "internet-facing"},
                   "serviceMutatorWebhook": True})
        self.assertEqual(written["controllerConfig"]["args"]["default-load-balancer-scheme"],
                         "internet-facing")
        self.assertTrue(written["controllerConfig"]["serviceMutatorWebhook"])


class ReadingThePinnedChart(unittest.TestCase):
    """Exit 1 only when the chart repository answered and ruled the pin out.

    The metadata read and the archive read fail the same ways, and each maps
    to the status registry.ChartUnavailable carries: a pin the repository says
    is not there is a finding about this catalog, and a repository that could
    not be read says nothing about it.
    """

    def unavailable(self, answered):
        def read(*args, **kwargs):
            raise gate.registry.ChartUnavailable("scripted", answered=answered)
        return read

    def exit_status(self, attr, answered, call):
        real = getattr(gate.registry, attr)
        setattr(gate.registry, attr, self.unavailable(answered))
        real_require = gate.gatelib.require
        gate.gatelib.require = lambda tool: None
        try:
            with self.assertRaises(SystemExit) as caught, \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                call(PIN)
        finally:
            setattr(gate.registry, attr, real)
            gate.gatelib.require = real_require
        return caught.exception.code, out.getvalue() + err.getvalue()

    def test_metadata_ruled_out_by_the_repository_is_a_finding(self):
        code, said = self.exit_status("chart_metadata", True, gate.app_version)
        self.assertEqual(code, 1)
        self.assertIn(f"{PIN['chart']} {PIN['chartVersion']}: {PIN['chartRepo']} answered, "
                      f"and its answer rules the pin out", said)

    def test_metadata_that_could_not_be_read_cannot_run(self):
        code, said = self.exit_status("chart_metadata", False, gate.app_version)
        self.assertEqual(code, gate.gatelib.CANNOT_RUN)
        self.assertIn(f"Cannot run: {PIN['chart']} {PIN['chartVersion']} from "
                      f"{PIN['chartRepo']} could not be read:", said)

    def test_an_archive_ruled_out_by_the_repository_is_a_finding(self):
        code, _ = self.exit_status("chart_archive", True, gate.rendered_flags)
        self.assertEqual(code, 1)

    def test_an_archive_that_could_not_be_read_cannot_run(self):
        code, _ = self.exit_status("chart_archive", False, gate.rendered_flags)
        self.assertEqual(code, gate.gatelib.CANNOT_RUN)

    def test_the_app_version_is_what_the_chart_says_it_installs(self):
        real = gate.registry.chart_metadata
        gate.registry.chart_metadata = lambda *a, **k: {"appVersion": " v2.8.1 "}
        try:
            self.assertEqual(gate.app_version(PIN), "v2.8.1")
        finally:
            gate.registry.chart_metadata = real


class ReadingTheControllerSource(unittest.TestCase):
    """A source file is one registry client call, so its read ends at that call's bound.

    urlopen's timeout bounds each wait on the socket, not a whole response, so
    read with urlopen alone a server that keeps sending inside every timeout
    keeps the read going for as long as it likes, and the scheduled job is
    cancelled with nothing said about which host held it. The server here is
    scripted at urlopen, and urlopen itself answers from it as well as the
    client does, so what is held is the read this gate makes, however it makes
    it.
    """

    REF = "v2.8.1"
    PATH = "pkg/annotations/constants.go"
    URL = f"{gate.SOURCE}/{REF}/{PATH}"
    SOURCE = b"package annotations\n" * 2048

    def read(self, t: fake.Transport):
        """(what fetch returned, its exit status or None, everything it printed)."""
        out = io.StringIO()
        with mock.patch.object(urllib.request, "urlopen", t.urlopen), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                return gate.fetch(self.REF, self.PATH, t.bind(gate.registry.http_get)), \
                    None, out.getvalue()
            except SystemExit as exc:
                return None, exc.code, out.getvalue()

    def test_a_source_file_is_read_through_the_client(self):
        t = fake.Transport(self.SOURCE)
        text, code, _ = self.read(t)
        self.assertIsNone(code)
        self.assertEqual(text, self.SOURCE.decode())
        self.assertEqual(t.urls(), [self.URL])
        self.assertEqual(t.requests[0].get_header("User-agent"), gate.registry.USER_AGENT)

    def test_a_body_that_trickles_past_the_deadline_cannot_run(self):
        """Each read of the socket is charged just under HTTP_TIMEOUT, so no wait
        times out. The read is reported once the call's deadline has passed, with
        the rest of the body unread, and within CALL_BOUND_SECONDS."""
        t = fake.Transport()
        t.steps.append(t.trickle(self.SOURCE, piece=256,
                                 seconds=gate.registry.HTTP_TIMEOUT - 1))
        text, code, said = self.read(t)
        self.assertIsNone(text, "a body trickled past the deadline was read whole")
        self.assertEqual(code, gate.gatelib.CANNOT_RUN)
        self.assertIn(f"Cannot run: {self.URL} could not be read:", said)
        self.assertIn(f"ran out while the body of {self.URL} was arriving", said)
        self.assertGreater(t.responses[0].wire.unsent(), 0)
        self.assertLessEqual(t.elapsed, gate.registry.CALL_BOUND_SECONDS)

    def test_a_rate_limit_is_waited_out_as_the_host_asks(self):
        t = fake.Transport(fake.http_error(self.URL, 429, {"Retry-After": "7"}), self.SOURCE)
        text, code, _ = self.read(t)
        self.assertIsNone(code)
        self.assertEqual(text, self.SOURCE.decode())
        self.assertEqual(t.waits, [7.0])

    def test_a_file_the_ref_does_not_hold_is_a_finding(self):
        text, code, said = self.read(fake.Transport(fake.http_error(self.URL, 404)))
        self.assertIsNone(text)
        self.assertEqual(code, 1)
        self.assertIn(f"{self.PATH} is not in the controller source at {self.REF}", said)

    def test_a_source_that_could_not_be_read_cannot_run(self):
        """Only a 404 says the file is not there. A server fault, a network error or
        a rate limit that outlasts the retries says nothing about this catalog."""
        for name, steps in (
                ("server fault", [fake.http_error(self.URL, 500)]),
                ("network error", [urllib.error.URLError("no route")]),
                ("rate limit", [fake.http_error(self.URL, 429)]
                 * gate.registry.RETRY_ATTEMPTS)):
            with self.subTest(name):
                text, code, said = self.read(fake.Transport(*steps))
                self.assertIsNone(text)
                self.assertEqual(code, gate.gatelib.CANNOT_RUN)
                self.assertIn(f"Cannot run: {self.URL} could not be read:", said)


class FindingThePin(unittest.TestCase):
    """The controller's chart coordinates come from its ApplicationSet element.

    An element missing one of them, or no element at all, leaves this gate no
    version to read the controller at: a defect in the tree, exit 1, said in a
    sentence naming the ApplicationSet rather than a KeyError's traceback.
    """

    def pin_from(self, *docs):
        real = gate.gatelib.read_yaml_all
        gate.gatelib.read_yaml_all = lambda _path: list(docs)
        try:
            with self.assertRaises(SystemExit) as caught, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                gate.chart_pin()
        finally:
            gate.gatelib.read_yaml_all = real
        return caught.exception.code, err.getvalue()

    @staticmethod
    def appset(*elements):
        return {"kind": "ApplicationSet",
                "spec": {"generators": [{"list": {"elements": list(elements)}}]}}

    def test_an_element_missing_its_version_is_a_finding(self):
        element = {"appName": gate.ADDON_NAME, "chartRepo": PIN["chartRepo"],
                   "chart": PIN["chart"]}
        code, said = self.pin_from({"kind": "ConfigMap"}, self.appset(element))
        self.assertEqual(code, 1)
        self.assertIn(f"names {gate.ADDON_NAME} without chartVersion", said)

    def test_an_appset_with_no_controller_element_is_a_finding(self):
        code, said = self.pin_from(self.appset({"appName": "something-else"}))
        self.assertEqual(code, 1)
        self.assertIn(f"carries no {gate.ADDON_NAME} element", said)


class TheShippedCatalog(unittest.TestCase):
    def setUp(self):
        self.record = gate.load_records()
        self.pin = gate.chart_pin()
        self.policy = gate.policy_text()

    def test_the_pin_is_read_out_of_the_applicationset(self):
        self.assertEqual(self.pin["chart"], "aws-load-balancer-controller")
        self.assertTrue(self.pin["chartVersion"])

    def test_the_record_was_derived_at_the_pinned_version(self):
        self.assertEqual(self.record["controller"]["chartVersion"], self.pin["chartVersion"])

    def test_both_questions_are_derived_for(self):
        decides = {(s["decides"], s["kind"]) for s in self.record["symbols"].values()}
        self.assertIn(("scheme", "Service"), decides)
        self.assertIn(("scheme", "Ingress"), decides)
        self.assertIn(("ownership", "Service"), decides)

    def test_the_legacy_spelling_is_one_the_policy_reads(self):
        entry = self.record["symbols"]["Service.annotations.SvcLBSuffixInternal"]
        self.assertEqual(entry["status"], "read")
        self.assertIn(entry["annotation"], self.policy)

    def test_every_unread_input_says_why(self):
        for key, entry in self.record["symbols"].items():
            if entry["status"] != "read":
                with self.subTest(key=key):
                    self.assertTrue(entry.get("note"))

    def test_the_catalog_passes_its_own_gate(self):
        rc, said = verdict(self.record, self.pin, self.policy)
        self.assertEqual(rc, 0, said)

    def test_the_record_is_what_sync_would_write(self):
        doc = json.loads((ROOT / "scripts" / "lb-scheme-inputs.json").read_text())
        self.assertEqual(doc["_README"], gate.README)


if __name__ == "__main__":
    unittest.main()
