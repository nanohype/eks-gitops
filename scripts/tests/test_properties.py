"""Property-based tests for the four pieces of gate logic that carry an invariant.

An example-based test checks the cases someone thought of. A property states
what must hold for every input, and Hypothesis searches for an input that breaks
it, shrinking any it finds to a minimal case. The four covered here are the
decisions the gates rest on:

- verdicts.pinned, the digest-pin matcher: an admitted image is pinned exactly
  when it is the verified tag joined to one sha256 digest;
- verdicts.transport_failures, the transport-failure classifier: which lines of
  a verifier's output name a broken link, quoted within fixed bounds;
- check_value in check-label-values.py, the label-value grammar: it refuses
  what the API server refuses, and no value a template could render valid;
- the arithmetic in check-burn-rate-budgets.py, the burn-rate figure: the
  durations, the long window, the burn factors, and the percentage a claim is
  compared at.

Each property also carries, as an @example, every input that has broken it, so
those run on every run and a regression fails the same way each time. Every
other case is drawn afresh on each run.

Hypothesis keeps its example database, and the caches it builds while it runs,
under its home directory, which defaults to .hypothesis/ in the working
directory. Here that home is ~/.cache/eks-gitops/hypothesis, beside the chart
cache, so nothing lands in the tree. On a developer's machine the database
replays the failures earlier runs found. A CI runner starts with none, so a
failure there prints the @reproduce_failure line that replays it anywhere.
"""

from __future__ import annotations

import pathlib
import re
import string
import unittest
from fractions import Fraction

from gateloader import load
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st
from hypothesis.configuration import set_hypothesis_home_dir

verdicts = load("verdicts")
labels = load("check-label-values")
burn = load("check-burn-rate-budgets")

STORAGE = pathlib.Path.home() / ".cache" / "eks-gitops" / "hypothesis"
set_hypothesis_home_dir(STORAGE)
# No deadline: the suite runs under coverage's tracer, which slows each example
# unevenly, so a time limit per example would fail on the tracer rather than on
# the code. print_blob, because a CI runner keeps no database to replay from.
settings.register_profile("gates", deadline=None, print_blob=True)
settings.load_profile("gates")


# ── The digest-pin matcher ───────────────────────────────────────────────────

DIGESTS = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
# A tag as text of any kind: regular-expression metacharacters, newlines and all.
TAGS = st.text(min_size=1)

# Ways a pin can be wrong while looking nearly right. Each keeps the tag.
NOT_A_PIN = {
    "a digest one hex short": lambda tag, d: f"{tag}@sha256:{d[:-1]}",
    "a digest one hex long": lambda tag, d: f"{tag}@sha256:{d}0",
    "a newline after the digest": lambda tag, d: f"{tag}@sha256:{d}\n",
    "another algorithm": lambda tag, d: f"{tag}@sha512:{d}",
    "the algorithm in capitals": lambda tag, d: f"{tag}@SHA256:{d}",
    "a capital hex digit": lambda tag, d: f"{tag}@sha256:A{d[1:]}",
    "a letter that is not hex": lambda tag, d: f"{tag}@sha256:g{d[1:]}",
    "no @ before the digest": lambda tag, d: f"{tag}sha256:{d}",
    "a second digest": lambda tag, d: f"{tag}@sha256:{d}@sha256:{d}",
    "anything before the tag": lambda tag, d: f" {tag}@sha256:{d}",
}


class TheDigestPin(unittest.TestCase):
    @given(TAGS, DIGESTS)
    def test_the_tag_joined_to_a_sha256_digest_is_pinned(self, tagged, digest):
        self.assertTrue(verdicts.pinned(tagged, f"{tagged}@sha256:{digest}"))

    @given(TAGS, TAGS, DIGESTS)
    def test_a_pin_of_another_tag_is_not_this_tags_pin(self, tagged, other, digest):
        assume(other != tagged)
        self.assertFalse(verdicts.pinned(tagged, f"{other}@sha256:{digest}"))

    @given(TAGS, DIGESTS, st.sampled_from(sorted(NOT_A_PIN)))
    def test_a_near_miss_is_not_a_pin(self, tagged, digest, miss):
        self.assertFalse(verdicts.pinned(tagged, NOT_A_PIN[miss](tagged, digest)), miss)


# ── The transport-failure classifier ─────────────────────────────────────────

# One of each phrase the classifier exists to recognise, as the verifier's
# clients print it.
PHRASES = (
    "dial tcp: lookup ghcr.io: no such host",
    "read udp 10.0.0.2:41234->10.0.0.1:53: i/o timeout",
    "connect: connection refused",
    "read: connection reset by peer",
    "write: broken pipe",
    "net/http: TLS handshake timeout",
    "context deadline exceeded",
    "net/http: request canceled (Client.Timeout exceeded while awaiting headers)",
    "GET https://ghcr.io/v2/nanohype/x/blobs/sha256:0: unexpected EOF",
    "failed to build cosign verification opts: tuf: failed to download 1.root.json",
    "GET https://ghcr.io/v2/: unexpected status code 429 Too Many Requests",
    "GET https://ghcr.io/v2/: unexpected status code 502 Bad Gateway",
    "TOOMANYREQUESTS: retry-after: 1s",
    "[POST /api/v1/log/entries/retrieve][503] searchLogQueryDefault",
)
COLOURS = ("\x1b[0m", "\x1b[1m", "\x1b[31m", "\x1b[1;33m", "\x1b[90m")

# Text within one line, holding no colour code of its own.
LINE_TEXT = st.text(alphabet=st.characters(exclude_characters="\n\x1b"))
ASCII_LINE_TEXT = st.text(alphabet=st.characters(codec="ascii", exclude_characters="\n\x1b"))


def naming(text):
    """A line holding one of PHRASES somewhere in `text`."""
    return st.builds(
        lambda before, phrase, after: before + phrase + after, text, st.sampled_from(PHRASES), text
    )


OUTPUT = st.lists(st.one_of(LINE_TEXT, naming(LINE_TEXT)), max_size=12).map("\n".join)
ASCII_OUTPUT = st.lists(st.one_of(ASCII_LINE_TEXT, naming(ASCII_LINE_TEXT)), max_size=12).map(
    "\n".join
)


class TheTransportClassifier(unittest.TestCase):
    @given(LINE_TEXT, st.sampled_from(PHRASES), LINE_TEXT)
    def test_a_line_naming_a_failure_is_quoted_once(self, before, phrase, after):
        line = before + phrase + after
        quoted = verdicts.transport_failures(line)
        self.assertEqual(len(quoted), 1, quoted)
        self.assertIn(quoted[0], line)
        self.assertIsNotNone(verdicts.TRANSPORT_FAILURE.search(quoted[0]))

    @given(OUTPUT)
    def test_what_is_quoted_is_bounded_distinct_and_named(self, output):
        quoted = verdicts.transport_failures(output)
        lines = output.split("\n")
        self.assertLessEqual(len(quoted), verdicts.QUOTED)
        self.assertEqual(len(quoted), len(set(quoted)))
        for excerpt in quoted:
            self.assertLessEqual(len(excerpt), verdicts.WIDTH)
            self.assertTrue(any(excerpt in line for line in lines), excerpt)
            self.assertIsNotNone(verdicts.TRANSPORT_FAILURE.search(excerpt), excerpt)
        named = [line for line in lines if verdicts.TRANSPORT_FAILURE.search(line)]
        self.assertEqual(bool(quoted), bool(named))

    @given(OUTPUT, st.data())
    def test_colour_codes_anywhere_change_nothing(self, output, data):
        at = data.draw(st.lists(st.integers(0, len(output)), max_size=8))
        coloured = output
        for i in sorted(at, reverse=True):
            coloured = coloured[:i] + data.draw(st.sampled_from(COLOURS)) + coloured[i:]
        self.assertEqual(verdicts.transport_failures(coloured), verdicts.transport_failures(output))

    @given(ASCII_OUTPUT)
    def test_the_case_a_client_prints_in_changes_only_the_case_quoted(self, output):
        self.assertEqual(
            verdicts.transport_failures(output.swapcase()),
            [excerpt.swapcase() for excerpt in verdicts.transport_failures(output)],
        )


# ── The label-value grammar ──────────────────────────────────────────────────

ALNUM = string.ascii_letters + string.digits
LABEL_CHARS = ALNUM + "-_."
API_MAX = 63


def api_server_accepts(value: str) -> bool:
    """k8s.io/apimachinery's IsValidLabelValue, restated without a pattern."""
    if len(value) > API_MAX:
        return False
    if not value:
        return True
    return set(value) <= set(LABEL_CHARS) and value[0] in ALNUM and value[-1] in ALNUM


def label_text(max_middle: int):
    """Values of the grammar: empty, one alphanumeric, or alphanumeric ends around
    up to `max_middle` grammar characters."""
    return st.one_of(
        st.just(""),
        st.sampled_from(ALNUM),
        st.builds(
            lambda first, middle, last: first + middle + last,
            st.sampled_from(ALNUM),
            st.text(alphabet=LABEL_CHARS, max_size=max_middle),
            st.sampled_from(ALNUM),
        ),
    )


VALID_LABELS = label_text(API_MAX - 2)
# Characters near the grammar's edge: whitespace, separators, non-ASCII letters.
TRICKY = ("\n", "\r", "\t", " ", "/", ":", "@", "é", "ß", "\x00", " ", "-", ".", "_")
TEMPLATES = (
    "{{ .x }}",
    "{{ .metadata.labels.environment }}",
    '{{ index .metadata.labels "environment" }}',
)
# Values with no template in them, valid, too long, one character off, or arbitrary.
TEMPLATE_FREE = st.one_of(
    VALID_LABELS,
    label_text(API_MAX + 16),
    st.builds(
        lambda value, at, char: value[:at] + char + value[at:],
        VALID_LABELS,
        st.integers(0, API_MAX + 1),
        st.sampled_from(TRICKY),
    ),
    st.text(),
).filter(lambda value: labels.TEMPLATE.search(value) is None)


def spans(value: str):
    """`value` with a non-empty span of it to stand for what a template renders."""
    return st.integers(0, len(value) - 1).flatmap(
        lambda start: st.tuples(st.just(value), st.just(start), st.integers(start + 1, len(value)))
    )


class TheLabelValueGrammar(unittest.TestCase):
    @given(TEMPLATE_FREE)
    @example("\n")
    @example("0\n")
    @example("platform-engineering\n")
    def test_a_value_is_refused_exactly_when_the_api_server_refuses_it(self, value):
        self.assertEqual(labels.check_value(value) is None, api_server_accepts(value), repr(value))

    @given(TEMPLATE_FREE)
    def test_a_refusal_says_what_is_wrong(self, value):
        reason = labels.check_value(value)
        assume(reason is not None)
        outside = sorted({c for c in value if c not in LABEL_CHARS})
        if len(value) > API_MAX:
            self.assertIn(f"exceeds the {API_MAX}-char limit", reason)
        elif outside:
            self.assertEqual(reason, "contains " + ", ".join(repr(c) for c in outside))
        else:
            self.assertEqual(reason, "must start and end with an alphanumeric character")

    @given(VALID_LABELS.filter(bool).flatmap(spans), st.sampled_from(TEMPLATES))
    @example(("0-0", 0, 1), "{{ .x }}")
    @example(("0-0", 2, 3), "{{ .x }}")
    @example(("a.b", 0, 1), "{{ .metadata.labels.environment }}")
    @example(("a00.x", 4, 5), "{{ .x }}")
    def test_a_template_is_never_refused_for_what_it_renders(self, span, template):
        value, start, end = span
        raw = value[:start] + template + value[end:]
        self.assertIsNone(labels.check_value(raw), repr(raw))

    @given(
        st.text(alphabet=st.characters(exclude_characters="{}"), max_size=20),
        st.sampled_from(TEMPLATES),
        st.text(alphabet=st.characters(exclude_characters="{}"), max_size=20),
    )
    @example("", "{{ .x }}", "/nope")
    def test_text_beside_a_template_is_still_held_to_the_grammar(self, before, template, after):
        outside = sorted({c for c in before + after if c not in LABEL_CHARS})
        assume(outside)
        self.assertEqual(
            labels.check_value(before + template + after),
            "contains " + ", ".join(repr(c) for c in outside),
        )

    @given(
        st.sampled_from("-_."),
        label_text(API_MAX - 4),
        st.sampled_from(TEMPLATES),
        st.booleans(),
    )
    @example("-", "", "{{ .x }}", True)
    @example(".", "", "{{ .x }}", False)
    def test_an_end_the_literal_text_holds_must_be_alphanumeric(
        self, edge, rest, template, at_start
    ):
        raw = edge + rest + template if at_start else template + rest + edge
        self.assertEqual(
            labels.check_value(raw), "must start and end with an alphanumeric character"
        )


# ── The burn-rate figure ─────────────────────────────────────────────────────

UNITS = burn.UNIT_SECONDS
METRIC = st.from_regex(r"[a-z_][a-z0-9_]{0,15}", fullmatch=True)
MATCHER = st.builds(
    lambda name, value: f'{name}="{value}"',
    st.from_regex(r"[a-z_][a-z0-9_]{0,8}", fullmatch=True),
    st.text(alphabet=string.ascii_lowercase + string.digits + "-.", max_size=8),
)
SELECTORS = st.builds(
    lambda metric, matchers, spaced: (
        metric + ("{" + (", " if spaced else ",").join(matchers) + "}" if matchers else "")
    ),
    METRIC,
    st.lists(MATCHER, max_size=3),
    st.booleans(),
)
DURATIONS = st.builds(
    lambda count, unit: f"{count}{unit}", st.integers(1, 1000), st.sampled_from(sorted(UNITS))
)
# A factor and a budget as an expression writes them.
FACTOR_TEXT = st.from_regex(r"[0-9]{1,12}(\.[0-9]{1,12})?", fullmatch=True)
BUDGET_TEXT = st.from_regex(r"0\.[0-9]{1,4}", fullmatch=True)


def exactly(units: int, places: int) -> str:
    """`units` written with `places` digits after the point: 1234 and 2 are 12.34."""
    if places == 0:
        return str(units)
    sign, units = ("-", -units) if units < 0 else ("", units)
    return f"{sign}{units // 10**places}.{units % 10**places:0{places}d}"


class TheBurnRateFigure(unittest.TestCase):
    @given(st.integers(min_value=0, max_value=10**12))
    @example(0)
    def test_a_span_reads_back_from_how_it_is_written(self, total):
        written = burn.human(total)
        self.assertEqual(burn.seconds(written), total)
        for larger, size in UNITS.items():
            if size > UNITS[written[-1]] and total >= size:
                self.assertNotEqual(total % size, 0, f"{written}, where {larger} divides it")

    @given(st.integers(min_value=0, max_value=10**6), st.sampled_from(sorted(UNITS)))
    def test_a_written_duration_is_its_count_of_its_unit(self, count, unit):
        self.assertEqual(burn.seconds(f"{count}{unit}"), count * UNITS[unit])

    @given(st.lists(st.tuples(SELECTORS, DURATIONS), min_size=1, max_size=6))
    def test_the_long_window_is_the_longest_range_and_every_selector_over_it(self, reads):
        expr = " * ".join(f"sum(rate({selector}[{duration}]))" for selector, duration in reads)
        longest = max(burn.seconds(duration) for _, duration in reads)
        over_it = {
            re.sub(r"\s+", "", selector)
            for selector, duration in reads
            if burn.seconds(duration) == longest
        }
        self.assertEqual(burn.long_window(expr), (longest, over_it))

    @given(
        st.lists(st.tuples(BUDGET_TEXT, FACTOR_TEXT), min_size=1, max_size=4),
        st.lists(FACTOR_TEXT, max_size=3),
    )
    def test_the_factors_are_the_comparisons_against_the_budget_and_no_other(self, burns, guards):
        parts = [
            f"(sum(rate(errors[1h])) / sum(rate(total[1h])) / {budget} > bool {factor})"
            for budget, factor in burns
        ]
        parts += [f"(sum(rate(total[1h])) > bool {guard})" for guard in guards]
        self.assertEqual(burn.factors(" * ".join(parts)), {Fraction(f) for _, f in burns})

    @given(st.integers(), st.integers(min_value=0, max_value=6))
    @example(12345678901234567890123, 2)
    @example(6985601490518013, 1)
    @example(-10, 2)
    def test_a_percentage_is_written_exactly(self, units, places):
        value = Fraction(units, 10**places) / 100
        self.assertEqual(burn.as_percent(value, places), exactly(units, places))

    @given(st.fractions(), st.integers(min_value=0, max_value=4))
    def test_the_figure_the_gate_prints_is_one_it_accepts(self, value, places):
        printed = burn.as_percent(value, places)
        self.assertEqual(burn.as_percent(Fraction(printed) / 100, places), printed)

    @given(FACTOR_TEXT)
    @example("12.34567")
    @example("100000.1")
    @example("0.10")
    @example("007")
    def test_a_factor_prints_as_the_expression_writes_it(self, written):
        whole, _, fraction = written.partition(".")
        fraction = fraction.rstrip("0")
        want = (whole.lstrip("0") or "0") + (f".{fraction}" if fraction else "")
        self.assertEqual(burn.decimal(Fraction(written)), want)
        self.assertIn(want, written)

    @given(st.fractions())
    @example(Fraction(1, 3))
    @example(Fraction(-1, 200))
    def test_a_printed_factor_reads_back_as_the_value_it_is(self, value):
        self.assertEqual(Fraction(burn.decimal(value)), value)


if __name__ == "__main__":
    unittest.main()
