"""Unit tests for the chart provenance gate.

Two halves decide what this gate says. The offline verdict decides whether every
pin has a record and every record a pin; the live verdict decides what a chart
that redescribed itself, deprecated itself or could not be read turns into.

The registry read itself is registry.py's, and is tested in test_registry. What is
held here is that a read that fails reaches the live verdict as a sentence
rather than as an exception, with the status registry.ChartUnavailable's
`answered` earns, and that --sync records what upstream says or nothing at all.
"""

from __future__ import annotations

import contextlib
import email.message
import http.client
import io
import json
import pathlib
import tempfile
import unittest
import urllib.error
from unittest import mock

from gateloader import load

ccd = load("check-chart-deprecation")


def http_error(url: str, code: int):
    return urllib.error.HTTPError(url, code, f"status {code}", email.message.Message(), None)


MANIFEST = "https://r.example/v2/c/manifests/1.0.0"


def unavailable(message: str, *, answered: bool):
    return ccd.registry.ChartUnavailable(message, answered=answered)


class AFailedReadInTheLiveVerdict(unittest.TestCase):
    """What the client raises reaches the live verdict as a sentence, never a
    traceback, read through registry.chart_metadata's own classification."""

    PINS = {"c": {"repo": "oci://r.example/c", "version": "1.0.0", "source": "x.yaml"}}

    def live_failing_with(self, exc):
        out = io.StringIO()
        with mock.patch.object(ccd, "pins", return_value=self.PINS), \
                mock.patch.object(ccd, "load_records", return_value={}), \
                mock.patch.object(ccd.registry, "oci_chart_metadata", side_effect=exc), \
                contextlib.redirect_stdout(out):
            return ccd.check_live(), out.getvalue()

    def test_a_404_names_the_status_and_the_url_as_a_finding(self):
        rc, out = self.live_failing_with(http_error(MANIFEST, 404))
        self.assertEqual(rc, 1)
        self.assertIn(f"c: upstream answered, and its answer rules the pin out — "
                      f"HTTP 404 from {MANIFEST}", out)

    def test_an_exhausted_rate_limit_cannot_run_in_its_own_words(self):
        rc, out = self.live_failing_with(
            ccd.registry.RegistryError("r.example answered HTTP 429"))
        self.assertEqual(rc, ccd.gatelib.CANNOT_RUN)
        self.assertIn("c 1.0.0 from oci://r.example/c — RegistryError: r.example "
                      "answered HTTP 429", out)

    def test_a_network_error_cannot_run(self):
        rc, out = self.live_failing_with(urllib.error.URLError("no route"))
        self.assertEqual(rc, ccd.gatelib.CANNOT_RUN)
        self.assertIn("URLError", out)

    def test_a_dropped_or_truncated_response_cannot_run(self):
        for exc in (ConnectionResetError("reset by peer"),
                    http.client.IncompleteRead(b"partial", 10)):
            with self.subTest(exc=type(exc).__name__):
                rc, out = self.live_failing_with(exc)
                self.assertEqual(rc, ccd.gatelib.CANNOT_RUN)
                self.assertIn(type(exc).__name__, out)


class TheLiveVerdict(unittest.TestCase):
    PINS = {"c": {"repo": "oci://r.example/c", "version": "1.0.0", "source": "x.yaml"}}
    RECORDS = {"c": {"repo": "oci://r.example/c", "description": "a chart",
                     "deprecated": False}}

    def live(self, *metas, pins=None):
        """check_live over chart reads answering `metas` in pin order: a dict is
        the metadata upstream publishes, a ChartUnavailable a read that failed."""
        out = io.StringIO()
        with mock.patch.object(ccd, "pins", return_value=pins or self.PINS), \
                mock.patch.object(ccd, "load_records", return_value=self.RECORDS), \
                mock.patch.object(ccd.registry, "chart_metadata", side_effect=metas), \
                contextlib.redirect_stdout(out):
            return ccd.check_live(), out.getvalue()

    def test_a_matching_chart_passes(self):
        rc, _ = self.live({"description": "a chart"})
        self.assertEqual(rc, 0)

    def test_an_unreadable_chart_cannot_run(self):
        rc, out = self.live(unavailable("RegistryError: r.example answered HTTP 429",
                                        answered=False))
        self.assertEqual(rc, ccd.gatelib.CANNOT_RUN)
        self.assertIn("Cannot run: 1 of 1", out)
        self.assertIn("answered HTTP 429", out)

    def test_a_pin_upstream_ruled_out_fails(self):
        rc, out = self.live(unavailable(f"HTTP 404 from {MANIFEST}", answered=True))
        self.assertEqual(rc, 1)
        self.assertIn("rules the pin out", out)
        self.assertNotIn("Cannot run", out)

    def test_a_finding_outweighs_a_chart_that_could_not_be_read(self):
        pins = {**self.PINS, "d": {"repo": "oci://r.example/d", "version": "2.0.0",
                                   "source": "x.yaml"}}
        rc, out = self.live({"description": "a chart", "deprecated": True},
                            unavailable("URLError: no route", answered=False), pins=pins)
        self.assertEqual(rc, 1)
        self.assertIn("marked deprecated", out)
        self.assertIn("Cannot run: 1 of 2", out)

    def test_a_redescribed_chart_fails(self):
        rc, out = self.live({"description": "an enterprise product"})
        self.assertEqual(rc, 1)
        self.assertIn("changed what it says it is", out)

    def test_a_deprecated_chart_fails(self):
        rc, out = self.live({"description": "a chart", "deprecated": True})
        self.assertEqual(rc, 1)
        self.assertIn("marked deprecated", out)


class TheOfflineVerdict(unittest.TestCase):
    def offline(self, pins, records):
        with contextlib.redirect_stdout(io.StringIO()):
            return ccd.check_offline(pins, records)

    def test_the_shipped_catalog_passes(self):
        self.assertEqual(self.offline(ccd.pins(), ccd.load_records()), 0)

    def test_a_pin_with_no_record_fails(self):
        pins = dict(ccd.pins())
        pins["ghost"] = {"repo": "https://example.invalid", "version": "1.0.0",
                         "source": "x.yaml"}
        self.assertEqual(self.offline(pins, ccd.load_records()), 1)

    def test_a_record_with_no_pin_fails(self):
        records = dict(ccd.load_records())
        records["retired"] = {"repo": "https://example.invalid", "description": "x"}
        self.assertEqual(self.offline(ccd.pins(), records), 1)



class SyncRecordsWhatUpstreamSays(unittest.TestCase):
    PINS = {"c": {"repo": "oci://r.example/c", "version": "1.0.0", "source": "x.yaml"}}

    @contextlib.contextmanager
    def records(self, read):
        """A records file inside a scratch root, with each chart read patched by `read`."""
        with tempfile.TemporaryDirectory() as tmp:
            records = pathlib.Path(tmp) / "scripts" / "chart-provenance.json"
            records.parent.mkdir()
            with mock.patch.object(ccd, "pins", return_value=self.PINS), read, \
                    mock.patch.object(ccd, "ROOT", pathlib.Path(tmp)), \
                    mock.patch.object(ccd, "RECORDS", records):
                yield records

    def sync(self, meta):
        with self.records(mock.patch.object(ccd.registry, "chart_metadata",
                                            return_value=meta)) as records, \
                contextlib.redirect_stdout(io.StringIO()):
            rc = ccd.sync()
            return rc, json.loads(records.read_text())

    def refused(self, exc):
        """The exit status and output of a sync whose read raises `exc`, which
        must leave no record behind."""
        out = io.StringIO()
        with self.records(mock.patch.object(ccd.registry, "oci_chart_metadata",
                                            side_effect=exc)) as records:
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as caught:
                ccd.sync()
            self.assertFalse(records.exists(), "a sync that did not read every pin wrote")
        return caught.exception.code, out.getvalue()

    def test_the_description_and_flag_are_recorded(self):
        rc, written = self.sync({"description": "  a chart \n", "deprecated": True})
        self.assertEqual(rc, 0)
        self.assertEqual(written["charts"], {"c": {"repo": "oci://r.example/c",
                                                   "description": "a chart",
                                                   "deprecated": True}})

    def test_an_unreadable_chart_stops_the_sync_and_cannot_run(self):
        """A server fault says nothing about the pin, so the sync stops with the
        status for a read that could not be made, not with a finding."""
        code, out = self.refused(http_error(MANIFEST, 500))
        self.assertEqual(code, ccd.gatelib.CANNOT_RUN)
        self.assertIn("Cannot run: c 1.0.0 from oci://r.example/c could not be read:", out)
        self.assertIn(f"HTTP 500 from {MANIFEST}", out)

    def test_a_pin_upstream_ruled_out_stops_the_sync_as_a_finding(self):
        code, out = self.refused(http_error(MANIFEST, 404))
        self.assertEqual(code, 1)
        self.assertIn("c 1.0.0: oci://r.example/c answered, and its answer rules the pin out",
                      out)


class TheSelfTest(unittest.TestCase):
    def test_every_break_is_rejected_and_the_shipped_catalog_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = ccd.self_test()
        self.assertEqual(rc, 0, out.getvalue())
        self.assertNotIn("ACCEPTED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
