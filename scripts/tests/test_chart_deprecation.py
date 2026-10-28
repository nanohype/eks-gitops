"""Unit tests for the chart provenance gate.

Two halves decide what this gate says. The offline verdict decides whether every
pin has a record and every record a pin; the live verdict decides what a chart
that redescribed itself, deprecated itself or could not be read turns into.

The registry read itself is registry.py's, and is tested in test_registry. What is
held here is that a read that fails reaches the live verdict as a sentence
rather than as an exception, and that --sync records what upstream says.
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


class FetchReportsWhyNot(unittest.TestCase):
    """fetch() returns an `_error` the live check prints, never an exception."""

    def fetch_failing_with(self, exc):
        with mock.patch.object(ccd.registry, "oci_chart_metadata", side_effect=exc):
            return ccd.fetch("c", "oci://r.example/c", "1.0.0")

    def test_an_http_status_names_the_status_and_the_url(self):
        meta = self.fetch_failing_with(http_error("https://r.example/v2/c/manifests/1.0.0",
                                                  404))
        self.assertEqual(meta, {"_error": "HTTP 404 from https://r.example/v2/c/manifests/1.0.0"})

    def test_an_exhausted_rate_limit_is_reported_in_its_own_words(self):
        meta = self.fetch_failing_with(ccd.registry.RegistryError("r.example answered HTTP 429"))
        self.assertEqual(meta, {"_error": "RegistryError: r.example answered HTTP 429"})

    def test_a_network_error_is_reported(self):
        meta = self.fetch_failing_with(urllib.error.URLError("no route"))
        self.assertIn("URLError", meta["_error"])

    def test_a_dropped_or_truncated_response_is_reported(self):
        for exc in (ConnectionResetError("reset by peer"),
                    http.client.IncompleteRead(b"partial", 10)):
            with self.subTest(exc=type(exc).__name__):
                meta = self.fetch_failing_with(exc)
                self.assertIn(type(exc).__name__, meta["_error"])

    def test_an_https_pin_is_read_from_its_repository_index(self):
        with mock.patch.object(ccd.registry, "repo_index_entry",
                               return_value={"name": "c", "description": "a chart",
                                             "urls": ["c-1.0.0.tgz"], "digest": "ab"}):
            meta = ccd.fetch("c", "https://charts.example", "1.0.0")
        self.assertEqual(meta, {"name": "c", "description": "a chart"})


class TheLiveVerdict(unittest.TestCase):
    PINS = {"c": {"repo": "oci://r.example/c", "version": "1.0.0", "source": "x.yaml"}}
    RECORDS = {"c": {"repo": "oci://r.example/c", "description": "a chart",
                     "deprecated": False}}

    def live(self, meta):
        out = io.StringIO()
        with mock.patch.object(ccd, "pins", return_value=self.PINS), \
                mock.patch.object(ccd, "load_records", return_value=self.RECORDS), \
                mock.patch.object(ccd, "fetch", return_value=meta), \
                contextlib.redirect_stdout(out):
            return ccd.check_live(), out.getvalue()

    def test_a_matching_chart_passes(self):
        rc, _ = self.live({"description": "a chart"})
        self.assertEqual(rc, 0)

    def test_an_unreadable_chart_fails_with_the_reason(self):
        rc, out = self.live({"_error": "RegistryError: r.example answered HTTP 429"})
        self.assertEqual(rc, 1)
        self.assertIn("answered HTTP 429", out)

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

    def sync(self, meta):
        with tempfile.TemporaryDirectory() as tmp:
            records = pathlib.Path(tmp) / "scripts" / "chart-provenance.json"
            records.parent.mkdir()
            with mock.patch.object(ccd, "pins", return_value=self.PINS), \
                    mock.patch.object(ccd, "fetch", return_value=meta), \
                    mock.patch.object(ccd, "ROOT", pathlib.Path(tmp)), \
                    mock.patch.object(ccd, "RECORDS", records), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = ccd.sync()
            return rc, json.loads(records.read_text())

    def test_the_description_and_flag_are_recorded(self):
        rc, written = self.sync({"description": "  a chart \n", "deprecated": True})
        self.assertEqual(rc, 0)
        self.assertEqual(written["charts"], {"c": {"repo": "oci://r.example/c",
                                                   "description": "a chart",
                                                   "deprecated": True}})

    def test_an_unreadable_chart_stops_the_sync(self):
        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            self.sync({"_error": "HTTP 503 from https://r.example"})
        self.assertEqual(caught.exception.code, 1)


class TheSelfTest(unittest.TestCase):
    def test_every_break_is_rejected_and_the_shipped_catalog_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = ccd.self_test()
        self.assertEqual(rc, 0, out.getvalue())
        self.assertNotIn("ACCEPTED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
