import json
import unittest

from aegisscan.reports import render_csv, render_html_report, render_sarif


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = {
            "engine_version": "1.0.0",
            "scan_id": "test-id",
            "finished_at": "2026-08-23T00:00:00+00:00",
            "duration_ms": 12,
            "config": {"targets": ["<script>alert(1)</script>"]},
            "summary": {
                "security_score": 100,
                "grade": "A",
                "targets": 1,
                "probes_total": 1,
                "open_ports": 1,
                "findings": 0,
                "severity_counts": {},
            },
            "observations": [
                {
                    "target": "local",
                    "address": "127.0.0.1",
                    "port": 8000,
                    "protocol": "tcp",
                    "state": "open",
                    "latency_ms": 0.5,
                    "fingerprint": {"service": "http-alt", "product": "Demo"},
                }
            ],
            "findings": [],
        }

    def test_html_escapes_user_scope(self) -> None:
        rendered = render_html_report(self.document)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_csv_contains_service(self) -> None:
        self.assertIn("http-alt", render_csv(self.document))

    def test_sarif_is_valid_json(self) -> None:
        rendered = json.loads(render_sarif(self.document))
        self.assertEqual(rendered["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()

