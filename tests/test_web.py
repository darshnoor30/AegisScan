import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from aegisscan.web import AegisHandler, ScanManager


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {"AEGISSCAN_DATA_DIR": self.temp.name, "AEGISSCAN_ALLOW_PUBLIC": "false"},
        )
        self.environment.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), AegisHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.environment.stop()
        self.temp.cleanup()

    def _json(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.base}{path}", timeout=3) as response:
            return json.loads(response.read())

    def test_health_static_assets_and_not_found(self) -> None:
        self.assertEqual(self._json("/api/health")["version"], "1.1.0")
        with urllib.request.urlopen(f"{self.base}/static/context.css", timeout=3) as response:
            self.assertIn(b".risk-meta", response.read())
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        with self.assertRaises(urllib.error.HTTPError) as captured:
            urllib.request.urlopen(f"{self.base}/missing", timeout=3)
        self.assertEqual(captured.exception.code, 404)

    def test_manager_rejects_empty_target_before_queuing(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty target"):
            ScanManager().start({"targets": [], "authorized": True})

    def test_cross_site_post_is_rejected(self) -> None:
        request = urllib.request.Request(
            f"{self.base}/api/scans",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": "https://attacker.invalid",
                "Sec-Fetch-Site": "cross-site",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as captured:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(captured.exception.code, 400)

    def test_scan_poll_persistence_and_report(self) -> None:
        payload = json.dumps(
            {
                "targets": ["127.0.0.1"],
                "ports": str(self.server.server_address[1]),
                "timeout": 0.5,
                "concurrency": 5,
                "authorized": True,
                "environment": "development",
                "asset_criticality": "low",
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base}/api/scans",
            data=payload,
            headers={"Content-Type": "application/json", "Origin": self.base},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            queued = json.loads(response.read())
            self.assertEqual(response.status, 202)
        job = {}
        for _ in range(40):
            job = self._json(queued["status_url"])
            if job["status"] == "complete":
                break
            time.sleep(0.05)
        self.assertEqual(job["status"], "complete")
        scan_id = job["result"]["scan_id"]
        with urllib.request.urlopen(f"{self.base}/reports/{scan_id}.html", timeout=3) as response:
            self.assertIn(b"Contextual Exposure Model", response.read())
        self.assertTrue(self._json("/api/scans")["scans"])


if __name__ == "__main__":
    unittest.main()
