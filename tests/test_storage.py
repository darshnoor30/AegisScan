import tempfile
import unittest
from pathlib import Path

from aegisscan.storage import load_scan, recent_scans, save_scan


class StorageTests(unittest.TestCase):
    def test_round_trip_and_recent_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = {
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "started_at": "2026-01-01T00:00:00Z",
                "summary": {"targets": 1, "open_ports": 2, "security_score": 97},
            }
            path = save_scan(document, root)
            self.assertTrue(path.is_file())
            self.assertEqual(load_scan(document["scan_id"], root), document)
            self.assertEqual(recent_scans(directory=root)[0]["open_ports"], 2)

    def test_invalid_or_missing_identifier_is_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(load_scan("../secret", root))
            self.assertIsNone(load_scan("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", root))
            self.assertEqual(recent_scans(directory=root), [])

    def test_recent_scans_skips_corrupt_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scans = root / "scans"
            scans.mkdir()
            (scans / "bad.json").write_text("{", encoding="utf-8")
            self.assertEqual(recent_scans(directory=root), [])


if __name__ == "__main__":
    unittest.main()
