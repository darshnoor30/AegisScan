import unittest

from aegisscan.diff import compare_scans


def document(scan_id: str, services: list[dict]) -> dict:
    return {"scan_id": scan_id, "observations": services}


class DriftTests(unittest.TestCase):
    def test_finds_new_closed_and_changed_services(self) -> None:
        baseline = document(
            "before",
            [
                {"address": "10.0.0.1", "port": 22, "state": "open", "fingerprint": {"service": "ssh", "product": "A"}},
                {"address": "10.0.0.1", "port": 80, "state": "open", "fingerprint": {"service": "http"}},
            ],
        )
        current = document(
            "after",
            [
                {"address": "10.0.0.1", "port": 22, "state": "open", "fingerprint": {"service": "ssh", "product": "B"}},
                {"address": "10.0.0.1", "port": 443, "state": "open", "fingerprint": {"service": "https"}},
            ],
        )
        result = compare_scans(baseline, current)
        self.assertEqual(result["summary"], {"new": 1, "closed": 1, "changed": 1, "status": "drift-detected"})


if __name__ == "__main__":
    unittest.main()

