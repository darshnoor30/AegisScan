import tempfile
import unittest
from pathlib import Path

from aegisscan.demo import run_demo


class DemoTests(unittest.TestCase):
    def test_demo_scans_real_temporary_http_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, paths = run_demo(Path(directory) / "demo")
            self.assertEqual(document["summary"]["open_ports"], 1)
            self.assertEqual(document["observations"][0]["fingerprint"]["service"], "http")
            self.assertTrue(all(path.is_file() for path in paths.values()))


if __name__ == "__main__":
    unittest.main()
