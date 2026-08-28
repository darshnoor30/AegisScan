import tempfile
import unittest
from pathlib import Path

from aegisscan.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_loopback_benchmark_has_ground_truth_and_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "benchmark.json"
            document = run_benchmark(output)
            self.assertEqual(document["status"], "passed")
            self.assertEqual(document["metrics"]["tcp_state_accuracy"], 1.0)
            self.assertEqual(document["metrics"]["service_identification_accuracy"], 1.0)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
