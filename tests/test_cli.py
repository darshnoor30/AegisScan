import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegisscan.cli import main


class _Result:
    def to_dict(self) -> dict:
        return {
            "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "summary": {
                "security_score": 100,
                "grade": "A",
                "open_ports": 0,
                "findings": 0,
            },
        }


async def _fake_scan(*_args, **_kwargs) -> _Result:
    return _Result()


class CliTests(unittest.TestCase):
    def test_no_command_prints_help(self) -> None:
        self.assertEqual(main([]), 0)

    def test_invalid_serve_port_is_rejected(self) -> None:
        self.assertEqual(main(["serve", "--port", "70000"]), 2)

    def test_scan_command_writes_bundle_through_shared_engine(self) -> None:
        paths = {"json": Path("result.json")}
        with (
            patch("aegisscan.cli.scan", _fake_scan),
            patch("aegisscan.cli.save_scan"),
            patch("aegisscan.cli.write_report_bundle", return_value=paths),
        ):
            status = main(
                [
                    "scan",
                    "-t",
                    "127.0.0.1",
                    "-p",
                    "80",
                    "--environment",
                    "production",
                    "--asset-criticality",
                    "high",
                    "--i-own-or-have-permission",
                ]
            )
        self.assertEqual(status, 0)

    def test_diff_exit_code_reports_new_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "before.json"
            current = root / "after.json"
            output = root / "diff.json"
            baseline.write_text(json.dumps({"scan_id": "a", "observations": []}), encoding="utf-8")
            current.write_text(
                json.dumps(
                    {
                        "scan_id": "b",
                        "observations": [
                            {
                                "address": "127.0.0.1",
                                "port": 80,
                                "state": "open",
                                "fingerprint": {"service": "http"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            status = main(
                [
                    "diff",
                    "--baseline",
                    str(baseline),
                    "--current",
                    str(current),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(status, 2)
            self.assertTrue(output.is_file())

    def test_demo_and_benchmark_commands_report_status(self) -> None:
        demo_document = {"summary": {"open_ports": 1, "security_score": 100}}
        with patch("aegisscan.cli.run_demo", return_value=(demo_document, {"json": Path("demo.json")})):
            self.assertEqual(main(["demo"]), 0)
        benchmark = {
            "status": "passed",
            "metrics": {
                "tcp_state_accuracy": 1.0,
                "service_identification_accuracy": 1.0,
            },
        }
        with patch("aegisscan.cli.run_benchmark", return_value=benchmark):
            self.assertEqual(main(["benchmark"]), 0)


if __name__ == "__main__":
    unittest.main()
