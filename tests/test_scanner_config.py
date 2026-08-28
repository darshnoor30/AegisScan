import unittest

from aegisscan.scanner import ScanConfig


class ScanConfigTests(unittest.TestCase):
    def test_accepts_explicit_risk_context(self) -> None:
        ScanConfig(
            targets=["127.0.0.1"],
            ports=[80],
            environment="production",
            asset_criticality="critical",
        ).validate()

    def test_rejects_unknown_environment(self) -> None:
        with self.assertRaisesRegex(ValueError, "Environment"):
            ScanConfig(
                targets=["127.0.0.1"], ports=[80], environment="prod"
            ).validate()

    def test_rejects_unknown_asset_criticality(self) -> None:
        with self.assertRaisesRegex(ValueError, "criticality"):
            ScanConfig(
                targets=["127.0.0.1"], ports=[80], asset_criticality="essential"
            ).validate()


if __name__ == "__main__":
    unittest.main()
