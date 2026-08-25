import socket
import unittest

from aegisscan.intelligence import analyze_exposure
from aegisscan.models import Fingerprint, PortObservation, Target


class IntelligenceTests(unittest.TestCase):
    def test_critical_smb_exposure_is_explainable(self) -> None:
        asset = Target("server", "10.0.0.5", socket.AF_INET, False)
        observation = PortObservation(
            target="server",
            address="10.0.0.5",
            port=445,
            protocol="tcp",
            state="open",
            latency_ms=2.1,
            fingerprint=Fingerprint(service="smb"),
        )
        findings, summary = analyze_exposure([observation], [asset])
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("TCP connection", findings[0].evidence)
        self.assertIn("Block untrusted access", findings[0].recommendation)
        self.assertEqual(summary["security_score"], 75)
        self.assertEqual(summary["grade"], "C")

    def test_unknown_open_service_is_inventory_not_fake_finding(self) -> None:
        asset = Target("dev", "127.0.0.1", socket.AF_INET, False)
        observation = PortObservation(
            target="dev",
            address="127.0.0.1",
            port=49152,
            protocol="tcp",
            state="open",
            latency_ms=0.4,
        )
        findings, summary = analyze_exposure([observation], [asset])
        self.assertEqual(findings, [])
        self.assertEqual(summary["security_score"], 100)

    def test_expired_tls_certificate_adds_lifecycle_finding(self) -> None:
        asset = Target("app", "10.0.0.8", socket.AF_INET, False)
        observation = PortObservation(
            target="app",
            address="10.0.0.8",
            port=443,
            protocol="tcp",
            state="open",
            latency_ms=1.0,
            fingerprint=Fingerprint(
                service="https",
                tls={"certificate": {"days_until_expiry": -2, "not_after": "2026-01-01T00:00:00Z"}},
            ),
        )
        findings, _summary = analyze_exposure([observation], [asset])
        self.assertEqual(findings[0].title, "TLS certificate has expired")


if __name__ == "__main__":
    unittest.main()

