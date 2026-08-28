import socket
import unittest

from aegisscan.intelligence import analyze_exposure
from aegisscan.models import Fingerprint, PortObservation, Target


def observation(port: int, fingerprint: Fingerprint, address: str = "10.0.0.5") -> PortObservation:
    return PortObservation(
        target="server",
        address=address,
        port=port,
        protocol="tcp",
        state="open",
        latency_ms=2.1,
        fingerprint=fingerprint,
    )


class IntelligenceTests(unittest.TestCase):
    def test_confirmed_private_smb_keeps_critical_base_priority(self) -> None:
        asset = Target("server", "10.0.0.5", socket.AF_INET, False)
        item = observation(
            445,
            Fingerprint(
                service="smb",
                port_hint="smb",
                confidence="high",
                classification_method="protocol-probe",
                evidence=["SMB negotiation confirmed the protocol."],
            ),
        )
        findings, summary = analyze_exposure([item], [asset])
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].base_severity, "critical")
        self.assertIn("Protocol evidence", " ".join(findings[0].risk_factors))
        self.assertEqual(summary["security_score"], 75)

    def test_loopback_and_low_confidence_prevent_false_critical_grade(self) -> None:
        asset = Target("local", "127.0.0.1", socket.AF_INET, False)
        item = observation(
            27017,
            Fingerprint(
                service="mongodb",
                port_hint="mongodb",
                confidence="low",
                classification_method="port-registry",
            ),
            address="127.0.0.1",
        )
        findings, summary = analyze_exposure([item], [asset])
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].network_scope, "loopback")
        self.assertEqual(summary["security_score"], 97)
        self.assertEqual(summary["grade"], "A")

    def test_confirmed_service_overrides_dangerous_port_hint(self) -> None:
        asset = Target("local", "127.0.0.1", socket.AF_INET, False)
        item = observation(
            27017,
            Fingerprint(
                service="http",
                port_hint="mongodb",
                confidence="high",
                classification_method="http-response",
                evidence=["A valid HTTP response confirmed HTTP."],
                http={"status": "HTTP/1.0 200 OK"},
            ),
            address="127.0.0.1",
        )
        findings, _summary = analyze_exposure([item], [asset])
        self.assertFalse(any("MongoDB" in finding.title for finding in findings))
        self.assertTrue(any("HTTP" in finding.title for finding in findings))

    def test_public_production_criticality_promotes_confirmed_ssh(self) -> None:
        asset = Target("edge", "8.8.8.8", socket.AF_INET, True)
        item = observation(
            2222,
            Fingerprint(
                service="ssh",
                port_hint="unknown",
                confidence="high",
                classification_method="protocol-banner",
                evidence=["SSH banner signature matched."],
            ),
            address="8.8.8.8",
        )
        findings, _summary = analyze_exposure(
            [item], [asset], environment="production", asset_criticality="critical"
        )
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].network_scope, "public")

    def test_unknown_open_service_is_inventory_not_fake_finding(self) -> None:
        asset = Target("dev", "127.0.0.1", socket.AF_INET, False)
        item = observation(49152, Fingerprint(), address="127.0.0.1")
        findings, summary = analyze_exposure([item], [asset])
        self.assertEqual(findings, [])
        self.assertEqual(summary["security_score"], 100)

    def test_expired_tls_certificate_adds_lifecycle_finding(self) -> None:
        asset = Target("app", "10.0.0.8", socket.AF_INET, False)
        item = observation(
            443,
            Fingerprint(
                service="https",
                port_hint="https",
                confidence="high",
                classification_method="https-response",
                tls={
                    "protocol": "TLSv1.3",
                    "certificate": {
                        "days_until_expiry": -2,
                        "not_after": "2026-01-01T00:00:00Z",
                    },
                },
            ),
            address="10.0.0.8",
        )
        findings, _summary = analyze_exposure([item], [asset])
        self.assertEqual(findings[0].title, "TLS certificate has expired")

    def test_legacy_tls_and_missing_headers_are_evidence_findings(self) -> None:
        asset = Target("app", "10.0.0.8", socket.AF_INET, False)
        item = observation(
            443,
            Fingerprint(
                service="https",
                port_hint="https",
                confidence="high",
                classification_method="https-response",
                http={"status": "HTTP/1.0 200 OK", "security_headers": {}},
                tls={"protocol": "TLSv1"},
            ),
            address="10.0.0.8",
        )
        findings, _summary = analyze_exposure([item], [asset])
        titles = {finding.title for finding in findings}
        self.assertIn("Legacy TLS protocol negotiated", titles)
        self.assertIn("Recommended HTTPS response headers missing", titles)

    def test_rejects_invalid_context(self) -> None:
        with self.assertRaisesRegex(ValueError, "Environment"):
            analyze_exposure([], [], environment="mission-critical")


if __name__ == "__main__":
    unittest.main()
