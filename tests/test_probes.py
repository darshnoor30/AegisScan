import asyncio
import socket
import unittest

from aegisscan.models import Target
from aegisscan.probes import _parse_http, fingerprint_endpoint, identify_banner


class ProbeParserTests(unittest.TestCase):
    def test_http_parser_requires_real_http_status_line(self) -> None:
        self.assertEqual(_parse_http(b"not http\r\nServer: fake\r\n\r\n"), {})

    def test_http_parser_collects_security_headers_and_product_signal(self) -> None:
        parsed = _parse_http(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: search\r\n"
            b"X-Elastic-Product: Elasticsearch\r\n"
            b"Strict-Transport-Security: max-age=10\r\n"
            b"Content-Security-Policy: frame-ancestors 'none'\r\n\r\n"
            b"<title>Cluster</title>"
        )
        self.assertEqual(parsed["detected_service"], "elasticsearch")
        self.assertTrue(parsed["security_headers"]["strict_transport_security"])
        self.assertTrue(parsed["security_headers"]["frame_protection"])
        self.assertEqual(parsed["title"], "Cluster")

    def test_banner_classifier_is_conservative(self) -> None:
        self.assertEqual(identify_banner("SSH-2.0-OpenSSH_9.7")[0], "ssh")
        self.assertEqual(identify_banner("RFB 003.008")[0], "vnc")
        self.assertEqual(identify_banner("Welcome to a mystery service"), (None, None))


class NonStandardFingerprintTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        async def ssh_handler(
            _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.write(b"SSH-2.0-Aegis-Test\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        self.server = await asyncio.start_server(ssh_handler, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def test_identifies_ssh_on_non_standard_port(self) -> None:
        target = Target("local", "127.0.0.1", socket.AF_INET, False)
        fingerprint = await fingerprint_endpoint(target, self.port, 0.5)
        self.assertEqual(fingerprint.service, "ssh")
        self.assertEqual(fingerprint.confidence, "high")
        self.assertEqual(fingerprint.classification_method, "protocol-banner")


if __name__ == "__main__":
    unittest.main()
