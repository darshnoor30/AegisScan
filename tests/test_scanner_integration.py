import asyncio
import unittest

from aegisscan.scanner import ScanConfig, scan


class ScannerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        async def handler(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"SSH-2.0-AegisScan-Test\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        self.server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def test_real_loopback_connection_is_observed(self) -> None:
        result = await scan(
            ScanConfig(
                targets=["127.0.0.1"],
                ports=[self.port],
                timeout=0.5,
                concurrency=5,
                authorized=True,
                fingerprint=False,
            )
        )
        self.assertEqual(result.summary["open_ports"], 1)
        self.assertEqual(result.observations[0].port, self.port)
        self.assertEqual(result.observations[0].state, "open")
        self.assertEqual(result.summary["probes_total"], 1)


if __name__ == "__main__":
    unittest.main()

