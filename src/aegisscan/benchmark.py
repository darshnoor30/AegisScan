from __future__ import annotations

import asyncio
import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisscan.scanner import ScanConfig, scan


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = await asyncio.wait_for(reader.read(4096), timeout=1.0)
        if request.startswith((b"GET ", b"HEAD ")):
            body = b"<html><head><title>Aegis benchmark</title></head><body>verified</body></html>"
            response = (
                b"HTTP/1.0 200 OK\r\n"
                b"Server: AegisBenchmark/1.0\r\n"
                b"Content-Type: text/html\r\n"
                b"X-Content-Type-Options: nosniff\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            writer.write(response)
            await writer.drain()
    except (TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def _ssh_handler(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(b"SSH-2.0-AegisBenchmark_1.0\r\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _run() -> dict[str, Any]:
    http_server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
    ssh_server = await asyncio.start_server(_ssh_handler, "127.0.0.1", 0)
    http_port = int(http_server.sockets[0].getsockname()[1])
    ssh_port = int(ssh_server.sockets[0].getsockname()[1])
    closed_port = _unused_loopback_port()
    while closed_port in {http_port, ssh_port}:
        closed_port = _unused_loopback_port()

    expected = {http_port: "http", ssh_port: "ssh"}
    try:
        result = await scan(
            ScanConfig(
                targets=["127.0.0.1"],
                ports=[http_port, ssh_port, closed_port],
                timeout=0.6,
                concurrency=6,
                authorized=True,
                fingerprint=True,
                environment="development",
                asset_criticality="low",
            )
        )
    finally:
        http_server.close()
        ssh_server.close()
        await http_server.wait_closed()
        await ssh_server.wait_closed()

    observed = {item.port: item.fingerprint.service for item in result.observations}
    correct_services = sum(observed.get(port) == service for port, service in expected.items())
    expected_states = {"open": 2, "closed": 1}
    state_checks = [
        result.summary["states"]["open"] == expected_states["open"],
        result.summary["states"]["closed"] == expected_states["closed"],
    ]
    service_accuracy = correct_services / len(expected)
    state_accuracy = sum(state_checks) / len(state_checks)
    passed = state_accuracy == 1.0 and service_accuracy == 1.0
    return {
        "benchmark_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "passed" if passed else "failed",
        "purpose": "Deterministic loopback validation; not a production detection-rate claim.",
        "ground_truth": {
            "open_services": {"http": http_port, "ssh": ssh_port},
            "closed_port": closed_port,
            "non_standard_ports": True,
        },
        "metrics": {
            "tcp_state_accuracy": round(state_accuracy, 3),
            "service_identification_accuracy": round(service_accuracy, 3),
            "false_service_claims": sum(
                1 for port, service in observed.items() if port in expected and service != expected[port]
            ),
            "verified_services": result.summary["verified_services"],
            "scan_duration_ms": result.duration_ms,
        },
        "observed_services": {str(port): service for port, service in sorted(observed.items())},
    }


def run_benchmark(output: str | Path | None = None) -> dict[str, Any]:
    document = asyncio.run(_run())
    if output:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document
