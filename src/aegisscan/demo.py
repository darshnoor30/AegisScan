from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aegisscan.ports import parse_ports
from aegisscan.probes import HTTP_PORTS
from aegisscan.reports import write_report_bundle
from aegisscan.scanner import ScanConfig, scan


class _DemoHandler(BaseHTTPRequestHandler):
    server_version = "AegisDemo/1.0"

    def do_GET(self) -> None:  # noqa: N802
        body = (
            b"<!doctype html><html><head><title>AegisScan Verified Demo</title></head>"
            b"<body><h1>Authorized local test service</h1></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def run_demo(output: str | Path = "reports/demo") -> tuple[dict, dict[str, Path]]:
    """Start a harmless loopback service, scan it, and write a real report bundle."""
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 8000), _DemoHandler)
    except OSError:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _DemoHandler)
    port = int(server.server_address[1])
    HTTP_PORTS.add(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = ScanConfig(
            targets=["127.0.0.1"],
            ports=parse_ports(f"{port},{min(port + 1, 65535)}"),
            timeout=0.5,
            concurrency=10,
            authorized=True,
            fingerprint=True,
        )
        result = asyncio.run(scan(config))
        document = result.to_dict()
        return document, write_report_bundle(document, output)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

