from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import urlparse

from aegisscan.ports import parse_ports
from aegisscan.reports import render_html_report
from aegisscan.scanner import ScanConfig, scan
from aegisscan.storage import load_scan, recent_scans, save_scan

MAX_REQUEST_BYTES = 32_768


class ScanManager:
    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start(self, payload: dict[str, Any]) -> str:
        targets_value = payload.get("targets", [])
        if isinstance(targets_value, str):
            targets = [targets_value]
        elif isinstance(targets_value, list) and all(isinstance(item, str) for item in targets_value):
            targets = targets_value
        else:
            raise ValueError("targets must be a string or list of strings")

        ports = parse_ports(str(payload.get("ports", "default")))
        authorized = payload.get("authorized") is True
        requested_public = payload.get("allow_public") is True
        server_allows_public = os.environ.get("AEGISSCAN_ALLOW_PUBLIC", "false").lower() == "true"
        if requested_public and not server_allows_public:
            raise ValueError("This dashboard instance does not permit public-target scans")

        config = ScanConfig(
            targets=targets,
            ports=ports,
            timeout=float(payload.get("timeout", 0.8)),
            concurrency=int(payload.get("concurrency", 150)),
            delay_ms=int(payload.get("delay_ms", 0)),
            authorized=authorized,
            allow_public=requested_public and server_allows_public,
            fingerprint=payload.get("fingerprint", True) is not False,
        )
        config.validate()
        job_id = str(uuid.uuid4())
        with self._lock:
            self._jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "progress": {"stage": "queued", "completed": 0, "total": 0, "percent": 0},
            }
        thread = threading.Thread(target=self._execute, args=(job_id, config), daemon=True)
        thread.start()
        return job_id

    def _execute(self, job_id: str, config: ScanConfig) -> None:
        def update(progress: dict[str, Any]) -> None:
            with self._lock:
                job = self._jobs[job_id]
                job["status"] = "running"
                job["progress"] = progress

        try:
            result = asyncio.run(scan(config, progress=update))
            document = result.to_dict()
            save_scan(document)
            with self._lock:
                self._jobs[job_id] = {
                    "job_id": job_id,
                    "status": "complete",
                    "progress": {
                        "stage": "complete",
                        "completed": document["summary"]["probes_total"],
                        "total": document["summary"]["probes_total"],
                        "percent": 100,
                        "open": document["summary"]["open_ports"],
                    },
                    "result": document,
                }
        except (ValueError, OSError) as exc:
            with self._lock:
                self._jobs[job_id] = {
                    "job_id": job_id,
                    "status": "failed",
                    "error": str(exc),
                }
        except Exception as exc:  # Defensive boundary: never leave a dashboard job stuck.
            with self._lock:
                self._jobs[job_id] = {
                    "job_id": job_id,
                    "status": "failed",
                    "error": f"Unexpected scan error: {exc}",
                }

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None


MANAGER = ScanManager()


class AegisHandler(BaseHTTPRequestHandler):
    server_version = "AegisScan/1.0"

    def _security_headers(self, content_type: str, length: int, *, cache: bool = False) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("Cache-Control", "public, max-age=3600" if cache else "no-store")

    def _send_bytes(
        self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK, *, cache: bool = False
    ) -> None:
        self.send_response(status)
        self._security_headers(content_type, len(body), cache=cache)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status)

    def _send_report(self, body: bytes) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, name: str, content_type: str) -> None:
        try:
            body = files("aegisscan").joinpath("static", name).read_bytes()
        except (FileNotFoundError, OSError):
            self._send_json({"error": "Asset not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_bytes(body, content_type, cache=True)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._static("index.html", "text/html; charset=utf-8")
        elif path == "/static/app.css":
            self._static("app.css", "text/css; charset=utf-8")
        elif path == "/static/app.js":
            self._static("app.js", "text/javascript; charset=utf-8")
        elif path == "/api/health":
            self._send_json({"status": "ok", "service": "AegisScan", "version": "1.0.0"})
        elif path == "/api/scans":
            self._send_json({"scans": recent_scans()})
        elif path.startswith("/api/scans/"):
            job_id = path.removeprefix("/api/scans/")
            job = MANAGER.get(job_id)
            if job:
                self._send_json(job)
            else:
                document = load_scan(job_id)
                if document:
                    self._send_json({"job_id": job_id, "status": "complete", "result": document})
                else:
                    self._send_json({"error": "Scan not found"}, HTTPStatus.NOT_FOUND)
        elif path.startswith("/reports/") and path.endswith(".html"):
            identifier = path.removeprefix("/reports/").removesuffix(".html")
            job = MANAGER.get(identifier)
            document = job.get("result") if job else load_scan(identifier)
            if not document:
                self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            else:
                body = render_html_report(document).encode("utf-8")
                self._send_report(body)
        else:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/scans":
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= MAX_REQUEST_BYTES:
                raise ValueError("Request body is empty or too large")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("Content-Type must be application/json")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
            job_id = MANAGER.start(payload)
            self._send_json(
                {"job_id": job_id, "status": "queued", "status_url": f"/api/scans/{job_id}"},
                HTTPStatus.ACCEPTED,
            )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def log_message(self, message: str, *args: object) -> None:
        print(f"[web] {self.address_string()} - {message % args}")


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), AegisHandler)
    print(f"AegisScan dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop. Public targets are disabled unless explicitly enabled by policy.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AegisScan.")
    finally:
        server.server_close()
