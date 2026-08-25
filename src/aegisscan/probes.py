from __future__ import annotations

import asyncio
import hashlib
import html
import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from aegisscan.models import Fingerprint, Target

SERVICE_OVERRIDES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker-api",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9042: "cassandra",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

HTTP_PORTS = {80, 3000, 3001, 5000, 5985, 8000, 8008, 8080, 8081, 8888, 9200}
TLS_PORTS = {443, 465, 993, 995, 5986, 6443, 8443}
SERVER_FIRST_PORTS = {21, 22, 25, 110, 143, 3306, 5900}


def service_name(port: int) -> str:
    if port in SERVICE_OVERRIDES:
        return SERVICE_OVERRIDES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _clean_text(payload: bytes, limit: int = 300) -> str | None:
    if not payload:
        return None
    decoded = payload.decode("utf-8", errors="replace")
    decoded = re.sub(r"[^\x20-\x7E\r\n\t]", ".", decoded)
    decoded = re.sub(r"[\r\n\t ]+", " ", decoded).strip()
    return decoded[:limit] or None


def _hostname_label(target: Target) -> str | None:
    if "/" in target.label or _looks_like_ip(target.label):
        return None
    return target.label


async def _read_banner(target: Target, port: int, timeout: float) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.address, port, family=target.family), timeout=timeout
        )
        try:
            payload = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 1.0))
            return _clean_text(payload)
        finally:
            writer.close()
            await writer.wait_closed()
    except (TimeoutError, ConnectionError, OSError, ssl.SSLError):
        return None


def _parse_http(payload: bytes) -> dict[str, Any]:
    text = payload.decode("iso-8859-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.splitlines()
    status = lines[0][:160] if lines else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip().lower()] = value.strip()[:300]
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    title = None
    if title_match:
        title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip()[:160]
    return {
        key: value
        for key, value in {
            "status": status,
            "server": headers.get("server"),
            "content_type": headers.get("content-type"),
            "title": title,
        }.items()
        if value
    }


async def _probe_http(
    target: Target, port: int, timeout: float, *, use_tls: bool
) -> dict[str, Any] | None:
    context = None
    server_hostname = None
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        server_hostname = _hostname_label(target)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target.address,
                port,
                family=target.family,
                ssl=context,
                server_hostname=server_hostname,
            ),
            timeout=timeout,
        )
        try:
            host = _hostname_label(target) or target.address
            request = (
                f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: AegisScan/1.0 (authorized-security-audit)\r\n"
                "Accept: text/html,*/*;q=0.1\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="ignore"))
            await writer.drain()
            payload = await asyncio.wait_for(reader.read(32_768), timeout=timeout)
            return _parse_http(payload) if payload else None
        finally:
            writer.close()
            await writer.wait_closed()
    except (TimeoutError, ConnectionError, OSError, ssl.SSLError):
        return None


def _looks_like_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False


def _decode_certificate(der_bytes: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"sha256": hashlib.sha256(der_bytes).hexdigest()}
    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(der_bytes)
        now = datetime.now(UTC)
        expires = certificate.not_valid_after_utc
        result.update(
            {
                "subject": certificate.subject.rfc4514_string()[:500],
                "issuer": certificate.issuer.rfc4514_string()[:500],
                "serial_number": format(certificate.serial_number, "x"),
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": expires.isoformat(),
                "days_until_expiry": (expires - now).days,
            }
        )
    except (ImportError, ValueError):
        result["certificate_parser"] = "Install the optional 'tls' extra for certificate details"
    return result


async def _probe_tls(target: Target, port: int, timeout: float) -> dict[str, Any] | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    server_hostname = _hostname_label(target)
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target.address,
                port,
                family=target.family,
                ssl=context,
                server_hostname=server_hostname,
            ),
            timeout=timeout,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return None
            cipher = ssl_object.cipher()
            result: dict[str, Any] = {
                "protocol": ssl_object.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "alpn": ssl_object.selected_alpn_protocol(),
            }
            der_bytes = ssl_object.getpeercert(binary_form=True)
            if der_bytes:
                result["certificate"] = _decode_certificate(der_bytes)
            return {key: value for key, value in result.items() if value is not None}
        finally:
            writer.close()
            await writer.wait_closed()
    except (TimeoutError, ConnectionError, OSError, ssl.SSLError):
        return None


async def fingerprint_endpoint(target: Target, port: int, timeout: float) -> Fingerprint:
    """Perform minimal, protocol-aware identification without exploitation."""
    fingerprint = Fingerprint(service=service_name(port))
    if port in SERVER_FIRST_PORTS:
        fingerprint.banner = await _read_banner(target, port, timeout)
        if fingerprint.banner:
            fingerprint.product = fingerprint.banner[:120]

    if port in TLS_PORTS:
        fingerprint.tls = await _probe_tls(target, port, timeout)
        if port in {443, 5986, 6443, 8443}:
            fingerprint.http = await _probe_http(target, port, timeout, use_tls=True)
    elif port in HTTP_PORTS:
        fingerprint.http = await _probe_http(target, port, timeout, use_tls=False)

    if fingerprint.http and fingerprint.http.get("server"):
        fingerprint.product = str(fingerprint.http["server"])
    return fingerprint
