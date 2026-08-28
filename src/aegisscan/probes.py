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

HTTP_PORTS = {80, 2375, 3000, 3001, 5000, 5985, 8000, 8008, 8080, 8081, 8888, 9200}
TLS_PORTS = {443, 465, 993, 995, 5986, 6443, 8443}
SERVER_FIRST_PORTS = {21, 22, 25, 110, 143, 3306, 5900}


def service_name(port: int) -> str:
    if port in SERVICE_OVERRIDES:
        return SERVICE_OVERRIDES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def port_fingerprint(port: int) -> Fingerprint:
    """Create an explicit low-confidence port-registry hint."""
    hint = service_name(port)
    evidence = []
    method = "unverified"
    if hint != "unknown":
        evidence.append(f"Port {port}/tcp is commonly registered or associated with {hint}.")
        method = "port-registry"
    return Fingerprint(
        service=hint,
        port_hint=hint,
        confidence="low",
        classification_method=method,
        evidence=evidence,
    )


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
            payload = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 0.45))
            return _clean_text(payload)
        finally:
            writer.close()
            await writer.wait_closed()
    except (TimeoutError, ConnectionError, OSError, ssl.SSLError):
        return None


def identify_banner(banner: str) -> tuple[str | None, str | None]:
    """Classify conservative, high-signal server-first protocol banners."""
    normalized = banner.strip()
    lowered = normalized.lower()
    if normalized.startswith("SSH-"):
        return "ssh", normalized[:120]
    if normalized.startswith("RFB "):
        return "vnc", normalized[:120]
    if "mysql_native_password" in lowered or "mariadb" in lowered:
        return "mysql", normalized[:120]
    if lowered.startswith("+pong") or lowered.startswith("-noauth"):
        return "redis", normalized[:120]
    if lowered.startswith("+ok"):
        return "pop3", normalized[:120]
    if lowered.startswith("* ok"):
        return "imap", normalized[:120]
    if normalized.startswith("220") and ("smtp" in lowered or "esmtp" in lowered):
        return "smtp", normalized[:120]
    if normalized.startswith("220") and "ftp" in lowered:
        return "ftp", normalized[:120]
    return None, None


def _parse_http(payload: bytes) -> dict[str, Any]:
    text = payload.decode("iso-8859-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.splitlines()
    if not lines or not re.match(r"^HTTP/\d(?:\.\d)?\s+\d{3}(?:\s|$)", lines[0]):
        return {}
    status = lines[0][:160]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip().lower()] = value.strip()[:300]
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    title = None
    if title_match:
        title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip()[:160]

    detected_service = "http"
    server = headers.get("server", "")
    if headers.get("x-elastic-product", "").lower() == "elasticsearch":
        detected_service = "elasticsearch"
    elif "splunkd" in server.lower():
        detected_service = "splunk"
    elif "docker" in server.lower() or "docker api" in body[:500].lower():
        detected_service = "docker-api"

    security_headers = {
        "strict_transport_security": bool(headers.get("strict-transport-security")),
        "content_security_policy": bool(headers.get("content-security-policy")),
        "x_content_type_options": headers.get("x-content-type-options", "").lower() == "nosniff",
        "frame_protection": bool(
            headers.get("x-frame-options")
            or "frame-ancestors" in headers.get("content-security-policy", "").lower()
        ),
        "referrer_policy": bool(headers.get("referrer-policy")),
    }
    return {
        key: value
        for key, value in {
            "status": status,
            "server": server or None,
            "content_type": headers.get("content-type"),
            "title": title,
            "location": headers.get("location"),
            "detected_service": detected_service,
            "security_headers": security_headers,
        }.items()
        if value is not None
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
                "User-Agent: AegisScan/1.1 (authorized-security-audit)\r\n"
                "Accept: text/html,application/json,*/*;q=0.1\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="ignore"))
            await writer.drain()
            payload = await asyncio.wait_for(reader.read(32_768), timeout=timeout)
            parsed = _parse_http(payload) if payload else {}
            return parsed or None
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
        names: list[str] = []
        try:
            extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = extension.value.get_values_for_type(x509.DNSName)[:25]
        except x509.ExtensionNotFound:
            pass
        result.update(
            {
                "subject": certificate.subject.rfc4514_string()[:500],
                "issuer": certificate.issuer.rfc4514_string()[:500],
                "serial_number": format(certificate.serial_number, "x"),
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": expires.isoformat(),
                "days_until_expiry": (expires - now).days,
                "dns_names": names,
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


async def _probe_redis(target: Target, port: int, timeout: float) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.address, port, family=target.family), timeout=timeout
        )
        try:
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            payload = await asyncio.wait_for(reader.read(256), timeout=timeout)
            text = _clean_text(payload, limit=160)
            if text and (text.lower().startswith("+pong") or text.lower().startswith("-noauth")):
                return text
            return None
        finally:
            writer.close()
            await writer.wait_closed()
    except (TimeoutError, ConnectionError, OSError):
        return None


def _confirm(
    fingerprint: Fingerprint,
    *,
    service: str,
    method: str,
    evidence: str,
    product: str | None = None,
) -> None:
    fingerprint.service = service
    fingerprint.confidence = "high"
    fingerprint.classification_method = method
    fingerprint.evidence.append(evidence)
    if product:
        fingerprint.product = product[:120]


async def fingerprint_endpoint(target: Target, port: int, timeout: float) -> Fingerprint:
    """Perform bounded, non-authenticated protocol identification without exploitation."""
    fingerprint = port_fingerprint(port)
    probe_timeout = min(timeout, 0.8)

    if fingerprint.port_hint == "redis":
        redis_evidence = await _probe_redis(target, port, probe_timeout)
        if redis_evidence:
            fingerprint.banner = redis_evidence
            _confirm(
                fingerprint,
                service="redis",
                method="redis-ping",
                evidence="Redis responded to a non-authenticated PING probe.",
                product=redis_evidence,
            )
            return fingerprint

    should_read_banner = (
        port in SERVER_FIRST_PORTS or (port not in HTTP_PORTS and port not in TLS_PORTS)
    )
    if should_read_banner:
        fingerprint.banner = await _read_banner(target, port, probe_timeout)
        if fingerprint.banner:
            service, product = identify_banner(fingerprint.banner)
            if service:
                _confirm(
                    fingerprint,
                    service=service,
                    method="protocol-banner",
                    evidence=f"A protocol signature in the server-first banner confirmed {service}.",
                    product=product,
                )
                return fingerprint
            fingerprint.evidence.append("A server-first banner was collected but not classified.")

    if port in TLS_PORTS:
        fingerprint.tls = await _probe_tls(target, port, probe_timeout)
        if fingerprint.tls:
            fingerprint.confidence = "medium"
            fingerprint.classification_method = "tls-handshake"
            fingerprint.evidence.append(
                f"A TLS handshake succeeded using {fingerprint.tls.get('protocol', 'an unknown version')}."
            )
            fingerprint.http = await _probe_http(target, port, probe_timeout, use_tls=True)
            if fingerprint.http:
                detected = str(fingerprint.http.get("detected_service", "http"))
                service = "https" if detected == "http" else detected
                _confirm(
                    fingerprint,
                    service=service,
                    method="https-response",
                    evidence="A valid HTTP response was received over the negotiated TLS connection.",
                    product=str(fingerprint.http.get("server") or "") or None,
                )
        return fingerprint

    should_probe_http = port in HTTP_PORTS or fingerprint.port_hint == "unknown" or port >= 1024
    if should_probe_http:
        fingerprint.http = await _probe_http(target, port, probe_timeout, use_tls=False)
        if fingerprint.http:
            detected = str(fingerprint.http.get("detected_service", "http"))
            _confirm(
                fingerprint,
                service=detected,
                method="http-response",
                evidence="A syntactically valid HTTP response confirmed an HTTP-family service.",
                product=str(fingerprint.http.get("server") or "") or None,
            )
            return fingerprint

    if fingerprint.port_hint == "unknown" and port >= 1024:
        fingerprint.tls = await _probe_tls(target, port, probe_timeout)
        if fingerprint.tls:
            fingerprint.service = "tls"
            fingerprint.confidence = "medium"
            fingerprint.classification_method = "tls-handshake"
            fingerprint.evidence.append(
                f"A TLS handshake succeeded using {fingerprint.tls.get('protocol', 'an unknown version')}."
            )
            fingerprint.http = await _probe_http(target, port, probe_timeout, use_tls=True)
            if fingerprint.http:
                detected = str(fingerprint.http.get("detected_service", "http"))
                _confirm(
                    fingerprint,
                    service="https" if detected == "http" else detected,
                    method="https-response",
                    evidence="A valid HTTP response was received over the negotiated TLS connection.",
                    product=str(fingerprint.http.get("server") or "") or None,
                )
    return fingerprint
