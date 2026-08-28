from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Any

from aegisscan.models import Finding, PortObservation, Target

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"informational": 0, "low": 3, "medium": 7, "high": 15, "critical": 25}
VALID_ENVIRONMENTS = {"unknown", "development", "staging", "production"}
VALID_CRITICALITIES = {"low", "standard", "high", "critical"}


@dataclass(frozen=True, slots=True)
class ExposureRule:
    title: str
    base_severity: str
    category: str
    impact: str
    recommendation: str
    references: tuple[str, ...] = ()


SERVICE_RULES: dict[str, ExposureRule] = {
    "ftp": ExposureRule(
        "FTP service reachable",
        "high",
        "cleartext-protocol",
        "FTP can expose credentials and data when transport encryption is not enforced.",
        "Prefer SFTP/SSH. If FTP is required, restrict source networks and enforce an encrypted mode.",
        ("CWE-319",),
    ),
    "telnet": ExposureRule(
        "Telnet service reachable",
        "critical",
        "cleartext-protocol",
        "Telnet transmits session data without modern transport protection.",
        "Disable Telnet and migrate administration to SSH with strong authentication.",
        ("CWE-319",),
    ),
    "ssh": ExposureRule(
        "SSH administration service reachable",
        "medium",
        "remote-administration",
        "SSH is an authentication and administrative control surface that should have intentional reachability.",
        "Restrict sources, disable password login where practical, use managed keys or MFA, and monitor authentication.",
    ),
    "rpcbind": ExposureRule(
        "RPC port mapper reachable",
        "high",
        "service-discovery",
        "RPC service enumeration can reveal additional internal services and expand attack surface.",
        "Restrict RPC access to required management networks and remove unused RPC services.",
    ),
    "msrpc": ExposureRule(
        "Microsoft RPC endpoint mapper reachable",
        "high",
        "management-plane",
        "Remote RPC exposure increases the reachable Windows management surface.",
        "Limit access with host and network firewalls to trusted administration subnets.",
    ),
    "netbios-ssn": ExposureRule(
        "NetBIOS session service reachable",
        "high",
        "legacy-service",
        "NetBIOS reachability can reveal host and share information and may support legacy SMB paths.",
        "Disable NetBIOS where unnecessary and restrict file-sharing services to trusted networks.",
    ),
    "ldap": ExposureRule(
        "LDAP directory service reachable",
        "high",
        "identity-service",
        "Directory-service reachability exposes identity metadata and an authentication surface.",
        "Restrict LDAP to approved application networks and require TLS or signed and bound connections.",
    ),
    "smb": ExposureRule(
        "SMB service reachable",
        "critical",
        "file-sharing",
        "Reachable SMB expands the file-sharing and remote administration attack surface.",
        "Block untrusted access, disable SMBv1, require signing where appropriate, and patch endpoints.",
    ),
    "mssql": ExposureRule(
        "Microsoft SQL Server reachable",
        "high",
        "database",
        "Direct database reachability increases authentication, data-exposure, and misconfiguration risk.",
        "Place the database on a private segment and allow only approved application hosts.",
    ),
    "oracle": ExposureRule(
        "Oracle database listener reachable",
        "high",
        "database",
        "Direct listener reachability increases database discovery and authentication surface.",
        "Restrict listener access to approved application networks and use network encryption.",
    ),
    "nfs": ExposureRule(
        "NFS service reachable",
        "high",
        "file-sharing",
        "Reachable NFS may expose exported filesystems if host and export controls are weak.",
        "Restrict NFS to trusted clients, review exports, and enforce least privilege.",
    ),
    "docker-api": ExposureRule(
        "Docker API reachable",
        "critical",
        "container-management",
        "An unauthenticated or weakly protected Docker API can permit control of containers and the host.",
        "Disable unprotected TCP access. Prefer a protected Unix socket or mutually authenticated TLS.",
        ("CWE-306",),
    ),
    "mysql": ExposureRule(
        "MySQL service reachable",
        "high",
        "database",
        "Direct database reachability increases credential and data-access attack surface.",
        "Permit only approved application hosts and require encrypted, least-privilege accounts.",
    ),
    "rdp": ExposureRule(
        "Remote Desktop service reachable",
        "critical",
        "remote-administration",
        "RDP is a high-value authentication and remote-control surface.",
        "Place RDP behind VPN or ZTNA, require MFA and NLA, restrict sources, and monitor failed logons.",
    ),
    "postgresql": ExposureRule(
        "PostgreSQL service reachable",
        "high",
        "database",
        "Direct database reachability increases credential and data-access attack surface.",
        "Restrict pg_hba.conf and network firewalls to approved application identities and hosts.",
    ),
    "vnc": ExposureRule(
        "VNC remote-control service reachable",
        "critical",
        "remote-administration",
        "VNC provides an interactive remote-control surface and may lack strong transport protection.",
        "Place VNC behind VPN or ZTNA, require strong authentication, and restrict source networks.",
    ),
    "redis": ExposureRule(
        "Redis service reachable",
        "critical",
        "database",
        "A reachable Redis instance may expose sensitive cached data or administrative commands.",
        "Bind Redis to private interfaces, enable ACLs and TLS, and restrict access to application hosts.",
    ),
    "kubernetes-api": ExposureRule(
        "Kubernetes API reachable",
        "high",
        "container-management",
        "The Kubernetes API is a sensitive control-plane endpoint even when authentication is enabled.",
        "Restrict network reachability, disable anonymous access, enforce RBAC, and monitor audit logs.",
    ),
    "elasticsearch": ExposureRule(
        "Elasticsearch API reachable",
        "high",
        "database",
        "Direct API reachability may expose indexed data and cluster-administration functions.",
        "Require authentication and TLS, and restrict access to approved application and management hosts.",
    ),
    "memcached": ExposureRule(
        "Memcached service reachable",
        "critical",
        "database",
        "Memcached commonly lacks application-layer authentication and should not be broadly reachable.",
        "Bind to private interfaces, disable UDP if unused, and enforce network allowlists.",
        ("CWE-306",),
    ),
    "mongodb": ExposureRule(
        "MongoDB service reachable",
        "critical",
        "database",
        "Direct database reachability increases authentication and data-exposure risk.",
        "Bind to private interfaces, require authentication and TLS, and restrict application access.",
    ),
}


def _finding_id(address: str, port: int, category: str) -> str:
    digest = hashlib.sha256(f"{address}:{port}:{category}".encode()).hexdigest()[:12]
    return f"AEGIS-{digest.upper()}"


def _shift(severity: str, amount: int) -> str:
    index = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[max(0, min(index + amount, len(SEVERITY_ORDER) - 1))]


def _contextual_severity(
    base_severity: str,
    *,
    network_scope: str,
    confidence: str,
    environment: str,
    asset_criticality: str,
    apply_scope: bool = True,
) -> tuple[str, list[str]]:
    severity = base_severity
    factors: list[str] = [f"Base rule: {base_severity}."]
    if apply_scope:
        scope_adjustment = {"public": 1, "private": 0, "special": 0, "link-local": -1, "loopback": -2}
        adjustment = scope_adjustment.get(network_scope, 0)
        severity = _shift(severity, adjustment)
        factors.append(
            {
                "public": "Publicly routable target increases priority by one level.",
                "private": "Private-network reachability leaves the base priority unchanged.",
                "special": "Special-purpose address leaves the base priority unchanged.",
                "link-local": "Link-local reachability reduces priority by one level.",
                "loopback": "Loopback-only evidence reduces priority by two levels.",
            }.get(network_scope, "Unknown network scope leaves priority unchanged.")
        )
    if confidence == "low":
        severity = _shift(severity, -1)
        factors.append("Port-based identity is unverified, reducing priority by one level.")
    elif confidence == "high":
        factors.append("Protocol evidence confirms the service identity.")
    else:
        factors.append("Protocol-family evidence provides medium confidence.")

    if environment == "production":
        severity = _shift(severity, 1)
        factors.append("Production context increases priority by one level.")
    elif environment == "development":
        severity = _shift(severity, -1)
        factors.append("Development context reduces priority by one level.")
    else:
        factors.append(f"Environment '{environment}' does not change priority.")

    if asset_criticality in {"high", "critical"}:
        severity = _shift(severity, 1)
        factors.append(f"{asset_criticality.title()} asset criticality increases priority by one level.")
    elif asset_criticality == "low":
        severity = _shift(severity, -1)
        factors.append("Low asset criticality reduces priority by one level.")
    else:
        factors.append("Standard asset criticality does not change priority.")
    return severity, factors


def _make_finding(
    *,
    item: PortObservation,
    asset: Target,
    title: str,
    category: str,
    base_severity: str,
    confidence: str,
    evidence: str,
    impact: str,
    recommendation: str,
    references: tuple[str, ...] = (),
    environment: str,
    asset_criticality: str,
    apply_scope: bool = True,
) -> Finding:
    severity, risk_factors = _contextual_severity(
        base_severity,
        network_scope=asset.network_scope,
        confidence=confidence,
        environment=environment,
        asset_criticality=asset_criticality,
        apply_scope=apply_scope,
    )
    return Finding(
        finding_id=_finding_id(item.address, item.port, category),
        title=title,
        severity=severity,
        confidence=confidence,
        target=item.target,
        address=item.address,
        port=item.port,
        category=category,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        base_severity=base_severity,
        network_scope=asset.network_scope,
        risk_factors=risk_factors,
        score_deduction=SEVERITY_WEIGHT[severity],
        references=list(references),
    )


def _service_finding(
    item: PortObservation,
    asset: Target,
    *,
    environment: str,
    asset_criticality: str,
) -> Finding | None:
    fingerprint = item.fingerprint
    rule = SERVICE_RULES.get(fingerprint.service)
    if rule is None:
        return None
    confirmed = fingerprint.confidence == "high"
    title = rule.title if confirmed else f"Potential exposure: {rule.title}"
    if confirmed:
        evidence = (
            f"A TCP connection to {item.address}:{item.port} succeeded. "
            f"{' '.join(fingerprint.evidence) or 'Protocol evidence confirmed the service.'}"
        )
    else:
        evidence = (
            f"A TCP connection to {item.address}:{item.port} succeeded. "
            f"The service identity is inferred from the {fingerprint.port_hint} port association; "
            "validate the actual listening process."
        )
    return _make_finding(
        item=item,
        asset=asset,
        title=title,
        category=rule.category,
        base_severity=rule.base_severity,
        confidence=fingerprint.confidence,
        evidence=evidence,
        impact=rule.impact,
        recommendation=rule.recommendation,
        references=rule.references,
        environment=environment,
        asset_criticality=asset_criticality,
    )


def analyze_exposure(
    observations: list[PortObservation],
    assets: list[Target],
    *,
    environment: str = "unknown",
    asset_criticality: str = "standard",
) -> tuple[list[Finding], dict[str, Any]]:
    if environment not in VALID_ENVIRONMENTS:
        raise ValueError(f"Environment must be one of: {', '.join(sorted(VALID_ENVIRONMENTS))}")
    if asset_criticality not in VALID_CRITICALITIES:
        raise ValueError(f"Asset criticality must be one of: {', '.join(sorted(VALID_CRITICALITIES))}")

    asset_by_address = {asset.address: asset for asset in assets}
    findings: list[Finding] = []
    for item in observations:
        if item.state != "open":
            continue
        asset = asset_by_address[item.address]
        service_finding = _service_finding(
            item,
            asset,
            environment=environment,
            asset_criticality=asset_criticality,
        )
        if service_finding:
            findings.append(service_finding)

        if item.fingerprint.service == "http" and item.fingerprint.confidence == "high":
            http = item.fingerprint.http or {}
            findings.append(
                _make_finding(
                    item=item,
                    asset=asset,
                    title="Unencrypted HTTP service reachable",
                    category="cleartext-web",
                    base_severity="medium",
                    confidence="high",
                    evidence=(
                        f"A valid plaintext HTTP response was received from "
                        f"{item.address}:{item.port} ({http.get('status', 'status unknown')})."
                    ),
                    impact="Plaintext HTTP can expose session data or content when traffic crosses an untrusted path.",
                    recommendation="Use HTTPS for sensitive traffic, redirect HTTP to HTTPS, and protect any required plaintext endpoint by network policy.",
                    references=("CWE-319",),
                    environment=environment,
                    asset_criticality=asset_criticality,
                )
            )

        tls = item.fingerprint.tls or {}
        certificate = tls.get("certificate", {})
        days = certificate.get("days_until_expiry")
        if isinstance(days, int) and days < 30:
            expired = days < 0
            findings.append(
                _make_finding(
                    item=item,
                    asset=asset,
                    title="TLS certificate has expired" if expired else "TLS certificate expires soon",
                    category="tls-lifecycle",
                    base_severity="high" if expired else "medium",
                    confidence="high",
                    evidence=f"Observed certificate expiry: {certificate.get('not_after')} ({days} days).",
                    impact="Clients may reject the service, causing an outage or encouraging unsafe bypasses.",
                    recommendation="Renew and deploy the certificate, then verify the complete certificate chain.",
                    references=("CWE-298",),
                    environment=environment,
                    asset_criticality=asset_criticality,
                    apply_scope=False,
                )
            )

        protocol = str(tls.get("protocol", ""))
        if protocol in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
            findings.append(
                _make_finding(
                    item=item,
                    asset=asset,
                    title="Legacy TLS protocol negotiated",
                    category="tls-configuration",
                    base_severity="high",
                    confidence="high",
                    evidence=f"The endpoint negotiated {protocol}.",
                    impact="Legacy protocol versions lack modern cryptographic protections and may be prohibited by policy.",
                    recommendation="Disable legacy SSL/TLS versions and require TLS 1.2 or TLS 1.3 with modern ciphers.",
                    references=("CWE-326",),
                    environment=environment,
                    asset_criticality=asset_criticality,
                )
            )

        if item.fingerprint.service == "https" and item.fingerprint.http:
            headers = item.fingerprint.http.get("security_headers", {})
            required = {
                "strict_transport_security": "HSTS",
                "content_security_policy": "Content-Security-Policy",
                "x_content_type_options": "X-Content-Type-Options",
                "frame_protection": "frame protection",
                "referrer_policy": "Referrer-Policy",
            }
            missing = [label for key, label in required.items() if not headers.get(key)]
            if missing:
                findings.append(
                    _make_finding(
                        item=item,
                        asset=asset,
                        title="Recommended HTTPS response headers missing",
                        category="http-hardening",
                        base_severity="low",
                        confidence="high",
                        evidence=f"The root response did not present: {', '.join(missing)}.",
                        impact="Missing browser security directives can weaken defense in depth; applicability depends on the application.",
                        recommendation="Review the application context and add applicable response headers without breaking required functionality.",
                        references=("CWE-693",),
                        environment=environment,
                        asset_criticality=asset_criticality,
                    )
                )

    findings.sort(
        key=lambda finding: (
            -SEVERITY_ORDER.index(finding.severity),
            finding.address,
            finding.port,
            finding.finding_id,
        )
    )
    severity_counts = {severity: 0 for severity in reversed(SEVERITY_ORDER)}
    for finding in findings:
        severity_counts[finding.severity] += 1
    deduction = sum(finding.score_deduction for finding in findings)
    score = max(0, 100 - min(deduction, 100))
    if score >= 90:
        grade, posture = "A", "Strong"
    elif score >= 80:
        grade, posture = "B", "Guarded"
    elif score >= 70:
        grade, posture = "C", "Elevated"
    elif score >= 60:
        grade, posture = "D", "High"
    else:
        grade, posture = "F", "Critical"

    scope_counts = Counter(asset.network_scope for asset in assets)
    verified = sum(item.fingerprint.confidence == "high" for item in observations)
    inferred = sum(item.fingerprint.confidence == "low" for item in observations)
    return findings, {
        "security_score": score,
        "exposure_posture_score": score,
        "grade": grade,
        "posture": posture,
        "severity_counts": severity_counts,
        "scope_counts": dict(sorted(scope_counts.items())),
        "verified_services": verified,
        "inferred_services": inferred,
        "risk_context": {
            "environment": environment,
            "asset_criticality": asset_criticality,
        },
        "risk_model": (
            "Contextual Exposure Model v2: base rule adjusted by network scope, "
            "service confidence, environment, and asset criticality; prioritization aid only"
        ),
    }
