from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from aegisscan.models import Finding, PortObservation, Target

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"informational": 0, "low": 3, "medium": 7, "high": 14, "critical": 25}


@dataclass(frozen=True, slots=True)
class ExposureRule:
    title: str
    severity: str
    category: str
    impact: str
    recommendation: str
    references: tuple[str, ...] = ()


RULES: dict[int, ExposureRule] = {
    21: ExposureRule(
        "FTP service exposed",
        "high",
        "cleartext-protocol",
        "FTP can expose credentials and data when transport encryption is not enforced.",
        "Prefer SFTP/SSH. If FTP is required, restrict source networks and enforce an encrypted mode.",
        ("CWE-319",),
    ),
    23: ExposureRule(
        "Telnet service exposed",
        "critical",
        "cleartext-protocol",
        "Telnet transmits session data without modern transport protection.",
        "Disable Telnet and migrate administration to SSH with strong authentication.",
        ("CWE-319",),
    ),
    111: ExposureRule(
        "RPC port mapper exposed",
        "high",
        "service-discovery",
        "RPC service enumeration can reveal additional internal services and expand attack surface.",
        "Restrict RPC access to required management networks and remove unused RPC services.",
    ),
    135: ExposureRule(
        "Microsoft RPC endpoint mapper exposed",
        "high",
        "management-plane",
        "Remote RPC exposure increases the reachable Windows management surface.",
        "Limit access with host/network firewalls to trusted administration subnets.",
    ),
    139: ExposureRule(
        "NetBIOS session service exposed",
        "high",
        "legacy-service",
        "NetBIOS exposure can reveal host and share information and may support legacy SMB paths.",
        "Disable NetBIOS where unnecessary and restrict file-sharing services to trusted networks.",
    ),
    389: ExposureRule(
        "LDAP service exposed",
        "high",
        "identity-service",
        "Unrestricted directory-service reachability may expose identity metadata and authentication surface.",
        "Restrict LDAP to application networks and require TLS or signed/bound connections.",
    ),
    445: ExposureRule(
        "SMB service exposed",
        "critical",
        "file-sharing",
        "Reachable SMB expands the file-sharing and remote administration attack surface.",
        "Block untrusted access, disable SMBv1, require signing where appropriate, and patch endpoints.",
    ),
    1433: ExposureRule(
        "Microsoft SQL Server exposed",
        "high",
        "database",
        "Direct database reachability increases authentication, data-exposure, and misconfiguration risk.",
        "Place the database on a private segment and allow only approved application hosts.",
    ),
    1521: ExposureRule(
        "Oracle database listener exposed",
        "high",
        "database",
        "Direct listener reachability increases database discovery and authentication surface.",
        "Restrict listener access to approved application networks and use network encryption.",
    ),
    2049: ExposureRule(
        "NFS service exposed",
        "high",
        "file-sharing",
        "Reachable NFS may expose exported filesystems if host and export controls are weak.",
        "Restrict NFS to trusted clients, review exports, and enforce least privilege.",
    ),
    2375: ExposureRule(
        "Unencrypted Docker API exposed",
        "critical",
        "container-management",
        "An unauthenticated or weakly protected Docker API can allow control of containers and the host.",
        "Disable TCP port 2375. Use a protected Unix socket or mutually authenticated TLS on port 2376.",
        ("CWE-306",),
    ),
    3306: ExposureRule(
        "MySQL service exposed",
        "high",
        "database",
        "Direct database reachability increases credential and data-access attack surface.",
        "Permit only approved application hosts and require encrypted, least-privilege accounts.",
    ),
    3389: ExposureRule(
        "Remote Desktop service exposed",
        "critical",
        "remote-administration",
        "Reachable RDP is a high-value authentication and remote-control surface.",
        "Place RDP behind VPN/ZTNA, require MFA and NLA, restrict sources, and monitor failed logons.",
    ),
    5432: ExposureRule(
        "PostgreSQL service exposed",
        "high",
        "database",
        "Direct database reachability increases credential and data-access attack surface.",
        "Restrict pg_hba.conf and network firewalls to approved application identities and hosts.",
    ),
    5900: ExposureRule(
        "VNC remote-control service exposed",
        "critical",
        "remote-administration",
        "VNC provides an interactive remote-control surface and may lack strong transport protection.",
        "Place VNC behind VPN/ZTNA, require strong authentication, and restrict source networks.",
    ),
    6379: ExposureRule(
        "Redis service exposed",
        "critical",
        "database",
        "A reachable Redis instance may expose sensitive cached data or administrative commands.",
        "Bind Redis to private interfaces, enable ACLs/TLS, and restrict access to application hosts.",
    ),
    6443: ExposureRule(
        "Kubernetes API reachable",
        "high",
        "container-management",
        "The Kubernetes API is a sensitive control-plane endpoint even when authentication is enabled.",
        "Restrict network reachability, disable anonymous access, enforce RBAC, and monitor audit logs.",
    ),
    9200: ExposureRule(
        "Elasticsearch API exposed",
        "high",
        "database",
        "Direct API reachability may expose indexed data and cluster administration functions.",
        "Require authentication/TLS and restrict access to approved application and management hosts.",
    ),
    11211: ExposureRule(
        "Memcached service exposed",
        "critical",
        "database",
        "Memcached commonly lacks application-layer authentication and should not be broadly reachable.",
        "Bind to private interfaces, disable UDP if unused, and enforce network allowlists.",
        ("CWE-306",),
    ),
    27017: ExposureRule(
        "MongoDB service exposed",
        "critical",
        "database",
        "Direct database reachability increases authentication and data-exposure risk.",
        "Bind to private interfaces, require authentication/TLS, and restrict application access.",
    ),
}


def _promote(severity: str) -> str:
    index = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[min(index + 1, len(SEVERITY_ORDER) - 1)]


def _finding_id(address: str, port: int, category: str) -> str:
    digest = hashlib.sha256(f"{address}:{port}:{category}".encode()).hexdigest()[:12]
    return f"AEGIS-{digest.upper()}"


def analyze_exposure(
    observations: list[PortObservation], assets: list[Target]
) -> tuple[list[Finding], dict[str, Any]]:
    asset_by_address = {asset.address: asset for asset in assets}
    findings: list[Finding] = []
    for item in observations:
        if item.state != "open":
            continue
        asset = asset_by_address[item.address]
        if item.port in RULES:
            rule = RULES[item.port]
            severity = _promote(rule.severity) if asset.is_public else rule.severity
            public_note = " The address is globally routable." if asset.is_public else ""
            service = item.fingerprint.service
            banner = item.fingerprint.banner
            identity_confirmed = bool(banner)
            title = rule.title
            if not identity_confirmed:
                subject = rule.title.removesuffix(" exposed").removesuffix(" reachable")
                title = f"Potential exposure: {subject}"
            evidence = (
                f"A TCP connection to {item.address}:{item.port} succeeded. "
                f"Port-based service classification: {service}; validate the service identity."
            )
            if identity_confirmed:
                evidence = (
                    f"A TCP connection to {item.address}:{item.port} succeeded; "
                    f"a server-first protocol banner was observed: {banner}."
                )
            findings.append(
                Finding(
                    finding_id=_finding_id(item.address, item.port, rule.category),
                    title=title,
                    severity=severity,
                    confidence="high" if identity_confirmed else "medium",
                    target=item.target,
                    address=item.address,
                    port=item.port,
                    category=rule.category,
                    evidence=f"{evidence}{public_note}",
                    impact=rule.impact,
                    recommendation=rule.recommendation,
                    references=list(rule.references),
                )
            )

        certificate = (item.fingerprint.tls or {}).get("certificate", {})
        days = certificate.get("days_until_expiry")
        if isinstance(days, int) and days < 30:
            expired = days < 0
            tls_severity = "high" if expired else "medium"
            title = "TLS certificate has expired" if expired else "TLS certificate expires soon"
            findings.append(
                Finding(
                    finding_id=_finding_id(item.address, item.port, "tls-lifecycle"),
                    title=title,
                    severity=tls_severity,
                    confidence="high",
                    target=item.target,
                    address=item.address,
                    port=item.port,
                    category="tls-lifecycle",
                    evidence=f"Observed certificate expiry: {certificate.get('not_after')} ({days} days).",
                    impact="Clients may reject the service, causing an outage or encouraging unsafe bypasses.",
                    recommendation="Renew and deploy the certificate, then verify the complete certificate chain.",
                    references=["CWE-298"],
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
    deduction = sum(SEVERITY_WEIGHT[finding.severity] for finding in findings)
    score = max(0, 100 - min(deduction, 100))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return findings, {
        "security_score": score,
        "grade": grade,
        "severity_counts": severity_counts,
        "risk_model": "Exposure score v1; prioritization aid, not a compliance result",
    }
