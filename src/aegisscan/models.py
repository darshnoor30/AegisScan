from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class Target:
    label: str
    address: str
    family: int
    is_public: bool

    @property
    def network_scope(self) -> str:
        """Return the reachability context used by the exposure model."""
        address = ipaddress.ip_address(self.address)
        if address.is_loopback:
            return "loopback"
        if address.is_link_local:
            return "link-local"
        if address.is_global:
            return "public"
        if address.is_private:
            return "private"
        return "special"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["family"] = "IPv6" if self.family == 10 else "IPv4"
        data["network_scope"] = self.network_scope
        return data


@dataclass(slots=True)
class Fingerprint:
    service: str = "unknown"
    port_hint: str = "unknown"
    confidence: str = "low"
    classification_method: str = "unverified"
    evidence: list[str] = field(default_factory=list)
    product: str | None = None
    banner: str | None = None
    http: dict[str, Any] | None = None
    tls: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(slots=True)
class PortObservation:
    target: str
    address: str
    port: int
    protocol: str
    state: str
    latency_ms: float | None
    fingerprint: Fingerprint = field(default_factory=Fingerprint)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint.to_dict()
        return data


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    target: str
    address: str
    port: int
    category: str
    evidence: str
    impact: str
    recommendation: str
    base_severity: str
    network_scope: str
    risk_factors: list[str]
    score_deduction: int
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    schema_version: str
    scan_id: str
    engine_version: str
    started_at: str
    finished_at: str
    duration_ms: int
    config: dict[str, Any]
    assets: list[Target]
    observations: list[PortObservation]
    findings: list[Finding]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "engine_version": self.engine_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "config": self.config,
            "assets": [asset.to_dict() for asset in self.assets],
            "observations": [item.to_dict() for item in self.observations],
            "findings": [item.to_dict() for item in self.findings],
            "summary": self.summary,
        }
