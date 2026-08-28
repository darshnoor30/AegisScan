from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable

from aegisscan.models import Target

MAX_TARGETS = 256


class TargetPolicyError(ValueError):
    """Raised when a target violates an explicit scanning safety policy."""


def _validate_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if ip.is_multicast:
        raise TargetPolicyError(f"Multicast target is not supported: {ip}")
    if ip.is_unspecified:
        raise TargetPolicyError(f"Unspecified target is not supported: {ip}")


def _target(label: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Target:
    _validate_ip(ip)
    return Target(
        label=label,
        address=str(ip),
        family=socket.AF_INET6 if ip.version == 6 else socket.AF_INET,
        is_public=ip.is_global,
    )


def _resolve_hostname(name: str) -> list[Target]:
    try:
        records = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{name}': {exc}") from exc

    resolved: list[Target] = []
    seen: set[str] = set()
    for family, _socktype, _proto, _canonname, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = str(sockaddr[0])
        if address in seen:
            continue
        seen.add(address)
        resolved.append(_target(name, ipaddress.ip_address(address)))
    if not resolved:
        raise ValueError(f"Target '{name}' did not resolve to IPv4 or IPv6")
    return resolved


def expand_targets(values: Iterable[str], *, maximum: int = MAX_TARGETS) -> list[Target]:
    """Expand IPs, hostnames, and CIDRs while enforcing a deterministic scope cap."""
    raw_items = [part.strip() for value in values for part in value.split(",") if part.strip()]
    if not raw_items:
        raise ValueError("At least one target is required")

    targets: list[Target] = []
    seen: set[str] = set()
    for item in raw_items:
        item_targets: list[Target]
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR target '{item}'") from exc
            if network.num_addresses > maximum + 2:
                raise TargetPolicyError(
                    f"CIDR '{item}' is too large; a scan is limited to {maximum} targets"
                )
            item_targets = [_target(item, ip) for ip in network.hosts()]
            if not item_targets and network.num_addresses == 1:
                item_targets = [_target(item, network.network_address)]
        else:
            try:
                item_targets = [_target(item, ipaddress.ip_address(item))]
            except ValueError:
                item_targets = _resolve_hostname(item)

        for candidate in item_targets:
            if candidate.address in seen:
                continue
            seen.add(candidate.address)
            targets.append(candidate)
            if len(targets) > maximum:
                raise TargetPolicyError(f"A scan is limited to {maximum} resolved targets")
    return targets


def enforce_authorization(
    targets: list[Target], *, authorized: bool, allow_public: bool
) -> None:
    if not authorized:
        raise TargetPolicyError(
            "Authorization acknowledgement is required. Scan only systems you own or are permitted to test."
        )
    public = [target.address for target in targets if target.is_public]
    if public and not allow_public:
        preview = ", ".join(public[:3])
        suffix = "…" if len(public) > 3 else ""
        raise TargetPolicyError(
            f"Public targets are blocked by default ({preview}{suffix}). "
            "Use the explicit public-target opt-in only with written authorization."
        )
