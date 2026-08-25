from __future__ import annotations

import re

MAX_PORTS = 2_048

DEFAULT_PORTS = (
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3000,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    9200,
    11211,
    27017,
)

PRESETS: dict[str, tuple[int, ...]] = {
    "default": DEFAULT_PORTS,
    "web": (80, 443, 3000, 3001, 5000, 8000, 8008, 8080, 8081, 8443, 8888),
    "remote": (22, 23, 3389, 5900, 5985, 5986),
    "database": (1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017),
    "mail": (25, 110, 143, 465, 587, 993, 995),
}


def parse_ports(spec: str | None, *, maximum: int = MAX_PORTS) -> list[int]:
    """Parse a preset or comma-separated ports/ranges into a sorted unique list."""
    if not spec or spec.strip().lower() == "default":
        return list(DEFAULT_PORTS)

    spec = spec.strip().lower()
    if spec in PRESETS:
        return list(PRESETS[spec])

    if not re.fullmatch(r"[0-9,\-\s]+", spec):
        choices = ", ".join(PRESETS)
        raise ValueError(f"Invalid port expression. Use ports/ranges or a preset: {choices}")

    ports: set[int] = set()
    for token in (part.strip() for part in spec.split(",")):
        if not token:
            raise ValueError("Port expression contains an empty item")
        if "-" in token:
            pieces = token.split("-")
            if len(pieces) != 2 or not all(pieces):
                raise ValueError(f"Invalid port range: {token}")
            start, end = map(int, pieces)
            if start > end:
                raise ValueError(f"Port range must be ascending: {token}")
            if not (1 <= start <= 65_535 and 1 <= end <= 65_535):
                raise ValueError(f"Port outside 1-65535: {token}")
            if end - start + 1 > maximum:
                raise ValueError(f"A single range cannot exceed {maximum:,} ports")
            ports.update(range(start, end + 1))
        else:
            port = int(token)
            if not 1 <= port <= 65_535:
                raise ValueError(f"Port outside 1-65535: {port}")
            ports.add(port)
        if len(ports) > maximum:
            raise ValueError(f"A scan cannot exceed {maximum:,} unique ports")

    if not ports:
        raise ValueError("At least one port is required")
    return sorted(ports)

