from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from aegisscan import __version__
from aegisscan.intelligence import (
    VALID_CRITICALITIES,
    VALID_ENVIRONMENTS,
    analyze_exposure,
)
from aegisscan.models import PortObservation, ScanResult, Target
from aegisscan.probes import fingerprint_endpoint, port_fingerprint
from aegisscan.targets import enforce_authorization, expand_targets

ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class ScanConfig:
    targets: Sequence[str]
    ports: Sequence[int]
    timeout: float = 0.8
    concurrency: int = 200
    delay_ms: int = 0
    authorized: bool = False
    allow_public: bool = False
    fingerprint: bool = True
    environment: str = "unknown"
    asset_criticality: str = "standard"

    def validate(self) -> None:
        if not 0.1 <= self.timeout <= 10:
            raise ValueError("Timeout must be between 0.1 and 10 seconds")
        if not 1 <= self.concurrency <= 500:
            raise ValueError("Concurrency must be between 1 and 500")
        if not 0 <= self.delay_ms <= 5_000:
            raise ValueError("Delay must be between 0 and 5,000 milliseconds")
        if not self.ports:
            raise ValueError("At least one port is required")
        if len(set(self.ports)) > 2_048:
            raise ValueError("A scan cannot exceed 2,048 unique ports")
        if any(not 1 <= int(port) <= 65_535 for port in self.ports):
            raise ValueError("Ports must be between 1 and 65535")
        if self.environment not in VALID_ENVIRONMENTS:
            choices = ", ".join(sorted(VALID_ENVIRONMENTS))
            raise ValueError(f"Environment must be one of: {choices}")
        if self.asset_criticality not in VALID_CRITICALITIES:
            choices = ", ".join(sorted(VALID_CRITICALITIES))
            raise ValueError(f"Asset criticality must be one of: {choices}")


async def _connect_state(target: Target, port: int, timeout: float) -> tuple[str, float | None]:
    started = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.address, port, family=target.family), timeout=timeout
        )
        latency = round((time.perf_counter() - started) * 1_000, 2)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return "open", latency
    except ConnectionRefusedError:
        return "closed", round((time.perf_counter() - started) * 1_000, 2)
    except TimeoutError:
        return "filtered", None
    except OSError:
        return "error", None


async def scan(config: ScanConfig, progress: ProgressCallback | None = None) -> ScanResult:
    """Run a bounded asynchronous TCP connect scan and return structured evidence."""
    config.validate()
    assets = await asyncio.to_thread(expand_targets, config.targets)
    enforce_authorization(assets, authorized=config.authorized, allow_public=config.allow_public)
    ports = sorted(set(int(port) for port in config.ports))

    scan_id = str(uuid.uuid4())
    started_at = datetime.now(UTC)
    started_clock = time.perf_counter()
    total = len(assets) * len(ports)
    completed = 0
    states: Counter[str] = Counter()
    observations: list[PortObservation] = []
    queue: asyncio.Queue[tuple[Target, int] | None] = asyncio.Queue(
        maxsize=max(2, config.concurrency * 2)
    )

    def report(stage: str = "scanning") -> None:
        if progress:
            progress(
                {
                    "scan_id": scan_id,
                    "stage": stage,
                    "completed": completed,
                    "total": total,
                    "percent": round((completed / total) * 100, 1) if total else 100.0,
                    "open": states["open"],
                }
            )

    async def producer() -> None:
        for asset in assets:
            for port in ports:
                await queue.put((asset, port))
        for _ in range(min(config.concurrency, total)):
            await queue.put(None)

    async def worker() -> None:
        nonlocal completed
        while True:
            work = await queue.get()
            try:
                if work is None:
                    return
                asset, port = work
                state, latency = await _connect_state(asset, port, config.timeout)
                states[state] += 1
                if state == "open":
                    fingerprint = port_fingerprint(port)
                    if config.fingerprint:
                        try:
                            fingerprint = await fingerprint_endpoint(asset, port, config.timeout)
                        except Exception:
                            fingerprint.evidence.append(
                                "Active identification failed; only the port association is available."
                            )
                    observation = PortObservation(
                        target=asset.label,
                        address=asset.address,
                        port=port,
                        protocol="tcp",
                        state=state,
                        latency_ms=latency,
                    )
                    observation.fingerprint = fingerprint
                    observations.append(observation)
                completed += 1
                if config.delay_ms:
                    await asyncio.sleep(config.delay_ms / 1_000)
                if completed == total or completed % max(1, total // 100) == 0:
                    report()
            finally:
                queue.task_done()

    report("resolving")
    workers = [asyncio.create_task(worker()) for _ in range(min(config.concurrency, total))]
    await producer()
    await queue.join()
    await asyncio.gather(*workers)

    report("analyzing")
    observations.sort(key=lambda item: (item.address, item.port))
    findings, intelligence_summary = analyze_exposure(
        observations,
        assets,
        environment=config.environment,
        asset_criticality=config.asset_criticality,
    )
    finished_at = datetime.now(UTC)
    duration_ms = round((time.perf_counter() - started_clock) * 1_000)
    summary = {
        "targets": len(assets),
        "ports_per_target": len(ports),
        "probes_total": total,
        "states": {
            "open": states["open"],
            "closed": states["closed"],
            "filtered": states["filtered"],
            "error": states["error"],
        },
        "open_ports": len(observations),
        "findings": len(findings),
        "actionable_findings": sum(
            finding.severity != "informational" for finding in findings
        ),
        **intelligence_summary,
    }
    result = ScanResult(
        schema_version="1.1",
        scan_id=scan_id,
        engine_version=__version__,
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        duration_ms=duration_ms,
        config={
            "targets": list(config.targets),
            "ports": ports,
            "timeout": config.timeout,
            "concurrency": config.concurrency,
            "delay_ms": config.delay_ms,
            "fingerprint": config.fingerprint,
            "public_targets_enabled": config.allow_public,
            "environment": config.environment,
            "asset_criticality": config.asset_criticality,
        },
        assets=assets,
        observations=observations,
        findings=findings,
        summary=summary,
    )
    report("complete")
    return result
