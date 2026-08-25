from __future__ import annotations

from typing import Any


def compare_scans(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare open services and finding severities across two AegisScan results."""

    def services(document: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
        return {
            (str(item["address"]), int(item["port"])): item
            for item in document.get("observations", [])
            if item.get("state") == "open"
        }

    before = services(baseline)
    after = services(current)
    new_keys = sorted(after.keys() - before.keys())
    closed_keys = sorted(before.keys() - after.keys())
    shared_keys = sorted(before.keys() & after.keys())
    changed = []
    for key in shared_keys:
        old_fingerprint = before[key].get("fingerprint", {})
        new_fingerprint = after[key].get("fingerprint", {})
        if old_fingerprint != new_fingerprint:
            changed.append(
                {
                    "address": key[0],
                    "port": key[1],
                    "before": old_fingerprint,
                    "after": new_fingerprint,
                }
            )

    return {
        "baseline_scan_id": baseline.get("scan_id"),
        "current_scan_id": current.get("scan_id"),
        "new_services": [after[key] for key in new_keys],
        "closed_services": [before[key] for key in closed_keys],
        "changed_services": changed,
        "summary": {
            "new": len(new_keys),
            "closed": len(closed_keys),
            "changed": len(changed),
            "status": "drift-detected" if new_keys or changed else "stable-or-reduced",
        },
    }

