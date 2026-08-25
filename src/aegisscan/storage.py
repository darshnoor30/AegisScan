from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def data_directory() -> Path:
    configured = os.environ.get("AEGISSCAN_DATA_DIR")
    return Path(configured).expanduser() if configured else Path(".aegisscan")


def save_scan(document: dict[str, Any], directory: Path | None = None) -> Path:
    root = (directory or data_directory()) / "scans"
    root.mkdir(parents=True, exist_ok=True)
    scan_id = str(document["scan_id"])
    destination = root / f"{scan_id}.json"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=root, delete=False) as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(destination)
    return destination


def load_scan(scan_id: str, directory: Path | None = None) -> dict[str, Any] | None:
    if not scan_id or any(character not in "0123456789abcdef-" for character in scan_id.lower()):
        return None
    path = (directory or data_directory()) / "scans" / f"{scan_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def recent_scans(limit: int = 20, directory: Path | None = None) -> list[dict[str, Any]]:
    root = (directory or data_directory()) / "scans"
    if not root.exists():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            items.append(
                {
                    "scan_id": document.get("scan_id"),
                    "started_at": document.get("started_at"),
                    "targets": document.get("summary", {}).get("targets"),
                    "open_ports": document.get("summary", {}).get("open_ports"),
                    "security_score": document.get("summary", {}).get("security_score"),
                }
            )
        except (OSError, ValueError, TypeError):
            continue
        if len(items) >= limit:
            break
    return items

