from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from aegisscan import __version__
from aegisscan.benchmark import run_benchmark
from aegisscan.demo import run_demo
from aegisscan.diff import compare_scans
from aegisscan.intelligence import VALID_CRITICALITIES, VALID_ENVIRONMENTS
from aegisscan.ports import PRESETS, parse_ports
from aegisscan.reports import write_report_bundle
from aegisscan.scanner import ScanConfig, scan
from aegisscan.storage import save_scan
from aegisscan.web import serve


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisscan",
        description="Authorized attack-surface discovery and port intelligence.",
    )
    parser.add_argument("--version", action="version", version=f"AegisScan {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run an authorized TCP connect scan")
    scan_parser.add_argument("-t", "--target", action="append", required=True, help="IP, hostname, CIDR; repeatable")
    scan_parser.add_argument(
        "-p", "--ports", default="default", help=f"Ports/ranges or preset: {', '.join(PRESETS)}"
    )
    scan_parser.add_argument("--timeout", type=float, default=0.8, help="Per-connection timeout in seconds")
    scan_parser.add_argument("--concurrency", type=int, default=200, help="Concurrent connections (1-500)")
    scan_parser.add_argument("--delay-ms", type=int, default=0, help="Worker delay after each probe")
    scan_parser.add_argument("--no-fingerprint", action="store_true", help="Disable service identification")
    scan_parser.add_argument(
        "--environment",
        choices=sorted(VALID_ENVIRONMENTS),
        default="unknown",
        help="Deployment context used by the explainable risk model",
    )
    scan_parser.add_argument(
        "--asset-criticality",
        choices=sorted(VALID_CRITICALITIES),
        default="standard",
        help="Business criticality used by the explainable risk model",
    )
    scan_parser.add_argument(
        "--i-own-or-have-permission",
        dest="authorized",
        action="store_true",
        help="Required authorization acknowledgement",
    )
    scan_parser.add_argument(
        "--allow-public",
        action="store_true",
        help="Explicitly permit globally routable targets (written authorization required)",
    )
    scan_parser.add_argument("-o", "--output", default="reports/aegisscan", help="Report path without extension")

    serve_parser = subparsers.add_parser("serve", help="Start the local web dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: loopback only)")
    serve_parser.add_argument("--port", type=int, default=8765, help="Dashboard port")

    diff_parser = subparsers.add_parser("diff", help="Compare two JSON scan results for exposure drift")
    diff_parser.add_argument("--baseline", required=True, type=Path)
    diff_parser.add_argument("--current", required=True, type=Path)
    diff_parser.add_argument("-o", "--output", type=Path)

    demo_parser = subparsers.add_parser("demo", help="Run a verified scan against a temporary local service")
    demo_parser.add_argument("-o", "--output", default="reports/demo", help="Report path without extension")

    benchmark_parser = subparsers.add_parser(
        "benchmark", help="Measure scanner behavior against deterministic loopback ground truth"
    )
    benchmark_parser.add_argument(
        "-o", "--output", default="reports/benchmark.json", help="Benchmark JSON destination"
    )
    return parser


def _progress(event: dict[str, Any]) -> None:
    if event.get("stage") in {"scanning", "complete"}:
        message = (
            f"\r[{event.get('stage', 'scanning'):9}] {event.get('percent', 0):6.1f}%  "
            f"{event.get('completed', 0)}/{event.get('total', 0)} probes  "
            f"open: {event.get('open', 0)}"
        )
        print(message, end="\n" if event.get("stage") == "complete" else "", flush=True)


def _scan_command(args: argparse.Namespace) -> int:
    config = ScanConfig(
        targets=args.target,
        ports=parse_ports(args.ports),
        timeout=args.timeout,
        concurrency=args.concurrency,
        delay_ms=args.delay_ms,
        authorized=args.authorized,
        allow_public=args.allow_public,
        fingerprint=not args.no_fingerprint,
        environment=args.environment,
        asset_criticality=args.asset_criticality,
    )
    result = asyncio.run(scan(config, progress=_progress))
    document = result.to_dict()
    save_scan(document)
    paths = write_report_bundle(document, args.output)
    print(
        f"Contextual posture {document['summary']['security_score']}/100 "
        f"(grade {document['summary']['grade']}); "
        f"{document['summary']['open_ports']} open service(s), {document['summary']['findings']} finding(s)."
    )
    print("Reports:")
    for kind, path in paths.items():
        print(f"  {kind.upper():5} {path.resolve()}")
    return 0


def _diff_command(args: argparse.Namespace) -> int:
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    current = json.loads(args.current.read_text(encoding="utf-8"))
    comparison = compare_scans(baseline, current)
    rendered = json.dumps(comparison, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Drift report: {args.output.resolve()}")
    else:
        print(rendered, end="")
    return 2 if comparison["summary"]["new"] or comparison["summary"]["changed"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        if args.command == "scan":
            return _scan_command(args)
        if args.command == "serve":
            if not 1 <= args.port <= 65_535:
                raise ValueError("Port must be between 1 and 65535")
            serve(args.host, args.port)
            return 0
        if args.command == "diff":
            return _diff_command(args)
        if args.command == "demo":
            document, paths = run_demo(args.output)
            print(
                f"Verified local demo complete: {document['summary']['open_ports']} open service; "
                f"score {document['summary']['security_score']}/100."
            )
            for kind, path in paths.items():
                print(f"  {kind.upper():5} {path.resolve()}")
            return 0
        if args.command == "benchmark":
            document = run_benchmark(args.output)
            metrics = document["metrics"]
            print(
                f"Benchmark {document['status']}: TCP state accuracy "
                f"{metrics['tcp_state_accuracy']:.0%}; service identification accuracy "
                f"{metrics['service_identification_accuracy']:.0%}."
            )
            print(f"  JSON  {Path(args.output).resolve()}")
            return 0 if document["status"] == "passed" else 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0
