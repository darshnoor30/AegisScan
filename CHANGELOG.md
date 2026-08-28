# Changelog

## 1.1.0 — 2026-08-28

- replaced fixed port-only severity with Contextual Exposure Model v2;
- separated port hints from protocol-confirmed service identity and exposed evidence confidence;
- added loopback, link-local, private, public, and special-purpose scope semantics;
- added environment and asset-criticality context to CLI, API, dashboard, reports, and schema;
- added non-standard HTTP/HTTPS/SSH identification plus conservative banner and Redis probes;
- added TLS protocol, certificate SAN/lifecycle, and HTTPS header evidence;
- added deterministic loopback benchmark with explicit ground truth and limitations;
- expanded to 46 tests with 81% branch-aware coverage, Ruff, mypy, CodeQL, and Dependabot;
- added cross-site request rejection, active-job caps, and additional response security headers;
- updated dashboard, CSV, SARIF, HTML report, architecture, risk model, and recruiter brief.

## 1.0.0 — 2026-08-23

- asynchronous TCP connect scanner with bounded concurrency;
- CIDR, hostname, IPv4, and IPv6 target support;
- HTTP, TLS, and safe banner fingerprinting;
- explainable exposure score and prioritized remediation findings;
- baseline drift comparison and CI-friendly SARIF output;
- zero-dependency CLI and local web dashboard;
- JSON, CSV, SARIF, and standalone HTML reports;
- authorization and public-target safety controls;
- tests, CI pipeline, hardened container, threat model, and recruiter brief.
