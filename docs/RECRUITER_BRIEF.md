# Recruiter and interview brief

## One-line pitch

**AegisScan is a safe asynchronous exposure-intelligence platform that separates port hints from
verified protocol evidence, applies transparent scan context, and produces remediation and CI-ready
reports.**

## Résumé bullets

Use these after running the demo and benchmark and understanding the implementation:

- Engineered **AegisScan**, a Python attack-surface platform with bounded asynchronous TCP workers,
  hostname/CIDR expansion, IPv4/IPv6, and non-standard-port HTTP/HTTPS/SSH identification.
- Designed a deterministic Contextual Exposure Model that separates port hints from confirmed
  identity and explains how network scope, evidence confidence, environment, and asset criticality
  produce each effective severity.
- Built a responsive analyst dashboard, CLI, versioned JSON schema, JSON/CSV/HTML/SARIF reporting,
  baseline drift detection, atomic history, authorization controls, and hardened non-root container.
- Established a 46-test quality gate with 81% branch-aware coverage, Ruff, mypy, Python 3.11/3.12 CI,
  CodeQL, Dependabot, and a reproducible loopback ground-truth benchmark.

The 100% benchmark figures apply only to its declared two-service/one-closed-port loopback matrix.
Never present them as general production accuracy, and never invent users, scan volume, or speed.

## LinkedIn project description

> Built AegisScan to explore how defensive tools turn network reachability into defensible action.
> The platform performs authorized, bounded TCP discovery and collects conservative HTTP, TLS,
> certificate, Redis, and server-banner evidence. It separates low-confidence port hints from
> protocol-confirmed identity, then adjusts base exposure rules using loopback/private/public scope,
> environment, and asset criticality. A shared engine powers the local dashboard and CLI, with
> JSON/CSV/SARIF/HTML reports and baseline drift detection. I validated the release with 46 automated
> tests, 81% coverage, static typing, CI, CodeQL, a threat model, and a documented local benchmark.
> The central decision: an open port is evidence—not automatic proof of a service or vulnerability.

## 90-second demo

1. **Problem (10 sec):** “A port number is only a hint. Teams need verified evidence and context.”
2. **Safety (10 sec):** Show authorization, public-target denial, origin checks, and resource caps.
3. **Regression (15 sec):** Explain why loopback port 27017 is no longer automatically critical.
4. **Real scan (20 sec):** Run `aegisscan demo`; show identity method, confidence, and scope.
5. **Measurement (15 sec):** Run `aegisscan benchmark`; state its exact ground-truth limitations.
6. **Operations (20 sec):** Show risk factors, HTML/SARIF, CI checks, and baseline drift.

## Strong interview answers

### Why not call every open port a vulnerability?

Reachability is an observation. Even service identity requires evidence beyond a default port.
Vulnerability further depends on version, configuration, controls, and context. AegisScan stores
these layers separately and recommends deeper validation instead of inventing a CVE claim.

### Why does confirmed evidence override the port?

Any process can bind to any port. If port 27017 returns syntactically valid HTTP, calling it MongoDB
is a demonstrable false positive. The port remains in `port_hint`, but protocol evidence becomes
the selected identity.

### Why not add machine learning?

The current questions—did TCP connect and did a protocol signature match—are deterministic.
An unrelated intrusion dataset would not match the scanner's features or objective. ML would be
appropriate only for a separately defined anomaly problem with task-matched historical telemetry,
labelled ground truth, and independent evaluation.

### How does contextual priority work?

Each service has a documented base rule. Scope, confidence, environment, and criticality then apply
ordered severity shifts. The result preserves the base severity, effective severity, every factor,
and score deduction, so an analyst can audit or reject the summary.

### Why TCP connect instead of SYN scanning?

TCP connect is portable, requires no raw sockets or elevated privilege, and matches the safe
operational goal. The tradeoff is visible connections and less packet-level state detail than a SYN
scanner. That boundary is intentional and documented.

### How is concurrency bounded?

A fixed worker pool consumes a queue sized to twice the worker count. Backpressure prevents the
producer from materializing the entire target×port Cartesian product. The dashboard also caps active
jobs at two and retained in-memory jobs at 100.

### What would an enterprise version add?

Signed scan policies, authenticated multi-user access, distributed workers, asset-owner metadata,
approved windows, inventory connectors, tracing/metrics, signed results, and governed rule packs.
Each new active probe would receive its own threat-model and benchmark case.

### Where can results mislead?

Reachability changes with scanner location and firewall policy; timeouts are ambiguous; banners can
be hidden or deceptive; analyst-supplied context can be wrong; and the posture index is not CVSS,
compliance, or exploit probability. The evidence and risk factors remain the source of truth.

## Suggested repository topics

`cybersecurity` · `network-security` · `port-scanner` · `attack-surface-management` ·
`python` · `asyncio` · `soc` · `security-automation` · `sarif` · `devsecops`
