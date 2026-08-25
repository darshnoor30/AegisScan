# Recruiter and interview brief

## One-line pitch

**AegisScan is a safe, asynchronous network exposure platform that converts authorized TCP discovery
into explainable risk, remediation, drift detection, and CI-ready reports.**

## Résumé bullets

Use these after you have run the demo and can explain the implementation:

- Engineered **AegisScan**, a zero-dependency Python attack-surface platform using bounded asynchronous
  TCP workers, hostname/CIDR expansion, safe HTTP/TLS fingerprinting, and IPv4/IPv6 support.
- Designed an explainable exposure model that separates observed evidence from security conclusions
  and emits prioritized remediation through JSON, CSV, standalone HTML, and SARIF reports.
- Implemented authorization/public-scope controls, resource caps, atomic scan history, baseline drift
  detection, a responsive analyst dashboard, automated tests, CI, and a hardened non-root container.

Do not invent scan-volume, speed, user, or detection-accuracy numbers. Add a measured number only after
you run a documented benchmark in your own environment.

## LinkedIn project description

> Built AegisScan to explore how real security tooling moves from raw network data to defensible action.
> The platform performs authorized, bounded TCP discovery; collects safe HTTP, TLS, certificate, and
> banner evidence; then creates explainable exposure findings with impact and remediation. A shared
> engine powers both a local analyst dashboard and CLI, with JSON/CSV/SARIF/HTML outputs and baseline
> drift detection. I also added tests, CI, threat modeling, scope controls, and a non-root container.
> The key design principle: an open port is evidence of exposure—not automatic proof of vulnerability.

## 90-second demo

1. **Problem (10 sec):** “Port lists are noisy. Owners need evidence, priority, and a concrete action.”
2. **Safety (10 sec):** Show the authorization checkbox and explain public-target denial by default.
3. **Real scan (20 sec):** Run `aegisscan demo`; explain that it starts and scans an actual local service.
4. **Dashboard (20 sec):** Show progress, service evidence, exposure score, and remediation.
5. **Engineering (20 sec):** Open the architecture diagram and bounded queue implementation.
6. **Operations (10 sec):** Show HTML + SARIF output and `aegisscan diff` for configuration drift.

## Strong interview answers

### Why not call every open port a vulnerability?

Reachability is an observation. Vulnerability depends on version, configuration, controls, and context.
AegisScan keeps observation and interpretation separate, states confidence, and recommends validation.
That reduces false claims while still prioritizing risky exposure.

### Why TCP connect instead of SYN scanning?

TCP connect works without raw sockets or elevated privileges, is portable, and matches the project's
safe operational goal. The tradeoff is that connections are more visible and state classification is
less granular than a packet-level scanner—acceptable and explicitly documented here.

### How did you prevent concurrency from exhausting memory?

The engine uses a bounded async queue and a fixed worker pool. The producer cannot enqueue the entire
target×port space at once because backpressure stops it at twice the worker count.

### What would you add in an enterprise version?

Signed scan policies, authenticated multi-user access, distributed workers, asset ownership tags,
approved scan windows, authenticated inventory connectors, metrics/tracing, rule packs, and result
signing. I would preserve evidence/finding separation and introduce each probe through threat modeling.

### Where can results be misleading?

Firewall behavior varies by source location; a timeout can indicate filtering, packet loss, or service
delay; banners can be hidden or deceptive; and a successful TCP connection does not prove exploitability.
The report states these limitations and encourages asset-owner validation.

## Suggested repository topics

`cybersecurity` · `network-security` · `port-scanner` · `attack-surface-management` · `python` ·
`asyncio` · `soc` · `security-automation` · `sarif` · `devsecops`

