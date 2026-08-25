# Security policy

## Responsible use

AegisScan is designed only for systems you own or have explicit permission to test. It uses
ordinary TCP connections; it does not implement stealth, evasion, exploitation, credential
attacks, or persistence. Public-IP scanning is blocked by default in the web application and
requires an explicit CLI switch plus an authorization acknowledgement.

An open port is an **exposure signal**, not proof of a vulnerability. Findings are intentionally
worded to avoid unsupported vulnerability claims.

## Reporting a vulnerability

Do not open a public issue for a suspected security vulnerability. Email the maintainer with:

- affected version and component;
- reproducible steps using a harmless local target;
- impact and suggested mitigation, if known.

Please allow a reasonable remediation window before public disclosure.

## Built-in safety controls

- maximum 256 expanded targets and 2,048 ports per scan;
- explicit authorization acknowledgement;
- public-target opt-in and server-side policy gate;
- bounded concurrency and configurable timeouts;
- loopback-only dashboard binding by default;
- no raw sockets or elevated privileges;
- HTML escaping and strict API input validation;
- non-root, capability-free container.

