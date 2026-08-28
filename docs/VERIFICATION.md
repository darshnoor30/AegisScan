# Verification record

**Release:** AegisScan 1.1.0  
**Verified:** 2026-08-28  
**Runtime:** Python 3.12.13

## Completed checks

| Check | Result |
| --- | --- |
| Ruff lint | Passed |
| mypy static type check | Passed; no issues in 15 source files |
| Automated tests | 46/46 passed |
| Branch-aware coverage | 80.76%; enforced floor 70% |
| Loopback ground-truth benchmark | Passed; 100% state and service identity within declared matrix |
| False-positive regressions | Passed; loopback context and confirmed-service override |
| Real local demo | Passed; temporary HTTP service observed and identified |
| Dashboard/API end-to-end test | Passed; submit, poll, persist, retrieve, render |
| Cross-site request rejection | Passed |
| JSON, CSV, HTML, and SARIF generation | Passed |
| Python source/test byte-compilation | Passed |
| JSON result schema syntax | Passed |
| Browser JavaScript syntax | Passed |
| Editable installation and console entry point | Passed |
| Python wheel build | Passed |

## Security-intelligence regressions

The v1.0 model could assign critical priority to a loopback-only service inferred solely from a
default port. It also had no formal rule stating that protocol evidence must override a conflicting
port hint. v1.1 adds regression tests for both:

- inferred MongoDB on `127.0.0.1:27017` is low priority, not critical;
- confirmed HTTP on port 27017 cannot generate a MongoDB finding;
- confirmed SSH on a non-standard port is identified with high confidence;
- public production context and asset criticality are reflected explicitly in risk factors.

## Commands

```bash
ruff check src tests
mypy src
pytest --cov=aegisscan --cov-report=term-missing
python -m compileall -q src tests
node --check src/aegisscan/static/app.js
python -m json.tool schemas/aegisscan-result.schema.json
aegisscan demo --output reports/demo
aegisscan benchmark --output reports/benchmark.json
python -m pip wheel . --no-deps --wheel-dir dist
```

Network-security behavior varies by operating system, route, firewall, and source location. Repeat
the benchmark, demo, and an approved private-scope assessment in the intended deployment environment.
The published 100% benchmark result is limited to its deterministic local matrix.
