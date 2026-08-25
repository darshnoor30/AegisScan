# Verification record

**Release:** AegisScan 1.0.0  
**Verified:** 2026-08-24  
**Runtime:** Python 3.12

## Completed checks

| Check | Result |
| --- | --- |
| Python source and test byte-compilation | Passed |
| Unit and loopback integration tests | 19/19 passed |
| Real local demo scan | Passed; one temporary HTTP service observed |
| JSON, CSV, HTML, and SARIF generation | Passed |
| Dashboard HTML/CSS/JS and health endpoint | Passed |
| Dashboard scan submission and polling | Passed |
| Persisted report retrieval by stable scan ID | Passed |
| Dashboard/report security headers | Passed |
| Missing-authorization rejection | Passed with expected exit code 2 |
| JSON result schema syntax | Passed |
| Browser JavaScript syntax (`node --check`) | Passed |
| Editable installation and console entry point | Passed |
| Python wheel build | Passed (`aegisscan-1.0.0-py3-none-any.whl`) |

## Defect found and corrected during verification

The initial test run found that TLS certificate-expiry analysis only executed on ports that also had
a predefined exposure rule. This could omit a certificate lifecycle finding on standard HTTPS port
443. The analysis flow was corrected so TLS lifecycle evidence is evaluated independently of the
port-exposure rule, and the regression test now passes.

## Commands

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m compileall -q src tests
node --check src/aegisscan/static/app.js
python -m json.tool schemas/aegisscan-result.schema.json
aegisscan demo --output /tmp/aegisscan-final-demo
python -m pip wheel . --no-deps --no-build-isolation
```

Network-security behavior can vary by operating system, route, firewall, and source location. Repeat
the loopback demo and an approved private-scope assessment in the intended deployment environment.

