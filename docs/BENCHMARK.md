# Deterministic benchmark

## Purpose

`aegisscan benchmark` makes the scanner's core behavior measurable without downloading a dataset
or scanning an external host. It creates temporary services on `127.0.0.1`, records ground truth,
runs the production scan engine, writes JSON, and closes every service.

## Ground-truth matrix

| Endpoint | Port selection | Expected state | Expected identity |
| --- | --- | --- | --- |
| Minimal HTTP server | OS-assigned non-standard port | Open | HTTP, high confidence |
| SSH banner server | OS-assigned non-standard port | Open | SSH, high confidence |
| Unused loopback port | OS-assigned then released | Closed | No service observation |

Success requires both state checks and both identity checks to pass. The JSON result includes the
ephemeral ports, observed identities, scan duration, false-service-claim count, and metrics.

## Verified v1.1 result

The 2026-08-28 release run reported:

- TCP-state accuracy: 1.000;
- service-identification accuracy: 1.000;
- false service claims: 0;
- status: passed.

The command is executed in CI on Python 3.11 and 3.12 so regressions fail the build.

## Honest limitations

This benchmark is deliberately small and deterministic. It proves that the shipped engine can
identify the generated HTTP and SSH services on non-standard ports and distinguish a closed port in
the test environment. It does **not** estimate:

- accuracy across all protocols, operating systems, firewalls, or the public Internet;
- vulnerability-detection performance;
- false-negative rate for hidden or deceptive services;
- performance at enterprise scale.

Adding a service to the benchmark requires a safe local implementation, explicit expected evidence,
and a regression test. Production claims require a separate, representative evaluation design.
