# Contributing

Thank you for improving AegisScan. Keep contributions defensive, explainable, and safe.

1. Create a focused branch and issue.
2. Add or update tests before changing behavior.
3. Run `make verify` before opening a pull request.
4. Include a short threat-model note for changes that expand target scope or probing behavior.
5. Never add exploitation, stealth, credential attacks, or authorization bypasses.

Commit messages should use an imperative summary such as `Add TLS expiry finding`.

Any new service-identity probe must preserve port hints separately, define bounded request/read
behavior, add safe loopback tests, and document its evidence confidence and failure modes.
