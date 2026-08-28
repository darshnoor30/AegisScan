# Contextual Exposure Model v2

## Objective

The model prioritizes observed network exposure without pretending to calculate exploitability.
It is deterministic and auditable: the canonical result includes the base rule, effective severity,
network scope, evidence confidence, every adjustment, and the exact score deduction.

## Decision sequence

1. Retain a successful TCP connection as an observation.
2. Record the common-port identity as a low-confidence `port_hint`.
3. Replace the hint only when protocol evidence confirms another identity.
4. Select a service exposure rule from the resulting identity.
5. Apply context adjustments in this order: scope, confidence, environment, criticality.
6. Preserve both base and effective severity in the finding.

Confirmed protocol evidence wins over a port hint. For example, a valid HTTP response on port 27017
is classified as HTTP and cannot generate a MongoDB exposure finding.

## Adjustments

| Factor | Adjustment |
| --- | ---: |
| Public address | +1 severity |
| Private or special-purpose address | 0 |
| Link-local address | −1 severity |
| Loopback address | −2 severity |
| Low-confidence, port-inferred identity | −1 severity |
| Medium/high evidence confidence | 0 |
| Production environment | +1 severity |
| Staging/unknown environment | 0 |
| Development environment | −1 severity |
| High or critical asset criticality | +1 severity |
| Standard asset criticality | 0 |
| Low asset criticality | −1 severity |

Severity is clamped between informational and critical. Certificate lifecycle findings do not use
the network-scope adjustment because expiry is primarily an operational-control issue.

## Posture index

The posture index begins at 100 and subtracts the effective finding weights:

| Effective severity | Deduction |
| --- | ---: |
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 3 |
| Informational | 0 |

Total deduction is capped at 100. Letter grades are presentation bands: A ≥ 90, B ≥ 80, C ≥ 70,
D ≥ 60, and F < 60.

## Worked regression example

A loopback connection on port 27017 with no MongoDB protocol confirmation begins with a critical
MongoDB rule. Loopback reduces it two levels and low confidence reduces it one more level:

`critical → high → medium → low`

The effective finding is low, deducting 3 points rather than producing the former critical finding
and misleading F-grade posture.

## Limitations

- Scope describes the target address reached from this scanner, not every interface on the host.
- Private reachability can still be serious in a flat or compromised network.
- A banner may be hidden or intentionally deceptive; confidence reflects evidence type, not certainty.
- Environment and criticality are analyst-supplied context and should be reviewed with asset owners.
- The posture index is not compliance status, exploit probability, business risk in currency, or CVSS.

The evidence and per-finding risk factors remain authoritative when the summary score is unsuitable
for a particular governance process.
