from __future__ import annotations

import csv
import html
import json
from io import StringIO
from pathlib import Path
from typing import Any


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def _badge(severity: str) -> str:
    return f'<span class="badge {_escape(severity)}">{_escape(severity)}</span>'


def render_html_report(document: dict[str, Any]) -> str:
    summary = document.get("summary", {})
    observations = document.get("observations", [])
    findings = document.get("findings", [])
    score = int(summary.get("security_score", 0))
    grade = summary.get("grade", "—")
    score_color = "#53e0a1" if score >= 80 else "#ffcc66" if score >= 60 else "#ff6680"

    observation_rows = "".join(
        f"""
        <tr>
          <td><span class="mono">{_escape(item.get('address'))}</span></td>
          <td><span class="port">{_escape(item.get('port'))}/tcp</span></td>
          <td>{_escape(item.get('fingerprint', {}).get('service', 'unknown'))}</td>
          <td>{_escape(item.get('fingerprint', {}).get('product'))}</td>
          <td>{_escape(item.get('latency_ms'))} ms</td>
        </tr>"""
        for item in observations
    ) or '<tr><td colspan="5" class="empty">No open TCP ports were observed.</td></tr>'

    finding_cards = "".join(
        f"""
        <article class="finding { _escape(item.get('severity')) }">
          <div class="finding-head">
            <div>{_badge(str(item.get('severity', 'informational')))}
              <span class="finding-id">{_escape(item.get('finding_id'))}</span></div>
            <span class="mono">{_escape(item.get('address'))}:{_escape(item.get('port'))}</span>
          </div>
          <h3>{_escape(item.get('title'))}</h3>
          <dl>
            <dt>Evidence</dt><dd>{_escape(item.get('evidence'))}</dd>
            <dt>Why it matters</dt><dd>{_escape(item.get('impact'))}</dd>
            <dt>Recommended action</dt><dd>{_escape(item.get('recommendation'))}</dd>
          </dl>
        </article>"""
        for item in findings
    ) or '<div class="empty panel">No prioritized exposure findings were generated.</div>'

    counts = summary.get("severity_counts", {})
    target_scope = ", ".join(str(value) for value in document.get("config", {}).get("targets", []))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>AegisScan Security Assessment</title>
  <style>
    :root {{ --ink:#e9f0ff; --muted:#8e9ab5; --panel:#11182a; --line:#25314c;
      --blue:#6aa6ff; --violet:#987cff; --critical:#ff4d6d; --high:#ff8a5b;
      --medium:#ffcc66; --low:#5ed6c8; --informational:#7da6d8; }}
    * {{ box-sizing:border-box }}
    body {{ margin:0; background:#080c16; color:var(--ink); font:15px/1.6 Inter,Segoe UI,sans-serif }}
    .shell {{ max-width:1120px; margin:auto; padding:48px 24px 80px }}
    .eyebrow {{ color:var(--blue); text-transform:uppercase; letter-spacing:.16em; font-weight:800; font-size:12px }}
    h1 {{ font-size:46px; line-height:1.05; margin:10px 0 12px; letter-spacing:-.04em }}
    h2 {{ margin:44px 0 16px; font-size:24px }} h3 {{ margin:15px 0 12px }}
    .lede,.muted {{ color:var(--muted) }} .lede {{ max-width:740px; font-size:17px }}
    .hero {{ border:1px solid var(--line); border-radius:24px; padding:34px; background:
      radial-gradient(circle at 85% 10%,rgba(106,166,255,.18),transparent 30%),var(--panel) }}
    .score-row {{ display:flex; gap:28px; align-items:center; margin-top:30px; flex-wrap:wrap }}
    .score {{ width:136px; height:136px; border-radius:50%; display:grid; place-items:center;
      border:10px solid {score_color}; box-shadow:0 0 45px color-mix(in srgb,{score_color} 25%,transparent) }}
    .score strong {{ font-size:41px; display:block; line-height:1 }} .score span {{ color:var(--muted) }}
    .metrics {{ display:grid; grid-template-columns:repeat(4,minmax(120px,1fr)); gap:12px; flex:1 }}
    .metric,.panel {{ background:#0d1424; border:1px solid var(--line); border-radius:16px; padding:17px }}
    .metric strong {{ display:block; font-size:25px }} .metric span {{ color:var(--muted); font-size:12px }}
    .scope {{ margin-top:22px; padding-top:18px; border-top:1px solid var(--line) }}
    .mono,.port,.finding-id {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace }}
    .port {{ color:#a9caff }} .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:16px }}
    table {{ width:100%; border-collapse:collapse; background:var(--panel) }}
    th,td {{ text-align:left; padding:13px 15px; border-bottom:1px solid var(--line) }}
    th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em }}
    tr:last-child td {{ border-bottom:0 }}
    .finding {{ border:1px solid var(--line); border-left:4px solid var(--informational);
      background:var(--panel); border-radius:14px; padding:20px; margin:12px 0 }}
    .finding.critical {{ border-left-color:var(--critical) }} .finding.high {{ border-left-color:var(--high) }}
    .finding.medium {{ border-left-color:var(--medium) }} .finding.low {{ border-left-color:var(--low) }}
    .finding-head {{ display:flex; justify-content:space-between; gap:20px; color:var(--muted) }}
    .badge {{ display:inline-block; border-radius:99px; padding:3px 9px; text-transform:uppercase;
      font-size:10px; letter-spacing:.08em; font-weight:800; background:#26304a }}
    .badge.critical {{ background:#4d1421;color:#ff8fa5 }} .badge.high {{ background:#4a251b;color:#ffad8d }}
    .badge.medium {{ background:#493b19;color:#ffe096 }} .badge.low {{ background:#123f3b;color:#8aeadd }}
    .finding-id {{ font-size:12px; margin-left:8px }} dl {{ display:grid;grid-template-columns:150px 1fr;gap:8px 18px }}
    dt {{ color:var(--muted); font-size:12px; font-weight:700 }} dd {{ margin:0 }}
    .method {{ display:grid;grid-template-columns:1fr 1fr;gap:16px }}
    .empty {{ color:var(--muted); text-align:center; padding:28px }} footer {{ margin-top:50px;color:var(--muted) }}
    @media(max-width:760px) {{ h1{{font-size:34px}} .metrics{{grid-template-columns:1fr 1fr}}
      dl{{grid-template-columns:1fr}} .method{{grid-template-columns:1fr}} .finding-head{{display:block}} }}
    @media print {{ body{{background:#fff;color:#111}} .hero,.metric,.panel,.finding,table{{background:#fff}}
      :root{{--ink:#111;--muted:#555;--panel:#fff;--line:#ddd}} .shell{{padding:15px}} }}
  </style>
</head>
<body><main class="shell">
  <section class="hero">
    <div class="eyebrow">AegisScan • Authorized Security Assessment</div>
    <h1>Attack-surface intelligence,<br>backed by evidence.</h1>
    <p class="lede">TCP reachability, safe service identification, explainable exposure prioritization,
      and actionable remediation. An open port is reported as exposure—not automatically as a vulnerability.</p>
    <div class="score-row">
      <div class="score"><div><strong>{score}</strong><span>Grade { _escape(grade) }</span></div></div>
      <div class="metrics">
        <div class="metric"><strong>{_escape(summary.get('targets', 0))}</strong><span>RESOLVED ASSETS</span></div>
        <div class="metric"><strong>{_escape(summary.get('probes_total', 0))}</strong><span>TCP PROBES</span></div>
        <div class="metric"><strong>{_escape(summary.get('open_ports', 0))}</strong><span>OPEN SERVICES</span></div>
        <div class="metric"><strong>{_escape(summary.get('findings', 0))}</strong><span>PRIORITY FINDINGS</span></div>
      </div>
    </div>
    <div class="scope"><span class="muted">Scope</span> <span class="mono">{_escape(target_scope)}</span><br>
      <span class="muted">Scan ID</span> <span class="mono">{_escape(document.get('scan_id'))}</span> ·
      <span class="muted">Completed</span> {_escape(document.get('finished_at'))} ·
      <span class="muted">Duration</span> {_escape(document.get('duration_ms'))} ms</div>
  </section>

  <h2>Risk overview</h2>
  <div class="metrics">
    <div class="metric"><strong>{_escape(counts.get('critical', 0))}</strong><span>CRITICAL</span></div>
    <div class="metric"><strong>{_escape(counts.get('high', 0))}</strong><span>HIGH</span></div>
    <div class="metric"><strong>{_escape(counts.get('medium', 0))}</strong><span>MEDIUM</span></div>
    <div class="metric"><strong>{_escape(counts.get('low', 0))}</strong><span>LOW</span></div>
  </div>

  <h2>Prioritized findings</h2>{finding_cards}
  <h2>Observed services</h2>
  <div class="table-wrap"><table><thead><tr><th>Address</th><th>Endpoint</th><th>Service</th>
    <th>Product evidence</th><th>Latency</th></tr></thead><tbody>{observation_rows}</tbody></table></div>

  <h2>Method and limitations</h2>
  <div class="method">
    <div class="panel"><strong>What AegisScan did</strong><p class="muted">Established standard TCP
      connections with bounded concurrency, then applied minimal protocol-aware HTTP, TLS, or server-banner
      identification to open endpoints.</p></div>
    <div class="panel"><strong>How to interpret this report</strong><p class="muted">Reachability can change with
      source location and firewall policy. Validate priority findings with asset owners. This report does not
      exploit services, authenticate, or prove a CVE.</p></div>
  </div>
  <footer>Generated by AegisScan { _escape(document.get('engine_version')) } · Use only on authorized systems.</footer>
</main></body></html>"""


def render_csv(document: dict[str, Any]) -> str:
    output = StringIO()
    fields = ["target", "address", "port", "protocol", "state", "latency_ms", "service", "product", "banner"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for item in document.get("observations", []):
        fingerprint = item.get("fingerprint", {})
        writer.writerow(
            {
                "target": item.get("target"),
                "address": item.get("address"),
                "port": item.get("port"),
                "protocol": item.get("protocol"),
                "state": item.get("state"),
                "latency_ms": item.get("latency_ms"),
                "service": fingerprint.get("service"),
                "product": fingerprint.get("product"),
                "banner": fingerprint.get("banner"),
            }
        )
    return output.getvalue()


def render_sarif(document: dict[str, Any]) -> str:
    findings = document.get("findings", [])
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = f"AEGIS-{finding.get('category', 'exposure').upper()}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.get("title"),
                "shortDescription": {"text": finding.get("title")},
                "help": {"text": finding.get("recommendation")},
                "properties": {"security-severity": finding.get("severity")},
            },
        )
        severity = finding.get("severity")
        level = "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note"
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.get("evidence")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"tcp://{finding.get('address')}:{finding.get('port')}"
                            }
                        }
                    }
                ],
                "properties": {
                    "finding_id": finding.get("finding_id"),
                    "severity": severity,
                    "recommendation": finding.get("recommendation"),
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisScan",
                        "version": document.get("engine_version"),
                        "informationUri": "https://github.com/darshnoor30/AegisScan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def write_report_bundle(document: dict[str, Any], output: str | Path) -> dict[str, Path]:
    base = Path(output)
    if base.suffix:
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": base.with_suffix(".json"),
        "csv": base.with_suffix(".csv"),
        "html": base.with_suffix(".html"),
        "sarif": base.with_suffix(".sarif.json"),
    }
    paths["json"].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    paths["csv"].write_text(render_csv(document), encoding="utf-8", newline="")
    paths["html"].write_text(render_html_report(document), encoding="utf-8")
    paths["sarif"].write_text(render_sarif(document), encoding="utf-8")
    return paths

