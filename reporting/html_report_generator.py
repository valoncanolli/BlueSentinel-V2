"""
reporting/html_report_generator.py
Self-contained HTML report generator for BlueSentinel v2.0.
All CSS and JS inlined. No external dependencies required to view.
"""
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)
REPORTS_DIR = Path(__file__).parent.parent / "reports"


def _severity_color(severity: str) -> str:
    return {"Critical": "#ff3b5c", "High": "#ffb800", "Medium": "#00d4ff", "Low": "#00ff88"}.get(severity, "#c8d8e8")


def _score_color(score: int) -> str:
    if score >= 86: return "#ff3b5c"
    if score >= 61: return "#ffb800"
    if score >= 31: return "#00d4ff"
    return "#00ff88"


def _render_alert_row(alert: Dict[str, Any]) -> str:
    sev = alert.get("severity", "Low")
    color = _severity_color(sev)
    ai = alert.get("ai_analysis") or {}
    ai_summary = ai.get("summary", "N/A") if isinstance(ai, dict) else "N/A"
    return f"""
    <tr style="border-left: 3px solid {color}">
        <td><span style="color:{color};font-weight:bold">{sev}</span></td>
        <td>{alert.get('alert_type', 'Unknown')}</td>
        <td>{alert.get('message', '')[:150]}</td>
        <td>{alert.get('mitre_technique', '')}</td>
        <td>{alert.get('timestamp', '')[:19]}</td>
        <td style="color:#8899aa;font-size:0.85em">{ai_summary[:100]}</td>
    </tr>"""


def generate_html_report(result: Any) -> str:
    return generate_html_report_from_dict(
        result.to_dict() if hasattr(result, "to_dict") else result.__dict__
    )


def generate_html_report_from_dict(data: Dict[str, Any]) -> str:
    REPORTS_DIR.mkdir(exist_ok=True)
    hostname = data.get("hostname", socket.gethostname())
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"BlueSentinel_Report_{hostname}_{ts}.html"
    output_path = REPORTS_DIR / filename

    score = data.get("threat_score", 0)
    score_color = _score_color(score)
    alerts = data.get("alerts", [])
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    ai_summary = data.get("ai_summary", "AI summary not available.")
    ai_provider = data.get("ai_provider_used", "N/A")
    yara_matches = data.get("yara_matches", [])
    beaconing = data.get("beaconing_alerts", [])
    ioc_matches = data.get("ioc_matches", [])
    errors = data.get("errors", [])
    scan_id = data.get("scan_id", "N/A")
    started_at = data.get("started_at", "")[:19]
    duration = data.get("duration_seconds", 0)

    alert_rows = "".join(_render_alert_row(a) for a in sorted(
        alerts,
        key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.get("severity", "Low"), 4)
    )[:200])

    yara_rows = ""
    for m in yara_matches[:50]:
        yara_rows += f"""<tr>
            <td style="color:#ff3b5c">{m.get('rule_name','')}</td>
            <td>{m.get('file_path','')[:80]}</td>
            <td><span style="color:{_severity_color(m.get('severity','Medium'))}">{m.get('severity','')}</span></td>
            <td>{', '.join(m.get('rule_tags', []))}</td>
        </tr>"""

    beacon_rows = ""
    for b in beaconing[:20]:
        conf = b.get("confidence", 0)
        conf_color = "#ff3b5c" if conf > 80 else "#ffb800"
        beacon_rows += f"""<tr>
            <td style="color:{conf_color}">{b.get('dst_ip','')}:{b.get('dst_port','')}</td>
            <td>{b.get('connection_count','')}</td>
            <td>{b.get('mean_iat_seconds','')}</td>
            <td style="color:{conf_color}">{conf:.0f}%</td>
        </tr>"""

    error_section = ""
    if errors:
        error_items = "".join(f"<li style='color:#ffb800'>{e}</li>" for e in errors)
        error_section = f"<h2>Scan Errors</h2><ul>{error_items}</ul>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BlueSentinel v2.0 — Security Report — {hostname}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap');
  :root {{
    --bg: #0a0e1a;
    --panel: #0f1629;
    --border: #1e3a5f;
    --cyan: #00d4ff;
    --red: #ff3b5c;
    --amber: #ffb800;
    --green: #00ff88;
    --text: #c8d8e8;
    --muted: #667788;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; padding: 40px; max-width: 1400px; margin: 0 auto; }}
  h1 {{ font-family: 'JetBrains Mono', monospace; color: var(--cyan); font-size: 2rem; margin-bottom: 8px; }}
  h2 {{ color: var(--cyan); font-family: 'JetBrains Mono', monospace; font-size: 1.2rem; margin: 32px 0 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
  h3 {{ color: var(--text); margin: 16px 0 8px; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; }}
  .header-meta {{ text-align: right; color: var(--muted); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; line-height: 1.8; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 16px; margin-bottom: 32px; }}
  .kpi {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
  .kpi .value {{ font-family: 'JetBrains Mono', monospace; font-size: 2.5rem; font-weight: 700; }}
  .kpi .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .ai-summary {{ background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--cyan); border-radius: 8px; padding: 24px; margin: 16px 0 32px; line-height: 1.8; }}
  .ai-provider-badge {{ display: inline-block; background: #0d2040; border: 1px solid var(--cyan); color: var(--cyan); padding: 2px 10px; border-radius: 4px; font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 16px 0; }}
  th {{ background: #0d1b30; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; padding: 10px 12px; text-align: left; font-size: 0.75rem; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #0f1e33; font-family: 'JetBrains Mono', monospace; word-break: break-all; }}
  tr:hover td {{ background: #0d1b30; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin: 16px 0; }}
  .confidential {{ text-align: center; color: var(--red); font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; letter-spacing: 2px; border: 1px solid var(--red); padding: 8px; margin-bottom: 32px; }}
  .footer {{ margin-top: 64px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.75rem; text-align: center; font-family: 'JetBrains Mono', monospace; }}
  @media print {{ body {{ background: white; color: black; padding: 20px; }} .panel {{ border: 1px solid #ccc; }} }}
</style>
</head>
<body>
<div class="confidential">⚠ CONFIDENTIAL — SECURITY REPORT — AUTHORIZED PERSONNEL ONLY ⚠</div>
<div class="header">
  <div>
    <h1>🛡 BlueSentinel v2.0</h1>
    <p style="color:var(--muted);font-family:'JetBrains Mono',monospace">AI-Augmented Threat Detection Report</p>
  </div>
  <div class="header-meta">
    <div>Host: <span style="color:var(--cyan)">{hostname}</span></div>
    <div>Scan ID: {scan_id}</div>
    <div>Started: {started_at} UTC</div>
    <div>Duration: {duration:.1f}s</div>
    <div>AI Provider: <span style="color:var(--cyan)">{ai_provider.upper()}</span></div>
    <div>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
  </div>
</div>

<div class="kpi-grid">
  <div class="kpi"><div class="value" style="color:{score_color}">{score}</div><div class="label">Risk Score</div></div>
  <div class="kpi"><div class="value" style="color:#ff3b5c">{critical}</div><div class="label">Critical</div></div>
  <div class="kpi"><div class="value" style="color:#ffb800">{high}</div><div class="label">High</div></div>
  <div class="kpi"><div class="value">{len(alerts)}</div><div class="label">Total Alerts</div></div>
  <div class="kpi"><div class="value" style="color:#00d4ff">{len(yara_matches)}</div><div class="label">YARA Matches</div></div>
  <div class="kpi"><div class="value" style="color:#ff3b5c">{len(beaconing)}</div><div class="label">Beaconing</div></div>
</div>

<h2>Executive Summary</h2>
<div class="ai-summary">
  <div class="ai-provider-badge">AI: {ai_provider.upper()}</div>
  <p style="line-height:1.8">{ai_summary.replace(chr(10), '<br>')}</p>
</div>

<h2>Security Alerts ({len(alerts)} total)</h2>
<div class="panel">
<table>
  <thead><tr><th>Severity</th><th>Type</th><th>Message</th><th>MITRE</th><th>Timestamp</th><th>AI Summary</th></tr></thead>
  <tbody>{alert_rows}</tbody>
</table>
</div>

<h2>YARA Scan Results ({len(yara_matches)} matches)</h2>
<div class="panel">
{"<p style='color:var(--muted)'>No YARA matches detected.</p>" if not yara_rows else f"""
<table>
  <thead><tr><th>Rule</th><th>File Path</th><th>Severity</th><th>Tags</th></tr></thead>
  <tbody>{yara_rows}</tbody>
</table>"""}
</div>

<h2>Network Beaconing Analysis ({len(beaconing)} flows)</h2>
<div class="panel">
{"<p style='color:var(--green)'>No beaconing detected.</p>" if not beacon_rows else f"""
<table>
  <thead><tr><th>Destination</th><th>Connections</th><th>Avg Interval (s)</th><th>Confidence</th></tr></thead>
  <tbody>{beacon_rows}</tbody>
</table>"""}
</div>

<h2>IOC Matches ({len(ioc_matches)})</h2>
<div class="panel">
{"<p style='color:var(--green)'>No IOC matches found.</p>" if not ioc_matches else "<ul>" + "".join(f"<li style='font-family:JetBrains Mono,monospace;padding:4px 0'>{m.get('indicator','')} — {m.get('category','')} ({m.get('source','')})</li>" for m in ioc_matches[:50]) + "</ul>"}
</div>

{error_section}

<div class="footer">
  <p>BlueSentinel v2.0 — Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
  <p>Author: Valon Canolli | MIT License | FOR AUTHORIZED USE ONLY</p>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report generated: {output_path}")
    return str(output_path)
