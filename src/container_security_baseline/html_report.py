"""Standalone HTML report writer (no CDN)."""

from __future__ import annotations

import html
from pathlib import Path

from container_security_baseline.models import Report
from container_security_baseline.redaction import ensure_no_secret_leak


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_html_report(report: Report) -> str:
    findings_rows = []
    for f in report.findings:
        if f.status.value == "Pass":
            continue
        findings_rows.append(
            "<tr>"
            f"<td>{_e(f.rule_id)}</td>"
            f"<td>{_e(f.severity.value)}</td>"
            f"<td>{_e(f.status.value)}</td>"
            f"<td>{_e(f.service or f.stage or '-')}</td>"
            f"<td>{_e(f.summary)}</td>"
            f"<td>{_e(f.file)}</td>"
            f"<td>{_e(f.evidence_redacted)}</td>"
            f"<td>{_e(f.remediation)}</td>"
            "</tr>"
        )

    sev_cards = (
        "".join(
            f"<div class='card sev-{_e(k.lower())}'><div class='num'>{_e(v)}</div>"
            f"<div class='lbl'>{_e(k)}</div></div>"
            for k, v in report.severity_counts.items()
        )
        or "<div class='card'><div class='num'>0</div><div class='lbl'>Findings</div></div>"
    )

    services = "".join(f"<li>{_e(s)}</li>" for s in report.compose_services) or "<li>None</li>"
    stages = "".join(f"<li>{_e(s)}</li>" for s in report.dockerfile_stages) or "<li>None</li>"
    suppressions = (
        "".join(
            f"<li>{_e(s.get('id'))}: {_e(s.get('status'))} — {_e(s.get('justification') or s.get('reason') or '')}</li>"
            for s in report.suppressions
        )
        or "<li>None</li>"
    )
    limitations = "".join(f"<li>{_e(x)}</li>" for x in report.limitations)
    recommendations = "".join(f"<li>{_e(x)}</li>" for x in report.recommendations)
    warnings = "".join(f"<li>{_e(x)}</li>" for x in report.parsing_warnings) or "<li>None</li>"

    synthetic_banner = ""
    if report.synthetic:
        synthetic_banner = (
            "<div class='banner' role='status'>"
            "<strong>SYNTHETIC DEMONSTRATION DATA</strong>"
            "<p>This report contains synthetic container-configuration data created "
            "exclusively for demonstration, testing, and documentation purposes.</p>"
            "</div>"
        )

    css = """
:root {
  --bg: #f4f7f5;
  --ink: #1a2421;
  --muted: #5c6b65;
  --accent: #0b6e4f;
  --card: #ffffff;
  --line: #d5e0db;
  --crit: #8f1d1d;
  --high: #9a4a00;
  --med: #8a6d00;
  --low: #3d5a80;
  --info: #4a5568;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  color: var(--ink);
  background:
    radial-gradient(circle at top left, #dceee6 0%, transparent 40%),
    linear-gradient(180deg, #eef5f1 0%, var(--bg) 40%, #e8efe9 100%);
  line-height: 1.45;
}
header, main, footer { max-width: 1100px; margin: 0 auto; padding: 1.25rem; }
header h1 { margin: 0 0 0.25rem; font-size: 1.8rem; letter-spacing: -0.02em; color: var(--accent); }
.meta { color: var(--muted); font-size: 0.95rem; }
.banner {
  background: #12352c;
  color: #f3fff9;
  border-radius: 10px;
  padding: 1rem 1.25rem;
  margin: 1rem 0 1.5rem;
}
.banner strong { display: block; font-size: 1.05rem; margin-bottom: 0.35rem; }
.scorebox {
  display: flex; gap: 1rem; flex-wrap: wrap; align-items: stretch; margin: 1rem 0 1.5rem;
}
.score {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1.25rem 1.5rem;
  min-width: 160px;
}
.score .value { font-size: 2.6rem; font-weight: 700; color: var(--accent); }
.score .grade { font-size: 1.2rem; color: var(--muted); }
.cards { display: flex; flex-wrap: wrap; gap: 0.75rem; flex: 1; }
.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 0.85rem 1rem;
  min-width: 110px;
}
.card .num { font-size: 1.5rem; font-weight: 700; }
.card .lbl { color: var(--muted); font-size: 0.85rem; }
.sev-critical .num { color: var(--crit); }
.sev-high .num { color: var(--high); }
.sev-medium .num { color: var(--med); }
.sev-low .num { color: var(--low); }
.sev-informational .num { color: var(--info); }
section {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1rem 1.25rem;
  margin-bottom: 1rem;
}
h2 { margin-top: 0; font-size: 1.15rem; color: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { border-bottom: 1px solid var(--line); padding: 0.55rem 0.4rem; text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
ul { margin: 0.25rem 0 0 1.1rem; }
.notice {
  border-left: 4px solid var(--accent);
  padding: 0.75rem 1rem;
  background: #f2faf6;
  border-radius: 0 8px 8px 0;
}
footer { color: var(--muted); font-size: 0.85rem; padding-bottom: 2rem; }
@media (max-width: 700px) {
  table, thead, tbody, th, td, tr { display: block; }
  th { display: none; }
  td { border: none; padding: 0.2rem 0; }
  tr { border-bottom: 1px solid var(--line); margin-bottom: 0.75rem; padding-bottom: 0.75rem; }
}
"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Container Security Baseline Report</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>container-security-baseline</h1>
  <div class="meta">Offline static analysis report · v{_e(report.tool_version)} · {_e(report.generated_at_utc)}</div>
  {synthetic_banner}
  <div class="scorebox">
    <div class="score">
      <div class="value">{_e(report.score)}</div>
      <div class="grade">Grade {_e(report.grade)}</div>
    </div>
    <div class="cards">{sev_cards}</div>
  </div>
</header>
<main>
  <section>
    <h2>Project summary</h2>
    <p><strong>Policy:</strong> {_e((report.policy or {}).get("name"))} ·
       <strong>Privacy:</strong> {_e(report.privacy_mode)} ·
       <strong>Parsing:</strong> {_e(report.parsing_status)} ·
       <strong>Exit code:</strong> {_e(report.exit_code)}</p>
    <p>{_e(report.score_explanation)}</p>
    <div class="notice">{_e(report.security_notice)}</div>
  </section>
  <section>
    <h2>Compose services</h2>
    <ul>{services}</ul>
  </section>
  <section>
    <h2>Dockerfile stages</h2>
    <ul>{stages}</ul>
  </section>
  <section>
    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Rule</th><th>Severity</th><th>Status</th><th>Target</th>
          <th>Summary</th><th>File</th><th>Evidence</th><th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {"".join(findings_rows) if findings_rows else '<tr><td colspan="8">No findings</td></tr>'}
      </tbody>
    </table>
  </section>
  <section>
    <h2>Suppressions</h2>
    <ul>{suppressions}</ul>
  </section>
  <section>
    <h2>Recommendations</h2>
    <ul>{recommendations}</ul>
  </section>
  <section>
    <h2>Input-safety / parsing warnings</h2>
    <ul>{warnings}</ul>
  </section>
  <section>
    <h2>Static-analysis limitations</h2>
    <ul>{limitations}</ul>
  </section>
  <section>
    <h2>Exit codes</h2>
    <ul>
      <li>0 — success / no policy failure</li>
      <li>1 — findings below fail threshold</li>
      <li>2 — policy failure (threshold or minimum score)</li>
      <li>3 — error (invalid input, parse failure, unsafe path)</li>
    </ul>
  </section>
</main>
<footer>
  Generated by container-security-baseline. No remote scripts, styles, fonts, or images are loaded.
</footer>
</body>
</html>
"""
    return ensure_no_secret_leak(html_doc)


def write_html_report(report: Report, path: str | Path) -> None:
    Path(path).write_text(render_html_report(report), encoding="utf-8")


__all__ = ["render_html_report", "write_html_report"]
