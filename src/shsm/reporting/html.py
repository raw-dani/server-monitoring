"""HTML report builder for weekly and monthly reports."""

from __future__ import annotations

import html
from typing import Any, Dict


def render_html_report(data: Dict[str, Any]) -> str:
    """Render a clean, modern, responsive HTML report."""
    kind = html.escape(str(data.get("kind", "Report")).upper())
    title = html.escape(str(data.get("title", f"Server Health & Security {kind} Report")))
    hostname = html.escape(str(data.get("hostname", "Server")))
    period_str = html.escape(str(data.get("period", "")))
    gen_time = html.escape(str(data.get("generated_at", "")))

    health_score = data.get("health_score", 100.0)
    health_cov = data.get("health_coverage", 100.0)
    sec_score = data.get("security_score", 100.0)
    sec_cov = data.get("security_coverage", 100.0)

    # Color helpers
    def score_color(val: float) -> str:
        if val >= 90:
            return "#10b981"  # Emerald
        if val >= 75:
            return "#f59e0b"  # Amber
        return "#ef4444"  # Red

    h_col = score_color(health_score)
    s_col = score_color(sec_score)

    findings = data.get("findings", [])
    components = data.get("components", {})
    services = data.get("services", [])
    websites = data.get("websites", [])

    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }
    .container { max-width: 960px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
    .header { border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 24px; }
    .header h1 { margin: 0 0 8px 0; font-size: 26px; color: #38bdf8; }
    .meta { font-size: 14px; color: #94a3b8; }
    .score-grid { display: flex; gap: 20px; margin-bottom: 28px; }
    .score-card { flex: 1; background: #0f172a; border-radius: 8px; border: 1px solid #334155; padding: 20px; text-align: center; }
    .score-card h3 { margin: 0 0 6px 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }
    .score-num { font-size: 42px; font-weight: 800; margin: 0; }
    .coverage { font-size: 12px; color: #64748b; margin-top: 4px; }
    .section-title { font-size: 18px; color: #f1f5f9; border-bottom: 1px solid #334155; padding-bottom: 8px; margin: 28px 0 16px 0; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }
    th { background-color: #0f172a; color: #94a3b8; text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; font-weight: 600; }
    td { padding: 10px 12px; border-bottom: 1px solid #334155; }
    tr:hover { background-color: #243247; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    .badge-crit { background-color: #7f1d1d; color: #fecaca; }
    .badge-high { background-color: #7c2d12; color: #fed7aa; }
    .badge-med { background-color: #78350f; color: #fef08a; }
    .badge-low { background-color: #1e3a8a; color: #bfdbfe; }
    .badge-pass { background-color: #064e3b; color: #a7f3d0; }
    .recommendation { background: #0f172a; border-left: 4px solid #38bdf8; padding: 12px 16px; margin-bottom: 12px; border-radius: 0 6px 6px 0; }
    .footer { text-align: center; margin-top: 36px; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 16px; }
    """

    out = [f"<!DOCTYPE html><html><head><meta charset='utf-8'/><title>{title}</title><style>{css}</style></head><body>"]
    out.append("<div class='container'>")

    # Header
    out.append("<div class='header'>")
    out.append(f"<h1>{title}</h1>")
    out.append(f"<div class='meta'>Server: <strong>{hostname}</strong> | Period: {period_str} | Generated: {gen_time}</div>")
    out.append("</div>")

    # Score Cards
    out.append("<div class='score-grid'>")
    out.append(f"<div class='score-card'><h3>Server Health Score</h3><div class='score-num' style='color:{h_col};'>{health_score:.1f}</div><div class='coverage'>Coverage: {health_cov:.0f}%</div></div>")
    out.append(f"<div class='score-card'><h3>Security Score</h3><div class='score-num' style='color:{s_col};'>{sec_score:.1f}</div><div class='coverage'>Coverage: {sec_cov:.0f}%</div></div>")
    out.append("</div>")

    # Component Breakdown Table
    if components:
        out.append("<h2 class='section-title'>Scores & Coverage by Subsystem</h2>")
        out.append("<table><thead><tr><th>Subsystem</th><th>Score</th><th>Coverage</th><th>Open Findings</th><th>Status</th></tr></thead><tbody>")
        for comp, d in components.items():
            sc = d.get("score", 100.0)
            cov = d.get("coverage", 100.0)
            lbl = html.escape(str(d.get("label", comp)))
            f_count = d.get("open_findings", 0)
            status_badge = "<span class='badge badge-pass'>HEALTHY</span>" if sc >= 90 else ("<span class='badge badge-med'>ATTENTION</span>" if sc >= 75 else "<span class='badge badge-crit'>CRITICAL</span>")
            out.append(f"<tr><td><strong>{lbl}</strong></td><td style='color:{score_color(sc)}; font-weight:700;'>{sc:.1f}</td><td>{cov:.0f}%</td><td>{f_count}</td><td>{status_badge}</td></tr>")
        out.append("</tbody></table>")

    # Top Issues / Open Findings
    out.append("<h2 class='section-title'>Active Findings & Security Issues</h2>")
    if findings:
        out.append("<table><thead><tr><th>Severity</th><th>Issue</th><th>Asset</th><th>Status</th></tr></thead><tbody>")
        for f in findings[:25]:
            sev = f.get("severity", "INFO")
            badge_cls = "badge-crit" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else ("badge-med" if sev == "MEDIUM" else "badge-low"))
            tit = html.escape(str(f.get("title", "")))
            ast = html.escape(str(f.get("asset", "-")))
            fst = html.escape(str(f.get("status", "OPEN")))
            out.append(f"<tr><td><span class='badge {badge_cls}'>{sev}</span></td><td>{tit}</td><td>{ast}</td><td>{fst}</td></tr>")
        out.append("</tbody></table>")
    else:
        out.append("<p style='color:#10b981;'>No active critical or high findings.</p>")

    # Service Incidents & Status
    if services:
        out.append("<h2 class='section-title'>Hosting & Critical Services</h2>")
        out.append("<table><thead><tr><th>Service / Unit</th><th>Role</th><th>State</th><th>PID</th><th>Restarts</th></tr></thead><tbody>")
        for s in services:
            u = html.escape(str(s.get("unit", "")))
            r = html.escape(str(s.get("role", "")))
            st = html.escape(str(s.get("active_state", "")))
            pid = str(s.get("main_pid", "-"))
            rst = str(s.get("n_restarts", 0))
            badge = "<span class='badge badge-pass'>ACTIVE</span>" if st == "active" else "<span class='badge badge-crit'>DOWN</span>"
            out.append(f"<tr><td>{u}</td><td>{r}</td><td>{badge}</td><td>{pid}</td><td>{rst}</td></tr>")
        out.append("</tbody></table>")

    # Website Uptime and SSL Expiry
    if websites:
        out.append("<h2 class='section-title'>Websites Availability & SSL Certificates</h2>")
        out.append("<table><thead><tr><th>Domain</th><th>HTTP Status</th><th>Response Time</th><th>SSL Expiry</th></tr></thead><tbody>")
        for w in websites:
            dom = html.escape(str(w.get("domain", "")))
            code = str(w.get("status_code", "-"))
            resp_ms = f"{w.get('response_ms', 0):.0f}ms" if w.get("response_ms") else "-"
            ssl_days = f"{w.get('ssl_days', 0):.0f} days" if w.get("ssl_days") is not None else "N/A"
            out.append(f"<tr><td><strong>{dom}</strong></td><td>{code}</td><td>{resp_ms}</td><td>{ssl_days}</td></tr>")
        out.append("</tbody></table>")

    # Footer
    out.append("<div class='footer'>Server Health & Security Monitoring (SHSM) &bull; GM Teknologi &bull; Asia/Jakarta Timezone</div>")
    out.append("</div></body></html>")
    return "\n".join(out)
