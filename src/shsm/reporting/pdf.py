"""PDF report generator using ReportLab."""

from __future__ import annotations

import os
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_pdf_report(data: Dict[str, Any], output_path: str) -> str:
    """Generate a clean, professional PDF report from the report data dictionary."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14,
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
    )
    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=cell_style,
        fontName="Helvetica-Bold",
    )

    story = []

    # Title & Metadata
    title = str(data.get("title", "Server Health & Security Report"))
    hostname = str(data.get("hostname", "Server"))
    period_str = str(data.get("period", ""))
    gen_time = str(data.get("generated_at", ""))

    story.append(Paragraph(title, title_style))
    story.append(Paragraph(f"Server: <b>{hostname}</b> | Period: {period_str} | Generated: {gen_time}", meta_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=14))

    # Executive Score Summary
    health_score = float(data.get("health_score", 100.0))
    health_cov = float(data.get("health_coverage", 100.0))
    sec_score = float(data.get("security_score", 100.0))
    sec_cov = float(data.get("security_coverage", 100.0))

    score_data = [
        [
            Paragraph(f"<b>Server Health Score</b><br/><font size='18' color='#0284c7'><b>{health_score:.1f}</b></font><br/>Coverage: {health_cov:.0f}%", styles["Normal"]),
            Paragraph(f"<b>Security Score</b><br/><font size='18' color='#059669'><b>{sec_score:.1f}</b></font><br/>Coverage: {sec_cov:.0f}%", styles["Normal"]),
        ]
    ]
    score_table = Table(score_data, colWidths=[270, 270])
    score_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    story.append(score_table)
    story.append(Spacer(1, 14))

    # Subsystems Breakdown Table
    components = data.get("components", {})
    if components:
        story.append(Paragraph("Subsystem Scores & Coverage", h2_style))
        comp_rows = [[
            Paragraph("<b>Subsystem</b>", cell_bold),
            Paragraph("<b>Score</b>", cell_bold),
            Paragraph("<b>Coverage</b>", cell_bold),
            Paragraph("<b>Open Issues</b>", cell_bold),
        ]]
        for comp, d in components.items():
            comp_rows.append([
                Paragraph(str(d.get("label", comp)), cell_style),
                Paragraph(f"{d.get('score', 100):.1f}", cell_style),
                Paragraph(f"{d.get('coverage', 100):.0f}%", cell_style),
                Paragraph(str(d.get("open_findings", 0)), cell_style),
            ])
        comp_table = Table(comp_rows, colWidths=[240, 100, 100, 100])
        comp_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(comp_table)
        story.append(Spacer(1, 14))

    # Active Findings Table
    findings = data.get("findings", [])
    story.append(Paragraph(f"Active Findings & Vulnerabilities ({len(findings)})", h2_style))
    if findings:
        f_rows = [[
            Paragraph("<b>Severity</b>", cell_bold),
            Paragraph("<b>Issue / Finding</b>", cell_bold),
            Paragraph("<b>Asset</b>", cell_bold),
            Paragraph("<b>Status</b>", cell_bold),
        ]]
        for f in findings[:25]:
            sev = str(f.get("severity", "INFO"))
            f_rows.append([
                Paragraph(sev, cell_bold),
                Paragraph(str(f.get("title", ""))[:80], cell_style),
                Paragraph(str(f.get("asset", "-"))[:30], cell_style),
                Paragraph(str(f.get("status", "OPEN")), cell_style),
            ])
        f_table = Table(f_rows, colWidths=[80, 260, 120, 80])
        f_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(f_table)
    else:
        story.append(Paragraph("No active security findings or critical issues.", cell_style))
    story.append(Spacer(1, 14))

    # Hosting & Services Table
    services = data.get("services", [])
    if services:
        story.append(Paragraph("Critical System & Hosting Services", h2_style))
        srv_rows = [[
            Paragraph("<b>Unit Name</b>", cell_bold),
            Paragraph("<b>Role</b>", cell_bold),
            Paragraph("<b>State</b>", cell_bold),
            Paragraph("<b>PID</b>", cell_bold),
        ]]
        for s in services:
            srv_rows.append([
                Paragraph(str(s.get("unit", "")), cell_style),
                Paragraph(str(s.get("role", "")), cell_style),
                Paragraph(str(s.get("active_state", "")), cell_style),
                Paragraph(str(s.get("main_pid", "-")), cell_style),
            ])
        srv_table = Table(srv_rows, colWidths=[200, 140, 100, 100])
        srv_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(srv_table)
        story.append(Spacer(1, 14))

    # Websites & SSL Table
    websites = data.get("websites", [])
    if websites:
        story.append(Paragraph("Websites Availability & SSL Status", h2_style))
        ws_rows = [[
            Paragraph("<b>Domain</b>", cell_bold),
            Paragraph("<b>HTTP Status</b>", cell_bold),
            Paragraph("<b>Response Time</b>", cell_bold),
            Paragraph("<b>SSL Expiry</b>", cell_bold),
        ]]
        for w in websites:
            resp_str = f"{w.get('response_ms', 0):.0f}ms" if w.get("response_ms") else "-"
            ssl_str = f"{w.get('ssl_days', 0):.0f} days" if w.get("ssl_days") is not None else "N/A"
            ws_rows.append([
                Paragraph(str(w.get("domain", "")), cell_style),
                Paragraph(str(w.get("status_code", "-")), cell_style),
                Paragraph(resp_str, cell_style),
                Paragraph(ssl_str, cell_style),
            ])
        ws_table = Table(ws_rows, colWidths=[220, 100, 110, 110])
        ws_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ws_table)
        story.append(Spacer(1, 14))

    # Footer note
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=10, spaceAfter=8))
    story.append(Paragraph("<font size='7' color='#94a3b8'>Server Health & Security Monitoring (SHSM) &bull; GM Teknologi &bull; Asia/Jakarta Timezone</font>", meta_style))

    doc.build(story)
    return output_path
