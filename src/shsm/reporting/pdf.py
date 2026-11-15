"""PDF report generator using ReportLab."""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

# Fix for Python <= 3.8 and specific OpenSSL environments where ReportLab calls
# hashlib.md5(usedforsecurity=False) but openssl_md5() does not accept keyword arguments.
try:
    hashlib.md5(b"test", usedforsecurity=False)
except TypeError:
    _orig_md5 = hashlib.md5

    def _compat_md5(*args, **kwargs):
        kwargs.pop("usedforsecurity", None)
        return _orig_md5(*args, **kwargs)

    hashlib.md5 = _compat_md5  # type: ignore[assignment]

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
    """Generate a clean, high-contrast, professional PDF report from the report data dictionary."""
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

    # Custom styles with high contrast
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
        spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=5,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#1e293b"),
    )
    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=cell_style,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"),
    )
    summary_p_style = ParagraphStyle(
        "SummaryText",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
    )

    story = []

    # Title & Metadata
    title = str(data.get("title", "Server Health & Security Report"))
    hostname = str(data.get("hostname", "Server"))
    period_str = str(data.get("period", ""))
    gen_time = str(data.get("generated_at", ""))

    story.append(Paragraph(title, title_style))
    story.append(Paragraph(f"Server: <b>{hostname}</b> | Periode: {period_str} | Dibuat: {gen_time}", meta_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # Executive Score Summary
    health_score = float(data.get("health_score", 100.0))
    health_cov = float(data.get("health_coverage", 100.0))
    sec_score = float(data.get("security_score", 100.0))
    sec_cov = float(data.get("security_coverage", 100.0))

    def score_color_pdf(score: float) -> str:
        if score >= 90:
            return "#047857"
        if score >= 75:
            return "#b45309"
        return "#b91c1c"

    def status_label(score: float) -> str:
        if score >= 90:
            return "Sangat Baik (Normal)"
        if score >= 75:
            return "Waspada / Perhatian"
        return "Kritis / Bermasalah"

    h_col = score_color_pdf(health_score)
    s_col = score_color_pdf(sec_score)

    score_data = [
        [
            Paragraph(
                f"<b>Kesehatan Server (Health)</b><br/>"
                f"<font size='22' color='{h_col}'><b>{health_score:.1f}</b></font><br/>"
                f"<b>{status_label(health_score)}</b><br/>"
                f"<font size='7' color='#64748b'>Cakupan Audit: {health_cov:.0f}%</font>",
                styles["Normal"],
            ),
            Paragraph(
                f"<b>Keamanan Server (Security)</b><br/>"
                f"<font size='22' color='{s_col}'><b>{sec_score:.1f}</b></font><br/>"
                f"<b>{status_label(sec_score)}</b><br/>"
                f"<font size='7' color='#64748b'>Cakupan Audit: {sec_cov:.0f}%</font>",
                styles["Normal"],
            ),
        ]
    ]
    score_table = Table(score_data, colWidths=[270, 270])
    score_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(score_table)
    story.append(Spacer(1, 10))

    # Non-technical Executive Summary Box
    overall_min = min(health_score, sec_score)
    if overall_min >= 90:
        summary_title_box = "<b>Kondisi Server: PRIMA & STABIL</b>"
        summary_text_box = (
            f"Server <b>{hostname}</b> saat ini dalam performa optimal tanpa kendala kritis. "
            "Seluruh service utama beroperasi normal dan tidak ada ancaman keamanan mendesak."
        )
        box_bg = colors.HexColor("#f0fdf4")
        box_border = colors.HexColor("#16a34a")
    elif overall_min >= 75:
        summary_title_box = "<b>Kondisi Server: PERLU PERHATIAN</b>"
        summary_text_box = (
            f"Server <b>{hostname}</b> masih beroperasi dengan baik namun terdapat catatan performa atau konfigurasi "
            "yang perlu ditindaklanjuti untuk mencegah potensi kendala lebih lanjut."
        )
        box_bg = colors.HexColor("#fffbeb")
        box_border = colors.HexColor("#d97706")
    else:
        summary_title_box = "<b>Kondisi Server: KRITIS / BUTUH PENANGANAN SEGERA</b>"
        summary_text_box = (
            f"Server <b>{hostname}</b> mengalami masalah serius. Tim teknis dihimbau segera menjalankan panduan "
            "solusi penanganan di bagian bawah laporan ini."
        )
        box_bg = colors.HexColor("#fef2f2")
        box_border = colors.HexColor("#dc2626")

    summary_table = Table(
        [[Paragraph(f"{summary_title_box}<br/>{summary_text_box}", summary_p_style)]],
        colWidths=[540],
    )
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), box_bg),
            ("BOX", (0, 0), (-1, -1), 1.5, box_border),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # Subsystems Breakdown Table
    components = data.get("components", {})
    if components:
        story.append(Paragraph("Rincian Kondisi Subsistem Server", h2_style))
        comp_rows = [[
            Paragraph("<b>Subsistem</b>", cell_bold),
            Paragraph("<b>Skor</b>", cell_bold),
            Paragraph("<b>Cakupan</b>", cell_bold),
            Paragraph("<b>Isu Terbuka</b>", cell_bold),
        ]]
        for comp, d in components.items():
            sc = float(d.get("score", 100))
            col = score_color_pdf(sc)
            comp_rows.append([
                Paragraph(str(d.get("label", comp)), cell_style),
                Paragraph(f"<font color='{col}'><b>{sc:.1f}</b></font>", cell_style),
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
        story.append(Spacer(1, 10))

    # Active Findings Table with Actionable Solutions
    findings = data.get("findings", [])
    story.append(Paragraph(f"Daftar Masalah Server & Solusi Penanganan ({len(findings)})", h2_style))
    if findings:
        f_rows = [[
            Paragraph("<b>Tingkat</b>", cell_bold),
            Paragraph("<b>Deskripsi Masalah & Solusi Penanganan</b>", cell_bold),
            Paragraph("<b>Target Aset</b>", cell_bold),
            Paragraph("<b>Status</b>", cell_bold),
        ]]
        for f in findings[:25]:
            sev = str(f.get("severity", "INFO")).upper()
            if sev == "CRITICAL":
                sev_color = "#991b1b"
            elif sev == "HIGH":
                sev_color = "#9a3412"
            elif sev == "MEDIUM":
                sev_color = "#854d0e"
            else:
                sev_color = "#075985"

            title_text = str(f.get("title", ""))[:90]
            rec = f.get("recommendation") or "Periksa konfigurasi dan lakukan pengawasan berkala."
            combined_desc = f"<b>{title_text}</b><br/><font color='#0284c7'><b>💡 Solusi:</b></font> <font color='#334155'>{rec}</font>"

            f_rows.append([
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", cell_bold),
                Paragraph(combined_desc, cell_style),
                Paragraph(str(f.get("asset", "-"))[:30], cell_style),
                Paragraph(str(f.get("status", "OPEN")), cell_style),
            ])
        f_table = Table(f_rows, colWidths=[65, 305, 110, 60])
        f_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(f_table)
    else:
        story.append(Paragraph("<font color='#047857'><b>✅ Tidak ditemukan masalah aktif.</b> Server dalam kondisi aman.</font>", cell_style))
    story.append(Spacer(1, 10))

    # Hosting & Services Table
    services = data.get("services", [])
    if services:
        story.append(Paragraph("Status Layanan Inti (Core Services)", h2_style))
        srv_rows = [[
            Paragraph("<b>Service / Unit</b>", cell_bold),
            Paragraph("<b>Fungsi Layanan</b>", cell_bold),
            Paragraph("<b>Status</b>", cell_bold),
            Paragraph("<b>PID</b>", cell_bold),
        ]]
        for s in services:
            st = str(s.get("active_state", "active" if s.get("active") else "down"))
            st_color = "#047857" if st == "active" or s.get("active") else "#b91c1c"
            st_text = "ACTIVE" if st == "active" or s.get("active") else "DOWN"
            srv_rows.append([
                Paragraph(str(s.get("unit", "")), cell_style),
                Paragraph(str(s.get("role", s.get("description", "-"))), cell_style),
                Paragraph(f"<font color='{st_color}'><b>{st_text}</b></font>", cell_style),
                Paragraph(str(s.get("main_pid", "-")), cell_style),
            ])
        srv_table = Table(srv_rows, colWidths=[180, 160, 100, 100])
        srv_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(srv_table)
        story.append(Spacer(1, 10))

    # Websites & SSL Table
    websites = data.get("websites", [])
    if websites:
        story.append(Paragraph("Ketersediaan Website & Sertifikat SSL", h2_style))
        ws_rows = [[
            Paragraph("<b>Domain</b>", cell_bold),
            Paragraph("<b>Status Akses</b>", cell_bold),
            Paragraph("<b>Waktu Respon</b>", cell_bold),
            Paragraph("<b>Masa Aktif SSL</b>", cell_bold),
        ]]
        for w in websites:
            resp_val = w.get("response_ms") or w.get("response_time_ms")
            resp_str = f"{resp_val:.0f}ms" if resp_val is not None else "-"
            ssl_val = w.get("ssl_days")
            ssl_str = f"{ssl_val:.0f} hari" if ssl_val is not None else "N/A"
            ws_rows.append([
                Paragraph(str(w.get("domain", "")), cell_style),
                Paragraph(str(w.get("status_code", "-")), cell_style),
                Paragraph(resp_str, cell_style),
                Paragraph(ssl_str, cell_style),
            ])
        ws_table = Table(ws_rows, colWidths=[200, 110, 110, 120])
        ws_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ws_table)
        story.append(Spacer(1, 10))

    # Footer note
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=8, spaceAfter=6))
    story.append(Paragraph("<font size='7' color='#64748b'>Sistem Pemantauan Server (SHSM) &bull; GM Teknologi &bull; Asia/Jakarta (WIB)</font>", meta_style))

    doc.build(story)
    return output_path
