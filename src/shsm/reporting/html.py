"""HTML report builder for weekly and monthly reports."""

from __future__ import annotations

import html
from typing import Any, Dict


def render_html_report(data: Dict[str, Any]) -> str:
    """Render a clean, high-contrast, executive & layperson-friendly HTML report."""
    kind = html.escape(str(data.get("kind", "Report")).upper())
    title = html.escape(str(data.get("title", f"Server Health & Security {kind} Report")))
    hostname = html.escape(str(data.get("hostname", "Server")))
    period_str = html.escape(str(data.get("period", "")))
    gen_time = html.escape(str(data.get("generated_at", "")))

    health_score = float(data.get("health_score", 100.0))
    health_cov = float(data.get("health_coverage", 100.0))
    sec_score = float(data.get("security_score", 100.0))
    sec_cov = float(data.get("security_coverage", 100.0))

    # Helper status & colors (High-contrast on white/light-gray backgrounds)
    def get_status_info(val: float) -> tuple[str, str, str, str]:
        """Returns (Label ID, Label EN, Text Color, Background Color)."""
        if val >= 90:
            return ("Sangat Baik (Normal)", "Excellent", "#047857", "#ecfdf5")
        if val >= 75:
            return ("Waspada / Perlu Perhatian", "Needs Attention", "#b45309", "#fffbeb")
        return ("Kritis / Bermasalah", "Critical Issue", "#b91c1c", "#fef2f2")

    h_label_id, _, h_fg, h_bg = get_status_info(health_score)
    s_label_id, _, s_fg, s_bg = get_status_info(sec_score)

    findings = data.get("findings", [])
    components = data.get("components", {})
    services = data.get("services", [])
    websites = data.get("websites", [])
    metrics = data.get("metrics_summary", {})

    # Determine overall condition for non-technical executive summary
    overall_min = min(health_score, sec_score)
    if overall_min >= 90:
        summary_title = "Kondisi Server Prima & Berjalan Lancar"
        summary_desc = (
            f"Server <strong>{hostname}</strong> beroperasi secara optimal dan stabil. "
            "Semua layanan utama aktif tanpa gangguan performa, serta tidak ditemukan celah keamanan berisiko tinggi. "
            "Tidak diperlukan tindakan darurat saat ini."
        )
        summary_badge = "<span class='badge badge-pass'>STATUS AMAN & STABIL</span>"
        summary_card_class = "summary-box summary-box-pass"
    elif overall_min >= 75:
        summary_title = "Server Beroperasi Namun Memerlukan Perhatian"
        summary_desc = (
            f"Server <strong>{hostname}</strong> tetap melayani trafik, namun terdapat beberapa indikasi beban kerja "
            "atau konfigurasi yang mendekati batas toleransi. Disarankan melakukan peninjauan berkala sesuai panduan di bawah."
        )
        summary_badge = "<span class='badge badge-med'>PERLU TINDAKAN PENCEGAHAN</span>"
        summary_card_class = "summary-box summary-box-med"
    else:
        summary_title = "Perhatian Khusus: Ditemukan Masalah Penting pada Server"
        summary_desc = (
            f"Server <strong>{hostname}</strong> mengalami kendala performa atau keamanan yang perlu segera ditangani. "
            "Diharapkan tim teknis atau pengelola sistem meninjau rekomendasi solusi perbaikan di bawah ini secepatnya."
        )
        summary_badge = "<span class='badge badge-crit'>PERLU TINDAKAN SEGERA</span>"
        summary_card_class = "summary-box summary-box-crit"

    css = """
    * { box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        background-color: #f1f5f9;
        color: #0f172a;
        margin: 0;
        padding: 32px 16px;
        line-height: 1.6;
        -webkit-font-smoothing: antialiased;
    }
    .container {
        max-width: 980px;
        margin: 0 auto;
        background-color: #ffffff;
        border-radius: 12px;
        border: 1px solid #cbd5e1;
        padding: 36px;
        box-shadow: 0 4px 16px rgba(15, 23, 42, 0.08);
    }
    .header {
        border-bottom: 2px solid #e2e8f0;
        padding-bottom: 20px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        flex-wrap: wrap;
        gap: 16px;
    }
    .header-main h1 {
        margin: 0 0 6px 0;
        font-size: 24px;
        font-weight: 700;
        color: #0f172a;
        letter-spacing: -0.02em;
    }
    .header-main .meta {
        font-size: 13px;
        color: #475569;
    }
    .header-brand {
        text-align: right;
    }
    .brand-title {
        font-size: 13px;
        font-weight: 700;
        color: #1e40af;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    .brand-sub {
        font-size: 11px;
        color: #64748b;
    }

    /* Executive Layperson Summary */
    .summary-box {
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 28px;
        border-left: 5px solid;
    }
    .summary-box-pass {
        background-color: #f0fdf4;
        border-color: #16a34a;
        color: #14532d;
    }
    .summary-box-med {
        background-color: #fffbeb;
        border-color: #d97706;
        color: #78350f;
    }
    .summary-box-crit {
        background-color: #fef2f2;
        border-color: #dc2626;
        color: #7f1d1d;
    }
    .summary-box h2 {
        margin: 0 0 8px 0;
        font-size: 17px;
        font-weight: 700;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .summary-box p {
        margin: 0;
        font-size: 14px;
        line-height: 1.6;
    }

    /* Score Cards */
    .score-grid {
        display: flex;
        gap: 20px;
        margin-bottom: 32px;
        flex-wrap: wrap;
    }
    .score-card {
        flex: 1;
        min-width: 260px;
        background: #f8fafc;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
        padding: 22px 20px;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .score-card h3 {
        margin: 0 0 6px 0;
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #475569;
    }
    .score-num {
        font-size: 44px;
        font-weight: 800;
        line-height: 1.1;
        margin: 6px 0;
    }
    .score-desc {
        font-size: 13px;
        font-weight: 600;
        margin-top: 4px;
    }
    .coverage {
        font-size: 12px;
        color: #64748b;
        margin-top: 4px;
    }

    /* Section Styling */
    .section-title {
        font-size: 17px;
        font-weight: 700;
        color: #0f172a;
        border-bottom: 2px solid #e2e8f0;
        padding-bottom: 8px;
        margin: 32px 0 16px 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .section-desc {
        font-size: 13px;
        color: #475569;
        margin: -8px 0 14px 0;
    }

    /* High Contrast Tables */
    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 24px;
        font-size: 13.5px;
        border: 1px solid #e2e8f0;
    }
    th {
        background-color: #f1f5f9;
        color: #0f172a;
        text-align: left;
        padding: 10px 14px;
        border-bottom: 2px solid #cbd5e1;
        font-weight: 700;
        font-size: 13px;
    }
    td {
        padding: 11px 14px;
        border-bottom: 1px solid #e2e8f0;
        color: #1e293b;
        vertical-align: middle;
    }
    tr:nth-child(even) td {
        background-color: #f8fafc;
    }
    tr:hover td {
        background-color: #f1f5f9;
    }

    /* Badges with High Contrast */
    .badge {
        display: inline-block;
        padding: 3px 9px;
        border-radius: 9999px;
        font-size: 11.5px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        white-space: nowrap;
    }
    .badge-crit { background-color: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
    .badge-high { background-color: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }
    .badge-med { background-color: #fef3c7; color: #854d0e; border: 1px solid #facc15; }
    .badge-low { background-color: #e0f2fe; color: #075985; border: 1px solid #38bdf8; }
    .badge-pass { background-color: #dcfce7; color: #166534; border: 1px solid #4ade80; }

    /* Actionable Problem Cards */
    .issue-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 14px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .issue-card-high { border-left-color: #f97316; }
    .issue-card-med { border-left-color: #eab308; }
    .issue-card-low { border-left-color: #0284c7; }
    .issue-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 8px;
        flex-wrap: wrap;
    }
    .issue-title {
        font-weight: 700;
        font-size: 14.5px;
        color: #0f172a;
    }
    .issue-asset {
        font-size: 12.5px;
        color: #475569;
        font-family: monospace;
        background: #f1f5f9;
        padding: 2px 6px;
        border-radius: 4px;
    }
    .issue-desc {
        font-size: 13px;
        color: #334155;
        margin: 4px 0 8px 0;
    }
    .issue-solution {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 8px 12px;
        margin-top: 8px;
        font-size: 13px;
        color: #0f172a;
    }
    .issue-solution strong {
        color: #0284c7;
        font-weight: 700;
    }

    .empty-state {
        background-color: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-radius: 6px;
        padding: 14px 18px;
        color: #166534;
        font-size: 13.5px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .footer {
        text-align: center;
        margin-top: 36px;
        font-size: 12px;
        color: #64748b;
        border-top: 1px solid #e2e8f0;
        padding-top: 18px;
        line-height: 1.6;
    }
    """

    out = [f"<!DOCTYPE html><html lang='id'><head><meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1.0'/><title>{title}</title><style>{css}</style></head><body>"]
    out.append("<div class='container'>")

    # Header
    out.append("<div class='header'>")
    out.append("<div class='header-main'>")
    out.append(f"<h1>{title}</h1>")
    out.append(f"<div class='meta'>Nama Server: <strong>{hostname}</strong> &bull; Periode: <strong>{period_str}</strong> &bull; Waktu Laporan: <strong>{gen_time}</strong></div>")
    out.append("</div>")
    out.append("<div class='header-brand'>")
    out.append("<div class='brand-title'>GM Teknologi</div>")
    out.append("<div class='brand-sub'>Server Health & Security</div>")
    out.append("</div>")
    out.append("</div>")

    # Layperson Executive Summary Box
    out.append(f"<div class='{summary_card_class}'>")
    out.append(f"<h2>{summary_badge} <span>{summary_title}</span></h2>")
    out.append(f"<p>{summary_desc}</p>")
    out.append("</div>")

    # Score Cards
    out.append("<div class='score-grid'>")
    out.append(
        f"<div class='score-card'>"
        f"<h3>Kesehatan Server (Health)</h3>"
        f"<div class='score-num' style='color:{h_fg};'>{health_score:.1f}</div>"
        f"<div class='score-desc' style='color:{h_fg};'>{h_label_id}</div>"
        f"<div class='coverage'>Cakupan Pengecekan: {health_cov:.0f}%</div>"
        f"</div>"
    )
    out.append(
        f"<div class='score-card'>"
        f"<h3>Keamanan Server (Security)</h3>"
        f"<div class='score-num' style='color:{s_fg};'>{sec_score:.1f}</div>"
        f"<div class='score-desc' style='color:{s_fg};'>{s_label_id}</div>"
        f"<div class='coverage'>Cakupan Pengecekan: {sec_cov:.0f}%</div>"
        f"</div>"
    )
    out.append("</div>")

    # Subsystem Breakdown Table
    if components:
        out.append("<div class='section-title'>Rincian Komponen & Layanan Server</div>")
        out.append("<div class='section-desc'>Ringkasan performa tiap subsistem server (CPU, RAM, Disk, Database, Web Server, dan Keamanan).</div>")
        out.append("<table><thead><tr><th>Subsistem</th><th>Nilai Skor</th><th>Cakupan Audit</th><th>Isu Terbuka</th><th>Status Kondisi</th></tr></thead><tbody>")
        for comp, d in components.items():
            sc = float(d.get("score", 100.0))
            cov = float(d.get("coverage", 100.0))
            lbl = html.escape(str(d.get("label", comp)))
            f_count = int(d.get("open_findings", 0))

            if sc >= 90:
                badge = "<span class='badge badge-pass'>NORMAL</span>"
                score_fg = "#047857"
            elif sc >= 75:
                badge = "<span class='badge badge-med'>PERLU CEK</span>"
                score_fg = "#b45309"
            else:
                badge = "<span class='badge badge-crit'>KRITIS</span>"
                score_fg = "#b91c1c"

            out.append(
                f"<tr>"
                f"<td><strong>{lbl}</strong></td>"
                f"<td style='color:{score_fg}; font-weight:700;'>{sc:.1f} / 100</td>"
                f"<td>{cov:.0f}%</td>"
                f"<td>{f_count} isu</td>"
                f"<td>{badge}</td>"
                f"</tr>"
            )
        out.append("</tbody></table>")

    # Findings & Problem Solutions (Informative for layperson + actionable solution)
    out.append("<div class='section-title'>Temuan Masalah & Solusi Penanganan</div>")
    out.append("<div class='section-desc'>Daftar masalah yang terdeteksi beserta panduan langkah penanganan konkret untuk tim teknis dan pengelola.</div>")

    if findings:
        for f in findings[:25]:
            sev = str(f.get("severity", "INFO")).upper()
            if sev == "CRITICAL":
                card_cls = "issue-card"
                badge_cls = "badge-crit"
                sev_label = "KRITIS"
            elif sev == "HIGH":
                card_cls = "issue-card issue-card-high"
                badge_cls = "badge-high"
                sev_label = "TINGGI"
            elif sev == "MEDIUM":
                card_cls = "issue-card issue-card-med"
                badge_cls = "badge-med"
                sev_label = "SEDANG"
            else:
                card_cls = "issue-card issue-card-low"
                badge_cls = "badge-low"
                sev_label = "RENDAH"

            tit = html.escape(str(f.get("title", "Temuan Tidak Berjudul")))
            ast = html.escape(str(f.get("asset", "-")))
            fst = html.escape(str(f.get("status", "OPEN")))
            rec = f.get("recommendation")
            evidence = f.get("evidence")

            # Fallback recommendation if empty
            if not rec:
                rec = "Lakukan pemeriksaan berkala pada komponen terkait dan pastikan konfigurasi sesuai standar keamanan."
            rec_safe = html.escape(str(rec))

            out.append(f"<div class='{card_cls}'>")
            out.append("<div class='issue-header'>")
            out.append(f"<span class='badge {badge_cls}'>{sev_label}</span>")
            out.append(f"<span class='issue-title'>{tit}</span>")
            if ast and ast != "-":
                out.append(f"<span class='issue-asset'>{ast}</span>")
            out.append(f"<span style='font-size:12px; color:#64748b; margin-left:auto;'>Status: <strong>{fst}</strong></span>")
            out.append("</div>")

            if evidence:
                out.append(f"<div class='issue-desc'><strong>Detail:</strong> {html.escape(str(evidence))}</div>")

            out.append(
                f"<div class='issue-solution'>"
                f"<strong>💡 Solusi & Rekomendasi Tindakan:</strong> {rec_safe}"
                f"</div>"
            )
            out.append("</div>")
    else:
        out.append("<div class='empty-state'>✅ <strong>Tidak ada masalah aktif</strong>: Seluruh audit keamanan dan kesehatan server saat ini berada dalam kondisi aman.</div>")

    # Hosting & Services Status
    if services:
        out.append("<div class='section-title'>Status Layanan Utama (Services)</div>")
        out.append("<div class='section-desc'>Status operasional daemon server (Web server OpenLiteSpeed/Nginx, Database MariaDB, Redis, dll).</div>")
        out.append("<table><thead><tr><th>Nama Service</th><th>Peran / Fungsi</th><th>Status Operasional</th><th>PID</th><th>Jumlah Restart</th></tr></thead><tbody>")
        for s in services:
            u = html.escape(str(s.get("unit", "-")))
            r = html.escape(str(s.get("role", s.get("description", "-"))))
            st = str(s.get("active_state", "active" if s.get("active") else "inactive"))
            pid = str(s.get("main_pid", "-"))
            rst = str(s.get("n_restarts", 0))

            if st == "active" or s.get("active"):
                badge = "<span class='badge badge-pass'>BERJALAN (ACTIVE)</span>"
            else:
                badge = "<span class='badge badge-crit'>BERHENTI (DOWN)</span>"

            out.append(f"<tr><td><strong>{u}</strong></td><td>{r}</td><td>{badge}</td><td>{pid}</td><td>{rst}</td></tr>")
        out.append("</tbody></table>")

    # Websites Availability and SSL
    if websites:
        out.append("<div class='section-title'>Ketersediaan Website & Sertifikat SSL</div>")
        out.append("<div class='section-desc'>Pemeriksaan apakah website dapat diakses dari publik dan sisa masa aktif keamanan SSL/HTTPS.</div>")
        out.append("<table><thead><tr><th>Domain Website</th><th>Status Akses</th><th>Waktu Respon</th><th>Sisa Waktu SSL</th><th>Status</th></tr></thead><tbody>")
        for w in websites:
            dom = html.escape(str(w.get("domain", "")))
            code = str(w.get("status_code", "-"))
            resp_val = w.get("response_ms") or w.get("response_time_ms")
            resp_ms = f"{resp_val:.0f} ms" if resp_val is not None else "-"
            ssl_days = w.get("ssl_days")

            if ssl_days is not None:
                ssl_text = f"{ssl_days:.0f} hari"
                if ssl_days <= 7:
                    ssl_badge = "<span class='badge badge-crit'>SEGERA PERPANJANG</span>"
                elif ssl_days <= 14:
                    ssl_badge = "<span class='badge badge-med'>PERLU PERPANJANGAN</span>"
                else:
                    ssl_badge = "<span class='badge badge-pass'>AMAN</span>"
            else:
                ssl_text = "N/A"
                ssl_badge = "<span class='badge badge-low'>TIDAK TERDETEKSI</span>"

            # Check HTTP status
            if str(code) in ("200", "301", "302") or "uptime" in str(code):
                st_badge = "<span class='badge badge-pass'>ONLINE</span>"
            else:
                st_badge = "<span class='badge badge-crit'>KENDALA</span>"

            out.append(
                f"<tr>"
                f"<td><strong>{dom}</strong></td>"
                f"<td>{code} ({st_badge})</td>"
                f"<td>{resp_ms}</td>"
                f"<td>{ssl_text}</td>"
                f"<td>{ssl_badge}</td>"
                f"</tr>"
            )
        out.append("</tbody></table>")

    # Footer
    out.append(
        "<div class='footer'>"
        "Sistem Pemantauan Server Otomatis (SHSM) &bull; GM Teknologi &bull; Waktu Indonesia Barat (WIB)<br/>"
        "<small>Laporan ini dihasilkan secara otomatis untuk memudahkan pemantauan kesehatan serta keamanan infrastruktur server.</small>"
        "</div>"
    )
    out.append("</div></body></html>")
    return "\n".join(out)

