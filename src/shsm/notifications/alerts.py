"""Alert management: deduplication, cooldown, grouping, recovery alerts, and email delivery."""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Sequence

from shsm.core.context import Context
from shsm.core.findings import FindingCandidate, Severity
from shsm.core.timeutils import from_iso
from shsm.notifications.smtp import SMTPTransport

CRITICAL_CHECK_IDS = {
    "service.openlitespeed",
    "service.mariadb",
    "mariadb.status",
    "cpu.usage",
    "disk.usage",
    "memory.available",
    "malware.heuristic",
    "clamav.malware",
    "integrity.modified",
    "ssl.certificate",
    "website.http",
    "website.dns",
}


class AlertManager:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.transport = SMTPTransport(ctx)

    def process_findings(
        self,
        new_findings: Sequence[FindingCandidate],
        resolved_finding_ids: Sequence[int],
    ) -> Dict[str, Any]:
        """Evaluate new/open findings against cooldown and thresholds, dispatching grouped alerts."""
        now = self.ctx.now()
        cooldown_min = int(self.ctx.config.get("alerts.cooldown_minutes", 60))
        min_sev_str = str(self.ctx.config.get("alerts.min_severity", "CRITICAL"))
        min_sev = getattr(Severity, min_sev_str, Severity.CRITICAL)

        to_alert: List[FindingCandidate] = []

        for cand in new_findings:
            if cand.severity.rank < min_sev.rank:
                continue

            fp = cand.fingerprint
            existing = self.ctx.alerts.get(fp)

            if not existing:
                # First time alerting
                to_alert.append(cand)
                self.ctx.alerts.activate(fp, None, cand.severity.value, cand.category, cand.title, now)
            else:
                last_time = from_iso(existing["last_notified_at"])
                if (now - last_time).total_seconds() >= cooldown_min * 60:
                    to_alert.append(cand)
                    self.ctx.alerts.touch(fp, now)

        # Dispatch alert email if any
        dispatched_count = 0
        if to_alert:
            dispatched_count = self._send_grouped_alert(to_alert)

        # Handle recovery notifications
        recovered_count = 0
        if self.ctx.config.get("alerts.recovery_notifications", True) and resolved_finding_ids:
            recovered_count = self._process_recoveries(resolved_finding_ids)

        return {
            "alerts_dispatched": dispatched_count,
            "recoveries_sent": recovered_count,
        }

    def _send_grouped_alert(self, findings: List[FindingCandidate]) -> int:
        now = self.ctx.now()
        hostname = socket.gethostname()
        subject = f"[CRITICAL][{hostname}] Server Monitoring Alert - {len(findings)} incident(s)"

        html_lines = [
            f"<h2>CRITICAL Monitoring Alert - {hostname}</h2>",
            f"<p>Detected <strong>{len(findings)}</strong> critical security/health incident(s) at {now.strftime('%Y-%m-%d %H:%M:%S UTC')}:</p>",
            "<ul>",
        ]

        fingerprints = []
        for f in findings:
            fingerprints.append(f.fingerprint)
            html_lines.append(
                f"<li><strong>[{f.severity.value}] {f.title}</strong><br/>"
                f"<em>Asset:</em> {f.asset or 'Server Host'}<br/>"
                f"<em>Evidence:</em> {f.evidence}<br/>"
                f"<em>Recommendation:</em> {f.recommendation}</li>"
            )
        html_lines.append("</ul>")
        html_lines.append("<p>Please log in via SSH or check <code>shsm status</code> for full details.</p>")
        html_body = "\n".join(html_lines)

        recipients = list(self.ctx.config.get("email.recipients", ["rohmataliwardani@gmail.com"]))
        ok, attempts, err = self.transport.send_email(subject, html_body, recipients=recipients)

        status_str = "SENT" if ok else "FAILED"
        self.ctx.alerts.add_delivery(now, "CRITICAL_ALERT", subject, recipients, status_str, attempts, err, fingerprints)
        return len(findings) if ok else 0

    def _process_recoveries(self, resolved_ids: Sequence[int]) -> int:
        now = self.ctx.now()
        hostname = socket.gethostname()
        recovered_findings = []

        for fid in resolved_ids:
            f = self.ctx.findings.by_id(fid)
            if not f:
                continue
            fp = f["fingerprint"]
            alert_row = self.ctx.alerts.get(fp)
            if alert_row and alert_row["state"] == "ACTIVE":
                self.ctx.alerts.recover(fp, now)
                recovered_findings.append(f)

        if not recovered_findings:
            return 0

        subject = f"[RECOVERED][{hostname}] Server Alert Resolved - {len(recovered_findings)} issue(s)"
        html_lines = [
            f"<h2>Alert Resolved / Recovered - {hostname}</h2>",
            f"<p>The following <strong>{len(recovered_findings)}</strong> previously alerted incident(s) returned to healthy status:</p>",
            "<ul>",
        ]
        for f in recovered_findings:
            html_lines.append(f"<li><strong>[{f['severity']}] {f['title']}</strong> (Asset: {f['asset'] or 'Server'})</li>")
        html_lines.append("</ul>")
        html_body = "\n".join(html_lines)

        recipients = list(self.ctx.config.get("email.recipients", ["rohmataliwardani@gmail.com"]))
        ok, attempts, err = self.transport.send_email(subject, html_body, recipients=recipients)
        self.ctx.alerts.add_delivery(now, "RECOVERY_ALERT", subject, recipients, "SENT" if ok else "FAILED", attempts, err, [f["fingerprint"] for f in recovered_findings])
        return len(recovered_findings) if ok else 0
