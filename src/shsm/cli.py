"""SHSM CLI entrypoint and command routing."""

from __future__ import annotations

import json
import sys
from typing import Optional

import click
import yaml

from shsm import __version__
from shsm.config import load_config
from shsm.core.context import Context
from shsm.core.findings import CollectorOutput
from shsm.core.runner import RunnerEngine
from shsm.database.connection import Database
from shsm.logging_config import setup_logging


def get_context(config_path: Optional[str] = None) -> Context:
    cfg = load_config(config_path)
    db = Database(cfg.db_path)
    # Ensure migrations are applied on start
    try:
        db.migrate()
    except Exception:
        pass
    setup_logging(
        level=cfg.get("general.log_level", "INFO"),
        log_dir=str(cfg.get("paths.log_dir")),
        secrets=cfg.secret_values(),
        console=False,
    )
    return Context(cfg, db)


@click.group()
@click.version_option(version=__version__, prog_name="Server Health & Security Monitoring (SHSM)")
@click.option("--config", "-c", "config_path", help="Path to config.yaml file", type=click.Path())
@click.pass_context
def main(ctx: click.Context, config_path: Optional[str]) -> None:
    """SHSM - Production Server Health & Security Monitoring CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


# ---------------------------------------------------------------- status & doctor
@main.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output status as JSON")
@click.pass_context
def cmd_status(click_ctx: click.Context, as_json: bool) -> None:
    """Show overall server health and security scores, services, and open findings."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.reporting.scoring import compute_scores

    scores = compute_scores(app_ctx)
    open_findings = app_ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"])
    services = app_ctx.inventory.latest_services()
    active_sites = app_ctx.inventory.active_websites()

    if as_json:
        click.echo(json.dumps({
            "scores": scores,
            "findings_count": len(open_findings),
            "services_count": len(services),
            "websites_count": len(active_sites),
        }, indent=2))
        return

    click.secho("==================================================", fg="cyan", bold=True)
    click.secho(f" SHSM SERVER STATUS (v{__version__})", fg="cyan", bold=True)
    click.secho("==================================================", fg="cyan", bold=True)
    click.echo(f"Health Score:   {scores['health_score']:.1f}/100  (Coverage: {scores['health_coverage']:.0f}%)")
    click.echo(f"Security Score: {scores['security_score']:.1f}/100  (Coverage: {scores['security_coverage']:.0f}%)")
    click.echo(f"Open Findings:  {len(open_findings)}")
    click.echo(f"Websites Monitored: {len(active_sites)}")
    click.echo("--------------------------------------------------")
    click.secho("Subsystems:", bold=True)
    for _comp, d in scores["components"].items():
        sc = d["score"]
        col = "green" if sc >= 90 else ("yellow" if sc >= 75 else "red")
        click.echo(f"  - {d['label']:<26} Score: ", nl=False)
        click.secho(f"{sc:5.1f}", fg=col, bold=True, nl=False)
        click.echo(f"  (Coverage: {d['coverage']:.0f}%, Issues: {d['open_findings']})")

    if open_findings:
        click.echo("--------------------------------------------------")
        click.secho("Top Active Issues:", fg="yellow", bold=True)
        for f in open_findings[:10]:
            sev_col = "red" if f["severity"] == "CRITICAL" else ("yellow" if f["severity"] == "HIGH" else "white")
            click.secho(f"  [{f['severity']}] ", fg=sev_col, bold=True, nl=False)
            click.echo(f"{f['title']} (Asset: {f['asset'] or 'Server'})")


@main.command("doctor")
@click.pass_context
def cmd_doctor(click_ctx: click.Context) -> None:
    """Check prerequisites, permissions, binaries, systemd timers, and database health."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    runner = app_ctx.runner
    click.secho("Running SHSM preflight diagnostics...", bold=True)

    # 1. Config validation
    val = app_ctx.config.validation
    if val.ok:
        click.secho("  [PASS] Configuration syntax and values valid", fg="green")
    else:
        click.secho(f"  [FAIL] Configuration errors: {val.errors}", fg="red")

    # 2. Secret permissions
    sec_errs = app_ctx.config.check_secret_permissions()
    if not sec_errs:
        click.secho("  [PASS] Secret file permissions secure (0600 / root)", fg="green")
    else:
        for se in sec_errs:
            click.secho(f"  [WARN] {se}", fg="yellow")

    # 3. Database check
    qcheck = app_ctx.db.quick_check()
    if qcheck == "ok":
        click.secho("  [PASS] SQLite database integrity ok (WAL mode enabled)", fg="green")
    else:
        click.secho(f"  [FAIL] SQLite database integrity check: {qcheck}", fg="red")

    # 4. Binaries check
    tools = ["systemctl", "mariadb", "mysql", "wp", "clamscan", "lynis", "rkhunter", "ufw"]
    for t in tools:
        p = runner.which(t)
        if p:
            click.secho(f"  [PASS] Found binary {t} at {p}", fg="green")
        else:
            click.secho(f"  [INFO] Optional tool {t} not found in PATH", fg="white")


# ---------------------------------------------------------------- config
@main.group("config")
def grp_config() -> None:
    """Manage and inspect configuration."""


@grp_config.command("validate")
@click.pass_context
def cmd_config_validate(click_ctx: click.Context) -> None:
    """Validate YAML configuration file."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    val = app_ctx.config.validation
    if val.ok:
        click.secho("Configuration is valid.", fg="green")
        if val.warnings:
            click.secho("Warnings:", fg="yellow")
            for w in val.warnings:
                click.echo(f"  - {w}")
    else:
        click.secho("Configuration validation failed:", fg="red", bold=True)
        for e in val.errors:
            click.secho(f"  - {e}", fg="red")
        sys.exit(1)


@grp_config.command("show")
@click.option("--redacted", is_flag=True, default=True, help="Redact all passwords and secrets (always enforced)")
@click.pass_context
def cmd_config_show(click_ctx: click.Context, redacted: bool) -> None:
    """Display active configuration with secrets strictly redacted."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    data = app_ctx.config.redacted()
    click.echo(yaml.safe_dump(data, sort_keys=False))


# ---------------------------------------------------------------- collect
@main.group("collect")
def grp_collect() -> None:
    """Run metric and status collectors."""


@grp_collect.command("health")
@click.pass_context
def cmd_collect_health(click_ctx: click.Context) -> None:
    """Collect CPU, RAM, swap, disk, process, and network metrics."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)

    def _do():
        from shsm.collectors import cpu, disk, memory, network, process

        out = CollectorOutput()
        sampler = process.ProcessSampler()
        sampler.prime()

        out_cpu = cpu.collect(app_ctx, sampler, interval=1.0)
        prows = out_cpu.meta.get("process_rows", [])
        out.merge(out_cpu)
        out.merge(memory.collect(app_ctx, prows))
        out.merge(disk.collect(app_ctx))
        out.merge(process.collect_processes(app_ctx, prows))
        out.merge(network.collect(app_ctx))
        return out

    code, out = engine.run_job("health", _do)
    click.secho(f"Health collection finished: {len(out.metrics)} metrics, {len(out.checks)} checks.", fg="green" if code == 0 else "yellow")


@grp_collect.command("services")
@click.pass_context
def cmd_collect_services(click_ctx: click.Context) -> None:
    """Monitor systemd services (OpenLiteSpeed, MariaDB, Redis, SSH, Fail2Ban)."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.collectors import services

    code, out = engine.run_job("services", lambda: services.collect(app_ctx))
    click.secho(f"Service collection finished: {len(out.checks)} units checked.", fg="green" if code == 0 else "yellow")


@grp_collect.command("databases")
@click.pass_context
def cmd_collect_databases(click_ctx: click.Context) -> None:
    """Run lightweight MariaDB and Redis monitoring checks."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)

    def _do():
        from shsm.collectors import mariadb, redis

        out = CollectorOutput()
        out.merge(mariadb.collect(app_ctx))
        out.merge(redis.collect(app_ctx))
        return out

    code, out = engine.run_job("databases", _do)
    click.secho("Database collection finished.", fg="green" if code == 0 else "yellow")


@grp_collect.command("openlitespeed")
@click.pass_context
def cmd_collect_openlitespeed(click_ctx: click.Context) -> None:
    """Incremental OpenLiteSpeed access and error log parser."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.collectors import openlitespeed

    code, out = engine.run_job("openlitespeed", lambda: openlitespeed.collect(app_ctx))
    click.secho("OpenLiteSpeed log processing finished.", fg="green" if code == 0 else "yellow")


# ---------------------------------------------------------------- websites
@main.group("websites")
def grp_websites() -> None:
    """Manage and check websites and SSL certificates."""


@grp_websites.command("discover")
@click.pass_context
def cmd_websites_discover(click_ctx: click.Context) -> None:
    """Discover websites from CyberPanel database, OpenLiteSpeed vhosts, and /home."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.discovery.cyberpanel import discover_websites

    sites = discover_websites(app_ctx)
    res = app_ctx.inventory.sync_websites(sites, app_ctx.now())
    click.secho(f"Discovered {res['active']} active website(s) ({res['added']} newly added, {res['removed']} removed).", fg="green")
    for s in sites:
        click.echo(f"  - {s['domain']:<30} Root: {s['doc_root']}")


@grp_websites.command("check")
@click.option("--ssl-only", is_flag=True, help="Run only SSL certificate checks")
@click.option("--no-ssl", is_flag=True, help="Skip SSL certificate checks")
@click.pass_context
def cmd_websites_check(click_ctx: click.Context, ssl_only: bool, no_ssl: bool) -> None:
    """Check website DNS, HTTP response times, and TLS certificates."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)

    def _do():
        out = CollectorOutput()
        if not ssl_only:
            from shsm.collectors import websites
            out.merge(websites.collect(app_ctx))
        if not no_ssl:
            from shsm.collectors import ssl
            out.merge(ssl.collect(app_ctx))
        return out

    job_name = "websites-ssl" if ssl_only else "websites-check"
    code, out = engine.run_job(job_name, _do)
    click.secho(f"Website checks finished ({len(out.checks)} check results).", fg="green" if code == 0 else "yellow")


# ---------------------------------------------------------------- wordpress
@main.group("wordpress")
def grp_wordpress() -> None:
    """Discover and audit WordPress installations."""


@grp_wordpress.command("discover")
@click.pass_context
def cmd_wordpress_discover(click_ctx: click.Context) -> None:
    """Discover WordPress sites in document roots."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.discovery.wordpress import discover_wordpress_sites

    sites = discover_wordpress_sites(app_ctx)
    res = app_ctx.inventory.sync_wordpress_sites(sites, app_ctx.now())
    click.secho(f"Discovered {res['active']} WordPress site(s).", fg="green")
    for s in sites:
        owner_info = f"owner: {s['owner']}" if s['is_safe_owner'] else "UNSAFE OWNER"
        click.echo(f"  - {s['domain']:<25} WP {s.get('wp_version') or '?'} in {s['path']} ({owner_info})")


@grp_wordpress.command("audit")
@click.pass_context
def cmd_wordpress_audit(click_ctx: click.Context) -> None:
    """Audit WordPress core, plugins, themes, and administrators via WP-CLI."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.security import wordpress

    code, out = engine.run_job("wordpress-audit", lambda: wordpress.audit_all(app_ctx))
    click.secho("WordPress audit completed.", fg="green" if code == 0 else "yellow")


# ---------------------------------------------------------------- security
@main.group("security")
def grp_security() -> None:
    """Host security auditing and malware scanning."""


@grp_security.command("scan")
@click.option("--profile", type=click.Choice(["quick", "full"]), default="quick", help="Scan profile")
@click.option("--only", help="Comma-separated list of scanners to run (heuristic, clamav, lynis, rootkit)")
@click.pass_context
def cmd_security_scan(click_ctx: click.Context, profile: str, only: Optional[str]) -> None:
    """Run malware, ClamAV, Lynis, and rootkit scans."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    targets = [s.strip().lower() for s in only.split(",")] if only else ["heuristic", "clamav", "lynis", "rootkit"]

    def _do():
        out = CollectorOutput()
        if "heuristic" in targets:
            from shsm.security import malware
            out.merge(malware.scan(app_ctx, profile=profile))
        if "clamav" in targets:
            from shsm.security import clamav
            out.merge(clamav.scan(app_ctx, profile=profile))
        if "lynis" in targets:
            from shsm.security import lynis
            out.merge(lynis.scan(app_ctx))
        if "rootkit" in targets:
            from shsm.security import rootkit
            out.merge(rootkit.scan(app_ctx))
        return out

    job_name = f"scan-{profile}"
    code, out = engine.run_job(job_name, _do, profile=profile)
    click.secho(f"Security scan ({profile}) finished: {len(out.findings)} finding(s).", fg="green" if code == 0 else "yellow")


@grp_security.command("audit")
@click.option("--scope", type=click.Choice(["host", "logs"]), default="host", help="Audit scope")
@click.pass_context
def cmd_security_audit(click_ctx: click.Context, scope: str) -> None:
    """Run SSH config, authentication log, firewall, and Fail2Ban audits."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)

    def _do():
        out = CollectorOutput()
        if scope == "logs":
            from shsm.security import ssh
            out.merge(ssh.collect(app_ctx))
        else:
            from shsm.security import fail2ban, firewall, ssh, vulnerability
            out.merge(ssh.collect(app_ctx))
            out.merge(firewall.collect(app_ctx))
            out.merge(fail2ban.collect(app_ctx))
            out.merge(vulnerability.check_vulnerabilities(app_ctx))
        return out

    code, out = engine.run_job(f"audit-{scope}", _do)
    click.secho(f"Security audit ({scope}) completed.", fg="green" if code == 0 else "yellow")


# ---------------------------------------------------------------- integrity
@main.group("integrity")
def grp_integrity() -> None:
    """File and system integrity monitoring (FIM)."""


@grp_integrity.command("status")
@click.pass_context
def cmd_integrity_status(click_ctx: click.Context) -> None:
    """Show current integrity baseline count and open integrity events."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    b_count = app_ctx.integrity.baseline_count()
    events = app_ctx.integrity.open_events()
    click.echo(f"Monitored Baseline Files: {b_count}")
    click.echo(f"Open Integrity Events:    {len(events)}")
    for ev in events:
        click.secho(f"  [{ev['severity']}] {ev['change_type']} on {ev['path']}", fg="red" if ev['severity'] == 'CRITICAL' else "yellow")


@grp_integrity.command("baseline")
@click.option("--review", is_flag=True, help="Review and build baseline interactively")
@click.option("--update", is_flag=True, help="Update baseline with current file state")
@click.pass_context
def cmd_integrity_baseline(click_ctx: click.Context, review: bool, update: bool) -> None:
    """Build or update file integrity baseline (explicit admin action)."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.security import integrity

    if not review and not update:
        click.secho("Specify --review or --update to build/modify the baseline.", fg="yellow")
        return

    count = integrity.build_or_update_baseline(app_ctx)
    app_ctx.runs.audit("admin", "BASELINE_UPDATE", "integrity", {"file_count": count}, app_ctx.now())
    click.secho(f"Successfully recorded integrity baseline for {count} path(s).", fg="green")


@grp_integrity.command("check")
@click.pass_context
def cmd_integrity_check(click_ctx: click.Context) -> None:
    """Check current file state against baseline."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.security import integrity

    code, out = engine.run_job("integrity", lambda: integrity.check(app_ctx))
    click.secho("Integrity check finished.", fg="green" if code == 0 else "yellow")


# ---------------------------------------------------------------- alerts & notifications
@main.group("alerts")
def grp_alerts() -> None:
    """Manage incident alerts."""


@grp_alerts.command("list")
@click.pass_context
def cmd_alerts_list(click_ctx: click.Context) -> None:
    """List recent and active alerts."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    alerts = app_ctx.alerts.all(limit=50)
    if not alerts:
        click.echo("No alerts recorded.")
        return
    for a in alerts:
        st_col = "red" if a["state"] == "ACTIVE" else "green"
        click.secho(f"[{a['state']}] ", fg=st_col, bold=True, nl=False)
        click.echo(f"[{a['severity']}] {a['title']} (notified {a['notify_count']} times, last: {a['last_notified_at']})")


@grp_alerts.command("test")
@click.pass_context
def cmd_alerts_test(click_ctx: click.Context) -> None:
    """Send test alert email to configured recipients."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.core.findings import Confidence, FindingCandidate, Severity
    from shsm.notifications.alerts import AlertManager

    mgr = AlertManager(app_ctx)
    test_cand = FindingCandidate(
        check_id="test.alert",
        category="health",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        title="Test Critical Alert from SHSM",
        evidence="Manual verification triggered via 'shsm alerts test'.",
        recommendation="No action needed. This confirms the alert pipeline is operational.",
        asset="localhost",
        source="cli_test",
    )
    res = mgr.process_findings([test_cand], [])
    click.secho(f"Alert test result: {res}", fg="green" if res["alerts_dispatched"] > 0 else "red")


# ---------------------------------------------------------------- email & external
@main.group("email")
def grp_email() -> None:
    """Email configuration and delivery test."""


@grp_email.command("test")
@click.pass_context
def cmd_email_test(click_ctx: click.Context) -> None:
    """Test SMTP connection and send a test email to default recipient."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.notifications.smtp import SMTPTransport

    transport = SMTPTransport(app_ctx)
    recipients = list(app_ctx.config.get("email.recipients", ["rohmataliwardani@gmail.com"]))
    click.echo(f"Sending test email to: {', '.join(recipients)}...")
    ok, attempts, err = transport.send_email(
        subject="[TEST] SHSM Monitor Email Verification",
        html_body="<h3>SHSM SMTP Test Succeeded</h3><p>Your server monitoring SMTP transport is functioning correctly.</p>",
        recipients=recipients,
    )
    if ok:
        click.secho(f"Test email successfully sent (attempts: {attempts}).", fg="green")
    else:
        click.secho(f"Failed to send email: {err}", fg="red")
        sys.exit(1)


@main.group("external")
def grp_external() -> None:
    """External monitoring heartbeat."""


@grp_external.command("test")
@click.pass_context
def cmd_external_test(click_ctx: click.Context) -> None:
    """Send a test heartbeat to the independent monitoring provider."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.notifications.external import send_heartbeat

    ok, attempts, err = send_heartbeat(app_ctx)
    if ok:
        click.secho("Heartbeat successfully accepted by external provider.", fg="green")
    else:
        click.secho(f"Heartbeat failed: {err}", fg="red")
        sys.exit(1)


@grp_external.command("send")
@click.pass_context
def cmd_external_send(click_ctx: click.Context) -> None:
    """Scheduled heartbeat send."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.notifications.external import send_heartbeat

    ok, attempts, err = send_heartbeat(app_ctx)
    if not ok:
        click.secho(f"Heartbeat error: {err}", fg="yellow")


# ---------------------------------------------------------------- reports
@main.group("report")
def grp_report() -> None:
    """Generate weekly and monthly reports."""


@grp_report.command("weekly")
@click.option("--preview", is_flag=True, help="Generate HTML and PDF without sending email")
@click.option("--send", is_flag=True, help="Generate and send report via email with PDF attached")
@click.pass_context
def cmd_report_weekly(click_ctx: click.Context, preview: bool, send: bool) -> None:
    """Generate weekly HTML & PDF report."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.reporting.weekly import generate_weekly_report

    html_p, pdf_p, r_id = generate_weekly_report(app_ctx, send_email=send)
    click.secho(f"Weekly report generated (ID: {r_id}):", fg="green")
    click.echo(f"  HTML: {html_p}")
    click.echo(f"  PDF:  {pdf_p}")
    if send:
        click.secho("  Report sent to email recipients.", fg="green")


@grp_report.command("monthly")
@click.option("--preview", is_flag=True, help="Generate HTML and PDF without sending email")
@click.option("--send", is_flag=True, help="Generate and send report via email with PDF attached")
@click.pass_context
def cmd_report_monthly(click_ctx: click.Context, preview: bool, send: bool) -> None:
    """Generate monthly HTML & PDF report."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.reporting.monthly import generate_monthly_report

    html_p, pdf_p, r_id = generate_monthly_report(app_ctx, send_email=send)
    click.secho(f"Monthly report generated (ID: {r_id}):", fg="green")
    click.echo(f"  HTML: {html_p}")
    click.echo(f"  PDF:  {pdf_p}")
    if send:
        click.secho("  Report sent to email recipients.", fg="green")


# ---------------------------------------------------------------- database & retention
@main.group("db")
def grp_db() -> None:
    """Database administration and migrations."""


@grp_db.command("migrate")
@click.pass_context
def cmd_db_migrate(click_ctx: click.Context) -> None:
    """Apply pending database migrations."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    applied = app_ctx.db.migrate()
    if applied:
        click.secho(f"Applied migrations: {applied}", fg="green")
    else:
        click.secho("Database schema is up to date.", fg="green")


@grp_db.command("status")
@click.pass_context
def cmd_db_status(click_ctx: click.Context) -> None:
    """Check database schema version and integrity."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    version = app_ctx.db.current_version()
    check = app_ctx.db.quick_check()
    click.echo(f"Database Path:    {app_ctx.db.path}")
    click.echo(f"Current Version:  {version}")
    click.echo(f"Integrity Check:  {check}")


@grp_db.command("backup")
@click.pass_context
def cmd_db_backup(click_ctx: click.Context) -> None:
    """Create a verified consistent SQLite snapshot backup."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.core.retention import perform_database_backup

    dest = perform_database_backup(app_ctx)
    click.secho(f"Database backed up successfully to: {dest}", fg="green")


# Alias 'database' to 'db'
main.add_command(grp_db, "database")


@main.group("retention")
def grp_retention() -> None:
    """Manage metric rollups and data purging."""


@grp_retention.command("run")
@click.pass_context
def cmd_retention_run(click_ctx: click.Context) -> None:
    """Execute rollups and purge expired samples per retention policy."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.core.retention import run_retention_and_rollups

    res = run_retention_and_rollups(app_ctx)
    click.secho(f"Retention run completed: {res}", fg="green")


if __name__ == "__main__":
    main()
