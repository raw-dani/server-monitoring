"""SHSM CLI entrypoint and command routing."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

import click
import yaml

from shsm import __version__
from shsm.config import load_config
from shsm.core.context import Context
from shsm.core.findings import CollectorOutput
from shsm.core.runner import RunnerEngine
from shsm.database.connection import Database
from shsm.logging_config import setup_logging


def get_context(config_path: Optional[str] = None, require_db: bool = True) -> Context:
    cfg = load_config(config_path)
    if require_db:
        db = Database(cfg.db_path)
        # Ensure migrations are applied only if database is newly initialized
        try:
            import os
            if not os.path.exists(cfg.db_path) or os.path.getsize(cfg.db_path) == 0:
                db.migrate()
        except Exception:
            pass
    else:
        # Use an in-memory database instance so that commands not needing historical
        # state (such as 'blocked', 'ban', 'unban') never block on SQLite file locks.
        db = Database(":memory:")

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


@grp_collect.command("mail")
@click.pass_context
def cmd_collect_mail(click_ctx: click.Context) -> None:
    """Monitor Postfix mail queue and detect unauthorized outbound SMTP connections."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.collectors import mail_queue

    code, out = engine.run_job("mail", lambda: mail_queue.collect(app_ctx))
    click.secho(f"Mail queue collection finished: {len(out.metrics)} metric(s), {len(out.checks)} check(s).",
                fg="green" if code == 0 else "yellow")


@grp_collect.command("ddos")
@click.pass_context
def cmd_collect_ddos(click_ctx: click.Context) -> None:
    """Monitor concurrent web sockets and detect SYN/HTTP floods."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.collectors import ddos

    code, out = engine.run_job("ddos", lambda: ddos.collect(app_ctx))
    click.secho(f"DDoS connection inspection finished: {len(out.findings)} finding(s).",
                fg="green" if code == 0 else "yellow")




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


@grp_websites.command("list")
@click.pass_context
def cmd_websites_list(click_ctx: click.Context) -> None:
    """List all registered websites with their latest HTTP and SSL status."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    items = app_ctx.inventory.latest_website_status()
    if not items:
        click.secho("No active websites registered in inventory. Run 'shsm websites discover' first.", fg="yellow")
        return

    click.secho(f"=== Monitored Websites ({len(items)} Active) ===", bold=True)
    click.echo(f"{'Domain':<28} {'HTTP Status':<14} {'Resp Time':<12} {'SSL Expiry':<18} {'Doc Root'}")
    click.echo("-" * 95)
    for it in items:
        dom = it["domain"]
        chk = it.get("last_check")
        ssl_info = it.get("last_ssl")

        if chk:
            code = chk.get("status_code")
            is_ok = bool(chk.get("ok"))
            if is_ok:
                http_status = f"{code} OK" if code else "OK"
                http_col = "green"
            else:
                http_status = f"{code} FAIL" if code else "FAILED"
                http_col = "red"
            ms_val = chk.get("response_ms")
            resp_str = f"{ms_val:.0f} ms" if ms_val is not None else "-"
        else:
            http_status = "Not Checked"
            http_col = "yellow"
            resp_str = "-"

        if ssl_info:
            days = ssl_info.get("days_remaining")
            if days is not None:
                days_int = int(days)
                ssl_str = f"{days_int}d remaining"
                ssl_col = "green" if days_int > 14 else "yellow" if days_int > 0 else "red"
            else:
                ssl_str = "Error"
                ssl_col = "red"
        else:
            ssl_str = "-"
            ssl_col = "white"

        root = it.get("doc_root") or "-"
        click.echo(f"{dom:<28} ", nl=False)
        click.secho(f"{http_status:<14} ", fg=http_col, nl=False)
        click.echo(f"{resp_str:<12} ", nl=False)
        click.secho(f"{ssl_str:<18} ", fg=ssl_col, nl=False)
        click.echo(f"{root}")


@grp_websites.command("remove")
@click.argument("domain")
@click.pass_context
def cmd_websites_remove(click_ctx: click.Context, domain: str) -> None:
    """Remove a website from active monitoring inventory."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    from shsm.core.timeutils import to_iso
    ts = to_iso(app_ctx.now())
    row = app_ctx.db.query_one("SELECT id FROM websites WHERE domain=?", (domain.strip().lower(),))
    if not row:
        click.secho(f"Website '{domain}' not found in inventory.", fg="yellow")
        return
    app_ctx.db.execute("UPDATE websites SET removed_at=? WHERE id=?", (ts, row["id"]))
    click.secho(f"[SUCCESS] Website '{domain}' has been removed from active monitoring.", fg="green")


@grp_websites.command("cleanup")
@click.option("--suspended/--no-suspended", "suspended", default=True, help="Remove domains containing '-suspended' (default: True)")
@click.option("--mail/--no-mail", "mail", default=True, help="Remove mail.* and webmail.* subdomains (default: True)")
@click.option("--failed", is_flag=True, help="Remove domains whose latest HTTP status is FAILED or has DNS error")
@click.option("--all-junk", is_flag=True, help="Remove suspended, mail subdomains, AND all FAILED domains in 1 go")
@click.option("--pattern", default=None, help="Regex pattern of domain names to remove (e.g. '\\.xyz$')")
@click.option("--purge", is_flag=True, help="Permanently delete from database instead of soft-delete")
@click.option("--dry-run", is_flag=True, help="Preview domains to be removed without making changes")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def cmd_websites_cleanup(
    click_ctx: click.Context,
    suspended: bool,
    mail: bool,
    failed: bool,
    all_junk: bool,
    pattern: Optional[str],
    purge: bool,
    dry_run: bool,
    yes: bool,
) -> None:
    """Batch clean up unused, suspended, mail subdomains, or dead websites in 1 command."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    items = app_ctx.inventory.latest_website_status()
    if not items:
        click.secho("No active websites registered in inventory.", fg="yellow")
        return

    if all_junk:
        suspended = True
        mail = True
        failed = True

    import re
    compiled_pattern = re.compile(pattern, re.IGNORECASE) if pattern else None

    candidates: List[tuple[Dict[str, Any], str]] = []
    for it in items:
        dom = it["domain"].lower()
        reasons = []

        if suspended and ("-suspended" in dom or dom.endswith(".suspended")):
            reasons.append("suspended vhost")
        if mail and (dom.startswith("mail.") or dom.startswith("webmail.")):
            reasons.append("mail/webmail subdomain")
        if failed:
            chk = it.get("last_check")
            if chk:
                if not chk.get("ok"):
                    err_msg = chk.get("error") or chk.get("status_code") or "down"
                    reasons.append(f"check failed ({err_msg})")
        if compiled_pattern and compiled_pattern.search(dom):
            reasons.append(f"matched pattern '{pattern}'")

        if reasons:
            candidates.append((it, ", ".join(reasons)))

    if not candidates:
        click.secho("No domains matched the cleanup criteria.", fg="green")
        return

    click.secho(f"=== Websites Cleanup Candidates ({len(candidates)} of {len(items)} websites) ===", bold=True)
    click.echo(f"{'Domain':<38} {'Reason':<35} {'Latest Status'}")
    click.echo("-" * 92)
    for it, reason in candidates:
        dom = it["domain"]
        chk = it.get("last_check")
        if chk:
            code = chk.get("status_code")
            st = f"{code} OK" if chk.get("ok") else (f"{code} FAIL" if code else "FAILED")
            col = "green" if chk.get("ok") else "red"
        else:
            st = "Not Checked"
            col = "yellow"
        click.echo(f"{dom:<38} {reason:<35} ", nl=False)
        click.secho(st, fg=col)

    click.echo("-" * 92)
    click.echo(f"Total to remove: {len(candidates)} | Active remaining: {len(items) - len(candidates)}")

    if dry_run:
        click.secho("\n[DRY RUN] No changes were made to inventory. Run without --dry-run to execute cleanup.", fg="cyan", bold=True)
        return

    if not yes:
        if not click.confirm(f"\nAre you sure you want to remove these {len(candidates)} domain(s)?", default=True):
            click.secho("Operation cancelled.", fg="yellow")
            return

    from shsm.core.timeutils import to_iso
    ts = to_iso(app_ctx.now())
    ids = [it["id"] for it, _ in candidates]

    with app_ctx.db.transaction():
        batch_size = 400
        for i in range(0, len(ids), batch_size):
            chunk = ids[i : i + batch_size]
            placeholders = ",".join("?" for _ in chunk)
            if purge:
                app_ctx.db.execute(f"DELETE FROM website_checks WHERE website_id IN ({placeholders})", tuple(chunk))
                app_ctx.db.execute(f"DELETE FROM ssl_certificates WHERE domain IN (SELECT domain FROM websites WHERE id IN ({placeholders}))", tuple(chunk))
                app_ctx.db.execute(f"DELETE FROM websites WHERE id IN ({placeholders})", tuple(chunk))
            else:
                app_ctx.db.execute(f"UPDATE websites SET removed_at=? WHERE id IN ({placeholders})", (ts,) + tuple(chunk))

    action_label = "purged permanently from database" if purge else "marked as removed from active monitoring"
    click.secho(f"\n[SUCCESS] Successfully {action_label} for {len(candidates)} domain(s).", fg="green", bold=True)
    click.echo(f"Active websites remaining: {len(items) - len(candidates)}")




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
            from shsm.security import fail2ban, firewall, php_audit, ssh, vulnerability
            out.merge(ssh.collect(app_ctx))
            out.merge(firewall.collect(app_ctx))
            out.merge(fail2ban.collect(app_ctx))
            out.merge(php_audit.collect(app_ctx))
            out.merge(vulnerability.check_vulnerabilities(app_ctx))
        return out

    code, out = engine.run_job(f"audit-{scope}", _do)
    click.secho(f"Security audit ({scope}) completed.", fg="green" if code == 0 else "yellow")


@grp_security.command("rbl")
@click.pass_context
def cmd_security_rbl(click_ctx: click.Context) -> None:
    """Check server public IP reputation across major DNSBL/RBL spam blocklists."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.security import rbl

    code, out = engine.run_job("security-rbl", lambda: rbl.scan(app_ctx))
    click.secho(f"RBL blacklist check completed: {len(out.findings)} finding(s).",
                fg="green" if code == 0 else "yellow")


@grp_security.command("ols-ddos")
@click.pass_context
def cmd_security_ols_ddos(click_ctx: click.Context) -> None:
    """Audit OpenLiteSpeed anti-DDoS, client throttling, and bot challenge configuration."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    engine = RunnerEngine(app_ctx)
    from shsm.security import ols_anti_ddos

    code, out = engine.run_job("security-ols-ddos", lambda: ols_anti_ddos.scan(app_ctx))
    click.secho(f"OLS Anti-DDoS audit completed: {len(out.findings)} finding(s).",
                fg="green" if code == 0 else "yellow")




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


# ---------------------------------------------------------------- findings
@main.group("findings")
def grp_findings() -> None:
    """Inspect and resolve detected security or health findings."""


@grp_findings.command("list")
@click.option("--status", type=click.Choice(["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED", "ALL"]), default="OPEN", help="Filter by status")
@click.option("--category", help="Filter by category (health, security)")
@click.option("--limit", default=50, help="Max findings to show")
@click.pass_context
def cmd_findings_list(click_ctx: click.Context, status: str, category: Optional[str], limit: int) -> None:
    """List recorded findings."""
    app_ctx = get_context(click_ctx.obj.get("config_path"))
    statuses = None if status == "ALL" else [status]
    items = app_ctx.findings.list(statuses=statuses, category=category, limit=limit)
    if not items:
        click.echo(f"No findings matching status '{status}'.")
        return
    click.echo(f"Found {len(items)} finding(s):")
    for f in items:
        col = "red" if f["severity"] == "CRITICAL" else ("yellow" if f["severity"] == "HIGH" else "cyan")
        click.secho(f"[{f['status']}] [{f['severity']}] {f['title']} (Asset: {f['asset']})", fg=col)
        click.echo(f"  UID: {f['uid']} | Check: {f['check_id']} | Last seen: {f['last_seen']}")


@grp_findings.command("resolve")
@click.argument("ident")
@click.option("--note", default="Resolved by admin", help="Resolution note")
@click.pass_context
def cmd_findings_resolve(click_ctx: click.Context, ident: str, note: str) -> None:
    """Resolve a finding by UID, or resolve batch ('all-malware' / 'all')."""
    from shsm.core.findings import FindingStatus

    app_ctx = get_context(click_ctx.obj.get("config_path"))
    now = app_ctx.now()
    if ident == "all-malware":
        rows = app_ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"])
        resolved_count = 0
        for r in rows:
            if r["check_id"].startswith("malware"):
                app_ctx.findings.set_status(r["uid"], FindingStatus.RESOLVED, note, now)
                resolved_count += 1
        click.secho(f"Resolved {resolved_count} malware finding(s).", fg="green")
        return
    if ident == "all":
        rows = app_ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"])
        for r in rows:
            app_ctx.findings.set_status(r["uid"], FindingStatus.RESOLVED, note, now)
        click.secho(f"Resolved {len(rows)} finding(s).", fg="green")
        return

    ok = app_ctx.findings.set_status(ident, FindingStatus.RESOLVED, note, now)
    if ok:
        click.secho(f"Finding {ident} marked as RESOLVED.", fg="green")
    else:
        click.secho(f"Finding {ident} not found.", fg="red")


# ---------------------------------------------------------------- firewall & fail2ban actions
@main.command("blocked")
@click.argument("ip", required=False)
@click.option("--check", is_flag=True, help="Check if specific IP is blocked")
@click.pass_context
def cmd_blocked(click_ctx: click.Context, ip: str, check: bool) -> None:
    """Inspect blocked IPs across Fail2Ban and iptables centrally."""
    app_ctx = get_context(click_ctx.obj.get("config_path"), require_db=False)
    from shsm.security import blocked

    if ip or check:
        target_ip = ip or ""
        res = blocked.check_ip_blocked(app_ctx, target_ip)
        if res["is_blocked"]:
            click.secho(f"[BLOCKED] IP '{target_ip}' is CURRENTLY BLOCKED by {len(res['matches'])} rule(s):", fg="red", bold=True)
            for m in res["matches"]:
                matched_sub = f" (via subnet {m['matched_subnet']})" if "matched_subnet" in m else ""
                click.echo(f"  * Source: {m['source'].upper()} | Chain/Jail: {m['jail_or_chain']} | Target: {m['target']}{matched_sub} | Note: {m['note']}")
        else:
            click.secho(f"[ALLOWED] IP '{target_ip}' is NOT blocked in Fail2Ban or iptables.", fg="green", bold=True)
        return

    # List all blocked IPs and subnets
    items = blocked.list_all_blocked(app_ctx)
    f2b_count = sum(1 for x in items if x["source"] == "fail2ban")
    ipt_count = sum(1 for x in items if x["source"] == "iptables")

    click.secho(f"=== Centralized Blocked IPs & Rules ({len(items)} Total: {f2b_count} Fail2Ban, {ipt_count} iptables) ===", bold=True)
    if not items:
        click.secho("No blocked IPs or drop rules found.", fg="green")
        return

    # Cap display to latest 50 entries if there are hundreds, to keep CLI responsive
    display_limit = 50
    display_items = items[:display_limit]
    click.echo(f"{'Source':<10} {'Target / IP / Subnet':<24} {'Jail/Chain':<14} {'Pkts':<8} {'Note'}")
    click.echo("-" * 75)
    for item in display_items:
        col = "yellow" if item["source"] == "fail2ban" else "red"
        click.secho(f"{item['source']:<10} {item['target']:<24} {item['jail_or_chain']:<14} {item['packets']:<8} {item['note']}", fg=col)

    if len(items) > display_limit:
        click.echo("-" * 75)
        click.secho(f"[INFO] Showing first {display_limit} of {len(items)} blocked targets. To check a specific IP, run: shsm blocked <IP>", fg="cyan")


@main.command("ban")
@click.argument("ip")
@click.option("--jail", default="auto", help="Target Fail2Ban jail (default: auto)")
@click.option("--iptables", is_flag=True, help="Block directly via iptables DROP rule")
@click.pass_context
def cmd_ban(click_ctx: click.Context, ip: str, jail: str, iptables: bool) -> None:
    """Ban an abusive or suspicious IP address (Fail2Ban or iptables)."""
    app_ctx = get_context(click_ctx.obj.get("config_path"), require_db=False)
    from shsm.security import blocked

    ok, msg = blocked.ban_ip_unified(app_ctx, ip, jail=jail, use_iptables=iptables)
    if ok:
        click.secho(f"[SUCCESS] {msg}", fg="green", bold=True)
    else:
        click.secho(f"[FAILED] {msg}", fg="red", bold=True)
        sys.exit(1)


@main.command("unban")
@click.argument("ip")
@click.option("--jail", default="auto", help="Target Fail2Ban jail (default: auto/all)")
@click.pass_context
def cmd_unban(click_ctx: click.Context, ip: str, jail: str) -> None:
    """Unban an IP address centrally from both Fail2Ban and iptables."""
    app_ctx = get_context(click_ctx.obj.get("config_path"), require_db=False)
    from shsm.security import blocked

    ok, messages = blocked.unban_ip_unified(app_ctx, ip, jail=jail)
    for m in messages:
        if "Deleted" in m or "unbanned" in m or "Success" in m:
            click.secho(f"[SUCCESS] {m}", fg="green")
        elif "No direct DROP" in m or "not installed" in m:
            click.echo(f"[INFO] {m}")
        else:
            click.secho(f"[NOTICE] {m}", fg="yellow")

    if not ok:
        click.secho(f"[WARNING] No active bans found or unban could not be confirmed for {ip}.", fg="yellow")


@main.command("block-scanners")
@click.option("--threshold", default=30, type=int, help="Minimum 404 count to trigger ban (default: 30)")
@click.option("--log-file", default=None, help="Path to access.log (default: from config)")
@click.option("--dry-run", is_flag=True, help="Only show IPs that would be banned without executing ban")
@click.pass_context
def cmd_block_scanners(click_ctx: click.Context, threshold: int, log_file: Optional[str], dry_run: bool) -> None:
    """Scan web server access log, aggregate 404 counts per IP, and ban abusive scanner IPs in iptables."""
    app_ctx = get_context(click_ctx.obj.get("config_path"), require_db=False)
    from shsm.security import blocked
    from shsm.collectors.openlitespeed import _ACCESS_LOG_LINE

    log_path = log_file or str(app_ctx.config.get("openlitespeed.access_log", "/usr/local/lsws/logs/access.log"))
    if not os.path.isfile(log_path):
        click.secho(f"[ERROR] Access log file not found at {log_path}", fg="red")
        sys.exit(1)

    click.echo(f"Scanning {log_path} for IPs with >= {threshold} 404 errors...")

    # Whitelist and local system IPs protection
    whitelist = set(app_ctx.config.get("security.ip_whitelist", ["127.0.0.1", "::1"]))
    cfg_ip = app_ctx.config.get("security.server_public_ip")
    if cfg_ip:
        whitelist.add(str(cfg_ip).strip())
    try:
        import socket
        hostname = socket.gethostname()
        for host_ip in socket.gethostbyname_ex(hostname)[2]:
            whitelist.add(host_ip)
    except Exception:
        pass

    ip_counts: Dict[str, int] = {}
    total_404s = 0
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _ACCESS_LOG_LINE.search(line)
            if m and m.group("status") == "404":
                if "SHSM-Monitor" in line:
                    continue
                ip = m.group("ip")
                if ip:
                    total_404s += 1
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

    targets = [
        (ip, cnt) for ip, cnt in ip_counts.items()
        if cnt >= threshold and ip not in whitelist and not ip.startswith("127.")
    ]
    targets.sort(key=lambda x: x[1], reverse=True)

    click.echo(f"Total 404 requests in log: {total_404s}. Found {len(targets)} external IP(s) exceeding threshold ({threshold}).")
    if not targets:
        click.secho("No external scanner IPs exceeded the threshold.", fg="green")
        return

    click.echo(f"\n{'IP Address':<20} {'404 Hits':<10} {'Action / Status'}")
    click.echo("-" * 65)

    banned_count = 0
    for ip, cnt in targets:
        if dry_run:
            click.echo(f"{ip:<20} {cnt:<10} [DRY-RUN] Would be blocked via iptables DROP")
        else:
            ok, msg = blocked.ban_ip_unified(app_ctx, ip, use_iptables=True)
            if ok:
                banned_count += 1
                click.secho(f"{ip:<20} {cnt:<10} [BANNED] {msg}", fg="green")
            else:
                click.secho(f"{ip:<20} {cnt:<10} [FAILED] {msg}", fg="yellow")

    if dry_run:
        click.secho(f"\nDry-run completed. {len(targets)} IP(s) match threshold >= {threshold}. To execute bans, run without --dry-run.", fg="cyan")
    else:
        click.secho(f"\nSuccessfully processed {len(targets)} IP(s) ({banned_count} newly blocked in iptables).", fg="green", bold=True)


if __name__ == "__main__":
    main()
