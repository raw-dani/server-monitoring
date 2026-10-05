"""WordPress security audit using WP-CLI executed as the site's Linux owner (never root)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "wp-cli"
CATEGORY = "wordpress"


def _find_wp_cli(ctx: Context) -> Optional[str]:
    cfg = ctx.config.get("wordpress.wp_cli")
    if cfg and cfg != "auto":
        return ctx.runner.which(cfg)
    for cand in ("wp", "wp-cli", "/usr/local/bin/wp"):
        p = ctx.runner.which(cand)
        if p:
            return p
    return None


def run_wp_cli(
    ctx: Context,
    site: Dict[str, Any],
    args: List[str],
    timeout: Optional[float] = None,
) -> Tuple[bool, str, str]:
    """Execute WP-CLI strictly as the Linux owner of the site."""
    wp_bin = _find_wp_cli(ctx)
    if not wp_bin:
        return False, "", "wp-cli binary not found"

    doc_root = site["doc_root"]
    owner = site.get("owner")
    if not site.get("is_safe_owner") or owner == "root":
        return False, "", f"refusing to run wp-cli as user '{owner}' (least privilege rule)"

    cmd = [wp_bin, f"--path={doc_root}", "--skip-plugins", "--skip-themes"] + args
    tout = timeout or float(ctx.config.get("wordpress.command_timeout_seconds", 90))

    # Drop privilege to site owner
    res = ctx.runner.run(cmd, timeout=tout, cwd=doc_root, user=owner)
    return res.ok, res.stdout, res.stderr


def audit_single_site(ctx: Context, site: Dict[str, Any], out: CollectorOutput) -> Dict[str, Any]:
    domain = site["domain"]
    site_id = site["id"]
    now = ctx.now()

    audit_summary: Dict[str, Any] = {
        "core_version": None,
        "core_update": None,
        "checksum_status": "UNKNOWN",
        "plugin_count": 0,
        "theme_count": 0,
        "admin_count": 0,
        "admins": [],
        "outdated_plugins": 0,
        "outdated_themes": 0,
        "status": "OK",
        "errors": [],
    }

    # 1. Core version
    ok, stdout, stderr = run_wp_cli(ctx, site, ["core", "version"])
    if not ok:
        err_msg = f"WP-CLI execution failed on {domain}: {stderr[:150]}"
        audit_summary["status"] = "ERROR"
        audit_summary["errors"].append(err_msg)
        out.check("wordpress.core", CATEGORY, CheckStatus.UNKNOWN, err_msg, asset=domain, source=SOURCE)
        return audit_summary

    core_ver = stdout.strip()
    audit_summary["core_version"] = core_ver

    # 2. Core check-update
    ok, stdout, _ = run_wp_cli(ctx, site, ["core", "check-update", "--format=json"])
    if ok and stdout.strip():
        try:
            updates = json.loads(stdout)
            if updates and isinstance(updates, list):
                audit_summary["core_update"] = updates[0].get("version")
                out.finding(
                    "wordpress.core",
                    CATEGORY,
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    f"WordPress core update available for {domain}",
                    f"Current version is {core_ver}; update to {updates[0].get('version')} is available.",
                    f"Update WordPress core for {domain} via CyberPanel or WP admin.",
                    asset=domain,
                    source=SOURCE,
                    key=f"{domain}:core_update",
                )
        except Exception:
            pass

    # 3. Checksums verification
    ok, stdout, stderr = run_wp_cli(ctx, site, ["core", "verify-checksums"])
    if ok:
        audit_summary["checksum_status"] = "VERIFIED"
        out.check(
            "wordpress.checksums",
            CATEGORY,
            CheckStatus.PASS,
            f"WordPress core files verified against official checksums on {domain}",
            asset=domain,
            source=SOURCE,
        )
    else:
        audit_summary["checksum_status"] = "FAILED"
        err_snippet = stderr.strip() or stdout.strip()
        out.check(
            "wordpress.checksums",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"WordPress core checksum verification failed on {domain}",
            asset=domain,
            source=SOURCE,
        )
        out.finding(
            "wordpress.checksums",
            CATEGORY,
            Severity.CRITICAL,
            Confidence.CONFIRMED,
            f"WordPress core checksum verification failed for {domain}",
            f"WP-CLI verify-checksums reported modified or added core files on {domain}: {err_snippet[:300]}.",
            "Inspect the modified files immediately. Replace them with fresh files from wordpress.org and check for malware.",
            asset=domain,
            source=SOURCE,
            key=f"{domain}:checksums",
        )

    # 4. Plugins
    ok, stdout, _ = run_wp_cli(ctx, site, ["plugin", "list", "--format=json"])
    plugins_list = []
    if ok and stdout.strip():
        try:
            raw_plugins = json.loads(stdout)
            outdated_p = 0
            for p in raw_plugins:
                slug = p.get("name")
                ver = p.get("version")
                st = p.get("status")
                up_avail = p.get("update") == "available"
                up_ver = p.get("update_version")
                if up_avail:
                    outdated_p += 1
                plugins_list.append({
                    "slug": slug,
                    "version": ver,
                    "status": st,
                    "update_available": up_avail,
                    "update_version": up_ver,
                })
            audit_summary["plugin_count"] = len(plugins_list)
            audit_summary["outdated_plugins"] = outdated_p
            ctx.inventory.replace_plugins(site_id, plugins_list, now)

            if outdated_p > 0:
                out.finding(
                    "wordpress.plugins",
                    CATEGORY,
                    Severity.LOW,
                    Confidence.HIGH,
                    f"{outdated_p} plugin update(s) available on {domain}",
                    f"Site {domain} has {outdated_p} plugins with pending updates.",
                    "Review and update plugins to their latest stable releases.",
                    asset=domain,
                    source=SOURCE,
                    key=f"{domain}:plugins_update",
                )
        except Exception as exc:
            audit_summary["errors"].append(f"Plugin parse error: {exc}")

    # 5. Themes
    ok, stdout, _ = run_wp_cli(ctx, site, ["theme", "list", "--format=json"])
    themes_list = []
    if ok and stdout.strip():
        try:
            raw_themes = json.loads(stdout)
            outdated_t = 0
            for t in raw_themes:
                slug = t.get("name")
                ver = t.get("version")
                st = t.get("status")
                up_avail = t.get("update") == "available"
                up_ver = t.get("update_version")
                if up_avail:
                    outdated_t += 1
                themes_list.append({
                    "slug": slug,
                    "version": ver,
                    "status": st,
                    "update_available": up_avail,
                    "update_version": up_ver,
                })
            audit_summary["theme_count"] = len(themes_list)
            audit_summary["outdated_themes"] = outdated_t
            ctx.inventory.replace_themes(site_id, themes_list, now)
        except Exception as exc:
            audit_summary["errors"].append(f"Theme parse error: {exc}")

    # 6. Administrators
    ok, stdout, _ = run_wp_cli(ctx, site, ["user", "list", "--role=administrator", "--fields=ID,user_login,user_email,roles", "--format=json"])
    if ok and stdout.strip():
        try:
            raw_admins = json.loads(stdout)
            admin_data = [
                {"id": a.get("ID"), "user_login": a.get("user_login"), "user_email": a.get("user_email")}
                for a in raw_admins
            ]
            audit_summary["admin_count"] = len(admin_data)
            audit_summary["admins"] = admin_data

            # Check against previous admin snapshot for unauthorized new admin detection!
            last_admins = ctx.inventory.last_successful_admin_snapshot(site_id)
            if last_admins is not None:
                last_logins = {la.get("user_login") for la in last_admins if la.get("user_login")}
                curr_logins = {ca.get("user_login") for ca in admin_data if ca.get("user_login")}
                new_admins = curr_logins - last_logins
                if new_admins:
                    admin_names = ", ".join(sorted([str(x) for x in new_admins]))
                    out.finding(
                        "wordpress.users",
                        CATEGORY,
                        Severity.HIGH,
                        Confidence.CONFIRMED,
                        f"New WordPress administrator account(s) detected on {domain}",
                        f"New administrator account(s) created: {admin_names}. Previous admin count was {len(last_admins)}, now {len(admin_data)}.",
                        "Verify whether this administrator account was created legitimately. Unauthorized admin creation is a common sign of compromise.",
                        asset=domain,
                        source=SOURCE,
                        key=f"{domain}:new_admin:{admin_names}",
                    )
        except Exception as exc:
            audit_summary["errors"].append(f"Admin parse error: {exc}")

    # Save complete audit record to DB
    ctx.inventory.add_wp_audit(site_id, now, audit_summary)
    return audit_summary


def audit_all(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    sites = ctx.inventory.active_wordpress_sites()
    if not sites:
        out.check("wordpress.audit", CATEGORY, CheckStatus.NOT_APPLICABLE, "No WordPress installations found to audit", source=SOURCE)
        return out

    wp_bin = _find_wp_cli(ctx)
    if not wp_bin:
        out.check("wordpress.audit", CATEGORY, CheckStatus.ERROR, "WP-CLI is not installed or not in PATH", source=SOURCE)
        out.error("wordpress.audit: wp-cli binary not found")
        return out

    for site in sites:
        audit_single_site(ctx, site, out)

    out.check("wordpress.audit", CATEGORY, CheckStatus.PASS, f"Audited {len(sites)} WordPress site(s)", source=SOURCE)
    return out
