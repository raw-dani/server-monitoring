"""WordPress security audit using WP-CLI executed as the site's Linux owner (never root)."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.security.malware import scan_file_heuristics

SOURCE = "wp-cli"
CATEGORY = "wordpress"
_HTACCESS_PHP_INJECT = re.compile(r"(?i)auto_(?:prepend|append)_file|SetHandler\s+application/x-httpd-php")


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

    is_safe = site.get("is_safe_owner")
    if is_safe is None:
        if owner and owner != "root":
            min_uid = int(ctx.config.get("wordpress.min_owner_uid", 100))
            try:
                import pwd
                uid = pwd.getpwnam(owner).pw_uid
                is_safe = (uid >= min_uid)
            except Exception:
                # If user lookup fails (e.g. non-POSIX test runner), check doc_root stat or accept non-root
                try:
                    import os
                    if doc_root and os.path.exists(doc_root):
                        st = os.stat(doc_root)
                        is_safe = (st.st_uid >= min_uid)
                    else:
                        is_safe = True
                except Exception:
                    is_safe = True
        else:
            is_safe = False

    if not is_safe or owner == "root":
        return False, "", f"refusing to run wp-cli as user '{owner}' (least privilege rule)"

    cmd = [wp_bin, f"--path={doc_root}", "--skip-plugins", "--skip-themes"] + args
    tout = timeout or float(ctx.config.get("wordpress.command_timeout_seconds", 90))

    # Avoid chdir(doc_root) before sudo when running as non-root 'shsm' (prevents PermissionError on 0711 dirs);
    # WP-CLI already receives --path=<doc_root>.
    is_non_root = hasattr(os, "geteuid") and os.geteuid() != 0
    run_cwd = None if is_non_root else doc_root
    res = ctx.runner.run(cmd, timeout=tout, cwd=run_cwd, user=owner)
    return res.ok, res.stdout, res.stderr


def scan_wp_entry_points(doc_root: str) -> List[Dict[str, Any]]:
    """Inspect critical WP files skipped by 'wp core verify-checksums' (wp-config.php, mu-plugins, .htaccess)."""
    hits: List[Dict[str, Any]] = []
    if not doc_root or not os.path.isdir(doc_root):
        return hits

    targets: List[str] = []
    for cfg_cand in (os.path.join(doc_root, "wp-config.php"), os.path.join(os.path.dirname(os.path.abspath(doc_root)), "wp-config.php")):
        if os.path.isfile(cfg_cand) and not os.path.islink(cfg_cand):
            targets.append(cfg_cand)
            break

    mu_dir = os.path.join(doc_root, "wp-content", "mu-plugins")
    if os.path.isdir(mu_dir) and not os.path.islink(mu_dir):
        try:
            for entry in os.scandir(mu_dir):
                if entry.is_file(follow_symlinks=False) and entry.name.endswith((".php", ".phtml")):
                    targets.append(entry.path)
        except OSError:
            pass

    for path in targets:
        for hf in scan_file_heuristics(path):
            hits.append({**hf, "path": path})

    ht_path = os.path.join(doc_root, ".htaccess")
    if os.path.isfile(ht_path) and not os.path.islink(ht_path):
        try:
            with open(ht_path, encoding="utf-8", errors="replace") as fh:
                ht_text = fh.read(65536)
            if _HTACCESS_PHP_INJECT.search(ht_text):
                hits.append({
                    "type": "htaccess_php_injection",
                    "severity": Severity.CRITICAL,
                    "confidence": Confidence.HIGH,
                    "title": "Suspicious PHP execution/prepend directive in .htaccess",
                    "evidence": f"Detected auto_prepend_file/SetHandler directive in {ht_path}.",
                    "recommendation": "Inspect .htaccess immediately and remove unauthorized auto_prepend_file or PHP handler rules.",
                    "path": ht_path,
                })
        except OSError:
            pass

    return hits


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
    core_has_update = False
    if ok and stdout.strip():
        try:
            updates = json.loads(stdout)
            if updates and isinstance(updates, list):
                core_has_update = True
                audit_summary["core_update"] = updates[0].get("version")
                out.check(
                    "wordpress.core",
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"WordPress {core_ver} on {domain} has update available ({updates[0].get('version')})",
                    asset=domain,
                    source=SOURCE,
                )
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
    if not core_has_update:
        out.check(
            "wordpress.core",
            CATEGORY,
            CheckStatus.PASS,
            f"WordPress core {core_ver} is up to date on {domain}",
            asset=domain,
            source=SOURCE,
        )

    # 3. Checksums verification + entry-point injection scan (wp-config.php, mu-plugins, .htaccess)
    ok, stdout, stderr = run_wp_cli(ctx, site, ["core", "verify-checksums"])
    entry_hits = scan_wp_entry_points(site.get("doc_root", ""))
    if ok and not entry_hits:
        audit_summary["checksum_status"] = "VERIFIED"
        out.check(
            "wordpress.checksums",
            CATEGORY,
            CheckStatus.PASS,
            f"WordPress core files and entry points verified clean on {domain}",
            asset=domain,
            source=SOURCE,
        )
    else:
        audit_summary["checksum_status"] = "FAILED" if not ok else "INJECTED"
        reasons = []
        if not ok:
            err_snippet = stderr.strip() or stdout.strip()
            reasons.append(f"verify-checksums mismatch: {err_snippet[:240]}")
        for hit in entry_hits[:5]:
            reasons.append(f"{hit['title']} ({hit['path']})")
        out.check(
            "wordpress.checksums",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"WordPress core/entry-point integrity check failed on {domain}",
            asset=domain,
            source=SOURCE,
        )
        out.finding(
            "wordpress.checksums",
            CATEGORY,
            Severity.CRITICAL,
            Confidence.CONFIRMED,
            f"WordPress core checksum or injection check failed for {domain}",
            f"Integrity/injection issues detected on {domain}: {'; '.join(reasons)}.",
            "Inspect modified core files, wp-config.php, .htaccess, and wp-content/mu-plugins immediately; replace core files from wordpress.org.",
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
                out.check(
                    "wordpress.plugins",
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"{outdated_p} plugin update(s) available on {domain} ({len(plugins_list)} total)",
                    asset=domain,
                    source=SOURCE,
                )
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
            else:
                out.check(
                    "wordpress.plugins",
                    CATEGORY,
                    CheckStatus.PASS,
                    f"All {len(plugins_list)} plugin(s) up to date on {domain}",
                    asset=domain,
                    source=SOURCE,
                )
        except Exception as exc:
            audit_summary["errors"].append(f"Plugin parse error: {exc}")
            out.check("wordpress.plugins", CATEGORY, CheckStatus.UNKNOWN, f"Plugin list parse error on {domain}", asset=domain, source=SOURCE)
    else:
        out.check("wordpress.plugins", CATEGORY, CheckStatus.UNKNOWN, f"Failed to list plugins on {domain}", asset=domain, source=SOURCE)

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
            new_admins: set = set()
            if last_admins is not None:
                last_logins = {la.get("user_login") for la in last_admins if la.get("user_login")}
                curr_logins = {ca.get("user_login") for ca in admin_data if ca.get("user_login")}
                new_admins = curr_logins - last_logins
                if new_admins:
                    admin_names = ", ".join(sorted([str(x) for x in new_admins]))
                    out.check(
                        "wordpress.users",
                        CATEGORY,
                        CheckStatus.CRITICAL,
                        f"New administrator account(s) detected on {domain}: {admin_names}",
                        asset=domain,
                        source=SOURCE,
                    )
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
            if not new_admins:
                out.check(
                    "wordpress.users",
                    CATEGORY,
                    CheckStatus.PASS,
                    f"Verified {len(admin_data)} administrator account(s) on {domain}",
                    asset=domain,
                    source=SOURCE,
                )
        except Exception as exc:
            audit_summary["errors"].append(f"Admin parse error: {exc}")
            out.check("wordpress.users", CATEGORY, CheckStatus.UNKNOWN, f"Admin list parse error on {domain}", asset=domain, source=SOURCE)
    else:
        out.check("wordpress.users", CATEGORY, CheckStatus.UNKNOWN, f"Failed to list administrators on {domain}", asset=domain, source=SOURCE)

    # Save complete audit record to DB
    ctx.inventory.add_wp_audit(site_id, now, audit_summary)
    return audit_summary


def audit_all(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    out.scope("wordpress.discovery")
    out.scope("wordpress.core")
    out.scope("wordpress.checksums")
    out.scope("wordpress.plugins")
    out.scope("wordpress.users")

    sites = ctx.inventory.active_wordpress_sites()
    if not sites:
        for cid in ("wordpress.discovery", "wordpress.core", "wordpress.checksums", "wordpress.plugins", "wordpress.users", "wordpress.audit"):
            out.check(cid, CATEGORY, CheckStatus.NOT_APPLICABLE, "No WordPress installations found to audit", source=SOURCE)
        return out

    out.check("wordpress.discovery", CATEGORY, CheckStatus.PASS, f"Tracking {len(sites)} active WordPress site(s)", source=SOURCE)

    wp_bin = _find_wp_cli(ctx)
    if not wp_bin:
        out.check("wordpress.audit", CATEGORY, CheckStatus.ERROR, "WP-CLI is not installed or not in PATH", source=SOURCE)
        out.error("wordpress.audit: wp-cli binary not found")
        return out

    for site in sites:
        audit_single_site(ctx, site, out)

    out.check("wordpress.audit", CATEGORY, CheckStatus.PASS, f"Audited {len(sites)} WordPress site(s)", source=SOURCE)
    return out
