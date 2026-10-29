"""CyberPanel website and virtual host discovery."""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional

from shsm.core.context import Context
from shsm.utils.paths import is_valid_domain, normalize_domain

log = logging.getLogger(__name__)


def should_ignore_domain(
    domain: str,
    ignore_suspended: bool = True,
    ignore_mail: bool = True,
) -> bool:
    """Determine whether a domain is a suspended alias or mail helper domain that should not be monitored as a website."""
    dom = domain.lower().strip()
    if ignore_suspended and ("-suspended" in dom or dom.endswith(".suspended")):
        return True
    if ignore_mail and (dom.startswith("mail.") or dom.startswith("webmail.")):
        return True
    return False


def discover_from_cyberpanel_mariadb(
    ctx: Context,
    ignore_suspended: bool = True,
    ignore_mail: bool = True,
) -> List[Dict[str, Any]]:
    """Query CyberPanel MariaDB database (authoritative source for CyberPanel sites)."""
    from shsm.collectors.mariadb import run_query

    results: List[Dict[str, Any]] = []
    # 1. Main websites table: websiteFunctions_websites
    query = (
        "SELECT domain, COALESCE(adminEmail, ''), COALESCE(externalApp, ''), COALESCE(path, '') "
        "FROM cyberpanel.websiteFunctions_websites;"
    )
    ok, stdout, stderr = run_query(ctx, query)
    if ok and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            raw_dom = parts[0].strip()
            dom = normalize_domain(raw_dom)
            if not dom or should_ignore_domain(dom, ignore_suspended, ignore_mail):
                continue

            admin_email = parts[1].strip() if len(parts) > 1 else ""
            ext_app = parts[2].strip() if len(parts) > 2 else ""
            custom_path = parts[3].strip() if len(parts) > 3 else ""

            doc_root = custom_path if (custom_path and custom_path.startswith("/")) else f"/home/{dom}/public_html"
            owner = ext_app if ext_app else (admin_email if admin_email else "nobody")
            group = "nobody"

            if os.path.exists(doc_root):
                try:
                    st = os.stat(doc_root)
                    import pwd
                    owner = pwd.getpwuid(st.st_uid).pw_name
                    import grp
                    group = grp.getgrgid(st.st_gid).gr_name
                except Exception:
                    pass

            results.append({
                "domain": dom,
                "doc_root": doc_root,
                "owner": owner,
                "group": group,
                "source": "cyberpanel_mariadb",
            })

    # 2. Child domains / subdomains table if present
    sub_query = (
        "SELECT domain, COALESCE(path, '') "
        "FROM cyberpanel.websiteFunctions_childdomains;"
    )
    ok_sub, stdout_sub, _ = run_query(ctx, sub_query)
    if ok_sub and stdout_sub:
        existing = {r["domain"] for r in results}
        for line in stdout_sub.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            sub_dom = normalize_domain(parts[0].strip())
            if not sub_dom or sub_dom in existing or should_ignore_domain(sub_dom, ignore_suspended, ignore_mail):
                continue
            sub_path = parts[1].strip() if len(parts) > 1 else ""
            doc_root = sub_path if (sub_path and sub_path.startswith("/")) else f"/home/{sub_dom}/public_html"

            owner = "nobody"
            group = "nobody"
            if os.path.exists(doc_root):
                try:
                    st = os.stat(doc_root)
                    import pwd
                    owner = pwd.getpwuid(st.st_uid).pw_name
                    import grp
                    group = grp.getgrgid(st.st_gid).gr_name
                except Exception:
                    pass

            results.append({
                "domain": sub_dom,
                "doc_root": doc_root,
                "owner": owner,
                "group": group,
                "source": "cyberpanel_mariadb_child",
            })

    return results


def discover_from_cyberpanel_db(
    db_path: Optional[str] = None,
    ignore_suspended: bool = True,
    ignore_mail: bool = True,
) -> List[Dict[str, Any]]:
    """Query CyberPanel internal SQLite database if it exists."""
    candidate_paths = [db_path] if db_path else [
        "/usr/local/CyberCP/CyberCP/db.sqlite3",
        "/usr/local/CyberPanel/cyberpanel/db.sqlite3",
        "/etc/cyberpanel/cyberpanel.db",
    ]

    target_db = None
    for p in candidate_paths:
        if p and os.path.isfile(p) and os.access(p, os.R_OK):
            target_db = p
            break

    if not target_db:
        return []

    results: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{target_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        ws_table = None
        for t in ("websiteFunctions_websites", "websites"):
            if t in tables:
                ws_table = t
                break

        if ws_table:
            rows = cur.execute(f"SELECT * FROM {ws_table}").fetchall()
            for r in rows:
                col_keys = r.keys()
                domain = r["domain"] if "domain" in col_keys else None
                if not domain or not is_valid_domain(domain) or should_ignore_domain(domain, ignore_suspended, ignore_mail):
                    continue

                owner = r["adminEmail"] if "adminEmail" in col_keys else "nobody"
                if "externalApp" in col_keys and r["externalApp"]:
                    owner = r["externalApp"]

                doc_root = f"/home/{domain}/public_html"
                if "path" in col_keys and r["path"]:
                    doc_root = r["path"]

                results.append({
                    "domain": domain.lower(),
                    "doc_root": doc_root,
                    "owner": owner,
                    "group": owner,
                    "source": "cyberpanel_sqlite",
                })
        conn.close()
    except Exception:
        pass
    return results


def discover_from_lsws_conf(
    vhost_dir: str = "/usr/local/lsws/conf/vhosts",
    httpd_conf: str = "/usr/local/lsws/conf/httpd_config.conf",
    ignore_suspended: bool = True,
    ignore_mail: bool = True,
) -> List[Dict[str, Any]]:
    """Discover websites from OpenLiteSpeed configuration (httpd_config.conf and vhosts dir)."""
    results: List[Dict[str, Any]] = []
    seen_domains = set()

    # 1. Parse OpenLiteSpeed master config httpd_config.conf (usually readable)
    if os.path.isfile(httpd_conf) and os.access(httpd_conf, os.R_OK):
        try:
            with open(httpd_conf, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            # Match virtualhost blocks: virtualhost <domain> { ... }
            vh_pattern = re.compile(r"virtualhost\s+([^\s{]+)\s*\{([^}]*)\}", re.MULTILINE | re.DOTALL)
            for m in vh_pattern.finditer(content):
                vh_name = m.group(1).strip()
                block = m.group(2)
                dom = normalize_domain(vh_name)
                if not dom or dom.lower() in ("example", "localhost", "default") or should_ignore_domain(dom, ignore_suspended, ignore_mail):
                    continue

                vh_root = None
                for line in block.splitlines():
                    line = line.strip()
                    if line.startswith("vhRoot"):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            vh_root = parts[1].strip()
                            break

                if vh_root:
                    vh_root = vh_root.replace("$VH_NAME", dom).replace("$VH_DOMAIN", dom)
                    if vh_root.endswith("/"):
                        vh_root = vh_root.rstrip("/")
                    doc_root = f"{vh_root}/public_html" if not vh_root.endswith("public_html") else vh_root
                else:
                    doc_root = f"/home/{dom}/public_html"

                owner = "nobody"
                group = "nobody"
                if os.path.exists(doc_root):
                    try:
                        st = os.stat(doc_root)
                        import pwd
                        owner = pwd.getpwuid(st.st_uid).pw_name
                        import grp
                        group = grp.getgrgid(st.st_gid).gr_name
                    except Exception:
                        pass

                seen_domains.add(dom)
                results.append({
                    "domain": dom,
                    "doc_root": doc_root,
                    "owner": owner,
                    "group": group,
                    "vhost_conf": None,
                    "source": "lsws_httpd_conf",
                })
        except Exception:
            pass

    # 2. Check OpenLiteSpeed vhosts directory if readable
    if os.path.isdir(vhost_dir):
        try:
            entries = list(os.scandir(vhost_dir))
        except Exception:
            entries = []

        for entry in entries:
            try:
                try:
                    if not entry.is_dir():
                        continue
                except (PermissionError, OSError):
                    continue

                domain = normalize_domain(entry.name)
                if not domain or domain in seen_domains or should_ignore_domain(domain, ignore_suspended, ignore_mail):
                    continue

                conf_path = os.path.join(entry.path, "vhost.conf")
                doc_root = None
                if os.path.isfile(conf_path) and os.access(conf_path, os.R_OK):
                    try:
                        with open(conf_path, encoding="utf-8", errors="replace") as fh:
                            for line in fh:
                                line = line.strip()
                                if line.startswith("docRoot"):
                                    parts = line.split(None, 1)
                                    if len(parts) == 2:
                                        doc_root = parts[1].replace("$VH_ROOT", "").replace("$VH_NAME", domain).replace("$VH_DOMAIN", domain).strip()
                                        if not doc_root.startswith("/"):
                                            doc_root = os.path.join("/home", domain, doc_root)
                    except OSError:
                        pass

                if not doc_root:
                    doc_root = f"/home/{domain}/public_html"

                owner = "nobody"
                group = "nobody"
                if os.path.exists(doc_root):
                    try:
                        st = os.stat(doc_root)
                        import pwd
                        owner = pwd.getpwuid(st.st_uid).pw_name
                        import grp
                        group = grp.getgrgid(st.st_gid).gr_name
                    except Exception:
                        pass

                seen_domains.add(domain)
                results.append({
                    "domain": domain,
                    "doc_root": doc_root,
                    "owner": owner,
                    "group": group,
                    "vhost_conf": conf_path if os.path.isfile(conf_path) else None,
                    "source": "lsws_vhost_conf",
                })
            except Exception:
                continue

    return results


def discover_from_home_directories(
    home_base: str = "/home",
    ignore_suspended: bool = True,
    ignore_mail: bool = True,
) -> List[Dict[str, Any]]:
    """Fallback: scan /home/*/public_html with resilient error handling."""
    if not os.path.isdir(home_base):
        return []

    results: List[Dict[str, Any]] = []
    try:
        dir_names = os.listdir(home_base)
    except Exception:
        return []

    for name in dir_names:
        try:
            entry_path = os.path.join(home_base, name)
            try:
                if not os.path.isdir(entry_path):
                    continue
            except (PermissionError, OSError):
                continue

            domain = normalize_domain(name)
            if not domain or should_ignore_domain(domain, ignore_suspended, ignore_mail):
                continue

            pub_html = os.path.join(entry_path, "public_html")
            try:
                if not os.path.isdir(pub_html):
                    continue
            except (PermissionError, OSError):
                pub_html = os.path.join(entry_path, "public_html")

            owner = "nobody"
            group = "nobody"
            if os.path.exists(pub_html):
                try:
                    st = os.stat(pub_html)
                    import pwd
                    owner = pwd.getpwuid(st.st_uid).pw_name
                    import grp
                    group = grp.getgrgid(st.st_gid).gr_name
                except Exception:
                    pass

            results.append({
                "domain": domain,
                "doc_root": pub_html,
                "owner": owner,
                "group": group,
                "source": "home_public_html",
            })
        except Exception:
            continue

    return results


def discover_websites(ctx: Context) -> List[Dict[str, Any]]:
    """Aggregate websites from CyberPanel MariaDB, SQLite, OpenLiteSpeed config, and /home."""
    discovered: Dict[str, Dict[str, Any]] = {}

    ignore_suspended = not ctx.config.get("websites.include_suspended", False)
    ignore_mail = not ctx.config.get("websites.include_mail_subdomains", False)

    # 1. Authoritative: CyberPanel MariaDB
    for site in discover_from_cyberpanel_mariadb(ctx, ignore_suspended=ignore_suspended, ignore_mail=ignore_mail):
        discovered[site["domain"]] = site

    # 2. CyberPanel SQLite database fallback
    for site in discover_from_cyberpanel_db(ignore_suspended=ignore_suspended, ignore_mail=ignore_mail):
        dom = site["domain"]
        if dom not in discovered:
            discovered[dom] = site

    # 3. OpenLiteSpeed config (httpd_config.conf and vhosts)
    vhost_dir = str(ctx.config.get("openlitespeed.vhost_conf_dir", "/usr/local/lsws/conf/vhosts"))
    httpd_conf = str(ctx.config.get("openlitespeed.httpd_conf", "/usr/local/lsws/conf/httpd_config.conf"))
    for site in discover_from_lsws_conf(vhost_dir, httpd_conf, ignore_suspended=ignore_suspended, ignore_mail=ignore_mail):
        dom = site["domain"]
        if dom not in discovered:
            discovered[dom] = site
        else:
            if site.get("vhost_conf"):
                discovered[dom]["vhost_conf"] = site["vhost_conf"]

    # 4. Fallback scan /home
    if ctx.config.get("websites.fallback_scan_home", True):
        for site in discover_from_home_directories(ignore_suspended=ignore_suspended, ignore_mail=ignore_mail):
            dom = site["domain"]
            if dom not in discovered:
                discovered[dom] = site

    # 5. Manual includes/excludes from configuration
    manual_includes = ctx.config.get("websites.include", [])
    for item in manual_includes:
        if isinstance(item, str):
            dom = normalize_domain(item)
            if dom and dom not in discovered:
                discovered[dom] = {
                    "domain": dom,
                    "doc_root": f"/home/{dom}/public_html",
                    "owner": "nobody",
                    "group": "nobody",
                    "source": "manual_config",
                }
        elif isinstance(item, dict) and "domain" in item:
            dom = normalize_domain(item["domain"])
            if dom:
                discovered[dom] = {
                    "domain": dom,
                    "doc_root": item.get("doc_root", f"/home/{dom}/public_html"),
                    "owner": item.get("owner", "nobody"),
                    "group": item.get("group", "nobody"),
                    "expected_status": item.get("expected_status"),
                    "source": "manual_config",
                }

    excludes = set(ctx.config.get("websites.exclude", []))
    final_sites = [s for s in discovered.values() if s["domain"] not in excludes]
    return sorted(final_sites, key=lambda s: s["domain"])


