"""CyberPanel website and virtual host discovery."""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Dict, List

from shsm.core.context import Context
from shsm.utils.paths import is_valid_domain, normalize_domain


def discover_from_cyberpanel_db(db_path: str = "/etc/cyberpanel/cyberpanel.db") -> List[Dict[str, Any]]:
    """Query CyberPanel internal SQLite database if it exists."""
    if not os.path.isfile(db_path) or not os.access(db_path, os.R_OK):
        return []

    results: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # CyberPanel websites table is commonly 'websiteFunctions_websites'
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
                if not domain or not is_valid_domain(domain):
                    continue

                owner = r["adminEmail"] if "adminEmail" in col_keys else "nobody"
                # CyberPanel uses domain owner user
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
                    "source": "cyberpanel_db",
                })
        conn.close()
    except Exception:
        pass
    return results


def discover_from_lsws_conf(vhost_dir: str = "/usr/local/lsws/conf/vhosts") -> List[Dict[str, Any]]:
    """Discover websites from OpenLiteSpeed virtual host configuration directories."""
    if not os.path.isdir(vhost_dir):
        return []

    results: List[Dict[str, Any]] = []
    try:
        for entry in os.scandir(vhost_dir):
            if not entry.is_dir():
                continue
            domain = normalize_domain(entry.name)
            if not domain:
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
                                    doc_root = parts[1].replace("$VH_ROOT", "").strip()
                                    if doc_root.startswith("/"):
                                        pass
                                    else:
                                        doc_root = os.path.join("/home", domain, doc_root)
                except OSError:
                    pass

            if not doc_root:
                doc_root = f"/home/{domain}/public_html"

            # Check owner from directory if it exists
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
                "domain": domain,
                "doc_root": doc_root,
                "owner": owner,
                "group": group,
                "vhost_conf": conf_path if os.path.isfile(conf_path) else None,
                "source": "lsws_vhost_conf",
            })
    except Exception:
        pass

    return results


def discover_from_home_directories(home_base: str = "/home") -> List[Dict[str, Any]]:
    """Fallback: scan /home/*/public_html."""
    if not os.path.isdir(home_base):
        return []

    results: List[Dict[str, Any]] = []
    try:
        for entry in os.scandir(home_base):
            if not entry.is_dir():
                continue
            pub_html = os.path.join(entry.path, "public_html")
            if os.path.isdir(pub_html):
                domain = normalize_domain(entry.name)
                if not domain:
                    continue

                owner = "nobody"
                group = "nobody"
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
        pass

    return results


def discover_websites(ctx: Context) -> List[Dict[str, Any]]:
    """Aggregate websites from CyberPanel DB, OpenLiteSpeed config, and /home directory layout."""
    discovered: Dict[str, Dict[str, Any]] = {}

    # 1. CyberPanel DB
    for site in discover_from_cyberpanel_db():
        discovered[site["domain"]] = site

    # 2. OpenLiteSpeed config
    vhost_dir = str(ctx.config.get("openlitespeed.vhost_conf_dir", "/usr/local/lsws/conf/vhosts"))
    for site in discover_from_lsws_conf(vhost_dir):
        dom = site["domain"]
        if dom not in discovered:
            discovered[dom] = site
        else:
            if site.get("vhost_conf"):
                discovered[dom]["vhost_conf"] = site["vhost_conf"]

    # 3. Fallback scan /home
    if ctx.config.get("websites.fallback_scan_home", True):
        for site in discover_from_home_directories():
            dom = site["domain"]
            if dom not in discovered:
                discovered[dom] = site

    # 4. Manual includes/excludes from configuration
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
