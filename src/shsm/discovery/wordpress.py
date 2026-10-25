"""WordPress site discovery from filesystem and wp-config.php detection."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from shsm.core.context import Context
from shsm.utils.paths import real


def _extract_wp_version(doc_root: str) -> Optional[str]:
    """Parse wp-includes/version.php safely without executing PHP code."""
    ver_file = os.path.join(doc_root, "wp-includes", "version.php")
    try:
        if not os.path.isfile(ver_file) or not os.access(ver_file, os.R_OK):
            return None
        with open(ver_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                # $wp_version = '6.4.2';
                m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", line)
                if m:
                    return m.group(1).strip()
    except (OSError, PermissionError):
        pass
    return None


def _find_wp_config(path: str) -> Optional[str]:
    """Find wp-config.php in path or parent directory."""
    try:
        c1 = os.path.join(path, "wp-config.php")
        if os.path.isfile(c1):
            return c1
        parent = os.path.dirname(os.path.abspath(path))
        c2 = os.path.join(parent, "wp-config.php")
        if os.path.isfile(c2):
            return c2
    except (OSError, PermissionError):
        pass
    return None


def is_wordpress_installation(path: str) -> bool:
    """Check if directory contains core WordPress files."""
    try:
        if not os.path.isdir(path):
            return False
        has_config = _find_wp_config(path) is not None
        has_includes = False
        has_content = False
        try:
            has_includes = os.path.isdir(os.path.join(path, "wp-includes"))
            has_content = os.path.isdir(os.path.join(path, "wp-content"))
        except (PermissionError, OSError):
            pass
        return (has_config or has_includes) and has_content
    except (PermissionError, OSError):
        return False


def discover_wordpress_sites(ctx: Context) -> List[Dict[str, Any]]:
    """Scan active discovered websites and subdirectories for WordPress installations."""
    active_websites = ctx.inventory.active_websites()
    if not active_websites:
        from shsm.discovery.cyberpanel import discover_websites
        active_websites = discover_websites(ctx)

    subdirs = ctx.config.get("wordpress.search_subdirs", ["wp", "blog", "wordpress"])
    extra_paths = ctx.config.get("wordpress.extra_paths", [])

    candidates: List[tuple[str, str]] = []  # (domain, path)

    for w in active_websites:
        doc_root = w.get("doc_root")
        if not doc_root:
            continue
        try:
            if not os.path.isdir(doc_root):
                continue
        except (PermissionError, OSError):
            continue

        dom = w["domain"]
        candidates.append((dom, doc_root))
        for sub in subdirs:
            cand = os.path.join(doc_root, sub)
            try:
                if os.path.isdir(cand):
                    candidates.append((dom, cand))
            except (PermissionError, OSError):
                pass

    for p in extra_paths:
        try:
            if os.path.isdir(p):
                candidates.append(("unknown", p))
        except (PermissionError, OSError):
            pass

    found_sites: List[Dict[str, Any]] = []
    seen_paths = set()

    min_uid = int(ctx.config.get("wordpress.min_owner_uid", 100))

    for dom, path in candidates:
        rpath = real(path)
        if rpath in seen_paths:
            continue
        if not is_wordpress_installation(rpath):
            continue

        seen_paths.add(rpath)
        wp_config = _find_wp_config(rpath)
        wp_ver = _extract_wp_version(rpath)

        owner = "nobody"
        grp = "nobody"
        uid = 65534
        gid = 65534
        try:
            st = os.stat(rpath)
            uid = st.st_uid
            gid = st.st_gid
            import pwd
            owner = pwd.getpwuid(uid).pw_name
            import grp as grp_mod
            grp = grp_mod.getgrgid(gid).gr_name
        except Exception:
            pass

        # Disallow root owner execution per security spec
        is_safe_owner = (uid >= min_uid) and (owner != "root")

        found_sites.append({
            "domain": dom,
            "path": rpath,
            "doc_root": rpath,
            "owner": owner,
            "group": grp,
            "uid": uid,
            "gid": gid,
            "is_safe_owner": is_safe_owner,
            "wp_config_path": wp_config,
            "wp_version": wp_ver,
            "php_version": None,
        })

    return found_sites

