"""Inventory tables: service checks, websites, website checks, SSL certificates, WordPress."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from shsm.core.timeutils import to_iso
from shsm.database.connection import Database


class InventoryRepo:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ services
    def add_service_check(self, now: datetime, row: Dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO service_checks (checked_at, unit, role, load_state, active_state, sub_state, main_pid, started_at, "
            "uptime_seconds, n_restarts, result, restart_detected, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (to_iso(now), row["unit"], row.get("role"), row.get("load_state"), row.get("active_state"),
             row.get("sub_state"), row.get("main_pid"), row.get("started_at"), row.get("uptime_seconds"),
             row.get("n_restarts"), row.get("result"), 1 if row.get("restart_detected") else 0, row.get("detail")),
        )

    def last_service_check(self, unit: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM service_checks WHERE unit=? ORDER BY id DESC LIMIT 1", (unit,))
        return dict(row) if row else None

    def restarts_since(self, unit: str, since: datetime) -> int:
        return int(self.db.scalar(
            "SELECT COUNT(*) FROM service_checks WHERE unit=? AND checked_at>=? AND restart_detected=1",
            (unit, to_iso(since)), default=0))

    def latest_services(self) -> List[Dict[str, Any]]:
        rows = self.db.query(
            "SELECT s.* FROM service_checks s JOIN (SELECT unit, MAX(id) AS mid FROM service_checks GROUP BY unit) m "
            "ON s.id = m.mid ORDER BY s.role, s.unit")
        return [dict(r) for r in rows]

    def service_incidents(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        rows = self.db.query(
            "SELECT unit, role, COUNT(*) AS samples, SUM(CASE WHEN active_state!='active' THEN 1 ELSE 0 END) AS down_samples, "
            "SUM(restart_detected) AS restarts FROM service_checks WHERE checked_at>=? AND checked_at<? GROUP BY unit, role "
            "ORDER BY unit", (to_iso(start), to_iso(end)))
        return [dict(r) for r in rows]

    def purge_service_checks(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM service_checks WHERE checked_at<?", (to_iso(before),)).rowcount

    # ------------------------------------------------------------------ websites
    def sync_websites(self, sites: Iterable[Dict[str, Any]], now: datetime) -> Dict[str, int]:
        ts = to_iso(now)
        seen = set()
        added = 0
        with self.db.transaction():
            for s in sites:
                seen.add(s["domain"])
                row = self.db.query_one("SELECT id, removed_at FROM websites WHERE domain=?", (s["domain"],))
                exp_status = s.get("expected_status")
                exp_json = json.dumps(exp_status) if exp_status else None
                values = (json.dumps(s.get("aliases", [])), s.get("doc_root"), s.get("owner"), s.get("group"),
                          s.get("vhost_conf"), s.get("source"), exp_json)
                if row is None:
                    self.db.execute(
                        "INSERT INTO websites (domain, aliases_json, doc_root, owner, grp, vhost_conf, source, expected_status_json, "
                        "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)", (s["domain"],) + values + (ts, ts))
                    added += 1
                else:
                    self.db.execute(
                        "UPDATE websites SET aliases_json=?, doc_root=?, owner=?, grp=?, vhost_conf=?, source=?, "
                        "expected_status_json=?, last_seen=?, removed_at=NULL WHERE id=?", values + (ts, row["id"]))
            removed = 0
            for r in self.db.query("SELECT id, domain FROM websites WHERE removed_at IS NULL"):
                if r["domain"] not in seen:
                    self.db.execute("UPDATE websites SET removed_at=? WHERE id=?", (ts, r["id"]))
                    removed += 1
        return {"added": added, "removed": removed, "active": len(seen)}

    def active_websites(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM websites WHERE removed_at IS NULL AND enabled=1 ORDER BY domain")]

    def website_id(self, domain: str) -> Optional[int]:
        row = self.db.query_one("SELECT id FROM websites WHERE domain=?", (domain,))
        return int(row["id"]) if row else None

    def add_website_check(self, website_id: int, now: datetime, scheme: str, dns_ok: Optional[bool], dns_addrs: str,
                          status_code: Optional[int], response_ms: Optional[float], chain: List[str],
                          https_redirect: Optional[bool], ok: bool, error: Optional[str]) -> None:
        self.db.execute(
            "INSERT INTO website_checks (website_id, checked_at, scheme, dns_ok, dns_addresses, status_code, response_ms, "
            "redirect_chain_json, https_redirect, ok, error) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (website_id, to_iso(now), scheme, None if dns_ok is None else int(dns_ok), dns_addrs, status_code,
             response_ms, json.dumps(chain), None if https_redirect is None else int(https_redirect), int(ok), error))

    def recent_check_results(self, website_id: int, scheme: str, n: int) -> List[bool]:
        rows = self.db.query(
            "SELECT ok FROM website_checks WHERE website_id=? AND scheme=? ORDER BY id DESC LIMIT ?", (website_id, scheme, n))
        return [bool(r["ok"]) for r in rows]

    def uptime(self, website_id: int, scheme: str, start: datetime, end: datetime) -> Optional[Dict[str, Any]]:
        row = self.db.query_one(
            "SELECT COUNT(*) AS n, SUM(ok) AS ok, AVG(response_ms) AS avg_ms, MAX(response_ms) AS max_ms FROM website_checks "
            "WHERE website_id=? AND scheme=? AND checked_at>=? AND checked_at<?", (website_id, scheme, to_iso(start), to_iso(end)))
        if not row or not row["n"]:
            return None
        return {"checks": row["n"], "ok": row["ok"] or 0, "uptime_percent": 100.0 * (row["ok"] or 0) / row["n"],
                "avg_ms": row["avg_ms"], "max_ms": row["max_ms"]}

    def purge_website_checks(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM website_checks WHERE checked_at<?", (to_iso(before),)).rowcount

    # ----------------------------------------------------------------------- ssl
    def add_ssl(self, domain: str, port: int, now: datetime, not_before: Optional[str], not_after: Optional[str],
                days: Optional[float], valid: Optional[bool], error: Optional[str]) -> None:
        self.db.execute(
            "INSERT INTO ssl_certificates (domain, port, checked_at, not_before, not_after, days_remaining, valid, error) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (domain, port, to_iso(now), not_before, not_after, days, None if valid is None else int(valid), error))

    def latest_ssl(self) -> List[Dict[str, Any]]:
        rows = self.db.query(
            "SELECT s.* FROM ssl_certificates s JOIN (SELECT domain, port, MAX(id) AS mid FROM ssl_certificates GROUP BY domain, port) m "
            "ON s.id=m.mid ORDER BY s.days_remaining")
        return [dict(r) for r in rows]

    def purge_ssl(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM ssl_certificates WHERE checked_at<?", (to_iso(before),)).rowcount

    # ------------------------------------------------------------------ wordpress
    def sync_wordpress_sites(self, sites: Iterable[Dict[str, Any]], now: datetime) -> Dict[str, int]:
        ts = to_iso(now)
        seen = set()
        with self.db.transaction():
            for s in sites:
                seen.add(s["path"])
                row = self.db.query_one("SELECT id FROM wordpress_sites WHERE path=?", (s["path"],))
                vals = (s["domain"], s["doc_root"], s.get("owner"), s.get("group"), s.get("wp_config_path"),
                        s.get("wp_version"), s.get("php_version"))
                if row is None:
                    self.db.execute(
                        "INSERT INTO wordpress_sites (domain, doc_root, owner, grp, wp_config_path, wp_version, php_version, path, "
                        "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)", vals + (s["path"], ts, ts))
                else:
                    self.db.execute(
                        "UPDATE wordpress_sites SET domain=?, doc_root=?, owner=?, grp=?, wp_config_path=?, wp_version=?, "
                        "php_version=?, last_seen=?, removed_at=NULL WHERE id=?", vals + (ts, row["id"]))
            removed = 0
            for r in self.db.query("SELECT id, path FROM wordpress_sites WHERE removed_at IS NULL"):
                if r["path"] not in seen:
                    self.db.execute("UPDATE wordpress_sites SET removed_at=? WHERE id=?", (ts, r["id"]))
                    removed += 1
        return {"active": len(seen), "removed": removed}

    def active_wordpress_sites(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM wordpress_sites WHERE removed_at IS NULL ORDER BY domain, path")]

    def replace_plugins(self, site_id: int, plugins: List[Dict[str, Any]], now: datetime) -> None:
        self._replace_inventory("wordpress_plugins", site_id, plugins, now)

    def replace_themes(self, site_id: int, themes: List[Dict[str, Any]], now: datetime) -> None:
        self._replace_inventory("wordpress_themes", site_id, themes, now)

    def _replace_inventory(self, table: str, site_id: int, items: List[Dict[str, Any]], now: datetime) -> None:
        assert table in ("wordpress_plugins", "wordpress_themes")
        with self.db.transaction():
            self.db.execute(f"DELETE FROM {table} WHERE site_id=?", (site_id,))  # noqa: S608 - table is whitelisted above
            for it in items:
                self.db.execute(
                    f"INSERT INTO {table} (site_id, slug, version, status, update_available, update_version, checked_at) "  # noqa: S608
                    "VALUES (?,?,?,?,?,?,?)",
                    (site_id, it["slug"], it.get("version"), it.get("status"), 1 if it.get("update_available") else 0,
                     it.get("update_version"), to_iso(now)))

    def plugins(self, site_id: int) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM wordpress_plugins WHERE site_id=? ORDER BY slug", (site_id,))]

    def themes(self, site_id: int) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM wordpress_themes WHERE site_id=? ORDER BY slug", (site_id,))]

    def add_wp_audit(self, site_id: int, now: datetime, audit: Dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO wordpress_audits (site_id, audited_at, core_version, core_update, checksum_status, plugin_count, theme_count, "
            "admin_count, admins_json, outdated_plugins, outdated_themes, status, errors_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (site_id, to_iso(now), audit.get("core_version"), audit.get("core_update"), audit.get("checksum_status"),
             audit.get("plugin_count"), audit.get("theme_count"), audit.get("admin_count"),
             json.dumps(audit.get("admins", [])), audit.get("outdated_plugins"), audit.get("outdated_themes"),
             audit.get("status", "OK"), json.dumps(audit.get("errors", []))))

    def last_wp_audit(self, site_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM wordpress_audits WHERE site_id=? ORDER BY id DESC LIMIT 1", (site_id,))
        return dict(row) if row else None

    def last_successful_admin_snapshot(self, site_id: int) -> Optional[List[Dict[str, Any]]]:
        row = self.db.query_one(
            "SELECT admins_json FROM wordpress_audits WHERE site_id=? AND admin_count IS NOT NULL ORDER BY id DESC LIMIT 1", (site_id,))
        if not row:
            return None
        try:
            return json.loads(row["admins_json"])
        except (TypeError, ValueError):
            return None

    def purge_wp_audits(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM wordpress_audits WHERE audited_at<?", (to_iso(before),)).rowcount

    # ---------------------------------------------------------- vulnerability cache
    def vuln_cache_get(self, source: str, kind: str, slug: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM vulnerability_cache WHERE source=? AND kind=? AND slug=?", (source, kind, slug))
        return dict(row) if row else None

    def vuln_cache_put(self, source: str, kind: str, slug: str, now: datetime, db_timestamp: Optional[str], payload: Any) -> None:
        self.db.execute(
            "INSERT INTO vulnerability_cache (source, kind, slug, fetched_at, db_timestamp, payload_json) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(source, kind, slug) DO UPDATE SET fetched_at=excluded.fetched_at, db_timestamp=excluded.db_timestamp, "
            "payload_json=excluded.payload_json",
            (source, kind, slug, to_iso(now), db_timestamp, json.dumps(payload, default=str)))
