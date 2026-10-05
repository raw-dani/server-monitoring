"""Unit tests for SQLite database schema and migrations."""



def test_migrations_create_expected_tables(test_db):
    expected_tables = [
        "schema_migrations",
        "server_info",
        "state_kv",
        "metric_samples",
        "metric_rollups_hourly",
        "metric_rollups_daily",
        "check_results",
        "service_checks",
        "websites",
        "website_checks",
        "ssl_certificates",
        "wordpress_sites",
        "wordpress_plugins",
        "wordpress_themes",
        "wordpress_audits",
        "findings",
        "integrity_baseline",
        "integrity_events",
        "scan_runs",
        "log_cursors",
        "alerts",
        "alert_deliveries",
        "reports",
        "report_deliveries",
        "external_heartbeats",
        "audit_log",
        "score_snapshots",
        "vulnerability_cache",
        "login_baseline",
    ]
    rows = test_db.query("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in rows]

    for t in expected_tables:
        assert t in tables, f"Expected table '{t}' was not found in database."


def test_foreign_keys_and_quick_check(test_db):
    fk = test_db.scalar("PRAGMA foreign_keys")
    assert fk == 1, "Foreign keys must be enabled"
    check = test_db.quick_check()
    assert check == "ok"


def test_migration_is_idempotent(test_db):
    applied = test_db.migrate()
    assert len(applied) == 0


def test_integrity_baseline_has_metadata_column(test_db):
    cols = [r["name"] for r in test_db.query("PRAGMA table_info(integrity_baseline)")]
    assert "metadata_json" in cols
