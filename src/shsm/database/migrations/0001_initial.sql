-- SHSM schema v1. All timestamps are UTC ISO-8601 text (YYYY-MM-DDTHH:MM:SSZ).

CREATE TABLE server_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    server_id TEXT NOT NULL,
    hostname TEXT,
    os_release TEXT,
    kernel TEXT,
    cpu_count INTEGER,
    memory_total_bytes INTEGER,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE state_kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE metric_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    metric TEXT NOT NULL,
    asset TEXT NOT NULL DEFAULT '',
    value REAL NOT NULL
);
CREATE INDEX idx_metric_samples_lookup ON metric_samples (metric, asset, ts);
CREATE INDEX idx_metric_samples_ts ON metric_samples (ts);

CREATE TABLE metric_rollups_hourly (
    metric TEXT NOT NULL,
    asset TEXT NOT NULL DEFAULT '',
    bucket_start TEXT NOT NULL,
    samples INTEGER NOT NULL,
    avg REAL NOT NULL,
    min REAL NOT NULL,
    max REAL NOT NULL,
    PRIMARY KEY (metric, asset, bucket_start)
);

CREATE TABLE metric_rollups_daily (
    metric TEXT NOT NULL,
    asset TEXT NOT NULL DEFAULT '',
    bucket_start TEXT NOT NULL,
    samples INTEGER NOT NULL,
    avg REAL NOT NULL,
    min REAL NOT NULL,
    max REAL NOT NULL,
    PRIMARY KEY (metric, asset, bucket_start)
);

CREATE TABLE check_results (
    check_id TEXT NOT NULL,
    asset TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT,
    details_json TEXT,
    source TEXT,
    checked_at TEXT NOT NULL,
    last_success_at TEXT,
    PRIMARY KEY (check_id, asset)
);

CREATE TABLE service_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at TEXT NOT NULL,
    unit TEXT NOT NULL,
    role TEXT,
    load_state TEXT,
    active_state TEXT,
    sub_state TEXT,
    main_pid INTEGER,
    started_at TEXT,
    uptime_seconds INTEGER,
    n_restarts INTEGER,
    result TEXT,
    restart_detected INTEGER NOT NULL DEFAULT 0,
    detail TEXT
);
CREATE INDEX idx_service_checks_unit ON service_checks (unit, checked_at);

CREATE TABLE websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    aliases_json TEXT,
    doc_root TEXT,
    owner TEXT,
    grp TEXT,
    vhost_conf TEXT,
    source TEXT,
    expected_status_json TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    removed_at TEXT
);

CREATE TABLE website_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL,
    scheme TEXT NOT NULL,
    dns_ok INTEGER,
    dns_addresses TEXT,
    status_code INTEGER,
    response_ms REAL,
    redirect_chain_json TEXT,
    https_redirect INTEGER,
    ok INTEGER NOT NULL,
    error TEXT
);
CREATE INDEX idx_website_checks ON website_checks (website_id, scheme, checked_at);

CREATE TABLE ssl_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    checked_at TEXT NOT NULL,
    not_before TEXT,
    not_after TEXT,
    days_remaining REAL,
    valid INTEGER,
    error TEXT
);
CREATE INDEX idx_ssl_domain ON ssl_certificates (domain, checked_at);

CREATE TABLE wordpress_sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    doc_root TEXT NOT NULL,
    owner TEXT,
    grp TEXT,
    wp_config_path TEXT,
    wp_version TEXT,
    php_version TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    removed_at TEXT
);

CREATE TABLE wordpress_plugins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES wordpress_sites(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    version TEXT,
    status TEXT,
    update_available INTEGER NOT NULL DEFAULT 0,
    update_version TEXT,
    checked_at TEXT NOT NULL,
    UNIQUE (site_id, slug)
);

CREATE TABLE wordpress_themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES wordpress_sites(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    version TEXT,
    status TEXT,
    update_available INTEGER NOT NULL DEFAULT 0,
    update_version TEXT,
    checked_at TEXT NOT NULL,
    UNIQUE (site_id, slug)
);

CREATE TABLE wordpress_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES wordpress_sites(id) ON DELETE CASCADE,
    audited_at TEXT NOT NULL,
    core_version TEXT,
    core_update TEXT,
    checksum_status TEXT,
    plugin_count INTEGER,
    theme_count INTEGER,
    admin_count INTEGER,
    admins_json TEXT,
    outdated_plugins INTEGER,
    outdated_themes INTEGER,
    status TEXT NOT NULL,
    errors_json TEXT
);
CREATE INDEX idx_wp_audits ON wordpress_audits (site_id, audited_at);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    check_id TEXT NOT NULL,
    component TEXT,
    asset TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT,
    recommendation TEXT,
    source TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    occurrences INTEGER NOT NULL DEFAULT 1,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    details_json TEXT,
    status_note TEXT,
    status_changed_at TEXT
);
CREATE INDEX idx_findings_status ON findings (status, severity);
CREATE INDEX idx_findings_check ON findings (check_id);

CREATE TABLE integrity_baseline (
    path TEXT PRIMARY KEY,
    file_type TEXT NOT NULL,
    sha256 TEXT,
    size INTEGER,
    uid INTEGER,
    gid INTEGER,
    mode INTEGER,
    mtime TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE integrity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    change_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    old_json TEXT,
    new_json TEXT,
    detected_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    resolved_at TEXT,
    UNIQUE (path, change_type, detected_at)
);
CREATE INDEX idx_integrity_events ON integrity_events (status, detected_at);

CREATE TABLE scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job TEXT NOT NULL,
    profile TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    pid INTEGER,
    exit_code INTEGER,
    complete INTEGER,
    duration_seconds REAL,
    summary_json TEXT,
    errors_json TEXT,
    tool_versions_json TEXT
);
CREATE INDEX idx_scan_runs ON scan_runs (job, started_at);

CREATE TABLE log_cursors (
    path TEXT PRIMARY KEY,
    device INTEGER,
    inode INTEGER,
    offset INTEGER NOT NULL,
    head_hash TEXT,
    size INTEGER,
    updated_at TEXT NOT NULL
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    first_alerted_at TEXT NOT NULL,
    last_notified_at TEXT NOT NULL,
    notify_count INTEGER NOT NULL DEFAULT 1,
    escalation_level INTEGER NOT NULL DEFAULT 0,
    recovered_at TEXT
);
CREATE INDEX idx_alerts_state ON alerts (state);

CREATE TABLE alert_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    recipients TEXT,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    fingerprints_json TEXT
);

CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    html_path TEXT,
    pdf_path TEXT,
    status TEXT NOT NULL,
    summary_json TEXT
);
CREATE INDEX idx_reports ON reports (kind, period_start);

CREATE TABLE report_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    recipients TEXT,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE external_heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    http_status INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    payload_summary_json TEXT
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details_json TEXT
);

CREATE TABLE score_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    health_score REAL,
    health_coverage REAL NOT NULL,
    security_score REAL,
    security_coverage REAL NOT NULL,
    details_json TEXT
);
CREATE INDEX idx_score_snapshots ON score_snapshots (ts);

CREATE TABLE vulnerability_cache (
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    slug TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    db_timestamp TEXT,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (source, kind, slug)
);

CREATE TABLE login_baseline (
    username TEXT NOT NULL,
    network TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    success_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (username, network)
);
