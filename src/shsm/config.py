"""Validated YAML configuration with safe defaults."""

from __future__ import annotations

import copy
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from shsm.utils.redact import redact_mapping

DEFAULT_CONFIG_PATH = "/etc/shsm/config.yaml"
ENV_CONFIG = "SHSM_CONFIG"

# secret name -> (config key holding the file path, environment variable override)
SECRETS = {
    "smtp_password": ("email.password_file", "SHSM_SMTP_PASSWORD"),
    "external_token": ("external_monitoring.token_file", "SHSM_EXTERNAL_TOKEN"),
    "redis_password": ("redis.password_file", "SHSM_REDIS_PASSWORD"),
    "mariadb_defaults": ("mariadb.defaults_file", "SHSM_MARIADB_DEFAULTS_FILE"),
    "vulnerability_api_key": ("vulnerability.api_key_file", "SHSM_VULN_API_KEY"),
}

DEFAULTS: Dict[str, Any] = {
    "general": {
        "server_name": "auto",
        "timezone": "Asia/Jakarta",
        "log_level": "INFO",
        "read_only": True,
        "data_retention_days": 365,
    },
    "paths": {
        "data_dir": "/var/lib/shsm",
        "log_dir": "/var/log/shsm",
        "config_dir": "/etc/shsm",
        "report_dir": "/var/lib/shsm/reports",
        "cache_dir": "/var/cache/shsm",
        "rules_dir": "/etc/shsm/rules",
        "lock_dir": "/var/lib/shsm/locks",
    },
    "email": {
        "enabled": True,
        "provider": "custom",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "security": "starttls",
        "username": "",
        "password_file": "/etc/shsm/secrets/smtp_password",
        "from_name": "GM Teknologi Server Monitor",
        "from_address": "",
        "recipients": ["rohmataliwardani@gmail.com"],
        "timeout_seconds": 20,
        "retries": 3,
        "retry_base_delay_seconds": 2,
        "retry_max_delay_seconds": 60,
    },
    "schedule": {
        "timezone": "Asia/Jakarta",
        "weekly_day": "monday",
        "weekly_time": "07:00",
        "monthly_day": 1,
        "monthly_time": "07:00",
    },
    "external_monitoring": {
        "enabled": False,
        "provider": "generic_webhook",
        "heartbeat_url": "",
        "token_file": "/etc/shsm/secrets/external_token",
        "interval_seconds": 300,
        "timeout_seconds": 15,
        "retries": 3,
        "report_critical_as_down": False,
    },
    "monitoring": {
        "metrics_interval_seconds": 60,
        "service_interval_seconds": 60,
        "database_interval_seconds": 300,
        "website_interval_seconds": 300,
        "ssl_interval_seconds": 21600,
        "wordpress_discovery_interval_seconds": 21600,
        "cpu_window_minutes": 5,
        "cpu_min_samples": 3,
        "top_processes": 5,
        "oom_lookback_minutes": 15,
        "disk_ignore_fstypes": [
            "squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "efivarfs",
            "fuse.lxcfs", "iso9660", "ramfs", "nsfs", "autofs", "devpts", "securityfs", "pstore", "bpf",
            "tracefs", "debugfs", "configfs", "fusectl", "mqueue", "hugetlbfs", "binfmt_misc",
        ],
        "disk_ignore_mountpoints": ["/boot/efi", "/snap"],
        "directory_size_targets": ["/var/log"],
        "directory_scan_interval_seconds": 3600,
        "directory_scan_max_entries": 200000,
        "directory_scan_max_seconds": 20,
    },
    "thresholds": {
        "cpu_warning": 80, "cpu_critical": 90, "cpu_emergency": 95,
        "load_per_cpu_warning": 1.5, "load_per_cpu_critical": 3.0, "load_per_cpu_emergency": 5.0,
        "cpu_steal_warning": 5, "cpu_steal_critical": 10, "cpu_steal_emergency": 25,
        "cpu_iowait_warning": 20, "cpu_iowait_critical": 40, "cpu_iowait_emergency": 60,
        "memory_available_warning_percent": 20,
        "memory_available_critical_percent": 10,
        "memory_available_emergency_percent": 5,
        "swap_warning": 50, "swap_critical": 75, "swap_emergency": 90,
        "disk_warning_percent": 80, "disk_critical_percent": 90, "disk_emergency_percent": 95,
        "inode_warning_percent": 80, "inode_critical_percent": 90, "inode_emergency_percent": 95,
        "disk_growth_warning_percent_per_day": 5,
        "log_growth_warning_mb_per_day": 1024,
        "ssl_warning_days": 30, "ssl_high_days": 14, "ssl_critical_days": 7,
        "website_response_warning_seconds": 3.0,
        "website_response_critical_seconds": 8.0,
        "website_failures_before_critical": 2,
        "mariadb_connections_warning_percent": 80,
        "mariadb_connections_critical_percent": 90,
        "mariadb_connections_emergency_percent": 95,
        "redis_memory_warning_percent": 80,
        "redis_memory_critical_percent": 90,
        "redis_latency_warning_ms": 50,
        "restarts_per_hour_warning": 3,
        "openlitespeed_5xx_rate_warning_percent": 5,
        "openlitespeed_5xx_rate_critical_percent": 20,
        "openlitespeed_min_requests": 100,
        "openlitespeed_php_fatal_warning": 5,
        "ssh_failed_warning": 50,
        "ssh_failed_critical": 500,
        "clamav_signature_warning_days": 3,
        "clamav_signature_critical_days": 7,
        "network_error_rate_warning_per_minute": 10,
        "zombie_warning": 20,
    },
    "services": {
        # role -> {units: [explicit unit names], patterns: [discovery patterns], required: bool}
        "roles": {
            "openlitespeed": {"patterns": ["lshttpd", "lsws", "openlitespeed"], "units": [], "required": True},
            "cyberpanel": {"patterns": ["lscpd", "cyberpanel"], "units": [], "required": False},
            "mariadb": {"patterns": ["mariadb", "mysql", "mysqld"], "units": [], "required": True},
            "redis": {"patterns": ["redis-server", "redis"], "units": [], "required": False},
            "ssh": {"patterns": ["ssh", "sshd"], "units": [], "required": True},
            "fail2ban": {"patterns": ["fail2ban"], "units": [], "required": False},
            "firewall": {"patterns": ["ufw", "firewalld", "csf", "lfd", "nftables", "netfilter-persistent"],
                         "units": [], "required": False},
            "cron": {"patterns": ["cron", "crond"], "units": [], "required": True},
        },
        "sensitive_unit_dirs": ["/etc/systemd/system", "/lib/systemd/system"],
    },
    "openlitespeed": {
        "enabled": "auto",
        "server_root": "/usr/local/lsws",
        "config_file": "/usr/local/lsws/conf/httpd_config.conf",
        "vhost_conf_dir": "/usr/local/lsws/conf/vhosts",
        "error_log": "/usr/local/lsws/logs/error.log",
        "access_log": "/usr/local/lsws/logs/access.log",
        "vhost_log_globs": ["/home/*/logs/*.access_log", "/home/*/logs/*.error_log"],
        "max_vhost_logs": 500,
        "max_bytes_per_run": 20 * 1024 * 1024,
        "max_lines_per_run": 400000,
        "process_names": ["openlitespeed", "lshttpd", "litespeed", "lsphp"],
    },
    "mariadb": {
        "enabled": "auto",
        "defaults_file": "",
        "binary": "auto",
        "socket": "",
        "host": "",
        "port": 3306,
        "timeout_seconds": 15,
        "size_interval_seconds": 86400,
        "error_log": "",
        "error_log_max_bytes": 5 * 1024 * 1024,
    },
    "redis": {
        "enabled": "auto",
        "host": "127.0.0.1",
        "port": 6379,
        "password_file": "",
        "username": "",
        "tls": False,
        "tls_verify": True,
        "timeout_seconds": 5,
    },
    "websites": {
        "include": [],  # list of domains or {domain, doc_root, expected_status}
        "exclude": [],
        "expected_status": {},  # domain -> [codes]
        "default_expected_status": [200],
        "max_workers": 4,
        "timeout_seconds": 10,
        "max_redirects": 5,
        "user_agent": "SHSM-Monitor/1.0",
        "check_www_aliases": False,
        "allowed_roots": ["/home", "/var/www"],
        "fallback_scan_home": True,
    },
    "wordpress": {
        "enabled": True,
        "wp_cli": "auto",
        "php_binary": "",
        "search_subdirs": ["wp", "blog", "wordpress"],
        "command_timeout_seconds": 90,
        "min_owner_uid": 100,
        "extra_paths": [],
        "max_sites": 500,
    },
    "vulnerability": {
        "provider": "none",  # none | wpscan
        "api_key_file": "/etc/shsm/secrets/wpscan_api_key",
        "cache_ttl_hours": 24,
        "max_requests_per_run": 25,
        "timeout_seconds": 20,
    },
    "scanning": {
        "quick_scan_daily": True,
        "full_scan_weekly": True,
        "full_scan_window": "02:00-05:00",
        "enforce_window": False,
        "max_workers": 2,
        "max_file_size_mb": 50,
        "max_depth": 20,
        "follow_symlinks": False,
        "scan_roots": [],  # extra approved roots; discovered docroots are always included
        "exclude_dirs": [
            "node_modules", "vendor", ".git", "cache", "wp-content/cache", "wp-content/upgrade",
            "wp-content/backups", "wp-content/updraft", "wp-content/ai1wm-backups", "wp-content/backup-db",
        ],
        "quick_lookback_hours": 36,
        "recent_php_days": 2,
        "max_runtime_seconds_quick": 900,
        "max_runtime_seconds_full": 10800,
        "max_findings_per_scan": 300,
        "content_read_bytes": 262144,
        "tmp_dirs": ["/tmp", "/var/tmp", "/dev/shm"],
        "nice": 19,
        "ionice_class": 3,
        "clamav": {
            "enabled": True,
            "prefer_daemon": True,
            "timeout_seconds_quick": 1800,
            "timeout_seconds_full": 10800,
            "max_filesize_mb": 50,
        },
        "lynis": {"enabled": True, "timeout_seconds": 1800, "report_file": "/var/log/lynis-report.dat"},
        "rootkit": {"enabled": True, "tools": ["rkhunter", "chkrootkit"], "timeout_seconds": 3600},
        "ignore_rules": [],
    },
    "integrity": {
        "paths": [
            "/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/sudoers.d/", "/etc/ssh/", "/etc/crontab",
            "/etc/cron.d/", "/etc/systemd/system/", "/etc/hosts", "/etc/fstab",
        ],
        "critical_paths": ["/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/shadow"],
        "extra_paths": [],
        "exclude": [],
        "max_files_per_dir": 5000,
        "max_file_size_mb": 50,
        "retention_days": 180,
        "include_discovered": True,
    },
    "security": {
        "ssh_log_candidates": ["/var/log/auth.log", "/var/log/secure"],
        "ssh_max_bytes_per_run": 20 * 1024 * 1024,
        "ssh_learning": True,
        "fail2ban_log": "/var/log/fail2ban.log",
        "allowed_public_ports": [],
        "known_public_processes": ["sshd", "openlitespeed", "lshttpd", "litespeed", "lscpd", "nginx", "apache2"],
        "documented_exceptions": [],  # [{check: "firewall.public_db", port: 3306, reason: "..."}]
        "suspicious_outbound_processes": ["nc", "ncat", "netcat", "socat", "bash", "sh", "dash", "zsh"],
        "apt_check": True,
        "firewall_backend": "auto",  # auto | csf | firewalld | ufw | iptables | nftables | custom | none
        "firewall_custom_cmd": [],
    },
    "alerts": {
        "enabled": True,
        "min_severity": "CRITICAL",
        "min_confidence": "MEDIUM",
        "cooldown_minutes": 60,
        "reminder_hours": 0,
        "recovery_notifications": True,
        "categories": {},  # category -> {enabled: bool, min_severity: str}
        "escalation": [],  # [{after_minutes: 120, recipients: [..]}]
        "max_items_per_email": 50,
    },
    "retention": {
        "raw_metrics_days": 30,
        "hourly_rollup_days": 90,
        "daily_rollup_months": 12,
        "findings_days": 365,
        "reports_days": 365,
        "integrity_days": 180,
        "scan_runs_days": 365,
        "backup_keep": 14,
    },
}

_VALID_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_CONFIDENCES = ("LOW", "MEDIUM", "HIGH", "CONFIRMED")
_WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")

# (dotted path, kind, min, max, choices)
_RULES: List[Tuple[str, str, Optional[float], Optional[float], Optional[tuple]]] = [
    ("general.log_level", "str", None, None, _VALID_LEVELS),
    ("general.read_only", "bool", None, None, None),
    ("general.data_retention_days", "int", 1, 3650, None),
    ("email.enabled", "bool", None, None, None),
    ("email.provider", "str", None, None, ("custom", "gmail", "brevo", "mailtrap", "mailtrap_sandbox", "sendgrid", "mailgun", "postmark", "ses", "local")),
    ("email.smtp_port", "int", 1, 65535, None),
    ("email.security", "str", None, None, ("starttls", "ssl", "none")),
    ("email.timeout_seconds", "int", 1, 300, None),
    ("email.retries", "int", 0, 10, None),
    ("schedule.weekly_day", "str", None, None, _WEEKDAYS),
    ("schedule.monthly_day", "int", 1, 28, None),
    ("external_monitoring.enabled", "bool", None, None, None),
    ("external_monitoring.provider", "str", None, None, ("generic_webhook", "uptime_kuma_push")),
    ("external_monitoring.interval_seconds", "int", 30, 86400, None),
    ("external_monitoring.timeout_seconds", "int", 1, 120, None),
    ("monitoring.metrics_interval_seconds", "int", 10, 3600, None),
    ("monitoring.cpu_window_minutes", "int", 1, 120, None),
    ("monitoring.cpu_min_samples", "int", 1, 120, None),
    ("scanning.max_workers", "int", 1, 8, None),
    ("scanning.max_file_size_mb", "int", 1, 1024, None),
    ("scanning.max_depth", "int", 1, 100, None),
    ("scanning.follow_symlinks", "bool", None, None, None),
    ("alerts.min_severity", "str", None, None, _SEVERITIES),
    ("alerts.min_confidence", "str", None, None, _CONFIDENCES),
    ("alerts.cooldown_minutes", "int", 0, 10080, None),
    ("vulnerability.provider", "str", None, None, ("none", "wpscan")),
    ("redis.port", "int", 1, 65535, None),
    ("mariadb.port", "int", 1, 65535, None),
    ("websites.max_workers", "int", 1, 16, None),
    ("websites.timeout_seconds", "int", 1, 120, None),
    ("wordpress.command_timeout_seconds", "int", 5, 900, None),
    ("security.firewall_backend", "str", None, None, ("auto", "csf", "firewalld", "ufw", "iptables", "nftables", "custom", "none")),
]

_PAIRED_THRESHOLDS = [
    ("cpu_warning", "cpu_critical", "cpu_emergency", True),
    ("swap_warning", "swap_critical", "swap_emergency", True),
    ("disk_warning_percent", "disk_critical_percent", "disk_emergency_percent", True),
    ("inode_warning_percent", "inode_critical_percent", "inode_emergency_percent", True),
    ("memory_available_emergency_percent", "memory_available_critical_percent",
     "memory_available_warning_percent", True),  # ascending for "lower is worse"
    ("ssl_critical_days", "ssl_high_days", "ssl_warning_days", True),
]


class ConfigError(Exception):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


@dataclass
class ValidationResult:
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _lookup(data: Dict[str, Any], dotted: str) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_WINDOW_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$")
_EMAIL_RE = re.compile(r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$")


def validate_config(data: Dict[str, Any], user_data: Optional[Dict[str, Any]] = None) -> ValidationResult:
    res = ValidationResult()
    # unknown keys (check what the user supplied, not the merged defaults)
    if user_data:
        for section, value in user_data.items():
            if section not in DEFAULTS:
                res.errors.append(f"unknown top-level section '{section}'")
                continue
            if isinstance(value, dict) and isinstance(DEFAULTS[section], dict):
                for key in value:
                    if key not in DEFAULTS[section]:
                        res.warnings.append(f"unknown setting '{section}.{key}' (ignored)")
            elif not isinstance(value, type(DEFAULTS[section])) and value is not None:
                res.errors.append(f"section '{section}' must be a mapping")

    for dotted, kind, lo, hi, choices in _RULES:
        value = _lookup(data, dotted)
        if value is None:
            res.errors.append(f"{dotted} is required")
            continue
        if kind == "bool" and not isinstance(value, bool):
            res.errors.append(f"{dotted} must be true or false")
        elif kind == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                res.errors.append(f"{dotted} must be an integer")
                continue
            if lo is not None and value < lo or hi is not None and value > hi:
                res.errors.append(f"{dotted} must be between {lo} and {hi}")
        elif kind == "str":
            if not isinstance(value, str):
                res.errors.append(f"{dotted} must be a string")
            elif choices and value not in choices:
                res.errors.append(f"{dotted} must be one of: {', '.join(choices)}")

    th = data.get("thresholds", {})
    for key, value in th.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            res.errors.append(f"thresholds.{key} must be a non-negative number")
    for a, b, c, _ in _PAIRED_THRESHOLDS:
        try:
            if not (th[a] <= th[b] <= th[c]):
                res.errors.append(f"thresholds must satisfy {a} <= {b} <= {c}")
        except (KeyError, TypeError):
            pass
    for pct in ("disk_warning_percent", "disk_critical_percent", "disk_emergency_percent",
                "inode_warning_percent", "inode_critical_percent", "inode_emergency_percent",
                "cpu_warning", "cpu_critical", "cpu_emergency"):
        if isinstance(th.get(pct), (int, float)) and th[pct] > 100:
            res.errors.append(f"thresholds.{pct} must be <= 100")

    email = data.get("email", {})
    recipients = email.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        res.errors.append("email.recipients must be a non-empty list")
    else:
        for r in recipients:
            if not isinstance(r, str) or not _EMAIL_RE.match(r):
                res.errors.append(f"email.recipients contains an invalid address: {r!r}")
    if email.get("enabled"):
        if not email.get("smtp_host"):
            res.errors.append("email.smtp_host is required when email is enabled")
        if not email.get("from_address") and not email.get("username"):
            res.warnings.append("email.from_address and email.username are empty; email sending will fail")
        elif email.get("from_address") and not _EMAIL_RE.match(str(email["from_address"])):
            res.errors.append("email.from_address is not a valid address")
    if email.get("security") == "none" and email.get("smtp_host") not in ("localhost", "127.0.0.1", "::1"):
        res.errors.append("email.security 'none' is only permitted for localhost")

    sched = data.get("schedule", {})
    for key in ("weekly_time", "monthly_time"):
        if not isinstance(sched.get(key), str) or not _TIME_RE.match(sched.get(key, "")):
            res.errors.append(f"schedule.{key} must be HH:MM")
    for key, value in (("general.timezone", _lookup(data, "general.timezone")),
                       ("schedule.timezone", _lookup(data, "schedule.timezone"))):
        try:
            from zoneinfo import ZoneInfo

            ZoneInfo(str(value))
        except Exception:
            res.errors.append(f"{key} is not a valid IANA timezone: {value!r}")

    window = _lookup(data, "scanning.full_scan_window")
    if not isinstance(window, str) or not _WINDOW_RE.match(window):
        res.errors.append("scanning.full_scan_window must look like HH:MM-HH:MM")

    ext = data.get("external_monitoring", {})
    if ext.get("enabled"):
        url = str(ext.get("heartbeat_url", ""))
        if not url:
            res.errors.append("external_monitoring.heartbeat_url is required when enabled")
        elif not url.lower().startswith("https://"):
            res.errors.append("external_monitoring.heartbeat_url must use https://")

    if data.get("general", {}).get("read_only") is False:
        res.errors.append("general.read_only=false is not supported in v1 (automatic remediation is not included)")

    for key, path in (("paths." + k, v) for k, v in data.get("paths", {}).items()):
        if not isinstance(path, str) or not path:
            res.errors.append(f"{key} must be a non-empty path")

    for role, spec in data.get("services", {}).get("roles", {}).items():
        if not isinstance(spec, dict):
            res.errors.append(f"services.roles.{role} must be a mapping")
            continue
        for unit in spec.get("units", []):
            if not re.match(r"^[A-Za-z0-9:_.@\\-]+(\.service)?$", str(unit)):
                res.errors.append(f"services.roles.{role}.units has an invalid unit name: {unit!r}")

    return res


class Config:
    """Immutable-ish wrapper over the merged configuration dictionary."""

    def __init__(self, data: Dict[str, Any], source: Optional[str] = None,
                 validation: Optional[ValidationResult] = None):
        self.data = data
        self.source = source
        self.validation = validation or validate_config(data)

    # ----- access helpers
    def get(self, dotted: str, default: Any = None) -> Any:
        value = _lookup(self.data, dotted)
        return default if value is None else value

    def section(self, name: str) -> Dict[str, Any]:
        return self.data.get(name, {})

    @property
    def timezone(self) -> str:
        return str(self.get("general.timezone", "Asia/Jakarta"))

    @property
    def data_dir(self) -> Path:
        return Path(self.get("paths.data_dir"))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "monitoring.db"

    @property
    def report_dir(self) -> Path:
        return Path(self.get("paths.report_dir"))

    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    @property
    def baseline_dir(self) -> Path:
        return self.data_dir / "baseline"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    def threshold(self, name: str) -> float:
        return self.data["thresholds"][name]

    # ----- secrets (never printed)
    def secret(self, name: str) -> Optional[str]:
        """Return the secret value from env override or file; ``None`` if unavailable."""
        key, env = SECRETS[name]
        if name == "mariadb_defaults":
            return None  # path-only secret, see secret_path
        if os.environ.get(env):
            return os.environ[env].strip()
        path = self.get(key)
        if not path:
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip() or None
        except OSError:
            return None

    def secret_path(self, name: str) -> Optional[str]:
        key, env = SECRETS[name]
        value = os.environ.get(env) if name == "mariadb_defaults" else None
        return value or self.get(key) or None

    def secret_values(self) -> List[str]:
        values = []
        for name in SECRETS:
            if name == "mariadb_defaults":
                continue
            v = self.secret(name)
            if v:
                values.append(v)
        return values

    def redacted(self) -> Dict[str, Any]:
        return redact_mapping(self.data)

    def check_secret_permissions(self) -> List[str]:
        """Return human-readable problems with secret file ownership/mode (POSIX only)."""
        problems: List[str] = []
        if not hasattr(os, "geteuid"):
            return problems
        for _name, (key, _env) in SECRETS.items():
            path = self.get(key)
            if not path or not os.path.exists(path):
                continue
            try:
                st = os.stat(path)
            except OSError as exc:
                problems.append(f"{path}: cannot stat ({exc.strerror})")
                continue
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o007:
                problems.append(f"{path}: world-accessible (mode {oct(mode)}, expected 0600 or 0640)")
            elif mode & 0o020:
                problems.append(f"{path}: group-writable (mode {oct(mode)}, expected 0600 or 0640)")
        return problems


def load_config(path: Optional[str] = None, require_file: bool = False) -> Config:
    """Load configuration from ``path`` (or $SHSM_CONFIG, or /etc/shsm/config.yaml) merged with defaults."""
    cfg_path = path or os.environ.get(ENV_CONFIG) or DEFAULT_CONFIG_PATH
    user: Dict[str, Any] = {}
    source: Optional[str] = None
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigError([f"{cfg_path}: invalid YAML: {exc}"]) from exc
        except OSError as exc:
            raise ConfigError([f"{cfg_path}: cannot read: {exc.strerror}"]) from exc
        if not isinstance(loaded, dict):
            raise ConfigError([f"{cfg_path}: top level must be a mapping"])
        user = loaded
        source = cfg_path
    elif require_file:
        raise ConfigError([f"configuration file not found: {cfg_path}"])
    merged = deep_merge(DEFAULTS, user)
    validation = validate_config(merged, user)
    return Config(merged, source, validation)
