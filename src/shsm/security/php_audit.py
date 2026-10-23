"""PHP security audit collector for CVE-2026-109618, CVE-2026-109619 (PHP2Shell),
vulnerable PHP versions, insecure php.ini directives, and uploads directory execution flags.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "php_security"
CATEGORY = "vulnerability"

# List of dangerous functions that must be disabled in php.ini
DANGEROUS_FUNCTIONS: Set[str] = {
    "exec",
    "shell_exec",
    "system",
    "passthru",
    "proc_open",
    "popen",
    "pcntl_exec",
}

# Versions known to be vulnerable to CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2 Critical)
# Format: (major, minor, min_patch_safe)
SAFE_PATCH_VERSIONS = {
    (8, 1): 32,  # Example: >= 8.1.32 safe
    (8, 2): 28,  # Example: >= 8.2.28 safe
    (8, 3): 16,  # Example: >= 8.3.16 safe
    (8, 4): 3,   # Example: >= 8.4.3 safe
}

_VER_RE = re.compile(r"PHP\s+(\d+)\.(\d+)\.(\d+)")


def parse_php_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse '8.2.14' or 'PHP 8.2.14 (...)' into (8, 2, 14)."""
    m = _VER_RE.search(version_str)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    # fallback for raw '8.2.14'
    parts = version_str.strip().split(".")
    if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
        p3 = parts[2].split("-")[0].split("+")[0]
        if p3.isdigit():
            return int(parts[0]), int(parts[1]), int(p3)
    return None


def is_vulnerable_to_php2shell(version_tuple: Tuple[int, int, int]) -> bool:
    """Check if the given (major, minor, patch) version is affected by PHP2Shell."""
    major, minor, patch = version_tuple
    # Any PHP 7.x or 5.x is EOL and unpatched => inherently vulnerable
    if major < 8:
        return True
    safe_patch = SAFE_PATCH_VERSIONS.get((major, minor))
    if safe_patch is None:
        # 8.0 is EOL without upstream fix, or unknown older release
        if (major, minor) < (8, 1):
            return True
        return False
    return patch < safe_patch


def check_php_ini_content(content: str, path: str) -> List[Dict[str, Any]]:
    """Inspect php.ini configuration text for insecure settings."""
    issues = []
    
    # Check disable_functions
    disable_funcs_val = ""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if line.lower().startswith("disable_functions"):
            parts = line.split("=", 1)
            if len(parts) == 2:
                disable_funcs_val = parts[1].strip()

    active_disabled = {f.strip().lower() for f in disable_funcs_val.split(",") if f.strip()}
    missing_dangerous = DANGEROUS_FUNCTIONS - active_disabled

    if missing_dangerous:
        issues.append({
            "type": "missing_disable_functions",
            "severity": Severity.HIGH,
            "title": f"Dangerous execution functions enabled in {os.path.basename(path)}",
            "evidence": f"Dangerous functions not disabled: {', '.join(sorted(missing_dangerous))}.",
            "recommendation": "Add dangerous execution functions (exec, shell_exec, system, passthru, proc_open, popen, pcntl_exec) to 'disable_functions' in php.ini.",
        })

    # Check allow_url_include
    if re.search(r"(?i)^\s*allow_url_include\s*=\s*(?:1|on|true|yes)\b", content, re.MULTILINE):
        issues.append({
            "type": "allow_url_include_enabled",
            "severity": Severity.CRITICAL,
            "title": f"CRITICAL: allow_url_include is enabled in {os.path.basename(path)}",
            "evidence": "allow_url_include is active, allowing direct Remote Code Execution (RCE) via remote file inclusion.",
            "recommendation": "Set 'allow_url_include = Off' in php.ini immediately.",
        })

    # Check allow_url_fopen
    if re.search(r"(?i)^\s*allow_url_fopen\s*=\s*(?:1|on|true|yes)\b", content, re.MULTILINE):
        issues.append({
            "type": "allow_url_fopen_warning",
            "severity": Severity.LOW,
            "title": f"allow_url_fopen is enabled in {os.path.basename(path)}",
            "evidence": "allow_url_fopen is active. If not strictly required by application, consider disabling.",
            "recommendation": "Evaluate if allow_url_fopen can be set to Off.",
        })

    return issues


def audit_uploads_protection(ctx: Context, doc_root: str, domain: str) -> List[Dict[str, Any]]:
    """Verify that execution of PHP scripts is disabled inside wp-content/uploads."""
    issues = []
    uploads_dir = os.path.join(doc_root, "wp-content", "uploads")
    if not os.path.isdir(uploads_dir):
        return issues

    htaccess_file = os.path.join(uploads_dir, ".htaccess")
    if not os.path.exists(htaccess_file):
        issues.append({
            "domain": domain,
            "severity": Severity.MEDIUM,
            "title": f"Missing execution block in WordPress uploads for {domain}",
            "evidence": f"No .htaccess found in {uploads_dir} to block direct PHP execution.",
            "recommendation": "Add .htaccess in uploads directory denying access to php/phtml files or disable script execution in OpenLiteSpeed vhost context.",
        })
    else:
        try:
            with open(htaccess_file, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            # Check for deny rules on php files
            has_php_deny = bool(re.search(r"(?i)\b(?:deny\s+from\s+all|require\s+all\s+denied)\b", content)) and bool(
                re.search(r"(?i)\.(?:php|phtml)", content)
            )
            if not has_php_deny:
                issues.append({
                    "domain": domain,
                    "severity": Severity.MEDIUM,
                    "title": f"Incomplete PHP block in uploads .htaccess on {domain}",
                    "evidence": f".htaccess exists at {htaccess_file} but does not explicitly deny PHP script execution.",
                    "recommendation": "Configure '<FilesMatch \"\\.(php|phtml|php[0-9])\\$\"> Require all denied </FilesMatch>' in uploads .htaccess.",
                })
        except OSError:
            pass

    return issues


def collect(ctx: Context) -> CollectorOutput:
    """Audit PHP versions, CVE-2026-109618/109619 exposure, and hardening."""
    out = CollectorOutput()

    # 1. Discover all PHP installations (system + OpenLiteSpeed/CyberPanel lsphp)
    php_candidates = [
        "php",
        "/usr/local/lsws/lsphp83/bin/php",
        "/usr/local/lsws/lsphp82/bin/php",
        "/usr/local/lsws/lsphp81/bin/php",
        "/usr/local/lsws/lsphp80/bin/php",
        "/usr/local/lsws/lsphp74/bin/php",
        "/usr/bin/php",
    ]

    checked_binaries: Set[str] = set()
    found_any_php = False

    for cand in php_candidates:
        bin_path = ctx.runner.which(cand)
        if not bin_path or bin_path in checked_binaries:
            continue
        checked_binaries.add(bin_path)
        found_any_php = True

        res = ctx.runner.run([bin_path, "-v"], timeout=5.0)
        if not res.ok:
            continue

        ver_tuple = parse_php_version(res.stdout)
        if not ver_tuple:
            continue

        v_str = f"{ver_tuple[0]}.{ver_tuple[1]}.{ver_tuple[2]}"
        
        # Check PHP2Shell vulnerability
        if is_vulnerable_to_php2shell(ver_tuple):
            out.finding(
                "php.cve_php2shell",
                CATEGORY,
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"PHP2Shell vulnerability (CVE-2026-109618 / CVE-2026-109619) detected in {os.path.basename(bin_path)} ({v_str})",
                f"Installed binary {bin_path} is running PHP {v_str}, which is vulnerable to remote code execution and webshell dropping (CVSS 9.2).",
                f"Immediately update PHP ({bin_path}) to the latest security release or patch provided by your distribution / CyberPanel repository.",
                asset=bin_path,
                source=SOURCE,
                key=f"{bin_path}:cve_php2shell",
            )
        else:
            out.check(
                f"php.version.{os.path.basename(bin_path)}",
                CATEGORY,
                CheckStatus.PASS,
                f"PHP {v_str} at {bin_path} is patched against CVE-2026-109618 / CVE-2026-109619",
                asset=bin_path,
                source=SOURCE,
            )

        # 2. Check php.ini configuration for this binary
        ini_res = ctx.runner.run([bin_path, "--ini"], timeout=5.0)
        if ini_res.ok:
            m = re.search(r"Loaded Configuration File:\s*(\S+)", ini_res.stdout)
            if m:
                ini_path = m.group(1).strip()
                if os.path.isfile(ini_path):
                    try:
                        with open(ini_path, "r", encoding="utf-8", errors="ignore") as fh:
                            ini_content = fh.read()
                        ini_issues = check_php_ini_content(ini_content, ini_path)
                        for issue in ini_issues:
                            out.finding(
                                f"php.ini.{issue['type']}",
                                CATEGORY,
                                issue["severity"],
                                Confidence.HIGH,
                                issue["title"],
                                issue["evidence"],
                                issue["recommendation"],
                                asset=ini_path,
                                source=SOURCE,
                                key=f"{ini_path}:{issue['type']}",
                            )
                    except OSError:
                        pass

    # 3. Check WordPress uploads execution prevention for discovered active sites
    try:
        sites = ctx.inventory.active_wordpress_sites()
    except Exception:
        sites = []

    for site in sites:
        doc_root = site.get("doc_root")
        domain = site.get("domain", "unknown")
        if doc_root and os.path.isdir(doc_root):
            upload_issues = audit_uploads_protection(ctx, doc_root, domain)
            for iss in upload_issues:
                out.finding(
                    "wordpress.uploads_php_execution",
                    "wordpress",
                    iss["severity"],
                    Confidence.HIGH,
                    iss["title"],
                    iss["evidence"],
                    iss["recommendation"],
                    asset=domain,
                    source=SOURCE,
                    key=f"{domain}:uploads_php_exec",
                )

    cve_findings = [f for f in out.findings if f.check_id == "php.cve_php2shell"]
    if cve_findings:
        out.check(
            "php.security",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"CRITICAL: {len(cve_findings)} PHP runtime(s) vulnerable to PHP2Shell (CVE-2026-109618/CVE-2026-109619)",
            source=SOURCE,
        )
    elif found_any_php:
        out.check(
            "php.security",
            CATEGORY,
            CheckStatus.PASS,
            f"Audited {len(checked_binaries)} PHP binary runtime(s); no PHP2Shell exposure found",
            source=SOURCE,
        )
    else:
        out.check(
            "php.security",
            CATEGORY,
            CheckStatus.NOT_APPLICABLE,
            "No PHP binary runtimes detected on system",
            source=SOURCE,
        )

    return out
