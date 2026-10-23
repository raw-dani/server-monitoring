"""Unit tests for PHP security auditor and PHP2Shell detection (CVE-2026-109618, CVE-2026-109619)."""

import os
import tempfile
from shsm.security.php_audit import (
    check_php_ini_content,
    is_vulnerable_to_php2shell,
    parse_php_version,
)
from shsm.security.malware import scan_file_heuristics


def test_parse_php_version():
    assert parse_php_version("PHP 8.2.14 (cli) (built: Dec 20 2023 20:20:20)") == (8, 2, 14)
    assert parse_php_version("8.1.31-ubuntu1") == (8, 1, 31)
    assert parse_php_version("8.3.15") == (8, 3, 15)
    assert parse_php_version("invalid") is None


def test_is_vulnerable_to_php2shell():
    # Vulnerable versions (below patch thresholds)
    assert is_vulnerable_to_php2shell((7, 4, 33)) is True
    assert is_vulnerable_to_php2shell((8, 0, 30)) is True
    assert is_vulnerable_to_php2shell((8, 1, 31)) is True
    assert is_vulnerable_to_php2shell((8, 2, 27)) is True
    assert is_vulnerable_to_php2shell((8, 3, 15)) is True
    assert is_vulnerable_to_php2shell((8, 4, 2)) is True

    # Safe / Patched versions
    assert is_vulnerable_to_php2shell((8, 1, 32)) is False
    assert is_vulnerable_to_php2shell((8, 2, 28)) is False
    assert is_vulnerable_to_php2shell((8, 3, 16)) is False
    assert is_vulnerable_to_php2shell((8, 4, 3)) is False
    assert is_vulnerable_to_php2shell((8, 4, 10)) is False


def test_check_php_ini_content():
    # Insecure ini content
    bad_ini = """
    disable_functions = 
    allow_url_include = On
    allow_url_fopen = On
    """
    issues = check_php_ini_content(bad_ini, "/etc/php/8.2/cli/php.ini")
    types = [i["type"] for i in issues]
    assert "missing_disable_functions" in types
    assert "allow_url_include_enabled" in types

    # Secure ini content
    good_ini = """
    disable_functions = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec
    allow_url_include = Off
    allow_url_fopen = Off
    """
    good_issues = check_php_ini_content(good_ini, "/etc/php/8.2/cli/php.ini")
    assert len(good_issues) == 0


def test_malware_heuristics_php2shell():
    # Dynamically construct test string at runtime to avoid static AV signature flagging on disk
    tag = "<?" + "php "
    code = tag + "sys" + "tem($_GE" + "T['c" + "md']);"
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        findings = scan_file_heuristics(temp_path)
        types = [find["type"] for find in findings]
        assert "php2shell_stager" in types
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_malware_heuristics_stream_wrapper():
    tag = "<?" + "php "
    code = tag + "inc" + "lude('php:" + "//in" + "put');"
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        findings = scan_file_heuristics(temp_path)
        types = [find["type"] for find in findings]
        assert "php_wrapper_abuse" in types
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
