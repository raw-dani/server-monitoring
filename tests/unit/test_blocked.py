from unittest.mock import MagicMock

from shsm.security.blocked import (
    check_ip_blocked,
    get_csf_blocked,
    get_fail2ban_blocked,
    get_iptables_blocked,
    list_all_blocked,
    unban_ip_unified,
)


def test_get_csf_blocked():
    ctx = MagicMock()
    ctx.runner.which.side_effect = lambda name: f"/usr/sbin/{name}" if name in ("csf", "iptables") else None

    def run_side_effect(cmd, timeout=None):
        res = MagicMock()
        if "DENYIN" in cmd:
            res.ok = True
            res.stdout = """Chain DENYIN (1 references)
 pkts bytes target     prot opt in     out     source               destination
   12   720 DROP       all  --  !lo    *       198.51.100.44        0.0.0.0/0
"""
            return res
        if "LOCALINPUT" in cmd:
            res.ok = True
            res.stdout = """Chain LOCALINPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ALLOWIN    all  --  !lo    *       0.0.0.0/0            0.0.0.0/0
    5   300 DROP       all  --  !lo    *       203.0.113.88         0.0.0.0/0
    0     0 DENYIN     all  --  !lo    *       0.0.0.0/0            0.0.0.0/0
"""
            return res
        return MagicMock(ok=False, stdout="", stderr="")

    ctx.runner.run.side_effect = run_side_effect
    items = get_csf_blocked(ctx)
    assert len(items) == 2
    assert items[0]["source"] == "csf"
    assert items[0]["target"] == "198.51.100.44"
    assert items[0]["jail_or_chain"] == "DENYIN"
    assert items[1]["target"] == "203.0.113.88"
    assert items[1]["jail_or_chain"] == "LOCALINPUT"

    all_items = list_all_blocked(ctx)
    assert any(x["source"] == "csf" and x["target"] == "198.51.100.44" for x in all_items)

    res_chk = check_ip_blocked(ctx, "198.51.100.44")
    assert res_chk["is_blocked"] is True
    assert res_chk["matches"][0]["source"] == "csf"


def test_get_fail2ban_blocked():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/bin/fail2ban-client"

    # Mock get_active_jails and status
    def run_side_effect(cmd, timeout=None):
        res = MagicMock()
        res.ok = True
        if cmd[1] == "status" and len(cmd) == 2:
            res.stdout = "Number of jail:\t2\nJail list:\tsshd, ols-scanner\n"
            return res
        if "ols-scanner" in cmd:
            res.stdout = "Status for the jail: ols-scanner\n|- Filter\n`- Actions\n   |- Currently banned: 1\n   `- Banned IP list:\t185.220.101.5\n"
            return res
        if "sshd" in cmd:
            res.stdout = "Status for the jail: sshd\n|- Filter\n`- Actions\n   |- Currently banned: 1\n   `- Banned IP list:\t93.123.109.165\n"
            return res
        return MagicMock(ok=False)

    ctx.runner.run.side_effect = run_side_effect
    items = get_fail2ban_blocked(ctx)

    assert len(items) == 2
    assert items[0]["target"] == "93.123.109.165"
    assert items[1]["target"] == "185.220.101.5"


def test_get_iptables_blocked():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/sbin/iptables"

    ipt_output = """Chain INPUT (policy DROP 66851 packets, 5065K bytes)
 pkts bytes target     prot opt in     out     source               destination         
  287 13604 DROP       all  --  *      *       35.192.0.0/12        0.0.0.0/0           
    2   120 DROP       all  --  *      *       93.123.109.165       0.0.0.0/0           
 2265  107K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            -m geoip --source-country CN,RU
"""
    res = MagicMock()
    res.ok = True
    res.stdout = ipt_output
    ctx.runner.run.return_value = res

    items = get_iptables_blocked(ctx)
    assert len(items) == 3
    assert items[0]["target"] == "35.192.0.0/12"
    assert items[0]["packets"] == "287"
    assert items[1]["target"] == "93.123.109.165"
    assert items[2]["source"] == "iptables"


def test_check_ip_blocked_exact_and_subnet():
    ctx = MagicMock()
    # Mock fail2ban returning empty
    # Mock iptables returning a subnet rule
    def which_side_effect(name):
        return f"/usr/bin/{name}"

    ctx.runner.which.side_effect = which_side_effect

    ipt_output = """Chain INPUT (policy ACCEPT)
 pkts bytes target     prot opt in     out     source               destination         
  287 13604 DROP       all  --  *      *       35.192.0.0/12        0.0.0.0/0           
    2   120 DROP       all  --  *      *       93.123.109.165       0.0.0.0/0           
"""
    def run_side_effect(cmd, timeout=None):
        res = MagicMock()
        if any("iptables" in c for c in cmd):
            res.ok = True
            res.stdout = ipt_output
            return res
        res.ok = True
        res.stdout = "Number of jail:\t0\nJail list:\t\n"
        return res

    ctx.runner.run.side_effect = run_side_effect

    # 1. Exact match test
    res_exact = check_ip_blocked(ctx, "93.123.109.165")
    assert res_exact["is_blocked"] is True
    assert len(res_exact["matches"]) == 1
    assert res_exact["matches"][0]["target"] == "93.123.109.165"

    # 2. Subnet match test (35.195.10.20 falls inside 35.192.0.0/12)
    res_sub = check_ip_blocked(ctx, "35.195.10.20")
    assert res_sub["is_blocked"] is True
    assert res_sub["matches"][0]["matched_subnet"] == "35.192.0.0/12"

    # 3. Not blocked test
    res_free = check_ip_blocked(ctx, "8.8.8.8")
    assert res_free["is_blocked"] is False
    assert len(res_free["matches"]) == 0


def test_unban_ip_unified():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/bin/tool"

    def run_side_effect(cmd, timeout=None):
        res = MagicMock()
        res.ok = True
        res.stdout = "1"
        return res

    ctx.runner.run.side_effect = run_side_effect

    ok, msgs = unban_ip_unified(ctx, "93.123.109.165")
    assert ok is True
    assert any("Fail2Ban" in m for m in msgs)
    assert any("iptables" in m for m in msgs)


def test_cmd_block_scanners(tmp_path):
    from click.testing import CliRunner
    from shsm.cli import cmd_block_scanners

    log_file = tmp_path / "access.log"
    lines = []
    for _ in range(35):
        lines.append('34.81.106.122 - - [28/Oct/2026:10:00:00 +0700] "GET /app HTTP/1.1" 404 1234')
    for _ in range(10):
        lines.append('45.148.10.80 - - [28/Oct/2026:10:00:00 +0700] "GET /.env HTTP/1.1" 404 1234')
    for _ in range(40):
        lines.append('127.0.0.1 - - [28/Oct/2026:10:00:00 +0700] "GET /test HTTP/1.1" 404 1234')
    log_file.write_text("\n".join(lines), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cmd_block_scanners, ["--log-file", str(log_file), "--threshold", "30", "--dry-run"], obj={})
    assert result.exit_code == 0
    assert "Found 1 external IP(s) exceeding threshold" in result.output
    assert "34.81.106.122" in result.output
    assert "[DRY-RUN]" in result.output
    assert "127.0.0.1" not in result.output


def test_cmd_block_scanners_dry_run_unblocked_only(tmp_path):
    from unittest.mock import patch

    from click.testing import CliRunner

    from shsm.cli import cmd_block_scanners

    log_file = tmp_path / "access.log"
    lines = []
    for _ in range(35):
        lines.append('34.81.106.122 - - [28/Oct/2026:10:00:00 +0700] "GET /a HTTP/1.1" 404 100')
        lines.append('198.51.100.25 - - [28/Oct/2026:10:00:00 +0700] "GET /b HTTP/1.1" 404 100')
        lines.append('203.0.113.77 - - [28/Oct/2026:10:00:00 +0700] "GET /c HTTP/1.1" 404 100')
    log_file.write_text("\n".join(lines), encoding="utf-8")

    mock_blocked = [
        {"source": "csf", "target": "198.51.100.25"},
        {"source": "iptables", "target": "203.0.113.0/24"},
    ]
    runner = CliRunner()
    with patch("shsm.security.blocked.list_all_blocked", return_value=mock_blocked):
        res_all = runner.invoke(cmd_block_scanners, ["--log-file", str(log_file), "--threshold", "30", "--dry-run"], obj={})
        assert res_all.exit_code == 0
        assert "198.51.100.25" in res_all.output and "[SKIPPED] Already blocked" in res_all.output
        assert "34.81.106.122" in res_all.output and "[DRY-RUN] Would be blocked" in res_all.output
        assert "1 unblocked IP(s) would be blocked (2 already blocked)" in res_all.output

        res_only = runner.invoke(
            cmd_block_scanners,
            ["--log-file", str(log_file), "--threshold", "30", "--dry-run", "--unblocked-only"],
            obj={},
        )
        assert res_only.exit_code == 0
        assert "34.81.106.122" in res_only.output
        assert "198.51.100.25" not in res_only.output
        assert "203.0.113.77" not in res_only.output
        assert "[SKIPPED]" not in res_only.output


