from unittest.mock import MagicMock
from shsm.security.blocked import (
    get_fail2ban_blocked,
    get_iptables_blocked,
    list_all_blocked,
    check_ip_blocked,
    unban_ip_unified,
    ban_ip_unified,
)


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
        if "iptables" in cmd[0] or (len(cmd) > 1 and "iptables" in cmd[1]):
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
