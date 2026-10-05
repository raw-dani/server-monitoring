"""Unit tests for flexible firewall detection."""

from shsm.core.context import Context
from shsm.core.subprocesses import CommandResult, Runner
from shsm.security.firewall import detect_active_firewall


class FakeFirewallRunner(Runner):
    def __init__(self, detected_tool: str = "iptables"):
        super().__init__()
        self.detected_tool = detected_tool

    def which(self, name: str):
        if self.detected_tool in name:
            return f"/usr/sbin/{name}"
        return None

    def run(self, args, **kwargs):
        cmd = args[0]
        if self.detected_tool in cmd:
            if "iptables" in cmd:
                return CommandResult(args=list(args), returncode=0, stdout="Chain INPUT (policy ACCEPT)\nACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0\n")
            if "csf" in cmd:
                return CommandResult(args=list(args), returncode=0, stdout="Chain csf ... active")
            if "firewall-cmd" in cmd:
                return CommandResult(args=list(args), returncode=0, stdout="running\n")
            if "ufw" in cmd:
                return CommandResult(args=list(args), returncode=0, stdout="Status: active\n")
            if "nft" in cmd:
                return CommandResult(args=list(args), returncode=0, stdout="table inet filter { chain input { type filter hook input priority 0; } }\n")
        return CommandResult(args=list(args), returncode=1, stderr="not found")


def test_detect_iptables(test_db, sample_config):
    ctx = Context(sample_config, test_db, runner=FakeFirewallRunner("iptables"))
    fw_name, is_active, desc = detect_active_firewall(ctx)
    assert is_active is True
    assert fw_name == "iptables"


def test_detect_csf(test_db, sample_config):
    ctx = Context(sample_config, test_db, runner=FakeFirewallRunner("csf"))
    fw_name, is_active, desc = detect_active_firewall(ctx)
    assert is_active is True
    assert fw_name == "csf"


def test_detect_firewalld(test_db, sample_config):
    ctx = Context(sample_config, test_db, runner=FakeFirewallRunner("firewall-cmd"))
    fw_name, is_active, desc = detect_active_firewall(ctx)
    assert is_active is True
    assert fw_name == "firewalld"


def test_detect_none(test_db, sample_config):
    ctx = Context(sample_config, test_db, runner=FakeFirewallRunner("unknown_fw"))
    fw_name, is_active, desc = detect_active_firewall(ctx)
    assert is_active is False
    assert fw_name == "none"
