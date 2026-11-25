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


def test_services_collector_prefers_active_csf_over_ufw(test_db, sample_config):
    from unittest.mock import patch

    from shsm.collectors import services
    from shsm.core.subprocesses import FakeRunner

    runner = FakeRunner(available={"systemctl", "csf", "sudo"})
    runner.responses["systemctl list-units"] = CommandResult(
        [], 0,
        stdout="ufw.service loaded active exited Uncomplicated firewall\nlfd.service loaded active running ConfigServer Security & Firewall\n",
    )
    runner.responses["systemctl show lfd.service"] = CommandResult(
        [], 0,
        stdout="Id=lfd.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=1234\nNRestarts=0\nResult=success\n",
    )
    runner.responses["systemctl list-units --state=failed"] = CommandResult([], 0, stdout="")

    sample_config.data["services"]["roles"] = {
        "firewall": {"patterns": ["csf", "lfd", "ufw"], "units": [], "required": False},
    }
    ctx = Context(sample_config, test_db, runner=runner)
    with patch("shsm.security.firewall.detect_active_firewall", return_value=("csf", True, "CSF active")):
        out = services.collect(ctx)

    chk = next(c for c in out.checks if c.check_id == "service.firewall")
    assert chk.asset == "lfd.service"
    latest = ctx.inventory.latest_services()
    assert len(latest) == 1
    assert latest[0]["unit"] == "lfd.service"


def test_doctor_reports_active_firewall_dynamically(test_db, sample_config):
    from unittest.mock import patch

    from click.testing import CliRunner

    from shsm.cli import main

    ctx = Context(sample_config, test_db, runner=FakeFirewallRunner("csf"))
    with patch("shsm.cli.get_context", return_value=ctx):
        res = CliRunner().invoke(main, ["doctor"])
    assert res.exit_code == 0
    assert "Active firewall backend: CSF" in res.output
    assert "Found defense tool csf" in res.output
