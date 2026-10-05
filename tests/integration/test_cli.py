"""Integration tests for the Click CLI."""

from click.testing import CliRunner

from shsm.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "SHSM" in result.output or "1.0.0" in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "health" in result.output
    assert "security" in result.output
    assert "doctor" in result.output
    assert "websites" in result.output
    assert "wordpress" in result.output
    assert "config" in result.output


def test_cli_config_show():
    runner = CliRunner()
    result = runner.invoke(main, ["config", "show", "--redacted"])
    assert result.exit_code == 0
    assert "general" in result.output
