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
    assert "db" in result.output


def test_cli_config_show():
    runner = CliRunner()
    result = runner.invoke(main, ["config", "show", "--redacted"])
    assert result.exit_code == 0
    assert "general" in result.output


def test_cli_db_commands(temp_dir, monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv("SHSM_PATHS_DATA_DIR", temp_dir)
    res_migrate = runner.invoke(main, ["db", "migrate"])
    assert res_migrate.exit_code == 0
    assert "migrations" in res_migrate.output.lower() or "schema" in res_migrate.output.lower()

    res_status = runner.invoke(main, ["db", "status"])
    assert res_status.exit_code == 0
    assert "Integrity Check:  ok" in res_status.output
