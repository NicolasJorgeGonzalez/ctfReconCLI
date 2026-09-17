import ctf_recon
from typer.testing import CliRunner
from ctf_recon.cli import app

runner = CliRunner()


def test_basic():
    assert ctf_recon is not None


def test_cli_import():
    assert app is not None


def test_cli_model_argument():
    # Test --help displays the model option
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--model" in result.output
    assert "-m" in result.output
    assert "--key" in result.output
    assert "-k" in result.output
    assert "gemini-2.5-flash" in result.output

    # Test passing custom model via --model
    result2 = runner.invoke(app, ["scan", "127.0.0.1", "--ai", "--model", "gemini-1.5-pro"])
    assert result2.exit_code == 0
    assert "gemini-1.5-pro" in result2.output

    # Test passing custom model via -m
    result3 = runner.invoke(app, ["scan", "10.10.10.1", "--ai", "-m", "gemini-2.5-pro"])
    assert result3.exit_code == 0
    assert "gemini-2.5-pro" in result3.output
