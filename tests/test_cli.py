from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
from unittest.mock import patch
import pytest
from typer.testing import CliRunner

from ctf_recon.cli import app
from ctf_recon.models import AIAnalysisResult

runner = CliRunner()


class MockCTFHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"Welcome to FaMAF CTF Challenge! Secret: FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}"
        )

    def log_message(self, format, *args):
        # Suppress server logging during tests
        pass


def test_cli_scan_offline(tmp_path: Path):
    output_report = tmp_path / "offline_report.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "127.0.0.1",
            "-p",
            "54321",
            "--timeout",
            "0.2",
            "-o",
            str(output_report),
        ],
    )

    assert result.exit_code == 0
    assert "Target: 127.0.0.1" in result.output
    assert "Ports to check: 1" in result.output
    assert output_report.exists()
    content = output_report.read_text(encoding="utf-8")
    assert "# CTF Recon & Triage Report: `127.0.0.1`" in content


def test_cli_scan_full_pipeline_with_mock_services(tmp_path: Path):
    httpd = HTTPServer(("127.0.0.1", 0), MockCTFHandler)
    port = httpd.server_port
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    output_report = tmp_path / "mock_report.md"

    mock_ai_result = AIAnalysisResult(
        probable_cves=["CVE-2021-41773"],
        service_criticality={"port " + str(port): "Critical"},
        suggested_cli_commands=["curl -v http://127.0.0.1:" + str(port)],
        attack_vectors=["Path traversal on Apache 2.4.49"],
    )

    try:
        with patch("ctf_recon.cli.run_ai_advisor", return_value=mock_ai_result):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "127.0.0.1",
                    "-p",
                    str(port),
                    "--ai",
                    "-m",
                    "gemini-3.6-flash",
                    "--timeout",
                    "1.0",
                    "-o",
                    str(output_report),
                ],
            )
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert result.exit_code == 0
    assert "Discovered Open Ports" in result.output
    assert str(port) in result.output
    assert "FLAG DETECTED" in result.output
    assert "FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}" in result.output
    assert "Gemini AI Triage" in result.output
    assert "CVE-2021-41773" in result.output

    # Verify exported markdown report
    assert output_report.exists()
    report_text = output_report.read_text(encoding="utf-8")
    assert "FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}" in report_text
    assert "CVE-2021-41773" in report_text


def test_cli_keyboard_interrupt():
    with patch("ctf_recon.cli._execute_scan", side_effect=KeyboardInterrupt):
        result = runner.invoke(app, ["scan", "127.0.0.1", "-p", "80"])
        assert result.exit_code == 130
        assert "Scan cancelled by user" in result.output


def test_cli_key_argument(tmp_path: Path):
    output_report = tmp_path / "key_report.md"
    with patch("ctf_recon.cli.run_ai_advisor", return_value=None) as mock_advisor:
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "-p",
                "54321",
                "-k",
                "custom_secret_key_999",
                "--timeout",
                "0.2",
                "-o",
                str(output_report),
            ],
        )
        assert result.exit_code == 0
        assert mock_advisor.called
        assert mock_advisor.call_args[1]["api_key"] == "custom_secret_key_999"

