import os
from pathlib import Path
import pytest

from ctf_recon.models import (
    AIAnalysisResult,
    FlagFinding,
    PortScanResult,
    TriageReport,
    WebTriageResult,
)
from ctf_recon.report.markdown_writer import (
    export_report_to_markdown,
    generate_markdown_report,
)


def test_generate_markdown_report_empty():
    report = TriageReport(target="192.168.1.100")
    md = generate_markdown_report(report)

    assert "# CTF Recon & Triage Report: `192.168.1.100`" in md
    assert "**Open Ports Detected:** 0" in md
    assert "No open ports were detected on this target" in md
    assert "No web applications were detected or triaged" in md
    assert "No flags or suspicious decoded Base64 tokens were discovered" in md
    assert "AI analysis was not enabled for this scan" in md


def test_generate_markdown_report_full():
    open_ports = [
        PortScanResult(port=80, state="open", banner="Apache/2.4.49 (Unix)"),
        PortScanResult(port=22, state="open", banner="OpenSSH 8.2p1"),
    ]
    web_findings = [
        WebTriageResult(
            url="http://192.168.1.100:80",
            status_code=200,
            server_header="Apache/2.4.49",
            x_powered_by="PHP/7.4",
            redirects=["301 -> http://192.168.1.100:80/index.php"],
            findings=["/robots.txt accessible", "Exposed Git repository: /.git/HEAD"],
            routes_checked=["/", "/robots.txt", "/.git/HEAD"],
        )
    ]
    flags_found = [
        FlagFinding(
            flag_text="FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}",
            source="http://192.168.1.100:80/robots.txt",
            format_type="regex",
        ),
        FlagFinding(
            flag_text="HTB{base64_secret_decoded}",
            source="header",
            format_type="base64_decoded",
        ),
    ]
    ai_analysis = AIAnalysisResult(
        probable_cves=["CVE-2021-41773", "CVE-2021-42013"],
        service_criticality={"port 80": "Critical", "port 22": "Low"},
        suggested_cli_commands=[
            "curl -s --path-as-is http://192.168.1.100:80/icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
        ],
        attack_vectors=["Apache 2.4.49 path traversal and RCE"],
    )

    report = TriageReport(
        target="192.168.1.100",
        open_ports=open_ports,
        web_findings=web_findings,
        flags_found=flags_found,
        ai_analysis=ai_analysis,
    )

    md = generate_markdown_report(report)

    # Ports check
    assert "`80`" in md
    assert "Apache/2.4.49" in md
    assert "`22`" in md

    # Web triage check
    assert "http://192.168.1.100:80" in md
    assert "PHP/7.4" in md
    assert "Exposed Git repository: /.git/HEAD" in md
    assert "301 -> http://192.168.1.100:80/index.php" in md

    # Flags check
    assert "FaMAF{br0k3n_4cc3ss_c0ntr0l_ch3ck_th3_0wn3r}" in md
    assert "HTB{base64_secret_decoded}" in md
    assert "`base64_decoded`" in md

    # AI check
    assert "CVE-2021-41773" in md
    assert "**Critical**" in md
    assert "curl -s --path-as-is" in md
    assert "Apache 2.4.49 path traversal" in md


def test_export_report_to_markdown(tmp_path: Path):
    report = TriageReport(
        target="ctf.local",
        open_ports=[PortScanResult(port=8080, banner="nginx")],
    )

    out_file = tmp_path / "subdir" / "custom_report.md"
    resolved_path = export_report_to_markdown(report, str(out_file))

    assert Path(resolved_path).exists()
    assert Path(resolved_path).is_file()
    saved_content = Path(resolved_path).read_text(encoding="utf-8")
    assert "# CTF Recon & Triage Report: `ctf.local`" in saved_content
    assert "`8080`" in saved_content
