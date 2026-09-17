import json
from datetime import datetime
from ctf_recon.models import (
    PortScanResult,
    WebTriageResult,
    FlagFinding,
    AIAnalysisResult,
    TriageReport
)

def test_port_scan_result():
    res = PortScanResult(port=80)
    assert res.port == 80
    assert res.state == "open"
    assert res.banner is None
    assert res.protocol == "tcp"

    res_json = json.loads(res.model_dump_json())
    assert res_json["port"] == 80
    assert res_json["state"] == "open"
    
    # Test with custom fields
    res2 = PortScanResult(port=443, state="filtered", banner="nginx", protocol="udp")
    assert res2.port == 443
    assert res2.state == "filtered"
    assert res2.banner == "nginx"
    assert res2.protocol == "udp"

def test_web_triage_result():
    res = WebTriageResult(url="http://example.com", status_code=200)
    assert res.url == "http://example.com"
    assert res.status_code == 200
    assert res.server_header is None
    assert res.redirects == []
    assert res.findings == []

def test_flag_finding():
    finding = FlagFinding(flag_text="HTB{test}", source="header")
    assert finding.flag_text == "HTB{test}"
    assert finding.source == "header"
    assert finding.format_type == "regex"

def test_ai_analysis_result():
    res = AIAnalysisResult()
    assert res.probable_cves == []
    assert res.service_criticality == {}
    assert res.suggested_cli_commands == []
    assert res.attack_vectors == []

def test_triage_report():
    report = TriageReport(target="127.0.0.1")
    assert report.target == "127.0.0.1"
    assert isinstance(report.scan_timestamp, datetime)
    assert report.open_ports == []
    assert report.web_findings == []
    assert report.flags_found == []
    assert report.ai_analysis is None

    # Test nested dump
    report.open_ports.append(PortScanResult(port=443))
    report_dict = report.model_dump()
    assert report_dict["target"] == "127.0.0.1"
    assert report_dict["open_ports"][0]["port"] == 443
    
    # Test JSON serialization of nested fields including datetime
    report_json = report.model_dump_json()
    assert "127.0.0.1" in report_json
    assert "443" in report_json
