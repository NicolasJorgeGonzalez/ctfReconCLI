import json
import os
from unittest.mock import MagicMock, patch
import pytest

from ctf_recon.models import (
    AIAnalysisResult,
    FlagFinding,
    PortScanResult,
    WebTriageResult,
)
from ctf_recon.triage.ai_advisor import AIAdvisor, run_ai_advisor


def test_offline_mode_returns_none():
    # When enable_ai is False, must return None without touching API key or network
    res = run_ai_advisor(
        target="10.10.10.10",
        open_ports=[PortScanResult(port=80, banner="Apache 2.4.49")],
        web_findings=[],
        flags_found=[],
        enable_ai=False,
    )
    assert res is None


def test_missing_api_key_degrades_gracefully(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    advisor = AIAdvisor(api_key=None)
    assert advisor.is_available() is False

    res = advisor.analyze(
        target="10.10.10.10",
        open_ports=[PortScanResult(port=80)],
        web_findings=[],
        flags_found=[],
    )
    assert res is None


def test_build_prompt():
    advisor = AIAdvisor(api_key="mock_key")
    open_ports = [PortScanResult(port=80, banner="nginx/1.18.0")]
    web_findings = [
        WebTriageResult(
            url="http://10.10.10.10:80",
            status_code=200,
            server_header="nginx/1.18.0",
            findings=["robots.txt accessible"],
            routes_checked=["/", "/robots.txt"],
        )
    ]
    flags_found = [
        FlagFinding(flag_text="FaMAF{test_flag}", source="header", format_type="regex")
    ]

    prompt = advisor.build_prompt("10.10.10.10", open_ports, web_findings, flags_found)
    assert "10.10.10.10" in prompt
    assert "Port 80/tcp" in prompt
    assert "nginx/1.18.0" in prompt
    assert "robots.txt accessible" in prompt
    assert "FaMAF{test_flag}" in prompt


def test_analyze_with_mocked_gemini_client():
    advisor = AIAdvisor(api_key="mock_key")
    
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "probable_cves": ["CVE-2021-41773"],
        "service_criticality": {"port 80": "High", "port 22": "Low"},
        "suggested_cli_commands": ["curl -i http://10.10.10.10:80/"],
        "attack_vectors": ["Test path traversal on Apache"]
    })
    mock_client.models.generate_content.return_value = mock_response
    advisor.client = mock_client

    res = advisor.analyze(
        target="10.10.10.10",
        open_ports=[PortScanResult(port=80, banner="Apache/2.4.49")],
        web_findings=[],
        flags_found=[],
    )

    assert isinstance(res, AIAnalysisResult)
    assert res.probable_cves == ["CVE-2021-41773"]
    assert res.service_criticality == {"port 80": "High", "port 22": "Low"}
    assert "curl -i http://10.10.10.10:80/" in res.suggested_cli_commands
    assert "Test path traversal on Apache" in res.attack_vectors
    assert mock_client.models.generate_content.called


def test_analyze_exception_graceful_handling():
    advisor = AIAdvisor(api_key="mock_key")
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError("API Connection failed")
    advisor.client = mock_client

    res = advisor.analyze(
        target="10.10.10.10",
        open_ports=[PortScanResult(port=80)],
        web_findings=[],
        flags_found=[],
    )
    assert res is None


def test_analyze_with_gemini_list_format():
    advisor = AIAdvisor(api_key="mock_key")
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "probable_cves": ["CVE-2023-1234"],
        "service_criticality": [
            {"service": "port 80", "criticality": "Critical"},
            {"service": "port 443", "criticality": "Medium"}
        ],
        "suggested_cli_commands": ["nikto -h http://10.10.10.10"],
        "attack_vectors": ["SQLi in login parameter"]
    })
    mock_client.models.generate_content.return_value = mock_response
    advisor.client = mock_client

    res = advisor.analyze(
        target="10.10.10.10",
        open_ports=[PortScanResult(port=80)],
        web_findings=[],
        flags_found=[],
    )

    assert isinstance(res, AIAnalysisResult)
    assert res.probable_cves == ["CVE-2023-1234"]
    assert res.service_criticality == {"port 80": "Critical", "port 443": "Medium"}
    assert res.suggested_cli_commands == ["nikto -h http://10.10.10.10"]
    assert res.attack_vectors == ["SQLi in login parameter"]

