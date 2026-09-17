import json
import logging
import os
from typing import List, Optional

from ctf_recon.models import (
    AIAnalysisResult,
    FlagFinding,
    PortScanResult,
    WebTriageResult,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-2.5-flash"


class AIAdvisor:
    """
    AI Triage Advisor integrating Google Gemini using the official google-genai SDK
    and Pydantic structured outputs.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = DEFAULT_MODEL,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name
        self.client = None

        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Could not initialize Google GenAI client: {e}")
                self.client = None

    def is_available(self) -> bool:
        """Returns True if the AI client is configured and ready."""
        return self.client is not None

    def build_prompt(
        self,
        target: str,
        open_ports: List[PortScanResult],
        web_findings: List[WebTriageResult],
        flags_found: List[FlagFinding],
    ) -> str:
        """Builds a structured prompt summarizing scan data for Gemini analysis."""
        ports_summary = [
            f"- Port {p.port}/{p.protocol} (state: {p.state}, banner: {p.banner or 'None'})"
            for p in open_ports
        ]
        
        web_summary = []
        for w in web_findings:
            info = f"- {w.url} (Status: {w.status_code}, Server: {w.server_header or 'None'}, X-Powered-By: {w.x_powered_by or 'None'})"
            if w.findings:
                info += f"\n  Findings: {', '.join(w.findings)}"
            if w.redirects:
                info += f"\n  Redirects: {' -> '.join(w.redirects)}"
            web_summary.append(info)

        flags_summary = [
            f"- [{f.format_type}] {f.flag_text} (Source: {f.source})"
            for f in flags_found
        ]

        prompt_lines = [
            f"You are an expert CTF security analyst reviewing initial reconnaissance data for target '{target}'.",
            "",
            "### Discovered Open Ports & Services:",
            "\n".join(ports_summary) if ports_summary else "No open ports detected.",
            "",
            "### Web Triage Findings:",
            "\n".join(web_summary) if web_summary else "No web endpoints detected.",
            "",
            "### Discovered Flags and Artifacts:",
            "\n".join(flags_summary) if flags_summary else "No flags found yet.",
            "",
            "Analyze these findings and synthesize:",
            "1. Probable CVEs or known software vulnerabilities based on detected services and versions.",
            "2. Service criticality mapping (e.g., {'port 80': 'High', 'port 22': 'Low'}).",
            "3. Suggested CLI commands to execute next for manual investigation and triage.",
            "4. Promising attack vectors or testing angles to explore in this CTF challenge.",
        ]

        return "\n".join(prompt_lines)

    def analyze(
        self,
        target: str,
        open_ports: List[PortScanResult],
        web_findings: List[WebTriageResult],
        flags_found: List[FlagFinding],
    ) -> Optional[AIAnalysisResult]:
        """
        Sends structured scan data to Gemini and returns structured output.
        Fails gracefully without raising exceptions if offline or on API errors.
        """
        if not self.is_available():
            logger.info("AI analysis skipped: Gemini API client not available.")
            return None

        prompt = self.build_prompt(target, open_ports, web_findings, flags_found)

        try:
            from google.genai import types

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AIAnalysisResult,
                ),
            )

            if response and response.text:
                return AIAnalysisResult.model_validate_json(response.text)
            return None

        except Exception as e:
            logger.warning(f"AI analysis failed or timed out: {e}")
            return None


def run_ai_advisor(
    target: str,
    open_ports: List[PortScanResult],
    web_findings: List[WebTriageResult],
    flags_found: List[FlagFinding],
    api_key: Optional[str] = None,
    enable_ai: bool = False,
    model_name: str = DEFAULT_MODEL,
) -> Optional[AIAnalysisResult]:
    """
    High-level entry point for AI analysis.
    If enable_ai is False, guarantees 100% offline operation without reading environment or network.
    """
    if not enable_ai:
        return None

    advisor = AIAdvisor(api_key=api_key, model_name=model_name)
    return advisor.analyze(target, open_ports, web_findings, flags_found)
