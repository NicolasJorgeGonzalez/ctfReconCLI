import json
import logging
import os
import time
from typing import List, Optional

from pydantic import BaseModel, Field

from ctf_recon.models import (
    AIAnalysisResult,
    FlagFinding,
    PortScanResult,
    WebTriageResult,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-3.6-flash"


class ServiceCriticalityItem(BaseModel):
    service: str = Field(description="Service name or port, e.g. 'port 80'")
    criticality: str = Field(description="Criticality level: 'Critical', 'High', 'Medium', 'Low'")


class GeminiAnalysisSchema(BaseModel):
    probable_cves: List[str] = Field(
        default_factory=list,
        description="Probable CVEs or known software vulnerabilities.",
    )
    service_criticality: List[ServiceCriticalityItem] = Field(
        default_factory=list,
        description="List of services and their criticality assessment.",
    )
    suggested_cli_commands: List[str] = Field(
        default_factory=list,
        description="Suggested CLI commands to run next.",
    )
    attack_vectors: List[str] = Field(
        default_factory=list,
        description="Promising attack vectors or testing angles to explore.",
    )


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

        max_retries = 3
        response = None

        for attempt in range(max_retries):
            try:
                from google.genai import types

                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=GeminiAnalysisSchema,
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                    ),
                )
                break
            except Exception as e:
                err_str = str(e)
                if (
                    ("503" in err_str or "UNAVAILABLE" in err_str or "high demand" in err_str.lower())
                    and attempt < max_retries - 1
                ):
                    wait_sec = (attempt + 1) * 2
                    logger.warning(
                        f"Gemini API experiencing high demand (503). Retrying in {wait_sec}s (attempt {attempt + 1}/{max_retries})..."
                    )
                    time.sleep(wait_sec)
                    continue

                logger.warning(f"AI analysis failed or timed out: {e}")
                return None

        if not response:
            logger.warning("Empty response received from Gemini API.")
            return None

        data = None
        if hasattr(response, "parsed") and response.parsed is not None:
            if isinstance(response.parsed, GeminiAnalysisSchema):
                data = response.parsed.model_dump()
            elif isinstance(response.parsed, dict):
                data = response.parsed

        if data is None and hasattr(response, "text") and response.text:
            text = response.text.strip()
            if text.startswith("```"):
                lines = text.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                text = "\n".join(lines).strip()
            try:
                data = json.loads(text)
            except Exception as parse_err:
                logger.warning(
                    f"Could not parse Gemini JSON response: {parse_err}. Response text: {response.text}"
                )
                return None

        if not data or not isinstance(data, dict):
            logger.warning("Gemini response did not contain expected dictionary data.")
            return None

        crit_data = data.get("service_criticality", [])
        crit_dict = {}
        if isinstance(crit_data, list):
            for item in crit_data:
                if isinstance(item, dict):
                    svc = item.get("service")
                    crit = item.get("criticality")
                    if svc and crit:
                        crit_dict[str(svc)] = str(crit)
                elif hasattr(item, "service") and hasattr(item, "criticality"):
                    crit_dict[str(item.service)] = str(item.criticality)
        elif isinstance(crit_data, dict):
            crit_dict = {str(k): str(v) for k, v in crit_data.items()}

        return AIAnalysisResult(
            probable_cves=data.get("probable_cves", []),
            service_criticality=crit_dict,
            suggested_cli_commands=data.get("suggested_cli_commands", []),
            attack_vectors=data.get("attack_vectors", []),
        )


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
