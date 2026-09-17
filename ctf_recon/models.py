from datetime import datetime
from typing import List, Dict, Optional

from pydantic import BaseModel, Field


class PortScanResult(BaseModel):
    port: int
    state: str = "open"
    banner: Optional[str] = None
    protocol: str = "tcp"


class WebTriageResult(BaseModel):
    url: str
    status_code: int
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    redirects: List[str] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)
    routes_checked: List[str] = Field(default_factory=list)


class FlagFinding(BaseModel):
    flag_text: str
    source: str
    format_type: str = "regex"


class AIAnalysisResult(BaseModel):
    probable_cves: List[str] = Field(default_factory=list)
    service_criticality: Dict[str, str] = Field(default_factory=dict)
    suggested_cli_commands: List[str] = Field(default_factory=list)
    attack_vectors: List[str] = Field(default_factory=list)


class TriageReport(BaseModel):
    target: str
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    open_ports: List[PortScanResult] = Field(default_factory=list)
    web_findings: List[WebTriageResult] = Field(default_factory=list)
    flags_found: List[FlagFinding] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysisResult] = None
