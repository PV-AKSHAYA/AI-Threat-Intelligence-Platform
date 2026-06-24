"""
Pydantic schemas matching the exact API contract from the hackathon PDF
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


# ─── Request Schemas ──────────────────────────────────────────────────────────

class AnalysisOptions(BaseModel):
    mitre_mapping: bool = True
    generate_rules: bool = True
    risk_scoring: bool = True


class ThreatAnalysisRequest(BaseModel):
    input_type: str = Field(..., description="text | cve | url | file")
    content: str = Field(..., min_length=1, max_length=50000)
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)


# ─── IOC Schemas ──────────────────────────────────────────────────────────────

class IOC(BaseModel):
    type: str
    value: str
    reputation: Optional[str] = None


# ─── Enrichment Schemas ───────────────────────────────────────────────────────

class CVEEnrichment(BaseModel):
    id: str
    cvss: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    exploit_available: bool = False
    malware_families: List[str] = []
    threat_actors: List[str] = []
    affected_products: Optional[str] = None
    published_date: Optional[str] = None


class EnrichmentResult(BaseModel):
    cves: List[CVEEnrichment] = []
    domains: List[Dict[str, Any]] = []
    ips: List[Dict[str, Any]] = []


# ─── MITRE Schemas ────────────────────────────────────────────────────────────

class MITRETechnique(BaseModel):
    tactic: str
    technique: str
    id: str
    confidence: str = "MEDIUM"
    description: Optional[str] = None
    detection: Optional[str] = None


# ─── Risk Schemas ─────────────────────────────────────────────────────────────

class RiskFactor(BaseModel):
    factor: str
    score: int


# ─── AI Report Schema ─────────────────────────────────────────────────────────

class AIReport(BaseModel):
    summary: str = ""
    attack_scenario: str = ""
    business_impact: str = ""
    immediate_actions: List[str] = []
    long_term_remediation: List[str] = []
    monitoring: List[str] = []


# ─── Detection Rules Schema ───────────────────────────────────────────────────

class DetectionRules(BaseModel):
    sigma: Optional[str] = None
    yara: Optional[str] = None
    splunk: Optional[str] = None
    sentinel_kql: Optional[str] = None
    elastic: Optional[str] = None


# ─── Full Response Schema ─────────────────────────────────────────────────────

class ThreatAnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    iocs: List[IOC] = []
    enrichment: EnrichmentResult = Field(default_factory=EnrichmentResult)
    mitre_mapping: List[MITRETechnique] = []
    risk_score: int = 0
    risk_level: str = "low"
    risk_factors: List[RiskFactor] = []
    ai_report: AIReport = Field(default_factory=AIReport)
    detection_rules: DetectionRules = Field(default_factory=DetectionRules)


# ─── History Schemas ──────────────────────────────────────────────────────────

class AnalysisSummary(BaseModel):
    analysis_id: str
    timestamp: str
    input_type: str
    input_preview: str
    risk_score: int
    risk_level: str
    iocs_count: int
    mitre_count: int


class AnalysisHistoryResponse(BaseModel):
    total: int
    page: int
    page_size: int
    analyses: List[AnalysisSummary]


# ─── Health Schema ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    services: Dict[str, str]
