"""
Risk Scoring Engine
Implements the exact scoring matrix from the hackathon PDF
with explainable factors
"""
import logging
from typing import List, Tuple, Dict, Any
from app.schemas.schemas import IOC, RiskFactor, EnrichmentResult
from app.services.enrichment import get_enrichment_summary

logger = logging.getLogger(__name__)

# ─── Scoring Constants (from PDF) ────────────────────────────────────────────

SCORE_CVSS_CRITICAL = 30   # CVSS > 9
SCORE_CVSS_HIGH = 20       # CVSS 7-9
SCORE_CVSS_MEDIUM = 10     # CVSS 4-7
SCORE_EXPLOIT_AVAILABLE = 25
SCORE_MALWARE_FAMILY = 15
SCORE_THREAT_ACTOR = 10
SCORE_HIGH_IOC_REPUTATION = 20

# ─── Risk Levels ──────────────────────────────────────────────────────────────

RISK_LEVELS = [
    (81, 100, "critical", "#EF4444"),
    (61, 80, "high", "#F97316"),
    (31, 60, "medium", "#EAB308"),
    (0, 30, "low", "#22C55E"),
]


def calculate_risk(
    iocs: List[IOC],
    enrichment: EnrichmentResult,
) -> Tuple[int, str, List[RiskFactor]]:
    """
    Calculate risk score using exact formula from hackathon PDF.
    Returns (score, level, factors)
    """
    factors: List[RiskFactor] = []
    total = 0

    summary = get_enrichment_summary(enrichment)

    # ── CVSS Scoring ──────────────────────────────────────────────────────────
    max_cvss = summary["max_cvss"]

    if max_cvss > 9.0:
        factors.append(RiskFactor(factor=f"CVSS > 9 (Critical) — Score: {max_cvss}", score=SCORE_CVSS_CRITICAL))
        total += SCORE_CVSS_CRITICAL
    elif max_cvss >= 7.0:
        factors.append(RiskFactor(factor=f"CVSS 7-9 (High) — Score: {max_cvss}", score=SCORE_CVSS_HIGH))
        total += SCORE_CVSS_HIGH
    elif max_cvss >= 4.0:
        factors.append(RiskFactor(factor=f"CVSS 4-7 (Medium) — Score: {max_cvss}", score=SCORE_CVSS_MEDIUM))
        total += SCORE_CVSS_MEDIUM

    # ── Exploit Availability ──────────────────────────────────────────────────
    if summary["has_exploit"]:
        factors.append(RiskFactor(factor="Public exploit available", score=SCORE_EXPLOIT_AVAILABLE))
        total += SCORE_EXPLOIT_AVAILABLE

    # ── Malware Family ────────────────────────────────────────────────────────
    malware = summary["malware_families"]
    if malware:
        label = f"Malware associated ({', '.join(malware[:2])})"
        factors.append(RiskFactor(factor=label, score=SCORE_MALWARE_FAMILY))
        total += SCORE_MALWARE_FAMILY

    # ── Threat Actor ──────────────────────────────────────────────────────────
    actors = summary["threat_actors"]
    if actors:
        label = f"Known threat actor ({', '.join(actors[:2])})"
        factors.append(RiskFactor(factor=label, score=SCORE_THREAT_ACTOR))
        total += SCORE_THREAT_ACTOR

    # ── IOC Reputation ────────────────────────────────────────────────────────
    malicious_iocs = [i for i in iocs if i.reputation in ("malicious", "critical")]
    suspicious_iocs = [i for i in iocs if i.reputation == "suspicious"]

    if malicious_iocs:
        rep_score = min(SCORE_HIGH_IOC_REPUTATION, len(malicious_iocs) * 8)
        factors.append(RiskFactor(
            factor=f"High IOC reputation ({len(malicious_iocs)} malicious, {len(suspicious_iocs)} suspicious)",
            score=rep_score
        ))
        total += rep_score
    elif suspicious_iocs:
        rep_score = min(10, len(suspicious_iocs) * 5)
        factors.append(RiskFactor(
            factor=f"Suspicious IOC reputation ({len(suspicious_iocs)} flagged)",
            score=rep_score
        ))
        total += rep_score

    # ── IOC Volume Bonus ──────────────────────────────────────────────────────
    total_iocs = len(iocs)
    if total_iocs >= 5 and total == 0:
        # Some base score for having multiple IOCs even without enrichment
        factors.append(RiskFactor(factor=f"Multiple IOCs detected ({total_iocs})", score=5))
        total += 5

    # Clamp to 0-100
    total = max(0, min(100, total))

    # Determine risk level
    level = "low"
    for low, high, lvl, _ in RISK_LEVELS:
        if low <= total <= high:
            level = lvl
            break

    logger.info(f"Risk calculated: {total} ({level}) with {len(factors)} factors")
    return total, level, factors


def get_risk_color(level: str) -> str:
    colors = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#22C55E",
    }
    return colors.get(level, "#6B7280")
