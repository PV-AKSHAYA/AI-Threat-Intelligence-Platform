"""
MITRE ATT&CK Mapping Service
Maps threat intelligence indicators and enrichment data
to MITRE ATT&CK techniques with confidence scoring.
"""

import json
import logging
import os
from typing import List, Dict, Any, Optional

from app.schemas.schemas import (
    IOC,
    MITRETechnique,
    EnrichmentResult,
)

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Load MITRE ATT&CK Database
# ------------------------------------------------------------------

_MITRE_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../seed_data/mitre_attack.json"
    )
)

_mitre_db: Dict[str, Any] = {}


def _load_mitre():
    global _mitre_db

    try:
        with open(_MITRE_PATH, "r", encoding="utf-8") as f:
            _mitre_db = json.load(f)

        logger.info(
            f"Loaded MITRE ATT&CK catalog: "
            f"{len(_mitre_db.get('techniques', {}))} techniques"
        )

    except Exception as e:
        logger.error(f"Failed to load MITRE catalog: {e}")
        _mitre_db = {
            "techniques": {},
            "tactics": []
        }


_load_mitre()

# ------------------------------------------------------------------
# IOC → Technique Heuristics
# ------------------------------------------------------------------

IOC_TYPE_TECHNIQUES = {
    "domain": ["T1566", "T1566.002", "T1071"],
    "url": ["T1566.002", "T1071"],
    "email": ["T1566", "T1566.001"],
    "ipv4": ["T1071", "T1041"],
    "cve": ["T1190", "T1068"],
    "md5": ["T1055", "T1486"],
    "sha1": ["T1055", "T1486"],
    "sha256": ["T1055", "T1486"],
}

# ------------------------------------------------------------------
# Malware Family → MITRE Mapping
# ------------------------------------------------------------------

MALWARE_TECHNIQUES = {
    "lockbit": ["T1486", "T1041", "T1059"],
    "conti": ["T1486", "T1021"],
    "mirai": ["T1190", "T1059"],
    "muhstik": ["T1190", "T1059.003"],
    "cobalt strike": ["T1059.001", "T1071", "T1055"],
    "emotet": ["T1566.001", "T1547.001"],
    "zipline": ["T1190", "T1071"],
    "thinspool": ["T1059"],
    "wirefire": ["T1071"],
}

# ------------------------------------------------------------------
# Confidence Helpers
# ------------------------------------------------------------------

def _score_to_confidence(score: int) -> str:
    if score >= 5:
        return "HIGH"

    if score >= 3:
        return "MEDIUM"

    return "LOW"


def _tactic_order(tactic: str) -> int:
    tactics = _mitre_db.get("tactics", [])

    try:
        return tactics.index(tactic)
    except ValueError:
        return 999


# ------------------------------------------------------------------
# Main Mapping Function
# ------------------------------------------------------------------

def map_to_mitre(
    text: str,
    iocs: List[IOC],
    enrichment: EnrichmentResult,
) -> List[MITRETechnique]:

    techniques_db = _mitre_db.get("techniques", {})

    scores: Dict[str, int] = {}

    text_lower = text.lower()

    # --------------------------------------------------------------
    # 1. IOC Heuristics
    # --------------------------------------------------------------

    for ioc in iocs:

        for technique_id in IOC_TYPE_TECHNIQUES.get(ioc.type, []):

            if technique_id in techniques_db:
                scores[technique_id] = (
                    scores.get(technique_id, 0) + 1
                )

    # --------------------------------------------------------------
    # 2. Keyword Matching
    # --------------------------------------------------------------

    for technique_id, technique_data in techniques_db.items():

        keywords = technique_data.get("keywords", [])

        matches = 0

        for keyword in keywords:

            if keyword.lower() in text_lower:
                matches += 1

        if matches:
            scores[technique_id] = (
                scores.get(technique_id, 0) +
                (matches * 2)
            )

    # --------------------------------------------------------------
    # 3. CVE Malware Families
    # --------------------------------------------------------------

    for cve in enrichment.cves:

        for family in cve.malware_families:

            family_lower = family.lower()

            for malware_name, mapped_techniques in MALWARE_TECHNIQUES.items():

                if malware_name in family_lower:

                    for technique_id in mapped_techniques:

                        if technique_id in techniques_db:
                            scores[technique_id] = (
                                scores.get(technique_id, 0) + 2
                            )

    # --------------------------------------------------------------
    # 4. Threat Actor TTPs
    # --------------------------------------------------------------

    enrichment_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "../../seed_data/enrichment_data.json"
        )
    )

    try:

        with open(enrichment_path, "r", encoding="utf-8") as f:
            enrichment_db = json.load(f)

        actor_db = enrichment_db.get(
            "threat_actors",
            {}
        )

        for cve in enrichment.cves:

            for actor in cve.threat_actors:

                actor_data = actor_db.get(actor)

                if not actor_data:
                    continue

                for technique_id in actor_data.get(
                    "ttps",
                    []
                ):

                    if technique_id in techniques_db:

                        scores[technique_id] = (
                            scores.get(technique_id, 0) + 3
                        )

    except Exception as e:
        logger.warning(
            f"Threat actor enrichment unavailable: {e}"
        )

    # --------------------------------------------------------------
    # Build Results
    # --------------------------------------------------------------

    results: List[MITRETechnique] = []

    for technique_id, score in sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    ):

        technique = techniques_db.get(technique_id)

        if not technique:
            continue

        results.append(
            MITRETechnique(
                tactic=technique["tactic"],
                technique=technique["name"],
                id=technique_id,
                confidence=_score_to_confidence(score),
                description=technique.get(
                    "description"
                ),
                detection=technique.get(
                    "detection"
                ),
            )
        )

    results.sort(
        key=lambda t: _tactic_order(t.tactic)
    )

    logger.info(
        f"Mapped {len(results)} MITRE ATT&CK techniques"
    )

    return results


# ------------------------------------------------------------------
# Attack Chain Builder
# ------------------------------------------------------------------

def get_attack_chain(
    techniques: List[MITRETechnique]
) -> List[Dict[str, Any]]:

    grouped: Dict[str, List[MITRETechnique]] = {}

    for technique in techniques:

        grouped.setdefault(
            technique.tactic,
            []
        ).append(technique)

    chain = []

    for tactic in _mitre_db.get("tactics", []):

        if tactic not in grouped:
            continue

        chain.append({
            "tactic": tactic,
            "techniques": [
                {
                    "id": t.id,
                    "name": t.technique,
                    "confidence": t.confidence,
                }
                for t in grouped[tactic]
            ]
        })

    return chain


def get_all_techniques():
    return _mitre_db.get(
        "techniques",
        {}
    )


def get_technique_by_id(
    technique_id: str
) -> Optional[Dict]:

    return _mitre_db.get(
        "techniques",
        {}
    ).get(
        technique_id.upper()
    )