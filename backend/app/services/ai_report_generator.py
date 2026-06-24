"""
AI Report Generator
Provider Priority:
1. Gemini
2. Groq
3. Local Fallback

Always returns a valid AIReport.
"""

import os
import logging
from typing import List
import json
from app.schemas.schemas import (
    IOC,
    AIReport,
    RiskFactor,
    MITRETechnique,
    EnrichmentResult,
)

logger = logging.getLogger(__name__)



# ============================================================
# GROQ
# ============================================================

def _try_groq(prompt: str):

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return None

    try:
        from groq import Groq

        client = Groq(api_key=api_key)

        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior threat intelligence analyst."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2
        )

        # print("\n===== GROQ RESPONSE =====")
        # print(completion.choices[0].message.content)
        # print("=========================\n")
        logger.info("Groq response received")
        return completion.choices[0].message.content

    except Exception as e:
        logger.error(f"Groq failed: {e}")
        return None


# ============================================================
# GEMINI
# ============================================================

def _try_gemini(prompt: str):

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return None

    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )

        return response.text

    except Exception as e:
        logger.error(f"Gemini failed: {e}")
        return None

# ============================================================
# LOCAL FALLBACK
# ============================================================

def _local_report(
    iocs: List[IOC],
    enrichment: EnrichmentResult,
    mitre: List[MITRETechnique],
    risk_score: int,
    risk_level: str,
) -> AIReport:

    cves = [c.id for c in enrichment.cves]

    summary = (
        f"Threat analysis identified {len(iocs)} indicators "
        f"with a risk score of {risk_score} ({risk_level.upper()})."
    )

    if cves:
        summary += f" CVEs detected: {', '.join(cves[:3])}."

    techniques = ", ".join(
        t.id for t in mitre[:5]
    )

    attack_scenario = (
        f"Observed activity maps to MITRE ATT&CK techniques "
        f"{techniques}. Attackers may leverage identified "
        f"indicators for initial access, execution, and persistence."
    )

    business_impact = (
        "Successful exploitation may lead to data loss, "
        "service disruption, credential compromise, "
        "and regulatory exposure."
    )

    return AIReport(
        summary=summary,
        attack_scenario=attack_scenario,
        business_impact=business_impact,
        immediate_actions=[
            "Block identified malicious domains and IPs",
            "Patch affected vulnerable systems",
            "Review firewall and SIEM alerts",
            "Investigate impacted hosts"
        ],
        long_term_remediation=[
            "Implement continuous vulnerability management",
            "Enable MFA across critical systems",
            "Conduct threat hunting exercises",
            "Strengthen endpoint monitoring"
        ],
        monitoring=[
            "Monitor DNS activity",
            "Monitor outbound network connections",
            "Create alerts for identified IOCs",
            "Track MITRE ATT&CK techniques"
        ]
    )


# ============================================================
# PUBLIC FUNCTION
# ============================================================

# def generate_ai_report(
#     raw_text: str,
#     iocs: List[IOC],
#     enrichment: EnrichmentResult,
#     mitre_techniques: List[MITRETechnique],
#     risk_score: int,
#     risk_level: str,
#     risk_factors: List[RiskFactor],
# ) -> AIReport:

# #     prompt = f"""
# # Generate a professional cyber threat intelligence report.

#     prompt = f"""
#    You are a senior threat intelligence analyst.

#     Return ONLY valid JSON.

# Format:

# {{
#   "summary": "...",
#   "attack_scenario": "...",
#   "business_impact": "...",
#   "immediate_actions": ["...","..."],
#   "long_term_remediation": ["...","..."],
#   "monitoring": ["...","..."]
# }}

# Risk Score: {risk_score}
# Risk Level: {risk_level}

# IOCs:
# {[ioc.model_dump() for ioc in iocs]}

# CVEs:
# {[cve.model_dump() for cve in enrichment.cves]}

# MITRE:
# {[m.id for m in mitre_techniques]}
# """

# Risk Score: {risk_score}
# Risk Level: {risk_level}

# IOCs:
# {[ioc.model_dump() for ioc in iocs]}

# CVEs:
# {[cve.model_dump() for cve in enrichment.cves]}

# MITRE:
# {[m.id for m in mitre_techniques]}
# """

#     # Gemini First
#     ai_text = _try_gemini(prompt)

#     # Groq Backup
#     if not ai_text:
#         ai_text = _try_groq(prompt)

#     # AI Success
#     # if ai_text:

#     #     return AIReport(
#     #         summary=ai_text[:800],
#     #         attack_scenario=ai_text[:800],
#     #         business_impact="See generated report",
#     #         immediate_actions=[
#     #             "Review generated report",
#     #             "Validate findings",
#     #             "Investigate indicators"
#     #         ],
#     #         long_term_remediation=[
#     #             "Apply security best practices"
#     #         ],
#     #         monitoring=[
#     #             "Monitor identified indicators"
#     #         ]
#     #     )
#      # AI Success
#     if ai_text:

#        return AIReport(
#         summary=ai_text[:1500],
#         attack_scenario="Generated by Groq AI",
#         business_impact="See AI summary above",
#         immediate_actions=[
#             "Review AI-generated report",
#             "Validate identified IOCs",
#             "Investigate affected systems",
#             "Patch vulnerable assets"
#         ],
#         long_term_remediation=[
#             "Implement vulnerability management",
#             "Strengthen endpoint monitoring",
#             "Enable MFA",
#             "Conduct threat hunting"
#         ],
#         monitoring=[
#             "Monitor identified domains",
#             "Monitor identified IPs",
#             "Track MITRE ATT&CK techniques",
#             "Review SIEM alerts"
#         ]
#     )

#     # Local Fallback
#     return _local_report(
#         iocs,
#         enrichment,
#         mitre_techniques,
#         risk_score,
#         risk_level
#     )


# # ============================================================
# # HEALTH API SUPPORT
# # ============================================================

# def get_cache_stats():

#     return {
#         "gemini_configured": bool(
#             os.getenv("GEMINI_API_KEY")
#         ),
#         "groq_configured": bool(
#             os.getenv("GROQ_API_KEY")
#         )
#     }

# def generate_ai_report(
#     raw_text: str,
#     iocs: List[IOC],
#     enrichment: EnrichmentResult,
#     mitre_techniques: List[MITRETechnique],
#     risk_score: int,
#     risk_level: str,
#     risk_factors: List[RiskFactor],
# ) -> AIReport:

#     #     prompt = f"""
#     # Generate a professional cyber threat intelligence report.

# #     prompt = f"""
# # You are a senior threat intelligence analyst.

# # Return ONLY valid JSON.

# # Format:

# # {{
# #   "summary": "...",
# #   "attack_scenario": "...",
# #   "business_impact": "...",
# #   "immediate_actions": ["...","..."],
# #   "long_term_remediation": ["...","..."],
# #   "monitoring": ["...","..."]
# # }}

# # Risk Score: {risk_score}
# # Risk Level: {risk_level}

# # IOCs:
# # {[ioc.model_dump() for ioc in iocs]}

# # CVEs:
# # {[cve.model_dump() for cve in enrichment.cves]}

# # MITRE:
# # {[m.id for m in mitre_techniques]}
# # """

#  prompt = f"""
# You are a senior threat intelligence analyst.

# Return ONLY valid JSON.

# Requirements:
# - summary must be detailed (2-4 sentences)
# - attack_scenario must be detailed (2-4 sentences)
# - business_impact must be detailed (2-4 sentences)
# - immediate_actions must contain AT LEAST 4 items
# - long_term_remediation must contain AT LEAST 4 items
# - monitoring must contain AT LEAST 4 items

# Format:

# {{
#   "summary": "...",
#   "attack_scenario": "...",
#   "business_impact": "...",
#   "immediate_actions": [
#     "...",
#     "...",
#     "...",
#     "..."
#   ],
#   "long_term_remediation": [
#     "...",
#     "...",
#     "...",
#     "..."
#   ],
#   "monitoring": [
#     "...",
#     "...",
#     "...",
#     "..."
#   ]
# }}

# Risk Score: {risk_score}
# Risk Level: {risk_level}

# IOCs:
# {[ioc.model_dump() for ioc in iocs]}

# CVEs:
# {[cve.model_dump() for cve in enrichment.cves]}

# MITRE:
# {[m.id for m in mitre_techniques]}
# """

#     # Gemini First
#  ai_text = _try_gemini(prompt)

#     # Groq Backup
#  if not ai_text:
#         ai_text = _try_groq(prompt)

    

#     # AI Success
    

# if ai_text:
#       try:

#         cleaned = ai_text.replace("```json", "")
#         cleaned = cleaned.replace("```", "")
#         cleaned = cleaned.strip()

#         data = json.loads(cleaned)

#       return AIReport(
#             summary=data.get("summary", ""),
#             attack_scenario=data.get("attack_scenario", ""),
#             business_impact=data.get("business_impact", ""),
#             immediate_actions=data.get("immediate_actions", []),
#             long_term_remediation=data.get("long_term_remediation", []),
#             monitoring=data.get("monitoring", [])
#         )

#       except Exception as e:
#         logger.error(f"AI JSON parse failed: {e}")

#     # Local Fallback
#     return _local_report(
#         iocs,
#         enrichment,
#         mitre_techniques,
#         risk_score,
#         risk_level
#     )

def generate_ai_report(
    raw_text: str,
    iocs: List[IOC],
    enrichment: EnrichmentResult,
    mitre_techniques: List[MITRETechnique],
    risk_score: int,
    risk_level: str,
    risk_factors: List[RiskFactor],
) -> AIReport:

    #     prompt = f"""
    # Generate a professional cyber threat intelligence report.

    prompt = f"""
You are a senior threat intelligence analyst.

Return ONLY valid JSON.

Requirements:
- summary must be detailed (2-4 sentences)
- attack_scenario must be detailed (2-4 sentences)
- business_impact must be detailed (2-4 sentences)
- immediate_actions must contain AT LEAST 4 items
- long_term_remediation must contain AT LEAST 4 items
- monitoring must contain AT LEAST 4 items

Format:

{{
  "summary": "...",
  "attack_scenario": "...",
  "business_impact": "...",
  "immediate_actions": [
    "...",
    "...",
    "...",
    "..."
  ],
  "long_term_remediation": [
    "...",
    "...",
    "...",
    "..."
  ],
  "monitoring": [
    "...",
    "...",
    "...",
    "..."
  ]
}}

Risk Score: {risk_score}
Risk Level: {risk_level}

IOCs:
{[ioc.model_dump() for ioc in iocs]}

CVEs:
{[cve.model_dump() for cve in enrichment.cves]}

MITRE:
{[m.id for m in mitre_techniques]}
"""

    # Gemini First
    ai_text = _try_gemini(prompt)

    # Groq Backup
    if not ai_text:
        ai_text = _try_groq(prompt)

    # AI Success
    if ai_text:
        try:

            # cleaned = ai_text.replace("```json", "")
            # cleaned = cleaned.replace("```", "")
            # cleaned = cleaned.strip()
            

            cleaned = ai_text.strip()

            if cleaned.startswith("```json"):
              cleaned = cleaned.replace("```json", "", 1)

            if cleaned.startswith("```"):
              cleaned = cleaned.replace("```", "", 1)

            if cleaned.endswith("```"):
             cleaned = cleaned[:-3]

            cleaned = cleaned.strip()
            data = json.loads(cleaned)

            return AIReport(
                summary=data.get("summary", ""),
                attack_scenario=data.get("attack_scenario", ""),
                business_impact=data.get("business_impact", ""),
                immediate_actions=data.get("immediate_actions", []),
                long_term_remediation=data.get("long_term_remediation", []),
                monitoring=data.get("monitoring", [])
            )

        except Exception as e:
            logger.error(f"AI JSON parse failed: {e}")

    # Local Fallback
    return _local_report(
        iocs,
        enrichment,
        mitre_techniques,
        risk_score,
        risk_level
    )