"""
Detection Rule Generator
Generates Sigma, YARA, Splunk, Sentinel KQL and Elastic rules
from extracted IOCs and MITRE ATT&CK techniques.
"""

import logging
from typing import List

from app.schemas.schemas import (
    IOC,
    MITRETechnique,
    DetectionRules,
)

logger = logging.getLogger(__name__)


def generate_detection_rules(
    iocs: List[IOC],
    mitre_techniques: List[MITRETechnique],
) -> DetectionRules:

    sigma = _generate_sigma(iocs, mitre_techniques)
    yara = _generate_yara(iocs)
    splunk = _generate_splunk(iocs)
    sentinel = _generate_sentinel(iocs)
    elastic = _generate_elastic(iocs)

    logger.info(
        f"Generated detection content from "
        f"{len(iocs)} IOCs and "
        f"{len(mitre_techniques)} MITRE techniques"
    )

    return DetectionRules(
        sigma=sigma,
        yara=yara,
        splunk=splunk,
        sentinel_kql=sentinel,
        elastic=elastic,
    )


# -------------------------------------------------------
# SIGMA
# -------------------------------------------------------

def _generate_sigma(
    iocs: List[IOC],
    mitre_techniques: List[MITRETechnique],
) -> str:

    domains = [
        i.value for i in iocs
        if i.type == "domain"
    ]

    ips = [
        i.value for i in iocs
        if i.type == "ipv4"
    ]

    hashes = [
        i.value for i in iocs
        if i.type in ("md5", "sha1", "sha256")
    ]

    technique_ids = [
        t.id for t in mitre_techniques
    ]

    lines = [
        "title: Threat Intelligence Detection",
        "id: generated-threat-rule",
        "status: experimental",
        "description: Generated from AI Threat Analysis",
        "author: AI Threat Intelligence Platform",
        "logsource:",
        "  category: network_connection",
        "detection:",
        "  selection:",
    ]

    if domains:
        lines.append("    query|contains:")
        for d in domains:
            lines.append(f"      - '{d}'")

    if ips:
        lines.append("    destination_ip:")
        for ip in ips:
            lines.append(f"      - '{ip}'")

    if hashes:
        lines.append("    hash:")
        for h in hashes:
            lines.append(f"      - '{h}'")

    lines.extend([
        "  condition: selection",
        "tags:",
    ])

    for tid in technique_ids:
        lines.append(f"  - attack.{tid.lower()}")

    return "\n".join(lines)


# -------------------------------------------------------
# YARA
# -------------------------------------------------------

def _generate_yara(
    iocs: List[IOC]
) -> str:

    strings = []

    idx = 1

    for ioc in iocs:

        if ioc.type in (
            "domain",
            "url",
            "email",
        ):
            strings.append(
                f'        $s{idx} = "{ioc.value}" nocase'
            )
            idx += 1

    if not strings:

        strings.append(
            '        $placeholder = "suspicious" nocase'
        )

    return f"""
rule Threat_Intelligence_IOCs
{{
    meta:
        author = "AI Threat Intelligence Platform"
        description = "Generated IOC detection rule"

    strings:
{chr(10).join(strings)}

    condition:
        any of them
}}
""".strip()


# -------------------------------------------------------
# SPLUNK
# -------------------------------------------------------

def _generate_splunk(
    iocs: List[IOC]
) -> str:

    parts = []

    for ioc in iocs:

        if ioc.type == "ipv4":
            parts.append(
                f'dest_ip="{ioc.value}"'
            )

        elif ioc.type == "domain":
            parts.append(
                f'domain="{ioc.value}"'
            )

        elif ioc.type == "url":
            parts.append(
                f'url="{ioc.value}"'
            )

        elif ioc.type == "cve":
            parts.append(
                f'"{ioc.value}"'
            )

    if not parts:
        parts.append("*")

    return (
        "search index=* ("
        + " OR ".join(parts)
        + ")"
    )


# -------------------------------------------------------
# SENTINEL KQL
# -------------------------------------------------------

def _generate_sentinel(
    iocs: List[IOC]
) -> str:

    clauses = []

    for ioc in iocs:

        if ioc.type == "ipv4":
            clauses.append(
                f'IPAddress == "{ioc.value}"'
            )

        elif ioc.type == "domain":
            clauses.append(
                f'DomainName == "{ioc.value}"'
            )

        elif ioc.type == "url":
            clauses.append(
                f'Url contains "{ioc.value}"'
            )

    if not clauses:
        clauses.append("true")

    return (
        "CommonSecurityLog\n"
        "| where "
        + " or ".join(clauses)
    )


# -------------------------------------------------------
# ELASTIC
# -------------------------------------------------------

def _generate_elastic(
    iocs: List[IOC]
) -> str:

    clauses = []

    for ioc in iocs:

        if ioc.type == "ipv4":
            clauses.append(
                f'destination.ip:"{ioc.value}"'
            )

        elif ioc.type == "domain":
            clauses.append(
                f'dns.question.name:"{ioc.value}"'
            )

        elif ioc.type == "url":
            clauses.append(
                f'url.full:"{ioc.value}"'
            )

    if not clauses:
        clauses.append("*")

    return " OR ".join(clauses)