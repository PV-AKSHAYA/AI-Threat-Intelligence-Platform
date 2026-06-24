"""
Threat Enrichment Service
Enriches extracted IOCs with CVE data, reputation scores, malware families, threat actors
"""
import json
import logging
import os
from typing import List, Dict, Any, Optional
from app.schemas.schemas import IOC, CVEEnrichment, EnrichmentResult

logger = logging.getLogger(__name__)

# Load enrichment data once at module level
_DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../seed_data/enrichment_data.json"))
_enrichment_db: Dict = {}

def _load_db():
    global _enrichment_db
    try:
        with open(_DATA_PATH, "r") as f:
            _enrichment_db = json.load(f)
        logger.info("Enrichment database loaded")
    except Exception as e:
        logger.error(f"Failed to load enrichment DB: {e}")
        _enrichment_db = {"cves": {}, "domains": {}, "ips": {}, "hashes": {}, "threat_actors": {}}

_load_db()


def enrich_iocs(iocs: List[IOC]) -> EnrichmentResult:
    """Enrich all extracted IOCs with threat intelligence context."""
    result = EnrichmentResult()

    for ioc in iocs:
        if ioc.type == "cve":
            cve_data = _enrich_cve(ioc.value.upper())
            if cve_data:
                result.cves.append(cve_data)
                # Update IOC reputation based on CVSS
                ioc.reputation = _cvss_to_reputation(cve_data.cvss)
            else:
                ioc.reputation = "unknown"

        elif ioc.type == "domain":
            domain_data = _enrich_domain(ioc.value)
            if domain_data:
                result.domains.append(domain_data)
                ioc.reputation = domain_data.get("reputation", "unknown")
            else:
                ioc.reputation = _heuristic_domain_reputation(ioc.value)

        elif ioc.type == "ipv4":
            ip_data = _enrich_ip(ioc.value)
            if ip_data:
                result.ips.append(ip_data)
                ioc.reputation = ip_data.get("reputation", "unknown")
            else:
                ioc.reputation = "unknown"

        elif ioc.type in ("md5", "sha1", "sha256"):
            hash_data = _enrich_hash(ioc.value)
            if hash_data:
                ioc.reputation = hash_data.get("reputation", "unknown")
            else:
                ioc.reputation = "unknown"

        elif ioc.type == "url":
            # Try to match domain from URL
            try:
                domain = ioc.value.split("//")[1].split("/")[0].split(":")[0]
                domain_data = _enrich_domain(domain)
                if domain_data:
                    ioc.reputation = domain_data.get("reputation", "unknown")
                else:
                    ioc.reputation = _heuristic_domain_reputation(domain)
            except Exception:
                ioc.reputation = "unknown"

        elif ioc.type == "email":
            ioc.reputation = "suspicious"

    return result


def _enrich_cve(cve_id: str) -> Optional[CVEEnrichment]:
    """Look up CVE in local database."""
    cve_db = _enrichment_db.get("cves", {})
    data = cve_db.get(cve_id)
    if data:
        return CVEEnrichment(
            id=data["id"],
            cvss=data.get("cvss"),
            severity=data.get("severity"),
            description=data.get("description"),
            exploit_available=data.get("exploit_available", False),
            malware_families=data.get("malware_families", []),
            threat_actors=data.get("threat_actors", []),
            affected_products=data.get("affected_products"),
            published_date=data.get("published_date"),
        )
    # Return a generic CVE enrichment for unknown CVEs
    return CVEEnrichment(
        id=cve_id,
        cvss=None,
        severity="unknown",
        description=f"CVE details not available in local database. Check NVD for {cve_id}.",
        exploit_available=False,
    )


def _enrich_domain(domain: str) -> Optional[Dict]:
    """Look up domain in local database."""
    domain_db = _enrichment_db.get("domains", {})
    data = domain_db.get(domain.lower())
    if data:
        return {"value": domain, **data}
    return None


def _enrich_ip(ip: str) -> Optional[Dict]:
    """Look up IP in local database."""
    ip_db = _enrichment_db.get("ips", {})
    data = ip_db.get(ip)
    if data:
        return {"value": ip, **data}
    return None


def _enrich_hash(hash_val: str) -> Optional[Dict]:
    """Look up hash in local database."""
    hash_db = _enrichment_db.get("hashes", {})
    return hash_db.get(hash_val.lower())


def _cvss_to_reputation(cvss: Optional[float]) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _heuristic_domain_reputation(domain: str) -> str:
    """Heuristic reputation scoring for unknown domains."""
    suspicious_keywords = [
        "update", "secure", "login", "verify", "account", "banking",
        "paypal", "microsoft", "apple", "google", "service", "cdn",
        "download", "install", "support", "helpdesk", "tech"
    ]
    domain_lower = domain.lower()
    score = sum(1 for kw in suspicious_keywords if kw in domain_lower)

    # Suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".online"]
    if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
        score += 2

    # Long subdomain
    if domain_lower.count(".") > 2:
        score += 1

    if score >= 3:
        return "suspicious"
    if score >= 1:
        return "potentially_suspicious"
    return "unknown"


def get_enrichment_summary(result: EnrichmentResult) -> Dict[str, Any]:
    """Get a summary of enrichment for risk scoring."""
    all_malware = set()
    all_actors = set()
    max_cvss = 0.0
    has_exploit = False

    for cve in result.cves:
        if cve.cvss and cve.cvss > max_cvss:
            max_cvss = cve.cvss
        if cve.exploit_available:
            has_exploit = True
        all_malware.update(cve.malware_families)
        all_actors.update(cve.threat_actors)

    return {
        "max_cvss": max_cvss,
        "has_exploit": has_exploit,
        "malware_families": list(all_malware),
        "threat_actors": list(all_actors),
    }
