"""
IOC Extraction Service
Extracts Indicators of Compromise from raw text using regex patterns
"""
import re
import logging
from typing import List, Dict, Any
from app.schemas.schemas import IOC

logger = logging.getLogger(__name__)

# ─── Regex Patterns ───────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "domain": re.compile(
        r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)'  # Not an IP
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|co|gov|edu|mil|int|xyz|info|biz|online|site|'
        r'ru|cn|uk|de|fr|jp|br|in|au|ca|nl|se|no|fi|dk|pl|it|es|pt|'
        r'top|app|dev|cloud|tech|ai|ml|security|cyber)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]\']{2,}'
    ),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
    "md5": re.compile(
        r'\b[a-fA-F0-9]{32}\b'
    ),
    "sha1": re.compile(
        r'\b[a-fA-F0-9]{40}\b'
    ),
    "sha256": re.compile(
        r'\b[a-fA-F0-9]{64}\b'
    ),
    "cve": re.compile(
        r'\bCVE-\d{4}-\d{4,7}\b',
        re.IGNORECASE
    ),
}

# IPs to exclude (private/loopback/broadcast)
PRIVATE_IP_PATTERNS = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.'),
    re.compile(r'^255\.'),
]

# Common words that look like hashes but aren't IOCs
HASH_EXCLUSIONS = {
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string - include for demo
}

# Common benign domains to exclude from false positives
BENIGN_DOMAINS = {
    "example.com", "test.com", "localhost.com", "microsoft.com",
    "google.com", "apple.com", "amazon.com", "github.com",
    "cloudflare.com", "fastly.com", "akamai.com",
}


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_PATTERNS)


def extract_iocs(text: str) -> List[IOC]:
    """
    Extract all IOC types from text, deduplicate, and return structured list.
    """
    if not text or not text.strip():
        return []

    found: Dict[str, IOC] = {}  # key = "type:value" for dedup

    # Extract URLs first (before domain to avoid double-counting)
    for match in PATTERNS["url"].finditer(text):
        url = match.group().rstrip(".,;:)'\"")
        key = f"url:{url.lower()}"
        if key not in found:
            found[key] = IOC(type="url", value=url, reputation="unknown")

    # Extract CVEs
    for match in PATTERNS["cve"].finditer(text):
        cve = match.group().upper()
        key = f"cve:{cve}"
        if key not in found:
            found[key] = IOC(type="cve", value=cve, reputation="unknown")

    # Extract IPs
    for match in PATTERNS["ipv4"].finditer(text):
        ip = match.group()
        if not is_private_ip(ip):
            key = f"ipv4:{ip}"
            if key not in found:
                found[key] = IOC(type="ipv4", value=ip, reputation="unknown")

    # Extract emails (before domain to avoid double)
    for match in PATTERNS["email"].finditer(text):
        email = match.group().lower()
        key = f"email:{email}"
        if key not in found:
            found[key] = IOC(type="email", value=email, reputation="unknown")

    # Extract domains (skip if already found in URL or email)
    url_domains = set()
    for k in found:
        if k.startswith("url:"):
            url = k[4:]
            try:
                domain_part = url.split("//")[1].split("/")[0].split(":")[0]
                url_domains.add(domain_part.lower())
            except Exception:
                pass

    for match in PATTERNS["domain"].finditer(text):
        domain = match.group().lower().rstrip(".")
        if domain in BENIGN_DOMAINS or domain in url_domains:
            continue
        # Skip email domains
        email_domains = {e.split("@")[1] for k, e in [(k, k[6:]) for k in found if k.startswith("email:")]}
        if domain in email_domains:
            continue
        key = f"domain:{domain}"
        if key not in found:
            found[key] = IOC(type="domain", value=domain, reputation="unknown")

    # Extract SHA256 first (longest, most specific)
    for match in PATTERNS["sha256"].finditer(text):
        h = match.group().lower()
        key = f"sha256:{h}"
        if key not in found:
            found[key] = IOC(type="sha256", value=h, reputation="unknown")

    # Extract SHA1
    sha256_hashes = {k[7:] for k in found if k.startswith("sha256:")}
    for match in PATTERNS["sha1"].finditer(text):
        h = match.group().lower()
        # Skip if it's a substring of a sha256
        if any(h in s for s in sha256_hashes):
            continue
        key = f"sha1:{h}"
        if key not in found:
            found[key] = IOC(type="sha1", value=h, reputation="unknown")

    # Extract MD5
    sha1_hashes = {k[5:] for k in found if k.startswith("sha1:")}
    for match in PATTERNS["md5"].finditer(text):
        h = match.group().lower()
        if any(h in s for s in sha256_hashes | sha1_hashes):
            continue
        key = f"md5:{h}"
        if key not in found:
            found[key] = IOC(type="md5", value=h, reputation="unknown")

    result = list(found.values())
    logger.info(f"Extracted {len(result)} IOCs from text ({len(text)} chars)")
    return result


def get_ioc_summary(iocs: List[IOC]) -> Dict[str, int]:
    """Return count by type."""
    summary: Dict[str, int] = {}
    for ioc in iocs:
        summary[ioc.type] = summary.get(ioc.type, 0) + 1
    return summary
