"""
Indicators of Compromise (IOC) Extractor for PhishGuard CLI.

Extracts, validates, deduplicates, and exports cyber threat intelligence
artifacts (IPv4, IPv6, URLs, Domains, Emails, MD5, SHA1, SHA256).
Supports defanging and exporting to JSON, CSV, and TXT formats.
"""

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Optional


# Regex patterns for IOC extraction
IPV4_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
IPV6_REGEX = r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}\b"
URL_REGEX = r"(?:https?|ftp|hxxps?):\/\/[^\s<>\"'()]+"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
DOMAIN_REGEX = r"\b(?!(?:https?|ftp)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"


@dataclass
class IOCContainer:
    """Stores structured and deduplicated IOC entities."""
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    md5: List[str] = field(default_factory=list)
    sha1: List[str] = field(default_factory=list)
    sha256: List[str] = field(default_factory=list)

    def total_count(self) -> int:
        return (
            len(self.ipv4) + len(self.ipv6) + len(self.urls) +
            len(self.domains) + len(self.emails) + len(self.md5) +
            len(self.sha1) + len(self.sha256)
        )

    def to_dict(self, defang: bool = False) -> Dict[str, List[str]]:
        if not defang:
            return {
                "ipv4": sorted(self.ipv4),
                "ipv6": sorted(self.ipv6),
                "urls": sorted(self.urls),
                "domains": sorted(self.domains),
                "emails": sorted(self.emails),
                "md5": sorted(self.md5),
                "sha1": sorted(self.sha1),
                "sha256": sorted(self.sha256),
            }
        return {
            "ipv4": [IOCExtractor.defang(i) for i in sorted(self.ipv4)],
            "ipv6": [IOCExtractor.defang(i) for i in sorted(self.ipv6)],
            "urls": [IOCExtractor.defang(i) for i in sorted(self.urls)],
            "domains": [IOCExtractor.defang(i) for i in sorted(self.domains)],
            "emails": [IOCExtractor.defang(i) for i in sorted(self.emails)],
            "md5": sorted(self.md5),
            "sha1": sorted(self.sha1),
            "sha256": sorted(self.sha256),
        }

    def to_json(self, indent: int = 2, defang: bool = False) -> str:
        return json.dumps(self.to_dict(defang=defang), indent=indent)

    def to_csv(self, defang: bool = False) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ioc_type", "value"])
        for ioc_type, items in self.to_dict(defang=defang).items():
            for item in items:
                writer.writerow([ioc_type, item])
        return output.getvalue()

    def to_txt(self, defang: bool = False) -> str:
        lines = []
        d = self.to_dict(defang=defang)
        for ioc_type, items in d.items():
            if items:
                lines.append(f"[{ioc_type.upper()}]")
                for item in items:
                    lines.append(f"  - {item}")
                lines.append("")
        return "\n".join(lines).strip()


class IOCExtractor:
    """Extracts and validates IOCs from arbitrary text or documents."""

    @staticmethod
    def defang(text: str) -> str:
        """Safely defangs URLs, IPs, domains, and emails for safe handling."""
        res = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
        # Replace dot before domain or IP octets
        res = res.replace(".", "[.]")
        res = res.replace("@", "[@]")
        return res

    @staticmethod
    def refang(text: str) -> str:
        """Re-arms defanged IOCs for legitimate lookup."""
        res = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
        res = res.replace("[.]", ".").replace("[@]", "@")
        return res

    @classmethod
    def extract_from_text(cls, raw_text: str) -> IOCContainer:
        """Parses and deduplicates all supported IOC categories from text."""
        if not raw_text:
            return IOCContainer()

        text = cls.refang(raw_text)

        # 1. URLs
        found_urls = set()
        for u in re.findall(URL_REGEX, text, re.IGNORECASE):
            clean_url = u.rstrip(".,;:)'\"]>")
            found_urls.add(clean_url)

        # 2. Emails
        found_emails = set()
        for e in re.findall(EMAIL_REGEX, text):
            clean_email = e.strip().lower()
            found_emails.add(clean_email)

        # 3. IPv4
        found_ipv4 = set()
        for ip in re.findall(IPV4_REGEX, text):
            try:
                parsed_ip = ipaddress.IPv4Address(ip)
                # Exclude local broadcast/zero addresses
                if not (ip.startswith("0.") or ip == "255.255.255.255"):
                    found_ipv4.add(ip)
            except ValueError:
                pass

        # 4. IPv6
        found_ipv6 = set()
        for ip in re.findall(IPV6_REGEX, text):
            try:
                ipaddress.IPv6Address(ip)
                if ip not in ("::", "::1"):
                    found_ipv6.add(ip)
            except ValueError:
                pass

        # 5. Hashes
        # Notice: SHA256 contains 64 hex, SHA1 40 hex, MD5 32 hex.
        # Filter to avoid substrings matching smaller hash regexes
        found_sha256 = set(re.findall(SHA256_REGEX, text, re.IGNORECASE))
        text_no_sha256 = re.sub(SHA256_REGEX, " ", text)

        found_sha1 = set(re.findall(SHA1_REGEX, text_no_sha256, re.IGNORECASE))
        text_no_sha1 = re.sub(SHA1_REGEX, " ", text_no_sha256)

        found_md5 = set(re.findall(MD5_REGEX, text_no_sha1, re.IGNORECASE))

        # 6. Domains
        # Exclude domains that are already captured in URLs, emails, or are common file extensions
        found_domains = set()
        candidate_domains = re.findall(DOMAIN_REGEX, text, re.IGNORECASE)
        common_false_tlds = {"png", "jpg", "jpeg", "gif", "txt", "pdf", "html", "js", "css", "py", "sh"}

        for d in candidate_domains:
            clean_domain = d.strip().lower().rstrip(".")
            tld = clean_domain.split(".")[-1]
            if tld in common_false_tlds:
                continue
            # Avoid matching IP addresses as domains
            if re.match(IPV4_REGEX, clean_domain):
                continue
            # Filter trivial hostnames
            if "." in clean_domain:
                found_domains.add(clean_domain)

        return IOCContainer(
            ipv4=sorted(list(found_ipv4)),
            ipv6=sorted(list(found_ipv6)),
            urls=sorted(list(found_urls)),
            domains=sorted(list(found_domains)),
            emails=sorted(list(found_emails)),
            md5=sorted(list(found_md5)),
            sha1=sorted(list(found_sha1)),
            sha256=sorted(list(found_sha256)),
        )
