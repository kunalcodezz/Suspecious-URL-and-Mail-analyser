"""
URL Analyzer for PhishGuard CLI.

Performs deep static inspection of uniform resource locators (URLs),
extracting structural components, detecting deception mechanisms,
and matching against heuristic security rules.
"""

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from detection.rules import URL_RULES, DetectionResult


# High-abuse TLDs commonly seen in phishing & disposable spam domains
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "loan",
    "surf", "fit", "buzz", "rest", "cam", "icu", "zip", "mov", "country",
    "stream", "download", "racing", "win", "bid"
}

# Common credential harvesting and phishing target keywords
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "update", "security", "secure", "authenticate", "confirm",
    "banking", "password", "credential", "wallet", "support", "helpdesk",
    "recover", "billing", "invoice", "payment", "unlock", "suspended",
    "validation", "re-activate", "reactivate", "session", "authorize"
]

# Suspicious file extensions for downloadable artifacts
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".iso", ".img", ".vbs", ".js", ".bat", ".cmd",
    ".ps1", ".hta", ".apk", ".dmg", ".msi", ".jar", ".wsf", ".pif"
}

# Standard web ports
STANDARD_PORTS = {80, 443}


@dataclass
class URLComponents:
    """Parsed components of an analyzed URL."""
    raw_url: str
    scheme: str
    host: str
    domain: str
    subdomain: str
    tld: str
    port: str
    path: str
    query: str
    query_params: Dict[str, List[str]]
    fragment: str
    length: int
    is_ip: bool
    ip_version: Optional[int] = None
    userinfo: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_url": self.raw_url,
            "scheme": self.scheme,
            "host": self.host,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "tld": self.tld,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "query_params": self.query_params,
            "fragment": self.fragment,
            "length": self.length,
            "is_ip": self.is_ip,
            "ip_version": self.ip_version,
            "userinfo": self.userinfo,
        }


def is_ip_address(host: str) -> Tuple[bool, Optional[int]]:
    """Checks whether the given hostname is an IPv4 or IPv6 address."""
    clean_host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(clean_host)
        return True, ip.version
    except ValueError:
        return False, None


def check_ip_obfuscation(host: str) -> bool:
    """Checks for dword integer, hex, or octal IP obfuscations."""
    # Check for pure DWORD (integer IP)
    if host.isdigit():
        val = int(host)
        if 0 < val <= 4294967295:
            return True

    # Check for hex components (e.g. 0x7f000001 or 0x7f.0.0.1)
    if any(part.lower().startswith("0x") for part in host.split(".")):
        return True

    # Check for octal components (e.g. 0177.0.0.1 where leading 0 is not just '0')
    parts = host.split(".")
    if len(parts) == 4 and any(p.startswith("0") and len(p) > 1 and p.isdigit() for p in parts):
        return True

    return False


def extract_domain_parts(host: str, is_ip: bool) -> Tuple[str, str, str]:
    """
    Extracts (subdomain, domain, tld) from hostname.
    Handles standard generic and country-code domains.
    """
    if is_ip or not host or host == "localhost":
        return "", host, ""

    labels = host.lower().split(".")
    if len(labels) <= 1:
        return "", host, ""

    # Known double-barrel TLDs (e.g., .co.uk, .com.au, .gov.uk)
    double_tlds = {"co.uk", "org.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br"}
    last_two = ".".join(labels[-2:])

    if len(labels) >= 3 and last_two in double_tlds:
        tld = last_two
        domain = labels[-3] + "." + tld
        subdomain = ".".join(labels[:-3])
    else:
        tld = labels[-1]
        domain = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])

    return subdomain, domain, tld


class URLAnalyzer:
    """Performs deep URL extraction and security detection."""

    def parse(self, raw_url: str) -> URLComponents:
        """Safely parses raw URL string into structured components."""
        url = raw_url.strip()
        # Add http if scheme is absent for parser stability
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url_to_parse = "http://" + url
            has_inferred_scheme = True
        else:
            url_to_parse = url
            has_inferred_scheme = False

        parsed = urllib.parse.urlsplit(url_to_parse)

        scheme = parsed.scheme.upper() if not has_inferred_scheme else "HTTP (Inferred)"
        netloc = parsed.netloc

        userinfo = None
        if "@" in netloc:
            userinfo, netloc = netloc.split("@", 1)

        # Extract host and port
        if ":" in netloc and not netloc.endswith("]"):  # Avoid breaking IPv6 [::1]
            host_part, port_part = netloc.rsplit(":", 1)
            port = port_part
            host = host_part
        else:
            host = netloc
            port = "Default"

        # Strip brackets from IPv6 host
        clean_host = host.strip("[]").lower()

        is_ip, ip_version = is_ip_address(clean_host)
        subdomain, domain, tld = extract_domain_parts(clean_host, is_ip)

        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        return URLComponents(
            raw_url=raw_url,
            scheme=scheme,
            host=clean_host,
            domain=domain,
            subdomain=subdomain,
            tld=tld,
            port=port,
            path=parsed.path or "/",
            query=parsed.query,
            query_params=query_params,
            fragment=parsed.fragment,
            length=len(raw_url),
            is_ip=is_ip,
            ip_version=ip_version,
            userinfo=userinfo,
        )

    def analyze(self, raw_url: str) -> Tuple[URLComponents, List[DetectionResult]]:
        """Parses URL and evaluates all security detection rules."""
        comp = self.parse(raw_url)
        results: List[DetectionResult] = []

        # URL001: IP address used as hostname
        if comp.is_ip:
            results.append(DetectionResult(
                rule=URL_RULES["URL001"],
                evidence=f"Host '{comp.host}' is a raw IPv{comp.ip_version} address instead of a domain name."
            ))

        # URL011: Hex / Octal / Dword obfuscated IP
        if not comp.is_ip and check_ip_obfuscation(comp.host):
            results.append(DetectionResult(
                rule=URL_RULES["URL011"],
                evidence=f"Host '{comp.host}' contains obfuscated numeric/hex/octal IP representation."
            ))

        # URL002: Suspicious URL length (> 75 chars)
        if comp.length > 75:
            results.append(DetectionResult(
                rule=URL_RULES["URL002"],
                evidence=f"URL length is {comp.length} characters (exceeds typical threshold of 75)."
            ))

        # URL003: Punycode / IDN homograph detected
        if "xn--" in comp.host.lower() or any(ord(c) > 127 for c in comp.host):
            results.append(DetectionResult(
                rule=URL_RULES["URL003"],
                evidence=f"Hostname '{comp.host}' contains Punycode ('xn--') or non-ASCII characters indicating homograph risk."
            ))

        # URL004: Suspicious / Non-standard port
        if comp.port != "Default":
            try:
                numeric_port = int(comp.port)
                if numeric_port not in STANDARD_PORTS:
                    results.append(DetectionResult(
                        rule=URL_RULES["URL004"],
                        evidence=f"URL uses non-standard web port '{comp.port}'."
                    ))
            except ValueError:
                results.append(DetectionResult(
                    rule=URL_RULES["URL004"],
                    evidence=f"Malformed port '{comp.port}' specified."
                ))

        # URL005: Excessive subdomains (> 3 dots in subdomain part)
        if comp.subdomain:
            subdomain_parts = comp.subdomain.split(".")
            if len(subdomain_parts) >= 3:
                results.append(DetectionResult(
                    rule=URL_RULES["URL005"],
                    evidence=f"Excessive subdomains detected ({len(subdomain_parts)} levels): '{comp.subdomain}'."
                ))

        # URL006: HTTP instead of HTTPS
        if comp.scheme.upper() in ["HTTP", "HTTP (INFERRED)"]:
            results.append(DetectionResult(
                rule=URL_RULES["URL006"],
                evidence=f"Insecure plaintext protocol '{comp.scheme}' used instead of HTTPS."
            ))

        # URL007: Suspicious URL encoding
        encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", comp.raw_url)
        if len(encoded_matches) >= 3 or ("%2f" in comp.raw_url.lower() or "%2e" in comp.raw_url.lower()):
            results.append(DetectionResult(
                rule=URL_RULES["URL007"],
                evidence=f"Found {len(encoded_matches)} percent-encoded characters, potentially concealing path or payload."
            ))

        # URL008: Embedded credentials (@ symbol)
        if comp.userinfo or "@" in comp.raw_url.split("?")[0]:
            results.append(DetectionResult(
                rule=URL_RULES["URL008"],
                evidence=f"Userinfo or '@' symbol detected before host: '{comp.userinfo or '@'}'. May mislead visual validation."
            ))

        # URL009: Suspicious phishing keywords
        url_lower = comp.raw_url.lower()
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        if matched_keywords:
            results.append(DetectionResult(
                rule=URL_RULES["URL009"],
                evidence=f"Contains phishing/credential harvesting keywords: {', '.join(matched_keywords[:4])}."
            ))

        # URL010: Suspicious high-risk TLD
        if comp.tld.lower() in SUSPICIOUS_TLDS:
            results.append(DetectionResult(
                rule=URL_RULES["URL010"],
                evidence=f"Domain uses high-abuse top-level domain '.{comp.tld}'."
            ))

        # URL012: Double slash or open redirect pattern in path
        if "//" in comp.path[1:] or ("http://" in comp.path.lower() or "https://" in comp.path.lower()):
            results.append(DetectionResult(
                rule=URL_RULES["URL012"],
                evidence=f"Path '{comp.path}' contains multiple slashes or embedded protocol, indicating open redirect."
            ))

        # URL013: Dangerous file extension
        path_lower = comp.path.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if path_lower.endswith(ext) or (ext + "?") in path_lower:
                results.append(DetectionResult(
                    rule=URL_RULES["URL013"],
                    evidence=f"Path targets potentially dangerous executable/payload extension '{ext}'."
                ))
                break

        # URL014: Brand impersonation hyphen abuse
        if comp.domain and comp.domain.count("-") >= 2:
            results.append(DetectionResult(
                rule=URL_RULES["URL014"],
                evidence=f"Domain '{comp.domain}' contains multiple hyphens ({comp.domain.count('-')}), common in brand lookalikes."
            ))

        return comp, results
