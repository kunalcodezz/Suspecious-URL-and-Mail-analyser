"""
DNS Analyzer for PhishGuard CLI.

Performs live DNS resolution queries (A, AAAA, MX, NS, TXT)
using dnspython with strict timeouts and robust exception handling.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class DNSResult:
    """Stores query results for various DNS record types."""
    domain: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    is_resolvable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "is_resolvable": self.is_resolvable,
            "a": self.a_records if self.a_records else "Not available",
            "aaaa": self.aaaa_records if self.aaaa_records else "Not available",
            "mx": self.mx_records if self.mx_records else "Not available",
            "ns": self.ns_records if self.ns_records else "Not available",
            "txt": self.txt_records if self.txt_records else "Not available",
            "errors": self.errors,
        }


class DNSAnalyzer:
    """Performs structured DNS enumeration."""

    def __init__(self, timeout: float = 3.0, lifetime: float = 5.0):
        self.timeout = timeout
        self.lifetime = lifetime

    def query(self, domain: str) -> DNSResult:
        """Queries DNS records for the specified domain."""
        result = DNSResult(domain=domain)

        if not HAS_DNSPYTHON:
            result.errors["general"] = "dnspython library not installed."
            return result

        if not domain or domain == "localhost":
            result.errors["general"] = "Invalid or local domain."
            return result

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime

        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        any_success = False

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                entries = []
                for rdata in answers:
                    if rtype == "MX":
                        # MX records have preference + exchange
                        entries.append(f"{rdata.exchange.to_text().rstrip('.')} (pref {rdata.preference})")
                    elif rtype == "TXT":
                        entries.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
                    else:
                        entries.append(rdata.to_text().rstrip("."))
                
                if entries:
                    any_success = True
                    if rtype == "A":
                        result.a_records = entries
                    elif rtype == "AAAA":
                        result.aaaa_records = entries
                    elif rtype == "MX":
                        result.mx_records = entries
                    elif rtype == "NS":
                        result.ns_records = entries
                    elif rtype == "TXT":
                        result.txt_records = entries
            except dns.resolver.NXDOMAIN:
                result.errors[rtype] = "NXDOMAIN (Domain does not exist)"
                # If domain doesn't exist, no point querying other records
                break
            except dns.resolver.NoAnswer:
                # Normal when record type doesn't exist for domain
                pass
            except dns.resolver.LifetimeTimeout:
                result.errors[rtype] = "Query timed out"
            except Exception as e:
                result.errors[rtype] = f"Error: {type(e).__name__}"

        result.is_resolvable = any_success
        return result
