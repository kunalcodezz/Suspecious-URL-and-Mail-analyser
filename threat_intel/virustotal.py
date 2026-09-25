"""
VirusTotal Threat Intelligence Client (API v3).

Queries VirusTotal for domains, IPs, and URLs using real API calls.
Never invents data or placeholders.
"""

import base64
import os
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


class VirusTotalClient:
    """Interacts with VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 6.0):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.timeout = timeout

    def is_configured(self) -> bool:
        """Returns True if a non-empty API key is present."""
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "PhishGuard-CLI/1.0",
        }

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Queries VirusTotal for domain reputation."""
        if not self.is_configured():
            return {
                "status": "skipped",
                "message": "Threat intelligence lookup skipped. API key not configured.",
            }

        url = f"{self.BASE_URL}/domains/{domain}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "status": "success",
                    "provider": "VirusTotal",
                    "target": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "categories": data.get("categories", {}),
                }
            elif resp.status_code == 404:
                return {
                    "status": "not_found",
                    "provider": "VirusTotal",
                    "message": "Target not observed in VirusTotal dataset.",
                }
            elif resp.status_code == 401 or resp.status_code == 403:
                return {
                    "status": "error",
                    "provider": "VirusTotal",
                    "message": "Authentication failed. Invalid or expired API key.",
                }
            else:
                return {
                    "status": "error",
                    "provider": "VirusTotal",
                    "message": f"API request failed with HTTP {resp.status_code}.",
                }
        except requests.exceptions.Timeout:
            return {"status": "error", "provider": "VirusTotal", "message": "Request timed out."}
        except Exception as e:
            return {"status": "error", "provider": "VirusTotal", "message": f"Connection error: {str(e)}"}

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Queries VirusTotal for IP reputation."""
        if not self.is_configured():
            return {
                "status": "skipped",
                "message": "Threat intelligence lookup skipped. API key not configured.",
            }

        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "status": "success",
                    "provider": "VirusTotal",
                    "target": ip,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "as_owner": data.get("as_owner", "N/A"),
                }
            elif resp.status_code == 404:
                return {
                    "status": "not_found",
                    "provider": "VirusTotal",
                    "message": "Target IP not observed in VirusTotal dataset.",
                }
            else:
                return {
                    "status": "error",
                    "provider": "VirusTotal",
                    "message": f"HTTP {resp.status_code}",
                }
        except Exception as e:
            return {"status": "error", "provider": "VirusTotal", "message": str(e)}

    def check_url(self, target_url: str) -> Dict[str, Any]:
        """Queries VirusTotal for URL reputation using base64 URL identifier."""
        if not self.is_configured():
            return {
                "status": "skipped",
                "message": "Threat intelligence lookup skipped. API key not configured.",
            }

        # VirusTotal v3 URL identifier: base64 without padding
        url_id = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8").strip("=")
        endpoint = f"{self.BASE_URL}/urls/{url_id}"

        try:
            resp = requests.get(endpoint, headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "status": "success",
                    "provider": "VirusTotal",
                    "target": target_url,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                }
            elif resp.status_code == 404:
                return {
                    "status": "not_found",
                    "provider": "VirusTotal",
                    "message": "URL not observed in VirusTotal dataset.",
                }
            else:
                return {
                    "status": "error",
                    "provider": "VirusTotal",
                    "message": f"HTTP {resp.status_code}",
                }
        except Exception as e:
            return {"status": "error", "provider": "VirusTotal", "message": str(e)}
