"""
AbuseIPDB Threat Intelligence Client.

Queries AbuseIPDB database for IP abuse confidence scores and threat reports.
Never invents mock results or placeholders.
"""

import os
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


class AbuseIPDBClient:
    """Interacts with AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 6.0):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.timeout = timeout

    def is_configured(self) -> bool:
        """Returns True if a non-empty API key is present."""
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        return {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "PhishGuard-CLI/1.0",
        }

    def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """Queries AbuseIPDB for IP reputation and abuse score."""
        if not self.is_configured():
            return {
                "status": "skipped",
                "message": "Threat intelligence lookup skipped. API key not configured.",
            }

        endpoint = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_in_days,
            "verbose": ""
        }

        try:
            resp = requests.get(endpoint, headers=self._headers(), params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "status": "success",
                    "provider": "AbuseIPDB",
                    "target": ip_address,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "usage_type": data.get("usageType", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported_at": data.get("lastReportedAt", "N/A"),
                }
            elif resp.status_code == 401 or resp.status_code == 403:
                return {
                    "status": "error",
                    "provider": "AbuseIPDB",
                    "message": "Authentication failed. Invalid or expired API key.",
                }
            elif resp.status_code == 429:
                return {
                    "status": "error",
                    "provider": "AbuseIPDB",
                    "message": "Rate limit exceeded.",
                }
            else:
                return {
                    "status": "error",
                    "provider": "AbuseIPDB",
                    "message": f"API request failed with HTTP {resp.status_code}",
                }
        except requests.exceptions.Timeout:
            return {"status": "error", "provider": "AbuseIPDB", "message": "Request timed out."}
        except Exception as e:
            return {"status": "error", "provider": "AbuseIPDB", "message": str(e)}
