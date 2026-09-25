"""
URLhaus Threat Intelligence Client (Abuse.ch).

Queries URLhaus database for active malware distribution URLs and malicious hosts.
Never invents mock results or placeholders.
"""

import os
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


class URLhausClient:
    """Interacts with Abuse.ch URLhaus API."""

    API_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 6.0):
        self.api_key = api_key or os.getenv("URLHAUS_API_KEY", "").strip()
        self.timeout = timeout

    def is_configured(self) -> bool:
        """Returns True if a non-empty API key is configured."""
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "PhishGuard-CLI/1.0",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def check_url(self, target_url: str) -> Dict[str, Any]:
        """Queries URLhaus for specific URL status."""
        if not self.is_configured():
            return {
                "status": "skipped",
                "message": "Threat intelligence lookup skipped. API key not configured.",
            }

        endpoint = f"{self.API_URL}/url/"
        try:
            resp = requests.post(endpoint, data={"url": target_url}, headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status")
                if query_status == "ok":
                    return {
                        "status": "success",
                        "provider": "URLhaus",
                        "target": target_url,
                        "urlhaus_status": data.get("url_status", "unknown"),
                        "threat": data.get("threat", "unknown"),
                        "tags": data.get("tags", []),
                        "date_added": data.get("date_added", "N/A"),
                        "reporter": data.get("reporter", "N/A"),
                    }
                elif query_status == "no_results":
                    return {
                        "status": "not_found",
                        "provider": "URLhaus",
                        "message": "Target URL not listed in URLhaus malware database.",
                    }
                else:
                    return {
                        "status": "info",
                        "provider": "URLhaus",
                        "message": f"URLhaus response: {query_status}",
                    }
            else:
                return {
                    "status": "error",
                    "provider": "URLhaus",
                    "message": f"HTTP {resp.status_code}",
                }
        except requests.exceptions.Timeout:
            return {"status": "error", "provider": "URLhaus", "message": "Request timed out."}
        except Exception as e:
            return {"status": "error", "provider": "URLhaus", "message": str(e)}

    def check_host(self, host: str) -> Dict[str, Any]:
        """Queries URLhaus for host or domain reputation."""
        if not self.is_configured():
            return {
                "status": "skipped",
                "message": "Threat intelligence lookup skipped. API key not configured.",
            }

        endpoint = f"{self.API_URL}/host/"
        try:
            resp = requests.post(endpoint, data={"host": host}, headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status")
                if query_status == "ok":
                    return {
                        "status": "success",
                        "provider": "URLhaus",
                        "target": host,
                        "url_count": data.get("url_count", 0),
                        "firstseen": data.get("firstseen", "N/A"),
                    }
                elif query_status == "no_results":
                    return {
                        "status": "not_found",
                        "provider": "URLhaus",
                        "message": "Host not listed in URLhaus database.",
                    }
                else:
                    return {
                        "status": "info",
                        "provider": "URLhaus",
                        "message": f"URLhaus response: {query_status}",
                    }
            else:
                return {
                    "status": "error",
                    "provider": "URLhaus",
                    "message": f"HTTP {resp.status_code}",
                }
        except Exception as e:
            return {"status": "error", "provider": "URLhaus", "message": str(e)}
