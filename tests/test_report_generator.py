"""Unit tests for Report Generator and Threat Intel clients."""

import json
import os
import tempfile
import unittest
from analyzers.report_generator import ReportGenerator
from threat_intel.virustotal import VirusTotalClient
from threat_intel.urlhaus import URLhausClient
from threat_intel.abuseipdb import AbuseIPDBClient


class TestReportingAndThreatIntel(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_report_generation(self):
        txt_path, json_path = ReportGenerator.generate(
            analysis_type="url",
            target="http://test-phish.com/login",
            extracted_info={"scheme": "HTTP", "host": "test-phish.com"},
            detection_results=[{"rule_id": "URL006", "name": "HTTP instead of HTTPS"}],
            risk_assessment={"score": 10, "severity": "INFORMATIONAL", "contributing_factors": []},
            iocs={"urls": ["http://test-phish.com/login"], "domains": ["test-phish.com"]},
            dns_info={"a": ["1.2.3.4"]},
            threat_intel={"virustotal": {"status": "skipped", "message": "API key not configured."}},
            output_dir=self.temp_dir.name,
        )

        self.assertTrue(os.path.exists(txt_path))
        self.assertTrue(os.path.exists(json_path))

        # Validate JSON format
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["metadata"]["target"], "http://test-phish.com/login")
            self.assertEqual(data["risk_assessment"]["score"], 10)

        # Validate TXT content
        with open(txt_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("PHISHGUARD ANALYSIS REPORT", content)
            self.assertIn("http://test-phish.com/login", content)

    def test_threat_intel_unconfigured_behavior(self):
        # Empty API keys should safely skip and return status "skipped" without errors or fake data
        vt = VirusTotalClient(api_key="")
        uh = URLhausClient(api_key="")
        abuse = AbuseIPDBClient(api_key="")

        self.assertFalse(vt.is_configured())
        self.assertFalse(uh.is_configured())
        self.assertFalse(abuse.is_configured())

        res_vt = vt.check_domain("example.com")
        self.assertEqual(res_vt["status"], "skipped")
        self.assertIn("skipped", res_vt["message"])

        res_uh = uh.check_url("http://example.com")
        self.assertEqual(res_uh["status"], "skipped")

        res_ab = abuse.check_ip("8.8.8.8")
        self.assertEqual(res_ab["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
