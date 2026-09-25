"""Unit tests for Email Analyzer and Email Detection Rules."""

import os
import tempfile
import unittest
from analyzers.email_analyzer import EmailAnalyzer, extract_auth_status


class TestEmailAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = EmailAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_temp_eml(self, content: str) -> str:
        filepath = os.path.join(self.temp_dir.name, "test_email.eml")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def test_normal_email(self):
        eml_content = """From: alice@example.com
To: bob@example.com
Subject: Project Status Update
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <12345@example.com>
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Hi Bob,
Here is the weekly update on the project. Let me know if you have questions.
Best,
Alice
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        self.assertEqual(comp.sender, "alice@example.com")
        self.assertEqual(comp.spf_result, "Pass")
        self.assertEqual(comp.dkim_result, "Pass")
        self.assertEqual(comp.dmarc_result, "Pass")
        self.assertEqual(len(results), 0)

    def test_reply_to_mismatch(self):
        eml_content = """From: security@paypal-alerts.com
Reply-To: attacker@evil-stealer.net
To: victim@target.com
Subject: Account Verification
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <67890@paypal-alerts.com>

Please verify your credentials immediately.
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL001", rule_ids)  # Reply-To mismatch

    def test_missing_authentication_and_headers(self):
        # No Authentication-Results, missing Date and Message-ID
        eml_content = """From: boss@corp.com
To: accountant@corp.com
Subject: Urgent wire transfer needed

Transfer the funds now.
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        self.assertEqual(comp.spf_result, "Not available")
        self.assertEqual(comp.dkim_result, "Not available")
        self.assertEqual(comp.dmarc_result, "Not available")
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL007", rule_ids)  # Missing headers

    def test_authentication_failure(self):
        eml_content = """From: support@trustedbank.com
To: user@domain.com
Subject: Security Notice
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <msg999@trustedbank.com>
Authentication-Results: mail.server.com; spf=fail; dkim=neutral; dmarc=fail

Action required on your bank account.
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        self.assertEqual(comp.spf_result, "Fail")
        self.assertEqual(comp.dmarc_result, "Fail")
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL003", rule_ids)  # Auth failure

    def test_display_name_spoofing(self):
        eml_content = """From: "security@legitbank.com" <phisher@spoofed-host.org>
To: target@victim.org
Subject: Urgent: Verify Account
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <spoof-01@spoofed-host.org>

Please verify your account immediately.
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL002", rule_ids)

    def test_dangerous_attachment(self):
        eml_content = """From: finance@company.com
To: user@company.com
Subject: Overdue Invoice
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <inv001@company.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Please find invoice attached.

--BOUNDARY
Content-Type: application/octet-stream; name="invoice_details.hta"
Content-Disposition: attachment; filename="invoice_details.hta"

<script>fake payload</script>
--BOUNDARY--
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        self.assertEqual(len(comp.attachments), 1)
        self.assertTrue(comp.attachments[0].is_suspicious)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL004", rule_ids)  # Dangerous attachment

    def test_suspicious_link_in_body(self):
        eml_content = """From: notice@secure-mail.com
To: victim@example.com
Subject: Notification
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <notif@secure-mail.com>

Click here to view document: http://192.168.1.55/download
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        self.assertIn("http://192.168.1.55/download", comp.extracted_urls)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL005", rule_ids)

    def test_return_path_mismatch(self):
        eml_content = """From: billing@trusted-service.com
Return-Path: <bounce@untrusted-relay.net>
To: client@example.com
Subject: Monthly Statement
Date: Fri, 25 Sep 2026 10:00:00 +0000
Message-ID: <stmt@trusted-service.com>

Here is your monthly statement.
"""
        path = self._write_temp_eml(eml_content)
        comp, results = self.analyzer.analyze(path)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("EMAIL008", rule_ids)


if __name__ == "__main__":
    unittest.main()
