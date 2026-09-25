"""Unit tests for URL Analyzer and URL Detection Rules."""

import unittest
from analyzers.url_analyzer import URLAnalyzer, check_ip_obfuscation, is_ip_address


class TestURLAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = URLAnalyzer()

    def test_normal_url(self):
        url = "https://www.example.com/about/team"
        comp, results = self.analyzer.analyze(url)
        self.assertEqual(comp.scheme, "HTTPS")
        self.assertEqual(comp.host, "www.example.com")
        self.assertEqual(comp.domain, "example.com")
        self.assertEqual(comp.subdomain, "www")
        self.assertFalse(comp.is_ip)
        # Should trigger 0 high or critical rules
        rule_ids = [r.rule.rule_id for r in results]
        self.assertNotIn("URL001", rule_ids)
        self.assertNotIn("URL006", rule_ids)

    def test_ip_based_url(self):
        url = "http://192.168.1.50/login"
        comp, results = self.analyzer.analyze(url)
        self.assertTrue(comp.is_ip)
        self.assertEqual(comp.ip_version, 4)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL001", rule_ids)  # IP address hostname
        self.assertIn("URL006", rule_ids)  # HTTP
        self.assertIn("URL009", rule_ids)  # Login keyword

    def test_punycode_url(self):
        url = "http://xn--pple-43d.com/verify"
        comp, results = self.analyzer.analyze(url)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL003", rule_ids)

    def test_long_url(self):
        url = "https://example.com/" + "a" * 120
        comp, results = self.analyzer.analyze(url)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL002", rule_ids)

    def test_excessive_subdomains(self):
        url = "https://account.security.verify.login.example.com/portal"
        comp, results = self.analyzer.analyze(url)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL005", rule_ids)

    def test_userinfo_at_symbol(self):
        url = "https://google.com@evil-phish.net/login"
        comp, results = self.analyzer.analyze(url)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL008", rule_ids)

    def test_dangerous_extension(self):
        url = "https://downloads.example.org/installer.scr"
        comp, results = self.analyzer.analyze(url)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL013", rule_ids)

    def test_suspicious_port(self):
        url = "http://example.com:8443/auth"
        comp, results = self.analyzer.analyze(url)
        rule_ids = [r.rule.rule_id for r in results]
        self.assertIn("URL004", rule_ids)

    def test_malformed_url_without_scheme(self):
        url = "10.0.0.1/admin"
        comp, results = self.analyzer.analyze(url)
        self.assertEqual(comp.host, "10.0.0.1")
        self.assertTrue(comp.is_ip)

    def test_ip_obfuscation_detection(self):
        self.assertTrue(check_ip_obfuscation("2130706433"))
        self.assertTrue(check_ip_obfuscation("0x7f000001"))
        self.assertTrue(check_ip_obfuscation("0177.0.0.1"))
        self.assertFalse(check_ip_obfuscation("example.com"))


if __name__ == "__main__":
    unittest.main()
