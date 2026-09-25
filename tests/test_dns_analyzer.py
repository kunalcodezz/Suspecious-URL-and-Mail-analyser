"""Unit tests for DNS Analyzer and error conditions."""

import unittest
from analyzers.dns_analyzer import DNSAnalyzer


class TestDNSAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = DNSAnalyzer(timeout=1.0, lifetime=2.0)

    def test_localhost_handling(self):
        res = self.analyzer.query("localhost")
        self.assertFalse(res.is_resolvable)
        self.assertIn("general", res.errors)

    def test_empty_domain(self):
        res = self.analyzer.query("")
        self.assertFalse(res.is_resolvable)

    def test_nonexistent_domain(self):
        # A test domain designed to fail resolution
        res = self.analyzer.query("this-domain-does-not-exist-12345-phishguard-test.invalid")
        self.assertFalse(res.is_resolvable)
        self.assertTrue(len(res.errors) > 0)


if __name__ == "__main__":
    unittest.main()
