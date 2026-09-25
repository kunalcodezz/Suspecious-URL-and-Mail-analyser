"""Unit tests for Risk Scoring Engine and Detection Rule evaluations."""

import unittest
from detection.rules import URL_RULES, EMAIL_RULES, DetectionResult, Rule
from detection.scoring import RiskScoringEngine


class TestRiskScoring(unittest.TestCase):
    def test_severity_tiers(self):
        self.assertEqual(RiskScoringEngine.get_severity(10), "INFORMATIONAL")
        self.assertEqual(RiskScoringEngine.get_severity(25), "LOW")
        self.assertEqual(RiskScoringEngine.get_severity(45), "MEDIUM")
        self.assertEqual(RiskScoringEngine.get_severity(65), "HIGH")
        self.assertEqual(RiskScoringEngine.get_severity(85), "CRITICAL")
        self.assertEqual(RiskScoringEngine.get_severity(100), "CRITICAL")

    def test_scoring_accumulation(self):
        results = [
            DetectionResult(rule=URL_RULES["URL001"], evidence="IPv4 host"),   # +30
            DetectionResult(rule=URL_RULES["URL003"], evidence="Punycode"),     # +25
            DetectionResult(rule=URL_RULES["URL006"], evidence="HTTP"),         # +10
        ]
        assessment = RiskScoringEngine.evaluate(results)
        self.assertEqual(assessment.score, 65)
        self.assertEqual(assessment.severity, "HIGH")
        self.assertEqual(len(assessment.contributing_factors), 3)

    def test_score_capped_at_100(self):
        # Create many high severity detections
        results = [
            DetectionResult(rule=URL_RULES["URL001"], evidence="IP"),          # 30
            DetectionResult(rule=URL_RULES["URL003"], evidence="Punycode"),    # 25
            DetectionResult(rule=EMAIL_RULES["EMAIL001"], evidence="Mismatch"),# 30
            DetectionResult(rule=EMAIL_RULES["EMAIL004"], evidence="Malware"), # 30
        ]
        assessment = RiskScoringEngine.evaluate(results)
        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.severity, "CRITICAL")

    def test_deduplication_of_rules(self):
        # Trigger same rule twice
        results = [
            DetectionResult(rule=URL_RULES["URL009"], evidence="Keyword login"),
            DetectionResult(rule=URL_RULES["URL009"], evidence="Keyword verify"),
        ]
        assessment = RiskScoringEngine.evaluate(results)
        # Should count score only once
        self.assertEqual(assessment.score, 10)
        self.assertEqual(len(assessment.contributing_factors), 1)


if __name__ == "__main__":
    unittest.main()
