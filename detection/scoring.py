"""
Risk Scoring Engine for PhishGuard CLI.

Calculates transparent, reproducible risk scores from triggered detection rules,
assigns severity ratings, and provides detailed factor breakdowns.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from detection.rules import DetectionResult


@dataclass
class RiskAssessment:
    """Represents the final evaluation and scoring breakdown."""
    score: int
    severity: str
    reasons: List[str]
    contributing_factors: List[Dict[str, Any]]
    results: List[DetectionResult]
    disclaimer: str = (
        "This is an automated risk assessment based on static heuristics and indicators. "
        "It does not constitute definitive proof that the target is malicious, nor does "
        "a low score guarantee safety. Always verify with sandbox analysis and threat intelligence."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "max_score": 100,
            "severity": self.severity,
            "reasons": self.reasons,
            "contributing_factors": self.contributing_factors,
            "detections": [d.to_dict() for d in self.results],
            "disclaimer": self.disclaimer,
        }


class RiskScoringEngine:
    """Computes risk scores from detection rule findings."""

    @staticmethod
    def get_severity(score: int) -> str:
        """Categorizes raw numerical score into standard severity tier."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFORMATIONAL"

    @classmethod
    def evaluate(cls, results: List[DetectionResult]) -> RiskAssessment:
        """
        Calculates cumulative risk score, capping at 100.
        Provides transparent breakdown of contributing factors.
        """
        raw_score = 0
        contributing_factors = []
        reasons = []

        # Deduplicate triggered rules by rule_id if multiple instances fired
        seen_rules = set()
        for res in results:
            rule_id = res.rule.rule_id
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            raw_score += res.rule.score
            contributing_factors.append({
                "rule_id": rule_id,
                "name": res.rule.name,
                "score": res.rule.score,
                "evidence": res.evidence,
            })
            reasons.append(f"[{res.rule.severity}] {res.rule.name}: {res.evidence}")

        final_score = min(100, raw_score)
        severity = cls.get_severity(final_score)

        return RiskAssessment(
            score=final_score,
            severity=severity,
            reasons=reasons,
            contributing_factors=contributing_factors,
            results=results,
        )
