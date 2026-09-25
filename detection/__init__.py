"""Detection package for PhishGuard."""
from detection.rules import Rule, DetectionResult, RuleRegistry, REGISTRY, URL_RULES, EMAIL_RULES
from detection.scoring import RiskAssessment, RiskScoringEngine

__all__ = [
    "Rule",
    "DetectionResult",
    "RuleRegistry",
    "REGISTRY",
    "URL_RULES",
    "EMAIL_RULES",
    "RiskAssessment",
    "RiskScoringEngine",
]
