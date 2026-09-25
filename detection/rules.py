"""
Detection Rules for PhishGuard CLI.

Defines modular, extensible security rules for evaluating URLs, emails,
and infrastructure artifacts using transparent indicators of compromise (IOCs)
and threat heuristics.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any


@dataclass
class Rule:
    """Definition of a detection rule."""
    rule_id: str
    name: str
    description: str
    severity: str  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    score: int
    category: str  # URL, EMAIL, NETWORK


@dataclass
class DetectionResult:
    """The triggered outcome of a detection rule."""
    rule: Rule
    evidence: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "name": self.rule.name,
            "severity": self.rule.severity,
            "score": self.rule.score,
            "description": self.rule.description,
            "evidence": self.evidence,
            "category": self.rule.category,
        }


# Standard URL Detection Rules
URL_RULES: Dict[str, Rule] = {
    "URL001": Rule(
        rule_id="URL001",
        name="IP address used as hostname",
        description="A raw IPv4 or IPv6 address is used instead of a legitimate domain name.",
        severity="HIGH",
        score=30,
        category="URL",
    ),
    "URL002": Rule(
        rule_id="URL002",
        name="Suspicious URL length",
        description="URL exceeds standard threshold (>75 characters), typical of obfuscation or credential tokens.",
        severity="MEDIUM",
        score=15,
        category="URL",
    ),
    "URL003": Rule(
        rule_id="URL003",
        name="Punycode / IDN homograph detected",
        description="Internationalized domain name (punycode 'xn--') detected, commonly used in visual homograph spoofing.",
        severity="HIGH",
        score=25,
        category="URL",
    ),
    "URL004": Rule(
        rule_id="URL004",
        name="Suspicious or non-standard port",
        description="URL connects to a non-standard web port (e.g. 8080, 8443, 8888, 4444, 21, 25).",
        severity="MEDIUM",
        score=15,
        category="URL",
    ),
    "URL005": Rule(
        rule_id="URL005",
        name="Excessive subdomains",
        description="Hostname contains more than 3 subdomain labels, often concealing actual root domain.",
        severity="MEDIUM",
        score=15,
        category="URL",
    ),
    "URL006": Rule(
        rule_id="URL006",
        name="HTTP instead of HTTPS",
        description="Unencrypted HTTP protocol used for transmission.",
        severity="LOW",
        score=10,
        category="URL",
    ),
    "URL007": Rule(
        rule_id="URL007",
        name="Suspicious URL encoding",
        description="URL contains excessive or irregular percent-encoding to evade filters and static scanners.",
        severity="LOW",
        score=10,
        category="URL",
    ),
    "URL008": Rule(
        rule_id="URL008",
        name="Embedded credentials (@ symbol in authority)",
        description="URL contains '@' userinfo symbol in the authority component to mislead human visual inspection.",
        severity="HIGH",
        score=25,
        category="URL",
    ),
    "URL009": Rule(
        rule_id="URL009",
        name="Suspicious phishing keyword",
        description="URL path, subdomain, or query contains security/banking/credential harvest terms.",
        severity="LOW",
        score=10,
        category="URL",
    ),
    "URL010": Rule(
        rule_id="URL010",
        name="Suspicious high-risk TLD",
        description="Domain uses a top-level domain frequently associated with spam, phishing, and disposable abuse.",
        severity="LOW",
        score=10,
        category="URL",
    ),
    "URL011": Rule(
        rule_id="URL011",
        name="IP address obfuscation (Hex/Octal/Dword)",
        description="Hostname contains integer or octal/hex encoded IP address to bypass naive string filters.",
        severity="HIGH",
        score=30,
        category="URL",
    ),
    "URL012": Rule(
        rule_id="URL012",
        name="Double-slash or open redirect path",
        description="URL path contains multiple consecutive slashes or embedded protocol indicators.",
        severity="MEDIUM",
        score=15,
        category="URL",
    ),
    "URL013": Rule(
        rule_id="URL013",
        name="Dangerous or executable file extension",
        description="URL references dangerous downloadable payload (.exe, .scr, .iso, .bat, .vbs, .apk, .dmg).",
        severity="HIGH",
        score=25,
        category="URL",
    ),
    "URL014": Rule(
        rule_id="URL014",
        name="Brand impersonation hyphenation",
        description="Domain contains multiple hyphens mimicking well-known brands (e.g., paypal-verify-login).",
        severity="LOW",
        score=10,
        category="URL",
    ),
}

# Standard Email Detection Rules
EMAIL_RULES: Dict[str, Rule] = {
    "EMAIL001": Rule(
        rule_id="EMAIL001",
        name="Reply-To mismatch",
        description="Reply-To header domain differs from the sender (From) address domain.",
        severity="HIGH",
        score=30,
        category="EMAIL",
    ),
    "EMAIL002": Rule(
        rule_id="EMAIL002",
        name="Suspicious sender display name spoofing",
        description="Sender display name contains an email address different from the actual header sender.",
        severity="HIGH",
        score=25,
        category="EMAIL",
    ),
    "EMAIL003": Rule(
        rule_id="EMAIL003",
        name="Email authentication failure",
        description="SPF, DKIM, or DMARC header verification explicitly reports Fail or SoftFail.",
        severity="HIGH",
        score=25,
        category="EMAIL",
    ),
    "EMAIL004": Rule(
        rule_id="EMAIL004",
        name="Suspicious or dangerous attachment",
        description="Email includes executable, script, macro-enabled, archive, or HTML attachment.",
        severity="HIGH",
        score=30,
        category="EMAIL",
    ),
    "EMAIL005": Rule(
        rule_id="EMAIL005",
        name="Suspicious link in email body",
        description="Email contains IP-based links, deceptive anchor text, or high-risk URLs.",
        severity="MEDIUM",
        score=20,
        category="EMAIL",
    ),
    "EMAIL006": Rule(
        rule_id="EMAIL006",
        name="Phishing urgency or credential keywords",
        description="Subject or body exhibits high-pressure urgency or security account action keywords.",
        severity="LOW",
        score=10,
        category="EMAIL",
    ),
    "EMAIL007": Rule(
        rule_id="EMAIL007",
        name="Missing standard email headers",
        description="Crucial RFC headers like Message-ID or Date are absent or malformed.",
        severity="LOW",
        score=10,
        category="EMAIL",
    ),
    "EMAIL008": Rule(
        rule_id="EMAIL008",
        name="Return-Path domain mismatch",
        description="The Return-Path (envelope sender) domain contradicts the From header domain.",
        severity="MEDIUM",
        score=15,
        category="EMAIL",
    ),
}


class RuleRegistry:
    """Central registry allowing dynamic registration and inspection of rules."""

    def __init__(self):
        self._rules: Dict[str, Rule] = {}
        for r in URL_RULES.values():
            self.register(r)
        for r in EMAIL_RULES.values():
            self.register(r)

    def register(self, rule: Rule) -> None:
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def list_rules(self, category: Optional[str] = None) -> List[Rule]:
        if category:
            return [r for r in self._rules.values() if r.category.upper() == category.upper()]
        return list(self._rules.values())


# Global default registry instance
REGISTRY = RuleRegistry()
