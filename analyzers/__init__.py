"""Analyzers package for PhishGuard."""
from analyzers.url_analyzer import URLAnalyzer, URLComponents
from analyzers.email_analyzer import EmailAnalyzer, EmailComponents, AttachmentInfo
from analyzers.dns_analyzer import DNSAnalyzer, DNSResult
from analyzers.ioc_extractor import IOCExtractor, IOCContainer
from analyzers.report_generator import ReportGenerator

__all__ = [
    "URLAnalyzer",
    "URLComponents",
    "EmailAnalyzer",
    "EmailComponents",
    "AttachmentInfo",
    "DNSAnalyzer",
    "DNSResult",
    "IOCExtractor",
    "IOCContainer",
    "ReportGenerator",
]
