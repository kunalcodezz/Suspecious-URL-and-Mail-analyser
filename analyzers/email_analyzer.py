"""
Email (.eml) Analyzer for PhishGuard CLI.

Performs static analysis of raw MIME email files, parsing headers,
authentication statuses (SPF, DKIM, DMARC), extracting text and HTML content,
identifying attachments and hashes, and running security detection rules.
"""

import email
import email.policy
import hashlib
import os
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Any, Tuple

from detection.rules import EMAIL_RULES, DetectionResult


# High-risk attachment file extensions
DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".application", ".gadget", ".msi", ".msp",
    ".com", ".hta", ".cpl", ".msc", ".jar", ".bat", ".cmd", ".vb",
    ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh",
    ".ps1", ".ps1xml", ".ps2", ".psc1", ".psc2", ".msh", ".msh1",
    ".iso", ".img", ".vhd", ".vhdx", ".docm", ".xlsm", ".pptm",
    ".html", ".htm", ".svg", ".zip", ".rar", ".7z", ".tar", ".gz"
}

# Phishing and urgency phrases in subject / body
EMAIL_URGENCY_KEYWORDS = [
    "urgent", "immediately", "account suspended", "unauthorized access",
    "security alert", "password expired", "action required", "verify your account",
    "wire transfer", "payment failed", "limited time", "suspicious activity",
    "payroll update", "invoice overdue", "confirm identity", "tax refund"
]


class SafeHTMLTextAndLinkExtractor(HTMLParser):
    """
    Safely extracts text and hyperlink targets from HTML without executing scripts.
    Never executes or evaluates embedded JavaScript or external resources.
    """
    def __init__(self):
        super().__init__()
        self.text_parts: List[str] = []
        self.links: List[str] = []
        self.in_script = False
        self.in_style = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        lower_tag = tag.lower()
        if lower_tag in ("script", "noscript"):
            self.in_script = True
        elif lower_tag == "style":
            self.in_style = True
        elif lower_tag == "a":
            for attr, val in attrs:
                if attr.lower() == "href" and val:
                    self.links.append(val.strip())

    def handle_endtag(self, tag: str):
        lower_tag = tag.lower()
        if lower_tag in ("script", "noscript"):
            self.in_script = False
        elif lower_tag == "style":
            self.in_style = False

    def handle_data(self, data: str):
        if not self.in_script and not self.in_style:
            cleaned = data.strip()
            if cleaned:
                self.text_parts.append(cleaned)

    def get_text(self) -> str:
        return " ".join(self.text_parts)


@dataclass
class AttachmentInfo:
    """Metadata regarding an extracted email attachment."""
    filename: str
    extension: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    is_suspicious: bool
    suspicious_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "extension": self.extension,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "is_suspicious": self.is_suspicious,
            "suspicious_reason": self.suspicious_reason,
        }


@dataclass
class EmailComponents:
    """Extracted headers, bodies, authentication results, and components."""
    file_path: str
    sender: str
    sender_domain: str
    reply_to: str
    reply_to_domain: str
    return_path: str
    return_path_domain: str
    recipient: str
    subject: str
    date: str
    message_id: str
    received_headers: List[str]
    spf_result: str
    dkim_result: str
    dmarc_result: str
    plain_text_body: str
    html_body: str
    extracted_urls: List[str]
    extracted_ips: List[str]
    attachments: List[AttachmentInfo]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "reply_to": self.reply_to,
            "reply_to_domain": self.reply_to_domain,
            "return_path": self.return_path,
            "return_path_domain": self.return_path_domain,
            "recipient": self.recipient,
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "received_headers": self.received_headers,
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
            "plain_text_body": self.plain_text_body[:500] + ("..." if len(self.plain_text_body) > 500 else ""),
            "has_html": bool(self.html_body),
            "extracted_urls": self.extracted_urls,
            "extracted_ips": self.extracted_ips,
            "attachments": [a.to_dict() for a in self.attachments],
        }


import email.utils

def extract_email_address_and_domain(header_val: str) -> Tuple[str, str, str]:
    """
    Extracts (display_name, email_address, domain) from standard header value
    using RFC-compliant email.utils.parseaddr.
    """
    if not header_val:
        return "", "", ""
    realname, addr = email.utils.parseaddr(str(header_val))
    addr = addr.strip().lower()
    domain = addr.split("@")[-1] if "@" in addr else ""
    return realname.strip(), addr, domain


def extract_auth_status(headers: List[str], auth_type: str) -> str:
    """
    Parses SPF, DKIM, and DMARC results from Authentication-Results and Received-SPF headers.
    Returns: 'Pass', 'Fail', 'SoftFail', 'Neutral', 'None', or 'Not available'.
    Never invents results.
    """
    auth_type_lower = auth_type.lower()
    
    # 1. Check Authentication-Results headers
    for h in headers:
        # Pattern e.g. dkim=pass, spf=pass, dmarc=fail
        pattern = rf"{auth_type_lower}\s*=\s*([a-zA-Z0-9_\-]+)"
        match = re.search(pattern, h, re.IGNORECASE)
        if match:
            res = match.group(1).capitalize()
            return res

    # 2. Check specific Received-SPF header if SPF was requested
    if auth_type_lower == "spf":
        for h in headers:
            if h.lower().startswith("received-spf:"):
                val = h.split(":", 1)[1].strip()
                first_word = val.split()[0].capitalize()
                return first_word

    return "Not available"


class EmailAnalyzer:
    """Processes .eml files securely and executes email threat detection rules."""

    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB safety limit

    def parse_eml(self, file_path: str) -> EmailComponents:
        """Reads and parses an .eml file safely with standard email library."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Email file not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(f"File size {file_size} bytes exceeds maximum safe limit of 25MB.")

        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)

        sender = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")
        date = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")

        sender_display, sender_addr, sender_domain = extract_email_address_and_domain(sender)
        _, _, reply_to_domain = extract_email_address_and_domain(reply_to)
        _, _, return_path_domain = extract_email_address_and_domain(return_path)

        # Collect Received and Authentication headers
        received_headers: List[str] = []
        auth_headers: List[str] = []
        for key, val in msg.items():
            k_lower = key.lower()
            if k_lower == "received":
                received_headers.append(str(val))
            elif k_lower in ("authentication-results", "received-spf", "dkim-signature"):
                auth_headers.append(f"{key}: {val}")

        spf_result = extract_auth_status(auth_headers, "spf")
        dkim_result = extract_auth_status(auth_headers, "dkim")
        dmarc_result = extract_auth_status(auth_headers, "dmarc")

        plain_text_parts: List[str] = []
        html_parts: List[str] = []
        extracted_urls: List[str] = []
        attachments: List[AttachmentInfo] = []

        # Iterate over MIME parts safely
        for part in msg.walk():
            # Check for attachments
            filename = part.get_filename()
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()

            if filename or content_disposition == "attachment":
                raw_payload = part.get_payload(decode=True) or b""
                safe_name = filename if filename else "unnamed_attachment"
                _, ext = os.path.splitext(safe_name.lower())
                
                md5 = hashlib.md5(raw_payload).hexdigest()
                sha1 = hashlib.sha1(raw_payload).hexdigest()
                sha256 = hashlib.sha256(raw_payload).hexdigest()
                
                is_suspicious = False
                reason = None
                if ext in DANGEROUS_ATTACHMENT_EXTENSIONS:
                    is_suspicious = True
                    reason = f"High-risk file extension '{ext}' commonly abused for malware delivery or credential harvesting."

                attachments.append(AttachmentInfo(
                    filename=safe_name,
                    extension=ext,
                    content_type=content_type,
                    size_bytes=len(raw_payload),
                    md5=md5,
                    sha1=sha1,
                    sha256=sha256,
                    is_suspicious=is_suspicious,
                    suspicious_reason=reason,
                ))
            elif content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")
                    plain_text_parts.append(text)
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    html = payload.decode(charset, errors="replace")
                    html_parts.append(html)
                except Exception:
                    pass

        plain_text_body = "\n".join(plain_text_parts)
        html_body = "\n".join(html_parts)

        # Extract URLs from plain text
        url_regex = r"https?://[^\s<>\"'()]+"
        for match in re.finditer(url_regex, plain_text_body):
            url = match.group(0).rstrip(".,;:)")
            if url not in extracted_urls:
                extracted_urls.append(url)

        # Safely extract URLs from HTML using SafeHTMLTextAndLinkExtractor
        if html_body:
            parser = SafeHTMLTextAndLinkExtractor()
            try:
                parser.feed(html_body)
                for link in parser.links:
                    if link.startswith(("http://", "https://")) and link not in extracted_urls:
                        extracted_urls.append(link)
                # If plain text was missing, use extracted text from HTML
                if not plain_text_body.strip():
                    plain_text_body = parser.get_text()
            except Exception:
                pass

        # Extract IPs from Received headers and body
        ip_regex = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        all_text_for_ips = " ".join(received_headers) + " " + plain_text_body
        raw_ips = re.findall(ip_regex, all_text_for_ips)
        extracted_ips: List[str] = []
        for ip in raw_ips:
            if ip not in extracted_ips and not ip.startswith(("127.", "0.")):
                extracted_ips.append(ip)

        return EmailComponents(
            file_path=file_path,
            sender=sender,
            sender_domain=sender_domain,
            reply_to=reply_to,
            reply_to_domain=reply_to_domain,
            return_path=return_path,
            return_path_domain=return_path_domain,
            recipient=recipient,
            subject=subject,
            date=date,
            message_id=message_id,
            received_headers=received_headers,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            plain_text_body=plain_text_body,
            html_body=html_body,
            extracted_urls=extracted_urls,
            extracted_ips=extracted_ips,
            attachments=attachments,
        )

    def analyze(self, file_path: str) -> Tuple[EmailComponents, List[DetectionResult]]:
        """Parses email and evaluates heuristic security detection rules."""
        comp = self.parse_eml(file_path)
        results: List[DetectionResult] = []

        # EMAIL001: Reply-To mismatch
        if comp.reply_to_domain and comp.sender_domain:
            if comp.reply_to_domain != comp.sender_domain:
                results.append(DetectionResult(
                    rule=EMAIL_RULES["EMAIL001"],
                    evidence=(
                        f"Reply-To domain '{comp.reply_to_domain}' does not match "
                        f"From domain '{comp.sender_domain}'."
                    )
                ))

        # EMAIL002: Sender display name spoofing
        # E.g. From: "PayPal Security <hacker@suspicious-server.com>"
        if '"' in comp.sender or "<" in comp.sender:
            name_part = comp.sender.split("<")[0]
            embedded_emails = re.findall(r"[\w\.-]+@([\w\.-]+)", name_part)
            if embedded_emails:
                spoofed_domain = embedded_emails[0].lower()
                if spoofed_domain != comp.sender_domain:
                    results.append(DetectionResult(
                        rule=EMAIL_RULES["EMAIL002"],
                        evidence=(
                            f"Display name references domain '{spoofed_domain}' "
                            f"which differs from actual sender '{comp.sender_domain}'."
                        )
                    ))

        # EMAIL003: Authentication failure (SPF/DKIM/DMARC)
        failures = []
        for auth_name, res in [("SPF", comp.spf_result), ("DKIM", comp.dkim_result), ("DMARC", comp.dmarc_result)]:
            if res.lower() in ["fail", "softfail", "permerror"]:
                failures.append(f"{auth_name} ({res})")

        if failures:
            results.append(DetectionResult(
                rule=EMAIL_RULES["EMAIL003"],
                evidence=f"Explicit authentication verification failure: {', '.join(failures)}."
            ))

        # EMAIL004: Suspicious attachment
        suspicious_attachments = [a for a in comp.attachments if a.is_suspicious]
        if suspicious_attachments:
            names = ", ".join(f"{a.filename} ({a.extension})" for a in suspicious_attachments)
            results.append(DetectionResult(
                rule=EMAIL_RULES["EMAIL004"],
                evidence=f"Contains potentially dangerous attachment(s): {names}."
            ))

        # EMAIL005: Suspicious link in body
        suspicious_links = []
        for url in comp.extracted_urls:
            # Check for raw IP address in URL host
            host_match = re.search(r"https?://([^/:\s]+)", url)
            if host_match:
                host = host_match.group(1)
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                    suspicious_links.append(f"IP-based URL: {url}")
                elif "xn--" in host.lower():
                    suspicious_links.append(f"Punycode URL: {url}")
        
        if suspicious_links:
            results.append(DetectionResult(
                rule=EMAIL_RULES["EMAIL005"],
                evidence=f"Suspicious links detected: {'; '.join(suspicious_links[:3])}."
            ))

        # EMAIL006: Phishing urgency keywords
        content_to_check = (comp.subject + " " + comp.plain_text_body).lower()
        matched_urgency = [kw for kw in EMAIL_URGENCY_KEYWORDS if kw in content_to_check]
        if len(matched_urgency) >= 2:
            results.append(DetectionResult(
                rule=EMAIL_RULES["EMAIL006"],
                evidence=f"Detected urgent phishing sentiment keywords: {', '.join(matched_urgency[:4])}."
            ))

        # EMAIL007: Missing standard headers
        missing = []
        if not comp.message_id:
            missing.append("Message-ID")
        if not comp.date:
            missing.append("Date")
        if missing:
            results.append(DetectionResult(
                rule=EMAIL_RULES["EMAIL007"],
                evidence=f"Missing essential RFC headers: {', '.join(missing)}."
            ))

        # EMAIL008: Return-Path mismatch
        if comp.return_path_domain and comp.sender_domain:
            if comp.return_path_domain != comp.sender_domain:
                results.append(DetectionResult(
                    rule=EMAIL_RULES["EMAIL008"],
                    evidence=(
                        f"Return-Path domain '{comp.return_path_domain}' "
                        f"differs from sender domain '{comp.sender_domain}'."
                    )
                ))

        return comp, results
