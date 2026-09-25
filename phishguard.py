#!/usr/bin/env python3
"""
PhishGuard CLI - Phishing URL & Email Analyzer
Designed for SOC Analysts and Cybersecurity Students.

Terminal-based defensive cybersecurity analysis tool providing local static analysis,
transparent heuristic risk scoring, IOC extraction, DNS querying, and optional threat intel.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, Optional, List

# Load environment variables early
from dotenv import load_dotenv
load_dotenv()

# Rich and Colorama terminal formatting
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

from analyzers.url_analyzer import URLAnalyzer
from analyzers.email_analyzer import EmailAnalyzer
from analyzers.dns_analyzer import DNSAnalyzer
from analyzers.ioc_extractor import IOCExtractor, IOCContainer
from analyzers.report_generator import ReportGenerator
from detection.rules import REGISTRY
from detection.scoring import RiskScoringEngine, RiskAssessment
from threat_intel.virustotal import VirusTotalClient
from threat_intel.urlhaus import URLhausClient
from threat_intel.abuseipdb import AbuseIPDBClient


# ─── Additional Rich imports for enhanced UI ───
if HAS_RICH:
    from rich.columns import Columns
    from rich.align import Align
    from rich.rule import Rule
    from rich.markup import escape
    from rich.style import Style
    from rich.padding import Padding
    from rich import box
    import time as _time


# ─── Version & metadata ───
__version__ = "1.0.0"
__codename__ = "Sentinel"


# ─── ASCII Art Logo ───
LOGO_ART = r"""
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""

SHIELD_ART = r"""
         ┌──────────────────┐
         │   ╔════════════╗ │
         │   ║  ██  ████  ║ │
         │   ║  ██  ████  ║ │
         │   ║  ██████████║ │
         │   ║  ██  ████  ║ │
         │   ║  ██  ████  ║ │
         │   ╚════════════╝ │
         └────────┬─────────┘
                  │
                  ▼
"""


def _get_threat_intel_status() -> tuple:
    """Check which threat intel APIs are configured."""
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    uh_key = os.environ.get("URLHAUS_API_KEY", "") or "configured"  # URLhaus is free
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    configured = sum(1 for k in [vt_key, abuse_key] if k) + 1  # URLhaus always available
    return configured, 3


# Terminal print helpers
def print_banner():
    """Display the startup banner with rich formatting or plain text fallback."""
    if HAS_RICH:
        console.clear()
        console.print()

        # ── Gradient ASCII logo ──
        logo_lines = LOGO_ART.strip("\n").split("\n")
        gradient_colors = [
            "#00ffff", "#00e5ff", "#00ccff", "#00b3ff",
            "#0099ff", "#0080ff", "#0066ff",
        ]
        for i, line in enumerate(logo_lines):
            color = gradient_colors[i % len(gradient_colors)]
            console.print(Align.center(Text(line, style=Style(color=color, bold=True))))

        console.print()

        # ── Subtitle tagline ──
        tagline = Text()
        tagline.append("⚡ ", style="bold yellow")
        tagline.append("Phishing Threat Analyzer", style="bold white")
        tagline.append("  •  ", style="dim")
        tagline.append("Designed for SOC Analysts & Cybersecurity Students", style="italic dim cyan")
        console.print(Align.center(tagline))
        console.print()

        # ── Status bar ──
        ti_configured, ti_total = _get_threat_intel_status()
        ti_color = "green" if ti_configured == ti_total else ("yellow" if ti_configured > 0 else "red")
        ti_icon = "●" if ti_configured == ti_total else ("◐" if ti_configured > 0 else "○")

        status_parts = Text()
        status_parts.append(f"  v{__version__} ", style="bold cyan")
        status_parts.append(f'"{__codename__}"', style="italic dim")
        status_parts.append("  │  ", style="dim")
        status_parts.append("Engine: ", style="dim")
        status_parts.append("● ACTIVE", style="bold green")
        status_parts.append("  │  ", style="dim")
        status_parts.append("Threat Intel: ", style="dim")
        status_parts.append(f"{ti_icon} {ti_configured}/{ti_total} APIs", style=f"bold {ti_color}")
        status_parts.append("  │  ", style="dim")
        status_parts.append("Rules: ", style="dim")
        try:
            rule_count = len(REGISTRY.list_rules())
        except Exception:
            rule_count = "?"
        status_parts.append(f"{rule_count} loaded", style="bold white")
        status_parts.append("  ", style="")

        console.print(Panel(
            Align.center(status_parts),
            border_style="dim cyan",
            box=box.HEAVY,
            padding=(0, 1),
        ))
        console.print()
    else:
        # ── Plain text fallback ──
        print("\n" + "=" * 70)
        print(LOGO_ART)
        print(f"  PhishGuard CLI v{__version__} \"{__codename__}\"")
        print("  Phishing Threat Analyzer for SOC Analysts")
        print("=" * 70)
        print()


def _print_menu_rich():
    """Display the interactive menu using Rich tables and styling."""
    menu_table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold bright_white on grey23",
        title="[bold bright_white]  MAIN MENU[/bold bright_white]",
        title_style="bold bright_white",
        padding=(0, 2),
        expand=False,
        min_width=62,
    )
    menu_table.add_column("#", style="bold", justify="center", width=4)
    menu_table.add_column("Action", style="bold bright_white", width=28)
    menu_table.add_column("Description", style="dim", width=38)

    menu_items = [
        ("1", "🔗  Analyze URL",           "Decompose, score & detect phishing URLs"),
        ("2", "📧  Analyze Email",         "Parse .eml files for threats & IOCs"),
        ("3", "🔍  Extract IOCs",          "Pull indicators from text or files"),
        ("4", "📋  Detection Rules",       "View all active heuristic rules"),
        ("5", "💾  Export Report",         "Save analysis to TXT & JSON"),
        ("6", "🚪  Exit",                  "Quit PhishGuard"),
    ]

    colors = ["bold cyan", "bold magenta", "bold yellow", "bold blue", "bold green", "bold red"]

    for (num, action, desc), color in zip(menu_items, colors):
        menu_table.add_row(
            Text(num, style=color),
            Text.from_markup(action),
            desc,
        )

    console.print(Align.center(menu_table))
    console.print()


def _print_menu_plain():
    """Display the interactive menu as plain text."""
    print("┌─────────────────────────────────────────┐")
    print("│              MAIN  MENU                 │")
    print("├────┬────────────────────────────────────┤")
    print("│ 1  │  Analyze URL                       │")
    print("│ 2  │  Analyze Email (.eml)              │")
    print("│ 3  │  Extract IOCs                      │")
    print("│ 4  │  View Detection Rules              │")
    print("│ 5  │  Export Report                     │")
    print("│ 6  │  Exit                              │")
    print("└────┴────────────────────────────────────┘")
    print()


def _prompt_input(prompt_text: str) -> str:
    """Styled input prompt."""
    if HAS_RICH:
        console.print(
            Text.assemble(
                ("  ❯ ", "bold cyan"),
                (prompt_text, "bold white"),
            ),
            end="",
        )
        return input("").strip()
    else:
        return input(f"  > {prompt_text}").strip()


def _print_farewell():
    """Display a styled exit message."""
    if HAS_RICH:
        console.print()
        farewell = Text()
        farewell.append("\n  🛡️  ", style="")
        farewell.append("Stay vigilant. Stay secure.", style="bold cyan")
        farewell.append("\n  ", style="")
        farewell.append("Thank you for using PhishGuard.", style="dim italic")
        farewell.append("\n", style="")
        console.print(Panel(
            Align.center(farewell),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(0, 2),
        ))
        console.print()
    else:
        print("\n  Stay vigilant. Stay secure.")
        print("  Thank you for using PhishGuard.\n")


def _print_error(message: str):
    """Print a styled error message."""
    if HAS_RICH:
        console.print(f"  [bold red]✘[/bold red]  {message}")
    else:
        print(f"  [!] {message}")


def _print_success(message: str):
    """Print a styled success message."""
    if HAS_RICH:
        console.print(f"  [bold green]✔[/bold green]  {message}")
    else:
        print(f"  [+] {message}")


def _print_info(message: str):
    """Print a styled info message."""
    if HAS_RICH:
        console.print(f"  [bold cyan]ℹ[/bold cyan]  {message}")
    else:
        print(f"  [*] {message}")


def _wait_for_enter():
    """Styled 'press enter to continue' prompt."""
    if HAS_RICH:
        console.print()
        console.print("  [dim italic]Press Enter to return to menu...[/dim italic]", end="")
        input("")
    else:
        input("\n  Press Enter to return to menu...")


def print_section_header(title: str):
    if HAS_RICH:
        console.print()
        console.print(Rule(f"[bold bright_white] {title} [/bold bright_white]", style="cyan", align="center"))
        console.print()
    else:
        separator = "=" * 40
        print(f"\n{separator}\n{title}\n{separator}\n")


def print_sub_header(title: str):
    if HAS_RICH:
        console.print()
        console.print(Rule(f"[bold] {title} [/bold]", style="dim cyan", align="left"))
        console.print()
    else:
        separator = "-" * 40
        print(f"\n{separator}\n{title}\n{separator}\n")


def format_severity(severity: str) -> str:
    color_map = {
        "CRITICAL": "[bold red]" if HAS_RICH else "",
        "HIGH": "[bold red]" if HAS_RICH else "",
        "MEDIUM": "[bold yellow]" if HAS_RICH else "",
        "LOW": "[bold blue]" if HAS_RICH else "",
        "INFORMATIONAL": "[dim]" if HAS_RICH else "",
    }
    end_tag = "[/]" if HAS_RICH else ""
    return f"{color_map.get(severity, '')}{severity}{end_tag}"


def print_detection_results(assessment: RiskAssessment):
    print_sub_header("DETECTION RESULTS")
    if not assessment.results:
        _print_info("No suspicious detection rules triggered.")
    else:
        for res in assessment.results:
            sev_tag = f"[{res.rule.severity}]"
            if HAS_RICH:
                color = "red" if res.rule.severity in ("HIGH", "CRITICAL") else ("yellow" if res.rule.severity == "MEDIUM" else "blue")
                console.print(f"  [{color}]▸ [{res.rule.severity}][/{color}] [bold]{res.rule.name}[/bold]")
                console.print(f"           Evidence: {res.evidence}")
            else:
                print(f"{sev_tag} {res.rule.name}")
                print(f"       Evidence: {res.evidence}")

    print_sub_header("RISK ASSESSMENT")

    # Rich risk score bar
    if HAS_RICH:
        score = assessment.score
        bar_width = 30
        filled = int(score / 100 * bar_width)
        if score >= 70:
            bar_color = "bold red"
            score_style = "bold red"
        elif score >= 40:
            bar_color = "bold yellow"
            score_style = "bold yellow"
        else:
            bar_color = "bold green"
            score_style = "bold green"
        bar = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * (bar_width - filled)}[/dim]"
        console.print(f"  Risk Score  {bar}  [{score_style}]{score}/100[/{score_style}]")
        console.print(f"  Severity    {format_severity(assessment.severity)}")
    else:
        print(f"Risk Score : {assessment.score}/100")
        print(f"Severity   : {assessment.severity}")

    print("\nReason:")
    if assessment.results:
        print("Multiple suspicious indicators were detected.")
    else:
        print("No immediate heuristic threat indicators detected.")

    print("\nContributing factors:")
    if not assessment.contributing_factors:
        print("None (+0)")
    else:
        for factor in assessment.contributing_factors:
            print(f"  {factor['rule_id']:<8} +{factor['score']:<3} ({factor['name']})")

    print(f"\n[NOTE] {assessment.disclaimer}")


def run_optional_threat_intel(target_type: str, target: str) -> Dict[str, Any]:
    """Runs configured Threat Intelligence APIs with clear feedback."""
    vt = VirusTotalClient()
    uh = URLhausClient()
    abuse = AbuseIPDBClient()
    ti_results = {}

    print_sub_header("THREAT INTELLIGENCE")

    # VirusTotal
    if not vt.is_configured():
        _print_info("VirusTotal lookup skipped. API key not configured.")
        ti_results["virustotal"] = {"status": "skipped", "message": "API key not configured."}
    else:
        _print_info(f"Querying VirusTotal for {target}...")
        if target_type == "url":
            res = vt.check_url(target)
        elif target_type == "ip":
            res = vt.check_ip(target)
        else:
            res = vt.check_domain(target)
        ti_results["virustotal"] = res
        _print_ti_result("VirusTotal", res)

    # URLhaus (URLs and Hosts)
    if target_type in ("url", "domain"):
        if not uh.is_configured():
            _print_info("URLhaus lookup skipped. API key not configured.")
            ti_results["urlhaus"] = {"status": "skipped", "message": "API key not configured."}
        else:
            _print_info(f"Querying URLhaus for {target}...")
            res = uh.check_url(target) if target_type == "url" else uh.check_host(target)
            ti_results["urlhaus"] = res
            _print_ti_result("URLhaus", res)

    # AbuseIPDB (IPs only)
    if target_type == "ip":
        if not abuse.is_configured():
            _print_info("AbuseIPDB lookup skipped. API key not configured.")
            ti_results["abuseipdb"] = {"status": "skipped", "message": "API key not configured."}
        else:
            _print_info(f"Querying AbuseIPDB for {target}...")
            res = abuse.check_ip(target)
            ti_results["abuseipdb"] = res
            _print_ti_result("AbuseIPDB", res)

    return ti_results


def _print_ti_result(provider: str, res: Dict[str, Any]):
    status = res.get("status")
    if status == "success":
        _print_success(f"{provider} Results:")
        for k, v in res.items():
            if k not in ("status", "provider", "target"):
                print(f"      {k}: {v}")
    elif status == "not_found":
        _print_info(f"{provider}: Not found in threat intelligence database.")
    elif status == "error":
        _print_error(f"{provider} Error: {res.get('message')}")


def run_dns_lookup(domain: str) -> Dict[str, Any]:
    """Runs DNS lookups for domain."""
    dns_analyzer = DNSAnalyzer()
    dns_res = dns_analyzer.query(domain)

    print_sub_header("DNS INFORMATION")

    if HAS_RICH:
        dns_table = Table(box=box.SIMPLE_HEAVY, border_style="dim cyan", show_header=True, header_style="bold cyan")
        dns_table.add_column("Record Type", style="bold yellow", width=12)
        dns_table.add_column("Values", style="white")

        def _fmt_records(records):
            return "\n".join(records) if records else "[dim]Not available[/dim]"

        dns_table.add_row("A", _fmt_records(dns_res.a_records))
        dns_table.add_row("AAAA", _fmt_records(dns_res.aaaa_records))
        dns_table.add_row("MX", _fmt_records(dns_res.mx_records))
        dns_table.add_row("NS", _fmt_records(dns_res.ns_records))
        dns_table.add_row("TXT", _fmt_records(dns_res.txt_records))
        console.print(dns_table)
    else:
        print("A:")
        if dns_res.a_records:
            for r in dns_res.a_records:
                print(f"  {r}")
        else:
            print("  Not available")

        print("\nAAAA:")
        if dns_res.aaaa_records:
            for r in dns_res.aaaa_records:
                print(f"  {r}")
        else:
            print("  Not available")

        print("\nMX:")
        if dns_res.mx_records:
            for r in dns_res.mx_records:
                print(f"  {r}")
        else:
            print("  Not available")

        print("\nNS:")
        if dns_res.ns_records:
            for r in dns_res.ns_records:
                print(f"  {r}")
        else:
            print("  Not available")

        print("\nTXT:")
        if dns_res.txt_records:
            for r in dns_res.txt_records:
                print(f"  {r}")
        else:
            print("  Not available")

    return dns_res.to_dict()


def handle_url_analysis(raw_url: str, run_dns: bool = False, run_ti: bool = False, auto_export: bool = False, json_mode: bool = False) -> Dict[str, Any]:
    """Coordinates URL analysis workflow."""
    analyzer = URLAnalyzer()
    comp, detection_results = analyzer.analyze(raw_url)
    assessment = RiskScoringEngine.evaluate(detection_results)

    # Extract IOCs from the URL itself
    iocs = IOCExtractor.extract_from_text(raw_url).to_dict()

    dns_info = None
    if run_dns and not comp.is_ip and comp.domain:
        dns_info = run_dns_lookup(comp.domain)

    ti_info = None
    if run_ti:
        target_type = "ip" if comp.is_ip else "url"
        ti_info = run_optional_threat_intel(target_type, raw_url)

    output_data = {
        "analysis_type": "url",
        "target": raw_url,
        "extracted_information": comp.to_dict(),
        "detections": [d.to_dict() for d in detection_results],
        "risk_assessment": assessment.to_dict(),
        "iocs": iocs,
        "dns_information": dns_info or {},
        "threat_intelligence": ti_info or {},
    }

    if json_mode:
        print(json.dumps(output_data, indent=2))
        return output_data

    # Print formatted output
    print_section_header("URL ANALYSIS")

    if HAS_RICH:
        url_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), border_style="dim")
        url_table.add_column("Field", style="bold cyan", width=14)
        url_table.add_column("Value", style="white")
        url_table.add_row("URL", f"[bold]{comp.raw_url}[/bold]")
        url_table.add_row("Scheme", comp.scheme)
        url_table.add_row("Host", comp.host)
        url_table.add_row("Domain", comp.domain or "N/A")
        url_table.add_row("Subdomain", comp.subdomain or "None")
        url_table.add_row("TLD", comp.tld or "N/A")
        url_table.add_row("Port", str(comp.port))
        url_table.add_row("Path", comp.path)
        url_table.add_row("URL Length", str(comp.length))
        if comp.query:
            url_table.add_row("Query Params", comp.query)
        console.print(url_table)
    else:
        print(f"URL:\n{comp.raw_url}\n")
        print(f"Scheme       : {comp.scheme}")
        print(f"Host         : {comp.host}")
        print(f"Domain       : {comp.domain or 'N/A'}")
        print(f"Subdomain    : {comp.subdomain or 'None'}")
        print(f"TLD          : {comp.tld or 'N/A'}")
        print(f"Port         : {comp.port}")
        print(f"Path         : {comp.path}")
        print(f"URL Length   : {comp.length}")
        if comp.query:
            print(f"Query Params : {comp.query}")

    print_detection_results(assessment)

    if auto_export:
        txt_path, json_path = ReportGenerator.generate(
            analysis_type="url",
            target=raw_url,
            extracted_info=comp.to_dict(),
            detection_results=[d.to_dict() for d in detection_results],
            risk_assessment=assessment.to_dict(),
            iocs=iocs,
            dns_info=dns_info,
            threat_intel=ti_info,
        )
        _print_success(f"Report exported to:\n    - {txt_path}\n    - {json_path}")

    return output_data


def handle_email_analysis(file_path: str, run_ti: bool = False, auto_export: bool = False, json_mode: bool = False) -> Optional[Dict[str, Any]]:
    """Coordinates .eml file analysis workflow."""
    if not os.path.exists(file_path):
        _print_error(f"File '{file_path}' does not exist.")
        return None

    analyzer = EmailAnalyzer()
    try:
        comp, detection_results = analyzer.analyze(file_path)
    except Exception as e:
        _print_error(f"Analysis failed: {str(e)}")
        return None

    assessment = RiskScoringEngine.evaluate(detection_results)

    # Extract all IOCs from body + urls + ips + attachments
    all_content_for_iocs = (
        f"{comp.sender} {comp.reply_to} {comp.subject} {comp.plain_text_body} "
        f"{' '.join(comp.extracted_urls)} {' '.join(comp.extracted_ips)} "
        f"{' '.join(a.sha256 for a in comp.attachments)}"
    )
    iocs = IOCExtractor.extract_from_text(all_content_for_iocs).to_dict()

    ti_info = None
    if run_ti and comp.sender_domain:
        ti_info = run_optional_threat_intel("domain", comp.sender_domain)

    output_data = {
        "analysis_type": "email",
        "target": file_path,
        "extracted_information": comp.to_dict(),
        "detections": [d.to_dict() for d in detection_results],
        "risk_assessment": assessment.to_dict(),
        "iocs": iocs,
        "threat_intelligence": ti_info or {},
    }

    if json_mode:
        print(json.dumps(output_data, indent=2))
        return output_data

    print_section_header("EMAIL ANALYSIS")

    if HAS_RICH:
        email_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), border_style="dim")
        email_table.add_column("Field", style="bold cyan", width=12)
        email_table.add_column("Value", style="white")
        email_table.add_row("File", comp.file_path)
        email_table.add_row("From", comp.sender or "Not available")
        email_table.add_row("Reply-To", comp.reply_to or "Not specified")
        email_table.add_row("To", comp.recipient or "Not available")
        email_table.add_row("Subject", f"[bold]{comp.subject or '(No Subject)'}[/bold]")
        email_table.add_row("Date", comp.date or "Not available")
        email_table.add_row("Message-ID", comp.message_id or "Not available")
        console.print(email_table)
    else:
        print(f"File      : {comp.file_path}")
        print(f"From      : {comp.sender or 'Not available'}")
        print(f"Reply-To  : {comp.reply_to or 'Not specified'}")
        print(f"To        : {comp.recipient or 'Not available'}")
        print(f"Subject   : {comp.subject or '(No Subject)'}")
        print(f"Date      : {comp.date or 'Not available'}")
        print(f"Message-ID: {comp.message_id or 'Not available'}")

    print_sub_header("AUTHENTICATION")
    if HAS_RICH:
        def _auth_status(val):
            val_lower = (val or "").lower()
            if "pass" in val_lower:
                return f"[bold green]✔ {val}[/bold green]"
            elif "fail" in val_lower:
                return f"[bold red]✘ {val}[/bold red]"
            return f"[dim]{val}[/dim]"
        console.print(f"  SPF   : {_auth_status(comp.spf_result)}")
        console.print(f"  DKIM  : {_auth_status(comp.dkim_result)}")
        console.print(f"  DMARC : {_auth_status(comp.dmarc_result)}")
    else:
        print(f"SPF   : {comp.spf_result}")
        print(f"DKIM  : {comp.dkim_result}")
        print(f"DMARC : {comp.dmarc_result}")

    print_sub_header("EXTRACTED URLS")
    if comp.extracted_urls:
        for idx, u in enumerate(comp.extracted_urls, 1):
            print(f"{idx}. {u}")
    else:
        _print_info("None detected.")

    print_sub_header("ATTACHMENTS")
    if comp.attachments:
        for a in comp.attachments:
            if HAS_RICH:
                risk_tag = " [bold red][HIGH RISK][/bold red]" if a.is_suspicious else ""
                console.print(f"  [bold]•[/bold] {a.filename} ({a.content_type}, {a.size_bytes} bytes){risk_tag}")
                console.print(f"      SHA256: [dim]{a.sha256}[/dim]")
                if a.suspicious_reason:
                    console.print(f"      [bold yellow]Alert: {a.suspicious_reason}[/bold yellow]")
            else:
                susp_flag = " [!] HIGH RISK" if a.is_suspicious else ""
                print(f"- {a.filename} ({a.content_type}, {a.size_bytes} bytes){susp_flag}")
                print(f"    SHA256: {a.sha256}")
                if a.suspicious_reason:
                    print(f"    Alert : {a.suspicious_reason}")
    else:
        _print_info("None detected.")

    print_detection_results(assessment)

    if auto_export:
        txt_path, json_path = ReportGenerator.generate(
            analysis_type="email",
            target=file_path,
            extracted_info=comp.to_dict(),
            detection_results=[d.to_dict() for d in detection_results],
            risk_assessment=assessment.to_dict(),
            iocs=iocs,
            threat_intel=ti_info,
        )
        _print_success(f"Report exported to:\n    - {txt_path}\n    - {json_path}")

    return output_data


def handle_ioc_extraction(target_input: str, export_format: Optional[str] = None, defang: bool = False, json_mode: bool = False):
    """Extracts and formats IOCs from text or file input."""
    # Check if target_input is a valid file
    if os.path.isfile(target_input):
        try:
            with open(target_input, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(5 * 1024 * 1024)  # 5MB max
        except Exception as e:
            _print_error(f"Could not read file: {e}")
            return
    else:
        content = target_input

    iocs = IOCExtractor.extract_from_text(content)

    if json_mode:
        print(iocs.to_json(defang=defang))
        return

    print_section_header("IOC EXTRACTION")

    if HAS_RICH:
        console.print(f"  Total IOCs Identified: [bold cyan]{iocs.total_count()}[/bold cyan]\n")
    else:
        print(f"Total IOCs Identified: {iocs.total_count()}\n")

    dict_repr = iocs.to_dict(defang=defang)

    for cat in ["urls", "domains", "ipv4", "ipv6", "emails", "sha256", "sha1", "md5"]:
        items = dict_repr.get(cat, [])
        if items:
            header_title = cat.upper()
            if HAS_RICH:
                console.print(f"  [bold yellow]{header_title}:[/bold yellow]")
                for item in items:
                    console.print(f"    [dim]•[/dim] {item}")
                console.print()
            else:
                print(f"{header_title}:")
                for item in items:
                    print(f"- {item}")
                print("")

    if export_format:
        fmt = export_format.lower()
        if fmt == "json":
            exported = iocs.to_json(defang=defang)
        elif fmt == "csv":
            exported = iocs.to_csv(defang=defang)
        else:
            exported = iocs.to_txt(defang=defang)

        out_path = f"iocs_extracted.{fmt}"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(exported)
        _print_success(f"IOCs exported successfully to: {out_path}")


def view_detection_rules():
    """Displays all detection rules configured in the engine."""
    print_section_header("PHISHGUARD DETECTION RULES")
    rules = REGISTRY.list_rules()

    if HAS_RICH:
        table = Table(
            title="[bold bright_white]Security Detection Rules[/bold bright_white]",
            header_style="bold cyan on grey23",
            box=box.ROUNDED,
            border_style="cyan",
            padding=(0, 1),
        )
        table.add_column("Rule ID", style="bold yellow", width=10)
        table.add_column("Category", width=8)
        table.add_column("Severity", width=12)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Rule Name", style="bold", width=30)
        table.add_column("Description")

        for r in rules:
            table.add_row(
                r.rule_id,
                r.category,
                format_severity(r.severity),
                f"+{r.score}",
                r.name,
                r.description
            )
        console.print(table)
    else:
        print(f"{'Rule ID':<10} {'Category':<8} {'Severity':<14} {'Score':<6} {'Name'}")
        print("-" * 75)
        for r in rules:
            print(f"{r.rule_id:<10} {r.category:<8} {r.severity:<14} +{r.score:<5} {r.name}")
            print(f"   -> {r.description}\n")


def interactive_menu():
    """Runs the main terminal interactive loop with enhanced UI."""
    last_analysis = None

    while True:
        print_banner()

        if HAS_RICH:
            _print_menu_rich()
        else:
            _print_menu_plain()

        try:
            choice = _prompt_input("Select an option [1-6]: ")
        except (KeyboardInterrupt, EOFError):
            _print_farewell()
            sys.exit(0)

        if choice == "1":
            print_section_header("🔗 URL ANALYSIS")
            try:
                url_input = _prompt_input("Enter URL: ")
            except (KeyboardInterrupt, EOFError):
                continue
            if not url_input:
                _print_error("URL cannot be empty.")
                _wait_for_enter()
                continue

            # Ask for optional DNS check
            do_dns = _prompt_input("Perform DNS resolution? [y/N]: ").lower() == "y"
            do_ti = _prompt_input("Query Threat Intelligence APIs? [y/N]: ").lower() == "y"

            if HAS_RICH:
                with console.status("[bold cyan]Analyzing URL...[/bold cyan]", spinner="dots"):
                    last_analysis = handle_url_analysis(
                        raw_url=url_input,
                        run_dns=do_dns,
                        run_ti=do_ti,
                        auto_export=False,
                        json_mode=False
                    )
            else:
                last_analysis = handle_url_analysis(
                    raw_url=url_input,
                    run_dns=do_dns,
                    run_ti=do_ti,
                    auto_export=False,
                    json_mode=False
                )

            # Export report prompt
            do_export = _prompt_input("Export report? [y/N]: ").lower()
            if do_export == "y":
                txt_p, json_p = ReportGenerator.generate(
                    analysis_type="url",
                    target=url_input,
                    extracted_info=last_analysis["extracted_information"],
                    detection_results=last_analysis["detections"],
                    risk_assessment=last_analysis["risk_assessment"],
                    iocs=last_analysis["iocs"],
                    dns_info=last_analysis.get("dns_information"),
                    threat_intel=last_analysis.get("threat_intelligence"),
                )
                _print_success(f"Report exported:\n    - {txt_p}\n    - {json_p}")

            _wait_for_enter()

        elif choice == "2":
            print_section_header("📧 EMAIL ANALYSIS")
            try:
                eml_path = _prompt_input("Enter path to .eml file: ").strip('"\'')
            except (KeyboardInterrupt, EOFError):
                continue
            if not eml_path:
                _print_error("Path cannot be empty.")
                _wait_for_enter()
                continue

            do_ti = _prompt_input("Query Threat Intelligence APIs? [y/N]: ").lower() == "y"

            if HAS_RICH:
                with console.status("[bold magenta]Analyzing email...[/bold magenta]", spinner="dots"):
                    last_analysis = handle_email_analysis(
                        file_path=eml_path,
                        run_ti=do_ti,
                        auto_export=False,
                        json_mode=False
                    )
            else:
                last_analysis = handle_email_analysis(
                    file_path=eml_path,
                    run_ti=do_ti,
                    auto_export=False,
                    json_mode=False
                )

            if last_analysis:
                do_export = _prompt_input("Export report? [y/N]: ").lower()
                if do_export == "y":
                    txt_p, json_p = ReportGenerator.generate(
                        analysis_type="email",
                        target=eml_path,
                        extracted_info=last_analysis["extracted_information"],
                        detection_results=last_analysis["detections"],
                        risk_assessment=last_analysis["risk_assessment"],
                        iocs=last_analysis["iocs"],
                        threat_intel=last_analysis.get("threat_intelligence"),
                    )
                    _print_success(f"Report exported:\n    - {txt_p}\n    - {json_p}")

            _wait_for_enter()

        elif choice == "3":
            print_section_header("🔍 IOC EXTRACTION")
            try:
                target_ioc = _prompt_input("Enter text, URL, or path to file: ").strip('"\'')
            except (KeyboardInterrupt, EOFError):
                continue
            if not target_ioc:
                _print_error("Input cannot be empty.")
                _wait_for_enter()
                continue

            do_defang = _prompt_input("Defang extracted IOCs? [y/N]: ").lower() == "y"
            handle_ioc_extraction(target_ioc, defang=do_defang)

            exp_opt = _prompt_input("Export IOCs? [1] JSON  [2] CSV  [3] TXT  [4] Skip: ")
            fmt_map = {"1": "json", "2": "csv", "3": "txt"}
            if exp_opt in fmt_map:
                handle_ioc_extraction(target_ioc, export_format=fmt_map[exp_opt], defang=do_defang)

            _wait_for_enter()

        elif choice == "4":
            view_detection_rules()
            _wait_for_enter()

        elif choice == "5":
            print_section_header("💾 EXPORT REPORT")
            if not last_analysis:
                _print_error("No active analysis in current session to export.")
                _print_info("Checking existing saved reports in 'reports/' directory...")
                if os.path.exists("reports"):
                    files = os.listdir("reports")
                    if files:
                        if HAS_RICH:
                            console.print("  [bold]Saved reports:[/bold]")
                            for f in sorted(files):
                                console.print(f"    [dim]📄[/dim] reports/{f}")
                        else:
                            print("Saved reports:")
                            for f in sorted(files):
                                print(f"  - reports/{f}")
                    else:
                        _print_info("No reports generated yet.")
                else:
                    _print_info("No reports directory found.")
            else:
                txt_p, json_p = ReportGenerator.generate(
                    analysis_type=last_analysis.get("analysis_type", "general"),
                    target=last_analysis.get("target", "target"),
                    extracted_info=last_analysis.get("extracted_information", {}),
                    detection_results=last_analysis.get("detections", []),
                    risk_assessment=last_analysis.get("risk_assessment", {}),
                    iocs=last_analysis.get("iocs", {}),
                    dns_info=last_analysis.get("dns_information"),
                    threat_intel=last_analysis.get("threat_intelligence"),
                )
                _print_success(f"Active session report exported:\n    - {txt_p}\n    - {json_p}")

            _wait_for_enter()

        elif choice == "6":
            _print_farewell()
            sys.exit(0)

        else:
            _print_error("Invalid selection. Please choose an option from 1 to 6.")
            _wait_for_enter()


def main():
    """CLI Argument Parsing and execution dispatcher."""
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard CLI - Phishing Threat Analyzer for SOC Analysts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 phishguard.py
  python3 phishguard.py --url "http://192.168.1.50/login"
  python3 phishguard.py --url "http://example.com" --dns --threat-intel
  python3 phishguard.py --url "http://example.com" --json
  python3 phishguard.py --email suspicious.eml
  python3 phishguard.py --email suspicious.eml --export
  python3 phishguard.py --extract-ioc suspicious.eml --defang
  python3 phishguard.py --rules
        """
    )

    parser.add_argument("--url", type=str, help="Analyze a suspicious URL")
    parser.add_argument("--email", type=str, help="Analyze an .eml raw email file")
    parser.add_argument("--extract-ioc", type=str, help="Extract IOCs from string or file")
    parser.add_argument("--dns", action="store_true", help="Perform DNS resolution lookups (A, AAAA, MX, NS, TXT)")
    parser.add_argument("--threat-intel", "--ti", action="store_true", help="Run optional Threat Intelligence lookups (VT, URLhaus, AbuseIPDB)")
    parser.add_argument("--export", action="store_true", help="Automatically export TXT and JSON report to reports/")
    parser.add_argument("--json", action="store_true", help="Output analysis findings as raw JSON")
    parser.add_argument("--defang", action="store_true", help="Defang extracted IOCs (e.g. hxxp, [.])")
    parser.add_argument("--rules", action="store_true", help="Display all active detection engine rules")
    parser.add_argument("--export-format", choices=["json", "csv", "txt"], help="Export format for extracted IOCs")

    args = parser.parse_args()

    # Rule inspection flag
    if args.rules:
        view_detection_rules()
        sys.exit(0)

    # URL Analysis mode
    if args.url:
        handle_url_analysis(
            raw_url=args.url,
            run_dns=args.dns,
            run_ti=args.threat_intel,
            auto_export=args.export,
            json_mode=args.json,
        )
        sys.exit(0)

    # Email Analysis mode
    if args.email:
        res = handle_email_analysis(
            file_path=args.email,
            run_ti=args.threat_intel,
            auto_export=args.export,
            json_mode=args.json,
        )
        sys.exit(0 if res else 1)

    # IOC Extraction mode
    if args.extract_ioc:
        handle_ioc_extraction(
            target_input=args.extract_ioc,
            export_format=args.export_format,
            defang=args.defang,
            json_mode=args.json,
        )
        sys.exit(0)

    # Default to interactive menu if no arguments passed
    interactive_menu()


if __name__ == "__main__":
    main()
