# PhishGuard CLI

> **A Command-Line Phishing URL & Email Analyzer for SOC Analysts and Cybersecurity Students.**

PhishGuard CLI is a terminal-based defensive security inspection tool that performs static analysis, heuristic risk scoring, artifact extraction, and threat intelligence lookups on suspicious URLs and raw `.eml` email files. Built specifically for Linux, Kali Linux, and security triage workstations, it adheres to defensive cybersecurity best practices: **zero execution of untrusted payloads, zero fake data, full transparency in scoring, and lightweight terminal-first design.**

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture & Directory Structure](#architecture--directory-structure)
- [Installation & Setup](#installation--setup)
- [Quick Start & Usage](#quick-start--usage)
  - [Interactive Menu Mode](#interactive-menu-mode)
  - [Command-Line Mode (CLI Flags)](#command-line-mode-cli-flags)
- [Detection Engine & Rules](#detection-engine--rules)
- [Risk Scoring Methodology](#risk-scoring-methodology)
- [IOC Extraction & Defanging](#ioc-extraction--defanging)
- [DNS Analysis](#dns-analysis)
- [Optional Threat Intelligence](#optional-threat-intelligence)
- [Report Generation](#report-generation)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Limitations & Disclaimers](#limitations--disclaimers)

---

## Overview

Security Operations Center (SOC) analysts and incident responders routinely encounter suspicious links and phishing reports. Running untrusted URLs or opening suspicious email attachments directly in a browser or desktop client introduces significant risk of exploitation or tracking.

**PhishGuard CLI** solves this by providing:
1. **Local Static URL Deconstruction**: Dissects protocol, authority, ports, paths, query tokens, and identifies deceptive patterns (IP hosts, homographs, userinfo obfuscations, high-risk TLDs).
2. **Safe MIME Email Parsing**: Audits headers, verifies email authentication (`SPF`, `DKIM`, `DMARC`), inspects attachment metadata/hashes, and parses text/HTML safely without executing JavaScript or rendering active content.
3. **Transparent Heuristic Risk Scoring**: Calculates a transparent 0–100 score where every point is attributed to a specific detection rule.
4. **Standardized IOC Extraction**: Identifies and deduplicates IPv4, IPv6, URLs, domains, emails, and cryptographic hashes (MD5, SHA1, SHA256), with one-click defanging (`hxxp://`, `[.]`) and export to JSON, CSV, or TXT.

---

## Key Features

- **100% Terminal-Based**: No web servers, no frameworks, no database engines.
- **Defensive Safety by Design**: Untrusted input is sanitized; attachments and JavaScript are never executed.
- **Authentic Verification**: SPF, DKIM, and DMARC results are extracted strictly from RFC authentication headers—never faked or guessed.
- **Extensible Detection Rule Engine**: Easily add new rules without altering core business logic.
- **Defanged IOC Sharing**: Export sanitized IOCs ready for ticketing systems, threat feeds, or SIEM ingestion.
- **Multi-Format Reporting**: Detailed reports in both human-readable plain text (`.txt`) and automated machine ingestion (`.json`).
- **Optional Real Threat Intelligence**: Integrates seamlessly with VirusTotal (v3), URLhaus, and AbuseIPDB when API keys are supplied.

---

## Architecture & Directory Structure

```text
phishguard/
│
├── phishguard.py               # Main CLI entrypoint (Interactive menu & argparse dispatcher)
│
├── analyzers/                  # Analysis and extraction modules
│   ├── __init__.py
│   ├── url_analyzer.py         # URL component parsing & heuristic detection
│   ├── email_analyzer.py       # MIME email parser, auth header audit, attachment safety
│   ├── dns_analyzer.py         # Live DNS resolver (A, AAAA, MX, NS, TXT)
│   ├── ioc_extractor.py        # IOC identification, defanging, multi-format export
│   └── report_generator.py     # TXT and JSON report generation engine
│
├── detection/                  # Heuristic engine & scoring
│   ├── __init__.py
│   ├── rules.py                # Rule definitions, registries, and detection results
│   └── scoring.py              # Transparent score calculation and factor attribution
│
├── threat_intel/               # Threat intelligence clients
│   ├── __init__.py
│   ├── virustotal.py           # VirusTotal v3 API client
│   ├── urlhaus.py              # Abuse.ch URLhaus API client
│   └── abuseipdb.py            # AbuseIPDB API v2 client
│
├── examples/                   # Safe sample test files
│   ├── suspicious.eml          # Simulated phishing email with headers and attachment
│   └── legitimate.eml          # Baseline clean email
│
├── reports/                    # Generated forensic reports
│
├── tests/                      # Automated unit test suite
│   ├── test_url_analyzer.py
│   ├── test_email_analyzer.py
│   ├── test_ioc_extractor.py
│   ├── test_rules_scoring.py
│   ├── test_dns_analyzer.py
│   └── test_report_generator.py
│
├── requirements.txt            # Python dependencies
├── .env.example                # Template for optional API keys
├── .gitignore
└── README.md
```

---

## Installation & Setup

### Requirements
- Linux (Ubuntu, Debian, Kali Linux, Arch) or macOS / Windows
- Python 3.9+

### Step 1: Clone or Navigate to Directory
```bash
cd phishguard
```

### Step 2: Create a Virtual Environment (Recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate    # On Linux/macOS
# or: .venv\Scripts\activate # On Windows PowerShell
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Threat Intelligence (Optional)
If you wish to query VirusTotal, URLhaus, or AbuseIPDB:
```bash
cp .env.example .env
```
Edit `.env` with your API keys:
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLHAUS_API_KEY=your_urlhaus_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```
> **Note**: If API keys are omitted or left blank, PhishGuard skips external lookups gracefully and relies purely on local static heuristics.

---

## Quick Start & Usage

### Interactive Menu Mode

Run without arguments to launch the interactive terminal interface:

```bash
python3 phishguard.py
```

Output:
```text
========================================
          PHISHGUARD CLI
     Phishing Threat Analyzer
========================================

[1] Analyze URL
[2] Analyze Email (.eml)
[3] Extract IOCs
[4] View Detection Rules
[5] Export Report
[6] Exit

Select an option:
```

---

### Command-Line Mode (CLI Flags)

PhishGuard supports direct, non-interactive execution for automation, scripting, and pipeline integration:

#### 1. Analyze a Suspicious URL
```bash
python3 phishguard.py --url "http://192.168.1.50/login"
```

#### 2. Analyze URL with Live DNS & Threat Intelligence
```bash
python3 phishguard.py --url "http://example.com" --dns --threat-intel
```

#### 3. Analyze an `.eml` Email File and Export Report
```bash
python3 phishguard.py --email examples/suspicious.eml --export
```

#### 4. Extract and Defang IOCs from Text or File
```bash
python3 phishguard.py --extract-ioc examples/suspicious.eml --defang
```

#### 5. Output Raw JSON for SIEM / Scripting Ingestion
```bash
python3 phishguard.py --url "http://192.168.1.50/login" --json
```

#### 6. Inspect Detection Rules
```bash
python3 phishguard.py --rules
```

---

## Example Terminal Output

### 1. URL Analysis

```text
========================================
URL ANALYSIS
========================================

URL:
http://192.168.1.50:8080/login/verification?user=target

Scheme       : HTTP
Host         : 192.168.1.50
Domain       : 192.168.1.50
Subdomain    : None
TLD          : N/A
Port         : 8080
Path         : /login/verification
URL Length   : 55
Query Params : user=target

----------------------------------------
DETECTION RESULTS
----------------------------------------

[HIGH] IP address used as hostname
       Evidence: Host '192.168.1.50' is a raw IPv4 address instead of a domain name.
[MEDIUM] Suspicious or non-standard port
       Evidence: URL uses non-standard web port '8080'.
[LOW] HTTP instead of HTTPS
       Evidence: Insecure plaintext protocol 'HTTP' used instead of HTTPS.
[LOW] Suspicious phishing keyword
       Evidence: Contains phishing/credential harvesting keywords: login, verification.

----------------------------------------
RISK ASSESSMENT
----------------------------------------

Risk Score : 65/100
Severity   : HIGH

Reason:
Multiple suspicious indicators were detected.

Contributing factors:
  URL001   +30  (IP address used as hostname)
  URL004   +15  (Suspicious or non-standard port)
  URL006   +10  (HTTP instead of HTTPS)
  URL009   +10  (Suspicious phishing keyword)

[NOTE] This is an automated risk assessment based on static heuristics and indicators.
It does not constitute definitive proof that the target is malicious, nor does a low
score guarantee safety. Always verify with sandbox analysis and threat intelligence.
```

---

### 2. Email Analysis

```text
========================================
EMAIL ANALYSIS
========================================

File      : examples/suspicious.eml
From      : PayPal Account Security <service-alert@notify-paypal-security-update.com>
Reply-To  : credential-collector@stealth-exfil.net
To        : target-analyst@security-operations.org
Subject   : Urgent Action Required: Your account has been suspended!
Date      : Fri, 25 Sep 2026 14:32:00 +0000
Message-ID: <20260925.143200.999@notify-paypal-security-update.com>

----------------------------------------
AUTHENTICATION
----------------------------------------

SPF   : Fail
DKIM  : Neutral
DMARC : Fail

----------------------------------------
EXTRACTED URLS
----------------------------------------

1. http://192.168.1.50:8080/login/verification?user=target&token=a83f9829f01b44ec

----------------------------------------
ATTACHMENTS
----------------------------------------

- verification_portal.html (application/octet-stream, 68 bytes) [!] HIGH RISK
    SHA256: 3711134933b3dd8c5672551a526b00802cd8219b86b68707117e47b4b03c7650
    Alert : High-risk file extension '.html' commonly abused for malware delivery or credential harvesting.

----------------------------------------
DETECTION RESULTS
----------------------------------------

[HIGH] Reply-To mismatch
       Evidence: Reply-To domain 'stealth-exfil.net' does not match From domain 'notify-paypal-security-update.com'.
[HIGH] Email authentication failure
       Evidence: Explicit authentication verification failure: SPF (Fail), DMARC (Fail).
[HIGH] Suspicious or dangerous attachment
       Evidence: Contains potentially dangerous attachment(s): verification_portal.html (.html).
[MEDIUM] Suspicious link in email body
       Evidence: Suspicious links detected: IP-based URL: http://192.168.1.50:8080/login/verification...
[LOW] Phishing urgency or credential keywords
       Evidence: Detected urgent phishing sentiment keywords: urgent, immediately, unauthorized access.
[MEDIUM] Return-Path domain mismatch
       Evidence: Return-Path domain 'bad-relay-domain.org' differs from sender domain 'notify-paypal-security-update.com'.

----------------------------------------
RISK ASSESSMENT
----------------------------------------

Risk Score : 100/100
Severity   : CRITICAL

Reason:
Multiple suspicious indicators were detected.

Contributing factors:
  EMAIL001 +30  (Reply-To mismatch)
  EMAIL003 +25  (Email authentication failure)
  EMAIL004 +30  (Suspicious or dangerous attachment)
  EMAIL005 +20  (Suspicious link in email body)
  EMAIL006 +10  (Phishing urgency or credential keywords)
  EMAIL008 +15  (Return-Path domain mismatch)
```

---

## Detection Engine & Rules

PhishGuard employs a modular rule architecture in `detection/rules.py`. Every rule contains a unique Rule ID, category, severity rating, point score, and description.

| Rule ID | Category | Severity | Score | Name | Description |
|:---|:---:|:---:|:---:|:---|:---|
| **URL001** | URL | HIGH | +30 | IP address used as hostname | Raw IPv4 or IPv6 used instead of domain name |
| **URL002** | URL | MEDIUM | +15 | Suspicious URL length | URL length exceeds standard threshold (>75 chars) |
| **URL003** | URL | HIGH | +25 | Punycode / IDN homograph detected | Hostname contains `xn--` or non-ASCII homoglyphs |
| **URL004** | URL | MEDIUM | +15 | Suspicious or non-standard port | Web traffic over unusual ports (8080, 8443, 8888, 4444) |
| **URL005** | URL | MEDIUM | +15 | Excessive subdomains | More than 3 subdomain labels concealing root domain |
| **URL006** | URL | LOW | +10 | HTTP instead of HTTPS | Unencrypted plaintext transport protocol |
| **URL007** | URL | LOW | +10 | Suspicious URL encoding | Heavy percent-encoding concealing dots, slashes, or script |
| **URL008** | URL | HIGH | +25 | Embedded credentials (@ symbol) | Authority contains `@` tricking human visual inspection |
| **URL009** | URL | LOW | +10 | Suspicious phishing keyword | Path, query, or subdomain contains login/verify/account |
| **URL010** | URL | LOW | +10 | Suspicious high-risk TLD | Uses heavily abused TLD (.tk, .ml, .xyz, .top, .work) |
| **URL011** | URL | HIGH | +30 | IP obfuscation (Hex/Octal/Dword) | Numeric representation bypasses naive string filters |
| **URL012** | URL | MEDIUM | +15 | Double-slash / open redirect path | Multiple slashes or embedded protocol in path |
| **URL013** | URL | HIGH | +25 | Dangerous file extension | Link points to executable (.exe, .scr, .iso, .vbs) |
| **URL014** | URL | LOW | +10 | Brand impersonation hyphenation | Domain contains multiple hyphens mimicking brands |
| **EMAIL001** | EMAIL | HIGH | +30 | Reply-To mismatch | Reply-To domain differs from From header domain |
| **EMAIL002** | EMAIL | HIGH | +25 | Sender display name spoofing | Display name references different domain than sender |
| **EMAIL003** | EMAIL | HIGH | +25 | Email authentication failure | SPF, DKIM, or DMARC explicitly reports Fail or SoftFail |
| **EMAIL004** | EMAIL | HIGH | +30 | Dangerous attachment | Attachment is executable, script, archive, or HTML form |
| **EMAIL005** | EMAIL | MEDIUM | +20 | Suspicious link in email body | Body contains IP-based links or deceptive anchors |
| **EMAIL006** | EMAIL | LOW | +10 | Phishing urgency keywords | Urgent pressure tactics ("account suspended", "verify now") |
| **EMAIL007** | EMAIL | LOW | +10 | Missing standard email headers | Missing RFC headers such as Message-ID or Date |
| **EMAIL008** | EMAIL | MEDIUM | +15 | Return-Path domain mismatch | Envelope Return-Path contradicts From domain |

---

## Risk Scoring Methodology

Risk scores are computed transparently by summing points from all triggered rules, capped at 100:

| Score Range | Severity Tier | Action Guideline |
|:---:|:---:|:---|
| **0 – 19** | `INFORMATIONAL` | Standard benign indicators; baseline activity |
| **20 – 39** | `LOW` | Minor anomalies detected; review context |
| **40 – 59** | `MEDIUM` | Multiple suspicious signals; recommend manual review |
| **60 – 79** | `HIGH` | Strong phishing indicators; isolate and escalate |
| **80 – 100** | `CRITICAL` | Severe threat indicators confirmed; block and contain |

Every analysis explicitly attributes which rules contributed points to the total score.

---

## IOC Extraction & Defanging

PhishGuard includes an IOC engine capable of extracting and sanitizing:
- **IPv4 & IPv6 Addresses**
- **URLs**
- **Domains & FQDNs**
- **Email Addresses**
- **Cryptographic Hashes**: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)

### Defanging
To prevent accidental clicks or weaponization when sharing IOCs in tickets:
- `http://` ➔ `hxxp://`
- `https://` ➔ `hxxps://`
- `.` ➔ `[.]`
- `@` ➔ `[@]`

### Multi-Format Export
Export IOCs in standard formats:
- **JSON**: Structured key-value arrays
- **CSV**: Two-column format (`ioc_type`, `value`) for Excel / SIEM loaders
- **TXT**: Sectioned lists formatted for plain text notes

---

## DNS Analysis

For target domains, PhishGuard queries standard authoritative DNS records via `dnspython`:
- **A** (IPv4 addresses)
- **AAAA** (IPv6 addresses)
- **MX** (Mail Exchange servers and priorities)
- **NS** (Name servers)
- **TXT** (SPF records, domain verification records)

Failures, timeouts, and NXDOMAIN conditions are caught and handled gracefully without crashing the analyzer.

---

## Optional Threat Intelligence

PhishGuard can query live external reputation providers without storing keys in code:
- **VirusTotal (v3 API)**: Domain, IP, and URL reputation stats.
- **URLhaus (Abuse.ch API)**: Active malware URL database status and tags.
- **AbuseIPDB (v2 API)**: IP abuse confidence score and incident report count.

> **Integrity Guarantee**: When keys are missing or services are unreachable, PhishGuard clearly states `[INFO] Threat intelligence lookup skipped. API key not configured.` It **never** creates synthetic or fake results.

---

## Report Generation

Reports are automatically stored in the `reports/` folder with timestamped filenames:
- `reports/report_YYYYMMDD_HHMMSS.txt`: Complete human-readable SOC incident report.
- `reports/report_YYYYMMDD_HHMMSS.json`: Machine-readable forensic payload containing all raw components, triggered rules, scores, extracted IOCs, and DNS data.

---

## Security Considerations

As a defensive tool inspecting potentially untrusted content, PhishGuard adheres to strict defensive programming:
1. **No Code Execution**: HTML email bodies are parsed with Python's streaming `html.parser`. Embedded JavaScript, stylesheets, and external assets are stripped and never executed.
2. **Safe Attachment Handling**: Attachments are inspected strictly in-memory or streamed as byte arrays to calculate hashes and detect MIME types. They are never written to executable locations or executed.
3. **DoS Prevention**: Strict file size limits (25MB max for `.eml` files, 5MB for text IOC inputs) prevent resource exhaustion.
4. **Network Safety**: DNS lookups have a 3-second timeout and 5-second lifetime limit. External HTTP threat intelligence lookups enforce strict 6-second timeouts.
5. **Credential Protection**: API keys are loaded via environment variables and `.env` files; they are never printed in cleartext in generated reports.

---

## Testing

PhishGuard includes an automated unit test suite covering normal inputs, edge cases, malformed data, and attacks:

```bash
# Run all unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Test coverage includes:
- Normal, clean URLs
- IP-based URLs and obfuscated IP representations (Hex, Octal, DWORD)
- Punycode / IDN homograph URLs
- Extremely long URLs and excessive subdomains
- Dangerous file extensions and non-standard web ports
- Normal emails with verified SPF/DKIM/DMARC
- Phishing emails with Reply-To mismatch, display name spoofing, and failed authentication
- Emails with dangerous attachments (`.html`, `.hta`, `.exe`)
- Malformed `.eml` files
- IOC extraction across all 8 data types, defanging, and export
- Risk scoring bounds, severity classification, and score capping
- DNS resolution exception handling
- Threat intelligence error and unconfigured states

---

## Limitations & Disclaimers

1. **Automated Heuristic Assessment**: Static heuristic scoring provides rapid prioritization for triage. A low score does not guarantee absolute safety (e.g., zero-day phishing on a newly registered benign service).
2. **Encrypted Attachments**: Password-protected archives (e.g., `.zip` with password) cannot be inspected internally by static analysis alone.
3. **Legitimate Use**: Designed for defensive cybersecurity analysis, SOC incident response, and academic educational training.

---

## License

MIT License. Developed for SOC analysts, incident response teams, and cybersecurity students.
