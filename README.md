# PhishGuard CLI

## Phishing URL and Email Analyzer

PhishGuard is a Python-based command-line tool for analyzing suspicious URLs and email files.

The project is built mainly for learning and practicing practical cybersecurity concepts such as phishing detection, email analysis, IOC extraction, DNS investigation, and basic threat intelligence.

The tool runs completely from the terminal and does not require a web interface.

---

## What PhishGuard Does

PhishGuard can analyze both URLs and `.eml` email files.

For URLs, it looks at different characteristics of the URL and checks for indicators that are commonly associated with suspicious or phishing links.

For emails, it extracts information from the email headers and body, identifies links and other indicators, and checks for suspicious characteristics.

The tool does not simply return "Phishing" or "Safe". It shows the indicators that were detected and explains how they contributed to the final risk score.

---

## Features

* URL analysis
* Email (`.eml`) analysis
* IOC extraction
* Rule-based phishing detection
* Risk scoring
* DNS analysis
* Email header analysis
* SPF, DKIM and DMARC information when available
* Suspicious URL detection
* Domain and IP analysis
* Optional threat intelligence integration
* TXT and JSON report generation
* Interactive terminal interface
* Command-line arguments for automation

---

## Requirements

You need the following installed on your system:

* Python 3.10 or newer
* Git
* Internet connection for DNS and optional threat-intelligence lookups

The project can be used on:

* Kali Linux
* Ubuntu
* Debian
* Windows
* macOS

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
```

Move into the project directory:

```bash
cd phishguard
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate the environment on Linux or Kali:

```bash
source venv/bin/activate
```

On Windows:

```powershell
venv\Scripts\activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

---

## Running the Tool

Start PhishGuard using:

```bash
python3 phishguard.py
```

The tool will open an interactive menu:

```text
========================================
             PHISHGUARD CLI
      Phishing URL & Email Analyzer
========================================

[1] Analyze URL
[2] Analyze Email
[3] Extract IOCs
[4] View Detection Rules
[5] Exit

Select an option:
```

Choose the operation you want to perform.

---

## Analyzing a URL

Select:

```text
[1] Analyze URL
```

Enter the URL you want to investigate:

```text
Enter URL: https://example.com/login
```

PhishGuard checks several characteristics, including:

* URL scheme
* Domain
* Subdomain
* TLD
* URL length
* Path
* Query parameters
* IP address usage
* Punycode
* Suspicious characters
* URL encoding
* HTTP or HTTPS
* Suspicious ports
* Other detection rules

The result will contain the observations and the rules that were triggered.

Example:

```text
========================================
URL ANALYSIS
========================================

URL:
http://192.168.1.50/login

Scheme       : HTTP
Host         : 192.168.1.50
Path         : /login

----------------------------------------
DETECTION RESULTS
----------------------------------------

[HIGH] IP address used instead of domain
[MEDIUM] HTTP connection
[LOW] Login-related keyword detected

----------------------------------------
RISK ASSESSMENT
----------------------------------------

Risk Score : 72/100
Severity   : HIGH
```

The risk score is an automated assessment based on the detected indicators. It is not a guarantee that a URL is malicious.

---

## Analyzing an Email

PhishGuard can analyze `.eml` files.

Select:

```text
[2] Analyze Email
```

Then provide the path:

```text
Enter path to .eml file:
samples/suspicious_email.eml
```

The tool extracts information such as:

* Sender
* Recipient
* Reply-To
* Subject
* Date
* Message-ID
* Received headers
* Authentication information
* URLs
* Domains
* IP addresses
* Attachments
* MIME types

It can also identify suspicious relationships between the sender and Reply-To addresses.

Example:

```text
========================================
EMAIL ANALYSIS
========================================

From:
security@example.com

Reply-To:
support@example.net

Subject:
Verify Your Account

----------------------------------------
SENDER ANALYSIS
----------------------------------------

[HIGH] Reply-To domain differs from sender domain

----------------------------------------
AUTHENTICATION
----------------------------------------

SPF   : Not available
DKIM  : Pass
DMARC : Fail
```

The tool only analyzes the email. It does not execute attachments, scripts, or other active content contained inside the email.

---

## Extracting IOCs

PhishGuard can extract common Indicators of Compromise from URLs and email files.

It currently supports:

```text
URLs
Domains
IPv4 addresses
IPv6 addresses
Email addresses
MD5 hashes
SHA1 hashes
SHA256 hashes
```

Example:

```text
========================================
IOC EXTRACTION
========================================

URLs:
- https://example.com/login

Domains:
- example.com

IPv4:
- 192.168.1.10

Email Addresses:
- attacker@example.com

SHA256:
- abc123...
```

These indicators can be exported for further investigation.

---

## Command-Line Usage

PhishGuard can also be used without the interactive menu.

Analyze a URL:

```bash
python3 phishguard.py --url "https://example.com"
```

Analyze an email:

```bash
python3 phishguard.py --email suspicious.eml
```

Extract IOCs from an email:

```bash
python3 phishguard.py --extract-ioc suspicious.eml
```

Request JSON output:

```bash
python3 phishguard.py --url "https://example.com" --json
```

This makes the tool easier to use in scripts and other security workflows.

---

## Detection Engine

PhishGuard uses a rule-based detection engine.

Some of the rules include:

```text
URL001 - IP address used as hostname
URL002 - Suspicious URL length
URL003 - Punycode detected
URL004 - Suspicious port
URL005 - Excessive subdomains
URL006 - HTTP instead of HTTPS
URL007 - Suspicious URL encoding

EMAIL001 - Reply-To mismatch
EMAIL002 - Suspicious sender domain
EMAIL003 - Authentication failure
EMAIL004 - Suspicious attachment
EMAIL005 - Suspicious link
```

Each rule provides information about why it was triggered.

This approach makes the result easier to understand than using a black-box classification system.

---

## Risk Scoring

PhishGuard uses a simple risk scoring system:

|  Score | Severity      |
| -----: | ------------- |
|   0–19 | Informational |
|  20–39 | Low           |
|  40–59 | Medium        |
|  60–79 | High          |
| 80–100 | Critical      |

The score is calculated from the detection rules that were triggered.

For example:

```text
Risk Score: 67/100

URL001   +30
URL003   +20
URL006   +10
URL007   +7
```

The score should be treated as an investigation aid rather than a final security decision.

---

## DNS Analysis

PhishGuard can perform DNS lookups for domains.

The tool can check records such as:

```text
A
AAAA
MX
NS
TXT
```

Example:

```text
========================================
DNS INFORMATION
========================================

A:
93.184.216.34

AAAA:
Not available

MX:
mail.example.com

NS:
ns1.example.com
```

DNS results depend on the network and DNS servers available at the time of analysis.

---

## Threat Intelligence

PhishGuard can optionally connect to external threat-intelligence services.

Possible integrations include:

* VirusTotal
* URLhaus
* AbuseIPDB

API keys should be stored in environment variables rather than directly in the source code.

Example `.env` file:

```env
VIRUSTOTAL_API_KEY=your_api_key
URLHAUS_API_KEY=your_api_key
ABUSEIPDB_API_KEY=your_api_key
```

Do not commit the `.env` file to GitHub.

Add it to `.gitignore`:

```gitignore
.env
venv/
__pycache__/
*.pyc
```

If no API key is configured, PhishGuard continues using its local analysis features.

---

## Reports

Investigation reports can be saved in the `reports` directory.

Example:

```text
reports/
├── report_20260926_001530.txt
└── report_20260926_001530.json
```

Reports contain information such as:

* Investigation time
* Target
* Analysis type
* Detected indicators
* Risk score
* Severity
* Extracted IOCs
* DNS information
* Threat-intelligence results
* Detection rules

---

## Project Structure

```text
phishguard/
│
├── phishguard.py
│
├── analyzers/
│   ├── __init__.py
│   ├── url_analyzer.py
│   ├── email_analyzer.py
│   ├── dns_analyzer.py
│   └── ioc_extractor.py
│
├── detection/
│   ├── __init__.py
│   ├── rules.py
│   └── scoring.py
│
├── threat_intel/
│   ├── __init__.py
│   ├── virustotal.py
│   ├── urlhaus.py
│   └── abuseipdb.py
│
├── reports/
│
├── tests/
│
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Testing

Run the tests using:

```bash
pytest
```

The test suite should cover things such as:

* URL parsing
* Suspicious URL detection
* IP-based URLs
* Punycode detection
* URL encoding
* Email parsing
* Reply-To mismatch
* IOC extraction
* Risk scoring
* DNS failures
* Invalid email files

Tests should use controlled examples rather than real malicious URLs or malware.

---

## Security Considerations

PhishGuard is designed to analyze untrusted input.

The tool should never:

* Execute email attachments
* Execute JavaScript from email content
* Run downloaded files
* Expose API keys
* Automatically execute suspicious content

Network requests should use reasonable timeouts and redirects should be handled carefully.

If an email contains confidential information, consider whether sending its indicators to an external threat-intelligence service is appropriate before enabling API integrations.

---

## Example Investigation

A typical investigation might look like this:

```text
Start PhishGuard

        |
        v

Analyze Email

        |
        v

Read suspicious_email.eml

        |
        v

Extract headers, URLs and IOCs

        |
        v

Run detection rules

        |
        v

Calculate risk score

        |
        v

Perform DNS / threat-intelligence checks

        |
        v

Review findings

        |
        v

Export investigation report
```

The goal is not just to provide a final verdict, but to give the analyst enough information to understand why the email or URL was considered suspicious.

---

## Learning Goals

This project is intended to provide practical experience with:

* Python
* Email security
* HTTP and URLs
* DNS
* IOC analysis
* Threat intelligence
* Detection engineering
* Phishing analysis
* Security automation
* SOC investigation workflows

---

## Limitations

PhishGuard is not a replacement for a commercial email security gateway or a complete malware-analysis platform.

A URL can appear normal while still being malicious, and a suspicious indicator does not necessarily mean that an item is malicious.

The results should therefore be treated as supporting evidence for an investigation.

---

## Disclaimer

PhishGuard is intended for educational and defensive cybersecurity purposes.

Only analyze URLs, emails, systems, and data that you are authorized to investigate.

The tool provides automated analysis and should not be treated as a definitive security verdict.

---

## Author

Kunal

Cybersecurity Student
Interested in SOC, Blue Team and Security Research
