"""
Report Generator for PhishGuard CLI.

Generates structured JSON and professional plain-text SOC analysis reports
saved with timestamped filenames in the reports/ directory.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Tuple, Optional


class ReportGenerator:
    """Creates formatted forensic reports in TXT and JSON formats."""

    @staticmethod
    def generate(
        analysis_type: str,
        target: str,
        extracted_info: Dict[str, Any],
        detection_results: list,
        risk_assessment: Dict[str, Any],
        iocs: Dict[str, Any],
        dns_info: Optional[Dict[str, Any]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
        output_dir: str = "reports",
    ) -> Tuple[str, str]:
        """
        Generates timestamped TXT and JSON reports.
        Returns paths: (txt_path, json_path).
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        iso_timestamp = datetime.now().isoformat()

        report_payload = {
            "metadata": {
                "tool": "PhishGuard CLI",
                "version": "1.0.0",
                "timestamp": iso_timestamp,
                "analysis_type": analysis_type,
                "target": target,
            },
            "risk_assessment": risk_assessment,
            "detections": detection_results,
            "extracted_information": extracted_info,
            "iocs": iocs,
            "dns_information": dns_info or {},
            "threat_intelligence": threat_intel or {},
        }

        # 1. Write JSON Report
        json_filename = f"report_{timestamp_str}.json"
        json_path = os.path.join(output_dir, json_filename)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)

        # 2. Write TXT Report
        txt_filename = f"report_{timestamp_str}.txt"
        txt_path = os.path.join(output_dir, txt_filename)

        lines = []
        lines.append("=" * 60)
        lines.append("                 PHISHGUARD ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"Target         : {target}")
        lines.append(f"Analysis Type  : {analysis_type.upper()}")
        lines.append(f"Generated At   : {iso_timestamp}")
        lines.append(f"Report ID      : PG-{timestamp_str}")
        lines.append("-" * 60)

        # Risk Assessment
        lines.append("RISK ASSESSMENT")
        lines.append("-" * 60)
        score = risk_assessment.get("score", 0)
        severity = risk_assessment.get("severity", "INFORMATIONAL")
        lines.append(f"Risk Score     : {score}/100")
        lines.append(f"Severity Tier  : {severity}")
        lines.append("")
        lines.append("Contributing Factors:")
        for factor in risk_assessment.get("contributing_factors", []):
            lines.append(f"  [{factor.get('rule_id')}] +{factor.get('score')} pts : {factor.get('name')}")
            lines.append(f"       Evidence: {factor.get('evidence')}")
        lines.append("")
        lines.append(f"Assessment Notice:\n  {risk_assessment.get('disclaimer', '')}")
        lines.append("-" * 60)

        # Extracted Information
        lines.append("EXTRACTED TARGET METADATA")
        lines.append("-" * 60)
        for k, v in extracted_info.items():
            if isinstance(v, (list, dict)):
                lines.append(f"{k.capitalize()}:")
                if isinstance(v, list):
                    for item in v[:10]:
                        lines.append(f"  - {item}")
                    if len(v) > 10:
                        lines.append(f"  ... ({len(v) - 10} more)")
                else:
                    for sub_k, sub_v in v.items():
                        lines.append(f"  {sub_k}: {sub_v}")
            else:
                lines.append(f"{k.capitalize():<18}: {v}")
        lines.append("-" * 60)

        # DNS Information
        if dns_info:
            lines.append("DNS RESOLUTION")
            lines.append("-" * 60)
            for rtype in ["a", "aaaa", "mx", "ns", "txt"]:
                val = dns_info.get(rtype, "Not available")
                lines.append(f"{rtype.upper():<6}:")
                if isinstance(val, list):
                    for item in val:
                        lines.append(f"  {item}")
                else:
                    lines.append(f"  {val}")
            lines.append("-" * 60)

        # Threat Intelligence
        if threat_intel:
            lines.append("THREAT INTELLIGENCE RESULTS")
            lines.append("-" * 60)
            for provider, res in threat_intel.items():
                lines.append(f"[{provider.upper()}]")
                if isinstance(res, dict):
                    status = res.get("status")
                    if status == "success":
                        for pk, pv in res.items():
                            if pk not in ("status", "provider"):
                                lines.append(f"  {pk}: {pv}")
                    elif status == "skipped":
                        lines.append(f"  [INFO] {res.get('message', 'Skipped')}")
                    elif status == "not_found":
                        lines.append(f"  [INFO] {res.get('message', 'Not found in dataset')}")
                    else:
                        lines.append(f"  Status: {status} - {res.get('message', '')}")
                lines.append("")
            lines.append("-" * 60)

        # Extracted IOCs
        lines.append("EXTRACTED INDICATORS OF COMPROMISE (IOCs)")
        lines.append("-" * 60)
        for ioc_cat, items in iocs.items():
            if items:
                lines.append(f"{ioc_cat.upper()}:")
                for item in items:
                    lines.append(f"  - {item}")
        lines.append("=" * 60)
        lines.append("End of Report")
        lines.append("=" * 60)

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return txt_path, json_path
